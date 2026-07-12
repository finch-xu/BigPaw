//! 连接管理:监听 accept + 出站连接缓存(每对端一条,失败重拨一次)。
//! 同步 IO,每连接一个读线程;写路径由调用方线程直接写(Mutex 串行)。

use crate::identity::Identity;
use crate::transport::proto::{self, Msg};
use crate::transport::tls;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_PORT: u16 = 24917;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("tls: {0}")]
    Tls(#[from] tls::TlsError),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("对端无可用地址")]
    NoAddress,
}

#[derive(Debug, Clone)]
pub struct MessageEvent {
    pub peer_fp: String,
    pub id: String,
    pub body: String,
    pub ts_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SentText {
    pub id: String,
    pub ts_ms: u64,
}

type ClientTls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
type ServerTls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

pub struct TransportManager {
    identity: Arc<Identity>,
    port: u16,
    /// 出站连接缓存:peer_fp -> 已握手连接(写侧)。M2 简化:出站连接只写不读,
    /// 对端的回话走它自己的出站连接(见下方 `dial` 注释)。
    outbound: Mutex<HashMap<String, ClientTls>>,
    events: Sender<MessageEvent>,
    /// 已接受入站连接的裸 TCP 克隆,供析构时强制断开(见 `Drop` 实现注释)。
    /// 键为自增连接 id;连接自然结束时由自己的读线程摘除。
    inbound_socks: Mutex<HashMap<u64, TcpStream>>,
    next_conn_id: AtomicU64,
}

impl TransportManager {
    pub fn start(
        identity: Arc<Identity>,
        preferred_port: u16,
        events: Sender<MessageEvent>,
    ) -> Result<Arc<Self>, TransportError> {
        let listener = match TcpListener::bind(("0.0.0.0", preferred_port)) {
            Ok(l) => l,
            // 首选端口被占(比如另一个实例):回退临时端口,实际端口经发现层广播
            Err(_) if preferred_port != 0 => TcpListener::bind(("0.0.0.0", 0))?,
            Err(e) => return Err(e.into()),
        };
        let port = listener.local_addr()?.port();
        let mgr = Arc::new(Self {
            identity: identity.clone(),
            port,
            outbound: Mutex::new(HashMap::new()),
            events,
            inbound_socks: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
        });

        let server_cfg = tls::server_config(&identity)?;
        let accept_mgr = Arc::downgrade(&mgr);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Some(mgr) = accept_mgr.upgrade() else {
                    break;
                };
                let Ok(tcp) = stream else { continue };
                let cfg = server_cfg.clone();
                let events = mgr.events.clone();
                let conn_id = mgr.next_conn_id.fetch_add(1, Ordering::Relaxed);
                if let Ok(clone) = tcp.try_clone() {
                    mgr.inbound_socks
                        .lock()
                        .expect("inbound lock")
                        .insert(conn_id, clone);
                }
                // 只在注册期间借用强引用;进入阻塞读循环前必须释放它——否则
                // 常驻的读线程会让 manager 永远无法把强引用计数降到 0,
                // Drop 就再也不会触发,断连重启时旧连接永远不会被强制关闭。
                let cleanup_mgr: Weak<Self> = Arc::downgrade(&mgr);
                drop(mgr);
                std::thread::spawn(move || {
                    let cleanup = || {
                        if let Some(mgr) = cleanup_mgr.upgrade() {
                            mgr.inbound_socks
                                .lock()
                                .expect("inbound lock")
                                .remove(&conn_id);
                        }
                    };
                    let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                        cleanup();
                        return;
                    };
                    // 未发 Hello 的连接不能无限占用线程/套接字:握手阶段设读超时。
                    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                    let mut tls_stream = rustls::StreamOwned::new(conn, tcp);
                    // 等待 Hello 完成握手并确认协议
                    let Ok(Msg::Hello { .. }) = proto::read_msg(&mut tls_stream) else {
                        cleanup();
                        return;
                    };
                    let Some(peer_fp) = tls::peer_fingerprint(&tls_stream.conn) else {
                        cleanup();
                        return;
                    };
                    // Hello 已收到,进入长连接读取阶段:取消握手期超时。
                    let _ = tls_stream.get_ref().set_read_timeout(None);
                    Self::read_loop(&events, peer_fp, &mut tls_stream);
                    cleanup();
                });
            }
        });
        Ok(mgr)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 服务端连接的读循环。M2 简化决策:出站连接只写不回读(对端回话走它自己
    /// 的出站连接),所以这里只需要服务端 `StreamOwned` 类型,不必对
    /// Server/Client 两种连接做泛型抽象。不是 `&self` 方法——见调用处注释,
    /// 读线程不持有 manager 的强引用,只借用事件 Sender(可独立于 manager 存活)。
    fn read_loop(events: &Sender<MessageEvent>, peer_fp: String, tls_stream: &mut ServerTls) {
        loop {
            match proto::read_msg(tls_stream) {
                Ok(Msg::Text { id, body, ts_ms }) => {
                    let ev = MessageEvent {
                        peer_fp: peer_fp.clone(),
                        id,
                        body,
                        ts_ms,
                    };
                    if events.send(ev).is_err() {
                        return;
                    }
                }
                Ok(Msg::Hello { .. }) => continue,
                Err(_) => return, // 断连/坏帧:退出读循环
            }
        }
    }

    fn dial(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
    ) -> Result<ClientTls, TransportError> {
        let cfg = tls::client_config(&self.identity, peer_fp)?;
        let mut last: Option<io::Error> = None;
        for ip in addrs {
            let sa = SocketAddr::new(*ip, port);
            match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
                Ok(tcp) => {
                    tcp.set_nodelay(true).ok();
                    let name = ServerName::try_from("bigpaw").expect("static name");
                    match rustls::ClientConnection::new(cfg.clone(), name) {
                        Ok(conn) => {
                            let mut tls_stream = rustls::StreamOwned::new(conn, tcp);
                            match proto::write_msg(
                                &mut tls_stream,
                                &Msg::Hello { v: proto::PROTO_V },
                            ) {
                                Ok(()) => {
                                    // 对称:也从出站连接收消息(对端可能沿此连接回话)
                                    // 读线程需要独立的流——TcpStream 可 try_clone,TLS 状态不可,
                                    // 因此 M2 出站连接只写不读;对端回话走它自己的出站连接。
                                    return Ok(tls_stream);
                                }
                                Err(e) => last = Some(e),
                            }
                        }
                        Err(e) => last = Some(io::Error::other(e)),
                    }
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last
            .map(TransportError::Io)
            .unwrap_or(TransportError::NoAddress))
    }

    /// 探测缓存连接是否已死。
    ///
    /// 单次 `write()` 不足以可靠探测"对端已完全关闭"的连接:经验证(见断线
    /// 重连集成测试),往一个已被对端 `shutdown`+关闭的 socket 写入,第一次
    /// 往往仍返回 `Ok`——数据其实已经丢了,只有*下一次*写入才会报错,但那时
    /// 消息早已发不出去。
    ///
    /// 直接在裸 TCP 层 `peek` 也不可靠:TLS 1.3 握手后服务端通常会自动发
    /// `NewSessionTicket` 记录,这些字节会静静地躺在客户端内核收缓冲区里
    /// (因为出站连接按设计只写不读),`peek` 会先看到它们而不是后面可能
    /// 紧跟着的 FIN,造成误判"仍存活"。正确做法是通过 TLS 层的 `read()`
    /// 把这些握手层记录喂给 rustls 处理掉(不产生应用层数据),直到确实
    /// 没有更多数据(`WouldBlock`,连接存活)或读到干净 EOF/错误(连接已
    /// 死)为止。若收到应用层数据,则为协议违反(出站连接只写不读),
    /// 视连接为可疑,强制重拨。
    fn conn_is_dead(conn: &mut ClientTls) -> bool {
        if conn.sock.set_nonblocking(true).is_err() {
            return false; // 无法探测:乐观放行,交给写失败兜底
        }
        let mut buf = [0u8; 256];
        let dead = match io::Read::read(conn, &mut buf) {
            Ok(0) => true,                                            // 干净 EOF:已死
            Ok(_) => true, // 收到应用数据:协议违反(出站连接只写),强制重拨
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false, // 无更多数据:仍存活
            Err(_) => true, // 其他错误:视为已死
        };
        let _ = conn.sock.set_nonblocking(false);
        dead
    }

    pub fn send_text(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
        body: &str,
    ) -> Result<SentText, TransportError> {
        let msg = Msg::Text {
            id: proto::new_id(),
            body: body.to_string(),
            ts_ms: proto::now_ms(),
        };
        let (id, ts_ms) = match &msg {
            Msg::Text { id, ts_ms, .. } => (id.clone(), *ts_ms),
            _ => unreachable!(),
        };

        // 改进点(相对 brief 参考实现):不在 dial() 期间持锁——dial 涉及网络
        // IO(连接超时可达 CONNECT_TIMEOUT),持锁会阻塞其他对端的并发发送。
        // 策略:先在短锁范围内尝试缓存连接;miss/失败则释放锁、在锁外 dial,
        // 写入成功后才重新加锁插入缓存。

        // 1) 尝试缓存连接(短锁,仅覆盖一次存活探测 + 一次写操作)。
        let cached_write_ok = {
            let mut cache = self.outbound.lock().expect("outbound lock");
            match cache.get_mut(peer_fp) {
                Some(conn) => {
                    let alive = !Self::conn_is_dead(conn);
                    if alive && proto::write_msg(conn, &msg).is_ok() {
                        true
                    } else {
                        cache.remove(peer_fp);
                        false
                    }
                }
                None => false,
            }
        };
        if cached_write_ok {
            return Ok(SentText { id, ts_ms });
        }

        // 2) 缓存 miss 或写失败:锁外重拨,避免持锁跨越网络 IO。
        let mut fresh = self.dial(peer_fp, addrs, port)?;
        proto::write_msg(&mut fresh, &msg)?;

        // 3) 写成功后再加锁插入缓存。
        let mut cache = self.outbound.lock().expect("outbound lock");
        cache.insert(peer_fp.to_string(), fresh);
        Ok(SentText { id, ts_ms })
    }
}

impl Drop for TransportManager {
    /// 强制断开所有当前存活的入站连接。
    ///
    /// 读线程不持有 manager 的强引用(见 `start` 中的注释),所以就算某个
    /// 对端的连接仍在阻塞读取,manager 本身也能正常降到 0 强引用并触发这里。
    /// 但反过来,如果不主动断开这些连接,对端(缓存写侧持有旧连接的一方)
    /// 永远不会发现连接已经"逻辑上"作废——直到操作系统层面真正关闭
    /// socket,对端的下一次写入才会失败并触发它自己的重拨逻辑。这正是
    /// "断线重连"集成测试要求的语义:manager 重启后,旧连接必须全部失效。
    fn drop(&mut self) {
        if let Ok(socks) = self.inbound_socks.lock() {
            for s in socks.values() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

//! 连接管理:监听 accept + 出站连接缓存(每对端一条,失败重拨一次)。
//! 同步 IO,每连接一个读线程;写路径由调用方线程直接写(Mutex 串行)。
//!
//! **文件传输设计注记**(M3):数据连接由**发送方主动拨号**——和消息连接
//! 同一个方向。控制帧(FileOffer/FileAccept/FileReject)走一条专用的
//! "offer 控制连接"(发送方 `dial()`,接收方走已有 accept-loop);数据字节
//! 走另一条**全新**的连接,首帧直接是 `FileStart{xfer_id, offset}`(没有
//! `Hello`)。接收方的 accept-loop 因此要对每条新连接的**第一帧**做分流:
//! `Hello` → 走原有的消息 read_loop;`FileStart` → 转入文件接收分支。
//!
//! 控制连接的回复(FileAccept/FileReject)必须从接收方"写回"到发送方,但
//! `respond_file` 是在任意调用方线程上被调用的,而真正持有该连接
//! `&mut ServerTls` 的是 accept-loop 为它开的读线程。为避免"跨阻塞 IO 持锁"
//! (见下面 `conn_is_dead` 的教训),两者之间**不共享一把锁**,而是用一条
//! `mpsc::channel`:`respond_file` 把决定塞进去,读线程原本阻塞在
//! `read_msg` 上处理完 FileOffer 后,转为阻塞在 `reply_rx.recv()` 上,
//! 唤醒后由**自己**(唯一持有该连接的线程)执行写回。manager 整体被 drop
//! 时,`pending_offers` 连带其中的 `reply_tx` 一起被丢弃,`recv()` 会立刻
//! 收到 `Err` 从而让该线程正常退出,不会永久悬挂。

use crate::identity::Identity;
use crate::net_ifaces::{self, IfaceSnapshot};
use crate::transport::filexfer;
use crate::transport::proto::{self, Msg};
use crate::transport::tls;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::watch;

pub const DEFAULT_PORT: u16 = 24917;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 进度事件节流间隔:两次 FileProgress 之间至少间隔这么久,末尾 done==total 除外。
const PROGRESS_THROTTLE: Duration = Duration::from_millis(150);

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
    /// 会话 id:单聊=对端指纹,群聊(M7c)=group_id。
    pub peer_fp: String,
    pub id: String,
    pub body: String,
    pub ts_ms: u64,
    /// 群消息的发送者指纹(M7c,TLS 层验证过);单聊恒为 None。
    pub sender_fp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SentText {
    pub id: String,
    pub ts_ms: u64,
}

/// `TransportManager` 对外上报的所有事件:既有的文本消息,也有 M3 新增的
/// 文件传输生命周期事件。
#[derive(Debug, Clone)]
pub enum TransportEvent {
    Message(MessageEvent),
    FileOffered {
        xfer_id: String,
        peer_fp: String,
        name: String,
        size: u64,
        /// 是否为文件夹报价(M5 IPMsg 兼容层新增,设计文档 §6):原生传输目前
        /// 只支持单文件,恒为 `false`;ipmsg 一侧的 `forward_ipmsg_event` 会
        /// 按 `IpmsgFileEntry::is_dir` 如实转发,供 UI 区分"文件夹接受时走
        /// GETDIRFILES/`request_dir`"还是"文件接受时走 GETFILEDATA/`request_file`"。
        is_dir: bool,
    },
    FileProgress {
        xfer_id: String,
        done: u64,
        total: u64,
    },
    FileDone {
        xfer_id: String,
        path: PathBuf,
    },
    FileFailed {
        xfer_id: String,
        reason: String,
    },
    /// 群聊帧(M7c):GroupInfo/GroupText/GroupLeave 原样上抛,`from_fp` 为
    /// TLS 层验证过的对端指纹(帧内不自报身份,解释权在 Core)。
    Group {
        from_fp: String,
        msg: Msg,
    },
    /// 群列表变化(M7c):Core 的群事件处理产生,携带最新全量列表供壳层
    /// 直接 emit 给前端(壳层事件线程不便反查 Core 状态)。
    GroupsChanged(Vec<crate::groups::Group>),
}

/// `offer_file` 的返回句柄。目前只携带 xfer_id,单独成类型是为了未来扩展
/// (比如取消传输)时不必再改调用方签名。
#[derive(Debug, Clone)]
pub struct FileHandle {
    pub xfer_id: String,
}

/// 接收方收到 `FileOffer` 之后、`respond_file` 决定之前的待决状态。
struct PendingOffer {
    peer_fp: String,
    name: String,
    size: u64,
    blake3: String,
    /// 决定(Accept/Reject)投递给读线程的通道——见模块顶部设计注记。
    reply_tx: mpsc::Sender<Msg>,
}

/// `respond_file(accept=true)` 登记的接收状态,供随后到达的 `FileStart`
/// 数据连接查询(这些字段要喂给 `filexfer::receive_into`)。
struct IncomingState {
    peer_fp: String,
    download_dir: PathBuf,
    name: String,
    size: u64,
    blake3: String,
    /// respond_file 为断点续传计算并写进 FileAccept 回复的 offset——唯一
    /// 权威值。随后到达的 FileStart 数据连接自带的 offset 必须与此一致
    /// (见 `handle_file_receive`),否则说明发送方状态过期/被篡改,不能信。
    offset: u64,
}

type ClientTls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
type ServerTls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

pub struct TransportManager {
    identity: Arc<Identity>,
    port: u16,
    /// 出站连接缓存:peer_fp -> 已握手连接(写侧)。M2 简化:出站连接只写不读,
    /// 对端的回话走它自己的出站连接(见下方 `dial` 注释)。
    outbound: Mutex<HashMap<String, ClientTls>>,
    events: Sender<TransportEvent>,
    /// 已接受入站连接的裸 TCP 克隆,供析构时强制断开(见 `Drop` 实现注释)。
    /// 键为自增连接 id;连接自然结束时由自己的读线程摘除。
    inbound_socks: Mutex<HashMap<u64, TcpStream>>,
    next_conn_id: AtomicU64,
    /// xfer_id -> 待决报价(本端是接收方时登记)。
    pending_offers: Mutex<HashMap<String, PendingOffer>>,
    /// xfer_id -> 已接受、等待 FileStart 数据连接到来的接收状态(本端是接收方)。
    incoming: Mutex<HashMap<String, IncomingState>>,
    /// xfer_id -> (源文件路径, 大小)。本端是发送方,等待 FileAccept/FileReject。
    outgoing: Mutex<HashMap<String, (PathBuf, u64)>>,
    /// 指向自身的弱引用,供 `offer_file` 生成的后台线程使用,
    /// 避免要求调用方以 `Arc<Self>` 形式调用(见 `start` 里 `Arc::new_cyclic`)。
    self_weak: Weak<Self>,
    /// 网卡快照订阅句柄(Step 6):`None` 表示未接线(构造时的默认值),
    /// 拨号时原样按传入顺序重试。之所以不做成构造参数,是为了不连锁改动
    /// 已有的 12 处 `TransportManager::start` 测试调用点——由 `set_iface_rx`
    /// 事后注入,真正接线是 Step 7 的事(core.rs 拿到 `InterfaceRegistry`
    /// 后调用一次)。
    ifaces: Mutex<Option<watch::Receiver<IfaceSnapshot>>>,
}

impl TransportManager {
    pub fn start(
        identity: Arc<Identity>,
        preferred_port: u16,
        events: Sender<TransportEvent>,
    ) -> Result<Arc<Self>, TransportError> {
        let listener = match TcpListener::bind(("0.0.0.0", preferred_port)) {
            Ok(l) => l,
            // 首选端口被占(比如另一个实例):回退临时端口,实际端口经发现层广播
            Err(_) if preferred_port != 0 => TcpListener::bind(("0.0.0.0", 0))?,
            Err(e) => return Err(e.into()),
        };
        let port = listener.local_addr()?.port();
        let mgr = Arc::new_cyclic(|weak_self| Self {
            identity: identity.clone(),
            port,
            outbound: Mutex::new(HashMap::new()),
            events,
            inbound_socks: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
            pending_offers: Mutex::new(HashMap::new()),
            incoming: Mutex::new(HashMap::new()),
            outgoing: Mutex::new(HashMap::new()),
            self_weak: weak_self.clone(),
            ifaces: Mutex::new(None),
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
                    // 未发首帧的连接不能无限占用线程/套接字:握手阶段设读超时。
                    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                    let mut tls_stream = rustls::StreamOwned::new(conn, tcp);
                    // 首帧分流:Hello → 消息连接(原逻辑);FileStart → 文件接收
                    // (M3 新增,见模块顶部设计注记)。其他/坏帧直接放弃连接。
                    match proto::read_msg(&mut tls_stream) {
                        Ok(Msg::Hello { .. }) => {
                            let Some(peer_fp) = tls::peer_fingerprint(&tls_stream.conn) else {
                                cleanup();
                                return;
                            };
                            // 首帧已收到,进入长连接读取阶段:取消握手期超时。
                            let _ = tls_stream.get_ref().set_read_timeout(None);
                            Self::read_loop(&cleanup_mgr, &events, peer_fp, &mut tls_stream);
                        }
                        Ok(Msg::FileStart { xfer_id, offset }) => {
                            let Some(peer_fp) = tls::peer_fingerprint(&tls_stream.conn) else {
                                cleanup();
                                return;
                            };
                            let _ = tls_stream.get_ref().set_read_timeout(None);
                            Self::handle_file_receive(
                                &cleanup_mgr,
                                &events,
                                xfer_id,
                                offset,
                                peer_fp,
                                &mut tls_stream,
                            );
                        }
                        _ => {}
                    }
                    cleanup();
                });
            }
        });
        Ok(mgr)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 注入网卡快照订阅句柄(Step 6 机制,Step 7 接线):设好之后,后续每次
    /// 拨号前都会 `borrow()` 一份最新快照做亲和排序(同网段地址优先)。
    /// 不在构造函数里加这个参数,是为了不连锁改动既有测试调用点——见字段
    /// 注释。可重复调用以替换订阅源(比如测试里换一个 receiver)。
    pub fn set_iface_rx(&self, rx: watch::Receiver<IfaceSnapshot>) {
        *self.ifaces.lock().expect("ifaces lock") = Some(rx);
    }

    /// 按当前网卡快照对拨号地址表做亲和度重排(同网段地址前置,组内保持
    /// 稳定顺序)。锁只覆盖 borrow+clone 这一步,不跨拨号 IO——`connect_and_send`
    /// 的 for 循环在锁外执行,不会因为持有 `ifaces` 锁而阻塞其他并发拨号。
    /// 未 `set_iface_rx` 或快照为空时:排序对全等 key 是稳定的,结果就是
    /// 原始传入顺序,天然满足"零漂移"要求,不需要额外分支。
    fn affinity_sorted_addrs(&self, addrs: &[IpAddr]) -> Vec<IpAddr> {
        let mut sorted = addrs.to_vec();
        let snapshot = {
            let guard = self.ifaces.lock().expect("ifaces lock");
            guard.as_ref().map(|rx| rx.borrow().clone())
        };
        if let Some(snapshot) = snapshot {
            net_ifaces::sort_by_affinity(&mut sorted, &snapshot.entries);
        }
        sorted
    }

    /// 服务端连接的读循环。M2 简化决策:出站连接只写不回读(对端回话走它自己
    /// 的出站连接),所以这里只需要服务端 `StreamOwned` 类型,不必对
    /// Server/Client 两种连接做泛型抽象。不是 `&self` 方法——见调用处注释,
    /// 读线程不持有 manager 的强引用,只借用事件 Sender 与一个 `Weak`
    /// (用于登记/查询 `pending_offers` 等小 map,绝不跨阻塞 IO 持有强引用)。
    fn read_loop(
        mgr: &Weak<Self>,
        events: &Sender<TransportEvent>,
        peer_fp: String,
        tls_stream: &mut ServerTls,
    ) {
        loop {
            match proto::read_msg(tls_stream) {
                Ok(Msg::Text { id, body, ts_ms }) => {
                    let ev = TransportEvent::Message(MessageEvent {
                        peer_fp: peer_fp.clone(),
                        id,
                        body,
                        ts_ms,
                        sender_fp: None,
                    });
                    if events.send(ev).is_err() {
                        return;
                    }
                }
                Ok(Msg::Hello { .. }) => continue, // 握手后不应再来 Hello;宽容忽略
                Ok(Msg::FileOffer {
                    xfer_id,
                    name,
                    size,
                    blake3,
                }) => {
                    // 这条连接从这一刻起专用于本次报价的控制往返:respond_file
                    // 在别的线程决定 accept/reject,通过下面这条仅本线程消费的
                    // channel 把决定传回来,再由本线程(唯一持有 &mut ServerTls
                    // 的线程)亲自写回。写完后这条连接的使命就结束了——对端不会
                    // 再在它上面发别的东西(它自己在阻塞等我们的回复)。
                    let (reply_tx, reply_rx) = mpsc::channel::<Msg>();
                    let Some(m) = mgr.upgrade() else { return };
                    m.pending_offers.lock().expect("pending lock").insert(
                        xfer_id.clone(),
                        PendingOffer {
                            peer_fp: peer_fp.clone(),
                            name: name.clone(),
                            size,
                            blake3,
                            reply_tx,
                        },
                    );
                    drop(m); // 不跨"等待应用层决定"持有强引用
                    if events
                        .send(TransportEvent::FileOffered {
                            xfer_id,
                            peer_fp: peer_fp.clone(),
                            name,
                            size,
                            is_dir: false, // 原生传输 M3 冻结范围:只支持单文件
                        })
                        .is_err()
                    {
                        return;
                    }
                    // 阻塞等 respond_file 的决定。若 manager 整体被 drop,
                    // pending_offers 连带 reply_tx 一起被丢弃,recv() 会立刻
                    // 收到 Err,本线程随之正常退出,不会永久悬挂。
                    if let Ok(reply) = reply_rx.recv() {
                        let _ = proto::write_msg(tls_stream, &reply);
                    }
                    return;
                }
                // 群聊帧(M7c):原样上抛给 Core 解释(成员校验/LWW 合并都在那边)。
                Ok(
                    msg @ (Msg::GroupInfo { .. } | Msg::GroupText { .. } | Msg::GroupLeave { .. }),
                ) => {
                    let ev = TransportEvent::Group {
                        from_fp: peer_fp.clone(),
                        msg,
                    };
                    if events.send(ev).is_err() {
                        return;
                    }
                }
                // 下面两种只会出现在发起方"专用 offer 控制连接"的读侧
                // (`await_offer_reply`),不会到这条服务端读循环里;防御性忽略。
                Ok(Msg::FileAccept { .. }) => continue,
                Ok(Msg::FileReject { .. }) => continue,
                // 数据连接的首帧在 accept-loop 分流阶段已经处理过,不会到这里。
                Ok(Msg::FileStart { .. }) => continue,
                Err(_) => return, // 断连/坏帧:退出读循环
            }
        }
    }

    /// 数据连接读侧(接收方):首帧 `FileStart` 已经在 accept-loop 里被识别
    /// 并消费掉,这里只管真正的字节流接收 + 落盘校验。不是 `&self` 方法,
    /// 理由同 `read_loop`——只借用 `Weak`。
    fn handle_file_receive(
        mgr: &Weak<Self>,
        events: &Sender<TransportEvent>,
        xfer_id: String,
        offset: u64,
        peer_fp: String,
        tls_stream: &mut ServerTls,
    ) {
        let state = {
            let Some(m) = mgr.upgrade() else { return };
            let removed = m.incoming.lock().expect("incoming lock").remove(&xfer_id);
            removed
        };
        let Some(state) = state else {
            let _ = events.send(TransportEvent::FileFailed {
                xfer_id,
                reason: "未知或已处理的传输".to_string(),
            });
            return;
        };
        if state.peer_fp != peer_fp {
            let _ = events.send(TransportEvent::FileFailed {
                xfer_id,
                reason: "数据连接对端指纹与报价方不符".to_string(),
            });
            return;
        }
        // 校验数据连接自带的 FileStart.offset 与 respond_file 当初算出、写进
        // FileAccept 回复里的续传点一致——不能信任发送方在数据连接上重新
        // 声称的 offset(状态可能过期,或被篡改)。不一致就判失败,不写任何
        // 字节(不调用 receive_into)。
        if offset != state.offset {
            let _ = events.send(TransportEvent::FileFailed {
                xfer_id,
                reason: "续传位置不一致".to_string(),
            });
            return;
        }

        let total = state.size;
        let mut last_emit: Option<Instant> = None;
        let progress_xfer = xfer_id.clone();
        let progress_events = events.clone();
        let mut on_progress = move |done: u64| {
            let now = Instant::now();
            let due = done == total
                || last_emit.is_none_or(|t| now.duration_since(t) >= PROGRESS_THROTTLE);
            if due {
                last_emit = Some(now);
                let _ = progress_events.send(TransportEvent::FileProgress {
                    xfer_id: progress_xfer.clone(),
                    done,
                    total,
                });
            }
        };

        match filexfer::receive_into(
            &state.download_dir,
            &state.name,
            state.size,
            state.offset,
            &state.blake3,
            tls_stream,
            &mut on_progress,
        ) {
            Ok(path) => {
                let _ = events.send(TransportEvent::FileDone { xfer_id, path });
            }
            Err(e) => {
                let _ = events.send(TransportEvent::FileFailed {
                    xfer_id,
                    reason: e.to_string(),
                });
            }
        }
    }

    /// 建连 + 握手 + 写首帧,地址列表依次重试。首帧参数化,供 `dial`(Hello)
    /// 与 `dial_data`(FileStart)共用同一套重试逻辑。
    fn connect_and_send(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
        first: &Msg,
    ) -> Result<ClientTls, TransportError> {
        let cfg = tls::client_config(&self.identity, peer_fp)?;
        // 拨号亲和排序(Step 6):锁只覆盖 borrow+clone(见 `affinity_sorted_addrs`
        // 注释),排好序的是这里新拷贝出的地址表,不影响调用方持有的原始切片。
        let sorted_addrs = self.affinity_sorted_addrs(addrs);
        let mut last: Option<io::Error> = None;
        for ip in &sorted_addrs {
            let sa = SocketAddr::new(*ip, port);
            match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
                Ok(tcp) => {
                    tcp.set_nodelay(true).ok();
                    let name = ServerName::try_from("bigpaw").expect("static name");
                    match rustls::ClientConnection::new(cfg.clone(), name) {
                        Ok(conn) => {
                            let mut tls_stream = rustls::StreamOwned::new(conn, tcp);
                            match proto::write_msg(&mut tls_stream, first) {
                                Ok(()) => return Ok(tls_stream),
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

    fn dial(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
    ) -> Result<ClientTls, TransportError> {
        // 对称:也从出站连接收消息(对端可能沿此连接回话)——读线程需要独立的
        // 流,TcpStream 可 try_clone,TLS 状态不可,因此 M2 出站连接只写不读;
        // 对端回话走它自己的出站连接。offer/control 连接同理(见 offer_file):
        // 它额外需要读一条回复,为此单独跑一个专用线程,不影响这里的约定。
        self.connect_and_send(peer_fp, addrs, port, &Msg::Hello { v: proto::PROTO_V })
    }

    /// 文件数据连接:没有 `Hello`,首帧直接是 `FileStart`——接收方 accept-loop
    /// 靠这一点把它和普通消息/offer 控制连接区分开(见模块顶部设计注记)。
    fn dial_data(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
        xfer_id: &str,
        offset: u64,
    ) -> Result<ClientTls, TransportError> {
        self.connect_and_send(
            peer_fp,
            addrs,
            port,
            &Msg::FileStart {
                xfer_id: xfer_id.to_string(),
                offset,
            },
        )
    }

    /// 双向注册的回连探测(M4):对一个刚被 `Seen` 的新对端主动拨号,做 TLS
    /// 握手并写 `Hello`,验证"我方也能连到它"(而不仅仅是收到了它的单向宣告)。
    /// 复用 `dial` 的建连/重试逻辑;成功即代表握手完成且首帧写入成功。
    ///
    /// 这是一条**用完即弃**的探测连接:不写任何消息、不读应答、也**不**塞进
    /// `outbound` 缓存——否则后续 `send_text` 可能复用一条只做过探测握手、
    /// 从未被对端当作"消息连接"对待的连接,污染消息/文件传输路径的假设。
    /// 探测完成后排空对端可能已发来的字节再讲连接丢弃关闭(见
    /// `drain_before_close` 注释,同样的"避免 RST 丢包"考虑其实对探测连接
    /// 影响不大,但保持和其他一次性连接一致的收尾方式)。
    pub fn probe_reachable(&self, peer_fp: &str, addrs: &[IpAddr], port: u16) -> bool {
        match self.dial(peer_fp, addrs, port) {
            Ok(mut conn) => {
                Self::drain_before_close(&mut conn);
                true
            }
            Err(_) => false,
        }
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

    /// 纯写连接(比如数据连接的发送侧)在关闭前主动排空对端可能已经发来的
    /// 字节。TLS 1.3 服务端握手完成后通常会自动下发 NewSessionTicket 记录
    /// (见 `conn_is_dead` 的注释);这类连接只写不读,若这些字节一直没被
    /// 读走,操作系统在 socket 关闭时可能因为"接收缓冲区还有未读数据"而发
    /// RST 而不是正常 FIN/四次挥手,这有可能让对端把我们最后刚写完、还没
    /// 被应用层读到的那部分数据一起丢弃。用一个短超时循环把这些字节读掉,
    /// 确保关闭时接收缓冲区是空的,退化为正常挥手。
    fn drain_before_close(conn: &mut ClientTls) {
        let _ = conn.sock.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf = [0u8; 4096];
        loop {
            match io::Read::read(conn, &mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
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
        self.send_msg(peer_fp, addrs, port, &msg)?;
        Ok(SentText { id, ts_ms })
    }

    /// 经缓存的出站连接向对端发一帧任意消息(M7c 抽出:send_text 与群聊扇出
    /// 共用同一条"缓存命中→锁外重拨→回填缓存"路径)。
    pub fn send_msg(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
        msg: &Msg,
    ) -> Result<(), TransportError> {
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
                    if alive && proto::write_msg(conn, msg).is_ok() {
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
            return Ok(());
        }

        // 2) 缓存 miss 或写失败:锁外重拨,避免持锁跨越网络 IO。
        let mut fresh = self.dial(peer_fp, addrs, port)?;
        proto::write_msg(&mut fresh, msg)?;

        // 3) 写成功后再加锁插入缓存。
        let mut cache = self.outbound.lock().expect("outbound lock");
        cache.insert(peer_fp.to_string(), fresh);
        Ok(())
    }

    /// 发起一次文件传输报价:算 hash → 生成 xfer_id → 经一条**专用**控制
    /// 连接(`dial()`,与 send_text 共用同一套建连/首帧重试逻辑,但不进
    /// `outbound` 缓存——见模块顶部设计注记)发 `FileOffer` → 记录待发送
    /// 路径 → 后台线程阻塞等待对端的 Accept/Reject。
    pub fn offer_file(
        &self,
        peer_fp: &str,
        addrs: &[IpAddr],
        port: u16,
        path: &Path,
    ) -> Result<FileHandle, TransportError> {
        let (size, blake3) = filexfer::hash_file(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let xfer_id = proto::new_id();

        self.outgoing
            .lock()
            .expect("outgoing lock")
            .insert(xfer_id.clone(), (path.to_path_buf(), size));

        let mut ctrl = match self.dial(peer_fp, addrs, port) {
            Ok(c) => c,
            Err(e) => {
                self.outgoing
                    .lock()
                    .expect("outgoing lock")
                    .remove(&xfer_id);
                return Err(e);
            }
        };
        let offer = Msg::FileOffer {
            xfer_id: xfer_id.clone(),
            name,
            size,
            blake3,
        };
        if let Err(e) = proto::write_msg(&mut ctrl, &offer) {
            self.outgoing
                .lock()
                .expect("outgoing lock")
                .remove(&xfer_id);
            return Err(e.into());
        }

        let weak = self.self_weak.clone();
        let events = self.events.clone();
        let peer_fp = peer_fp.to_string();
        let addrs = addrs.to_vec();
        let xfer_for_thread = xfer_id.clone();
        std::thread::spawn(move || {
            Self::await_offer_reply(weak, events, xfer_for_thread, peer_fp, addrs, port, ctrl);
        });

        Ok(FileHandle { xfer_id })
    }

    /// 专用 offer 控制连接的读侧(发起方):阻塞等一条回复,按结果分流。
    /// 不是 `&self` 方法——理由同 `read_loop`,只借用 `Weak`,且在真正开始
    /// 推流(可能耗时较长)之前就把强引用释放掉。
    fn await_offer_reply(
        mgr: Weak<Self>,
        events: Sender<TransportEvent>,
        xfer_id: String,
        peer_fp: String,
        addrs: Vec<IpAddr>,
        port: u16,
        mut ctrl: ClientTls,
    ) {
        // 对端可能迟迟不 accept/reject(等人工确认),但也不能无限占用这条
        // 阻塞读线程 + 底层 socket——给够时间(120s)但不是永久,超时后
        // read_msg 返回 Err,走下面既有的清理分支(见该分支注释)。
        let _ = ctrl
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(120)));
        let reply = proto::read_msg(&mut ctrl);
        match reply {
            Ok(Msg::FileAccept { offset, .. }) => {
                let entry = match mgr.upgrade() {
                    Some(m) => m.outgoing.lock().expect("outgoing lock").remove(&xfer_id),
                    None => None,
                };
                let Some((path, size)) = entry else { return };

                let dialed = match mgr.upgrade() {
                    Some(m) => m.dial_data(&peer_fp, &addrs, port, &xfer_id, offset),
                    None => return,
                };
                // 拨号之后不再需要强引用——推流阶段可能耗时较长,不该拖着
                // manager 的引用计数(与 read_loop/handle_file_receive 同样的
                // "不跨阻塞 IO 持有强引用"原则)。
                let mut data_conn = match dialed {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = events.send(TransportEvent::FileFailed {
                            xfer_id,
                            reason: e.to_string(),
                        });
                        return;
                    }
                };

                let mut last_emit: Option<Instant> = None;
                let progress_xfer = xfer_id.clone();
                let progress_events = events.clone();
                let mut on_progress = move |done: u64| {
                    let now = Instant::now();
                    let due = done == size
                        || last_emit.is_none_or(|t| now.duration_since(t) >= PROGRESS_THROTTLE);
                    if due {
                        last_emit = Some(now);
                        let _ = progress_events.send(TransportEvent::FileProgress {
                            xfer_id: progress_xfer.clone(),
                            done,
                            total: size,
                        });
                    }
                };

                let send_res =
                    filexfer::send_from(&path, offset, size, &mut data_conn, &mut on_progress);
                // 见 drain_before_close 的注释:这条数据连接自始至终只写不读,
                // 关闭前先排空对端可能已经发来的字节,避免触发 RST 丢尾包。
                Self::drain_before_close(&mut data_conn);
                match send_res {
                    Ok(()) => {
                        let _ = events.send(TransportEvent::FileDone { xfer_id, path });
                    }
                    Err(e) => {
                        let _ = events.send(TransportEvent::FileFailed {
                            xfer_id,
                            reason: e.to_string(),
                        });
                    }
                }
            }
            Ok(Msg::FileReject { .. }) => {
                if let Some(m) = mgr.upgrade() {
                    m.outgoing.lock().expect("outgoing lock").remove(&xfer_id);
                    let _ = events.send(TransportEvent::FileFailed {
                        xfer_id,
                        reason: "对端已拒绝".to_string(),
                    });
                }
            }
            // 读失败:包括上面设的 120s 超时(对端一直未 accept/reject)以及
            // 其他连接错误——都清理 outgoing 并上报,不留悬挂状态。
            Err(_) => {
                if let Some(m) = mgr.upgrade() {
                    m.outgoing.lock().expect("outgoing lock").remove(&xfer_id);
                }
                let _ = events.send(TransportEvent::FileFailed {
                    xfer_id,
                    reason: "对端无响应".to_string(),
                });
            }
            _ => {
                if let Some(m) = mgr.upgrade() {
                    m.outgoing.lock().expect("outgoing lock").remove(&xfer_id);
                }
                let _ = events.send(TransportEvent::FileFailed {
                    xfer_id,
                    reason: "未收到有效的 Accept/Reject 回复".to_string(),
                });
            }
        }
    }

    /// 接收方对一个待决报价做出决定。
    /// - `accept`:登记接收状态(供随后到达的 `FileStart` 数据连接查询),
    ///   算好断点续传 offset,回 `FileAccept`。
    /// - 拒绝:回 `FileReject`,不留任何接收状态。
    ///
    /// 未知/已处理过的 `xfer_id` 静默忽略(respond_file 是幂等的边界操作)。
    pub fn respond_file(
        &self,
        xfer_id: &str,
        accept: bool,
        download_dir: &Path,
    ) -> Result<(), TransportError> {
        let Some(po) = self
            .pending_offers
            .lock()
            .expect("pending lock")
            .remove(xfer_id)
        else {
            return Ok(());
        };

        if accept {
            let safe_name = match filexfer::safe_basename(&po.name) {
                Some(n) => n,
                None => {
                    // 对端文件名非法(可能路径穿越):拒绝并上报
                    let _ = po.reply_tx.send(Msg::FileReject {
                        xfer_id: xfer_id.to_string(),
                    });
                    let _ = self.events.send(TransportEvent::FileFailed {
                        xfer_id: xfer_id.to_string(),
                        reason: "非法文件名".to_string(),
                    });
                    return Ok(());
                }
            };
            let offset = filexfer::existing_offset(download_dir, &safe_name);
            self.incoming.lock().expect("incoming lock").insert(
                xfer_id.to_string(),
                IncomingState {
                    peer_fp: po.peer_fp,
                    download_dir: download_dir.to_path_buf(),
                    name: safe_name,
                    size: po.size,
                    blake3: po.blake3,
                    offset,
                },
            );
            let _ = po.reply_tx.send(Msg::FileAccept {
                xfer_id: xfer_id.to_string(),
                offset,
            });
        } else {
            let _ = po.reply_tx.send(Msg::FileReject {
                xfer_id: xfer_id.to_string(),
            });
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::net_ifaces::IfaceEntry;
    use std::net::Ipv4Addr;

    /// 构造一个仅用于本模块测试的 manager:临时目录身份 + 端口 0(系统分配)。
    /// 不做任何真实拨号,只用来验证 `affinity_sorted_addrs` 这一段纯排序逻辑。
    fn test_manager() -> Arc<TransportManager> {
        let dir = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(dir.path()).unwrap());
        let (tx, _rx) = mpsc::channel();
        TransportManager::start(identity, 0, tx).unwrap()
    }

    fn entry(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> IfaceEntry {
        IfaceEntry {
            name: name.to_string(),
            ip,
            netmask,
            broadcast: crate::net_ifaces::directed_broadcast(ip, netmask),
            is_virtual_hint: false,
        }
    }

    #[test]
    fn affinity_sorted_addrs_unchanged_when_no_receiver_set() {
        let mgr = test_manager();
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        ];
        let sorted = mgr.affinity_sorted_addrs(&addrs);
        assert_eq!(sorted, addrs, "未 set_iface_rx 时应保持原顺序");
    }

    #[test]
    fn affinity_sorted_addrs_unchanged_when_snapshot_is_empty() {
        let mgr = test_manager();
        let (_tx, rx) = watch::channel(IfaceSnapshot::default());
        mgr.set_iface_rx(rx);
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        ];
        let sorted = mgr.affinity_sorted_addrs(&addrs);
        assert_eq!(sorted, addrs, "空快照应保持原顺序");
    }

    #[test]
    fn affinity_sorted_addrs_puts_same_subnet_first() {
        let mgr = test_manager();
        let entries = vec![entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let (_tx, rx) = watch::channel(IfaceSnapshot {
            generation: 1,
            entries,
        });
        mgr.set_iface_rx(rx);

        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),      // 远端
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), // 同网段
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),      // 远端
        ];
        let sorted = mgr.affinity_sorted_addrs(&addrs);
        assert_eq!(
            sorted,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            "同网段地址应前置,远端地址维持原有相对顺序"
        );
    }

    #[test]
    fn set_iface_rx_reflects_live_snapshot_updates() {
        // 验证 manager 侧不是只读一次快照,而是每次拨号前都 borrow 最新值
        // (`watch::Sender::send` 更新后,后续 borrow() 应看到新数据)。
        let mgr = test_manager();
        let (tx, rx) = watch::channel(IfaceSnapshot::default());
        mgr.set_iface_rx(rx);

        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
        ];
        // 初始空快照:无重排。
        assert_eq!(mgr.affinity_sorted_addrs(&addrs), addrs);

        // 推送新快照后:同网段地址应前置。
        tx.send(IfaceSnapshot {
            generation: 2,
            entries: vec![entry(
                "en0",
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(255, 255, 255, 0),
            )],
        })
        .unwrap();
        let sorted = mgr.affinity_sorted_addrs(&addrs);
        assert_eq!(
            sorted,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        );
    }
}

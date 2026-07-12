//! IPMsg 发现/消息/文件传输服务:BR_ENTRY/ANSENTRY/BR_EXIT + SENDMSG/RECVMSG +
//! SENDMSG|FILEATTACHOPT over UDP 2425(设计文档 §6),TCP 侧 GETFILEDATA 供给见
//! `filexfer.rs`。
//!
//! 零 Tauri、零异步运行时,仅线程 + std::net + socket2,不依赖 bigpaw-core。
//! 严格生成:UDP 只发送标准的 BR_ENTRY/ANSENTRY/BR_EXIT/SENDMSG/RECVMSG 报文,
//! 其余命令号(如 GETFILEDATA/GETDIRFILES,均为 TCP-only)在 UDP dispatch 里静默忽略。

use crate::command::{self, Command};
use crate::filexfer::{self, IpmsgFileEntry, OfferedFiles};
use crate::proto::{self, Packet, BIGPAW_TAG};
use socket2::{Domain, Protocol as SockProtocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, UNIX_EPOCH};
use thiserror::Error;

/// 报文里不透明的版本字段;真实飞秋会带更复杂的版本串,我方只需固定一个值。
const IPMSG_VERSION: &str = "1";
/// recv_from 缓冲区大小,足够容纳标准 IPMsg 报文(含较长附加数据)。
const RECV_BUF_SIZE: usize = 2048;
/// recv_from 超时:让接收线程能定期醒来检查停止标志,而不是永久阻塞。
const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(500);
/// BR_ENTRY 周期刷新间隔(飞秋不强制周期,这里选择 ~30s 一次)。
const ENTRY_INTERVAL: Duration = Duration::from_secs(30);
/// 中断式休眠的步长,让停止标志能被及时观察到。
const SLEEP_STEP: Duration = Duration::from_millis(200);

/// 发现事件:上线(含弱身份 key、昵称、主机名、来源地址、是否为 BigPaw 对端)/下线。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpmsgEvent {
    Online {
        /// 弱身份:`ip:host`,同一 host 换 IP 或同一 IP 换 host 都视为新身份。
        key: String,
        nick: String,
        host: String,
        addr: SocketAddr,
        is_bigpaw: bool,
    },
    Offline {
        key: String,
    },
    /// 收到一条 SENDMSG 文本消息(`from` = 对端 nick,`body` = extra 原文)。
    TextReceived {
        key: String,
        from: String,
        body: String,
    },
    /// 收到一条 SENDMSG|FILEATTACHOPT 文件提供(`packet_no` = 这条 SENDMSG 自身的
    /// packet_no,后续 request_file/request_dir 的 `packetID` 引用它)。
    FileOffered {
        key: String,
        from: String,
        packet_no: u32,
        files: Vec<IpmsgFileEntry>,
    },
}

#[derive(Debug, Error)]
pub enum IpmsgError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// 2425 已被占用(常见于飞秋已在运行);必须明确报错,不能静默失败。
    #[error("port already in use")]
    PortInUse,
    /// 落盘文件名非法(可能路径穿越/Windows 危险名),或找不到有效文件名部分。
    #[error("非法文件名(可能路径穿越)")]
    BadName,
    /// 文件夹发送未实现(设计文档 §6 冻结:文件夹仅接收)。
    #[error("不支持发送文件夹(仅支持接收)")]
    FolderSendUnsupported,
}

/// extra 尾部附带 BIGPAW_TAG + self_token,供对端识别我方为 BigPaw,
/// 同时让自己能在 recv 侧识别出这是自己发出去又被操作系统广播回环的报文
/// (飞秋/feiq 会忽略这段附加数据,不影响与真实飞秋互通)。
fn entry_extra(nick: &str, self_token: &str) -> String {
    format!("{nick}{BIGPAW_TAG}{self_token}")
}

fn next_packet_no(counter: &AtomicU32) -> u32 {
    counter.fetch_add(1, Ordering::Relaxed)
}

/// 绑定 0.0.0.0:port 的 UDP socket:REUSEADDR + BROADCAST。
/// bind 失败且是 AddrInUse → 返回 `IpmsgError::PortInUse`(不静默,2425 被占用需明确报错)。
fn bind_socket(port: u16) -> Result<UdpSocket, IpmsgError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;

    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into();
    match socket.bind(&SockAddr::from(bind_addr)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Err(IpmsgError::PortInUse),
        Err(e) => return Err(IpmsgError::Io(e)),
    }

    socket.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
    Ok(socket.into())
}

/// 中断式休眠:每 SLEEP_STEP 检查一次停止标志,避免长睡眠拖慢 shutdown。
fn interruptible_sleep(stop: &AtomicBool, dur: Duration) {
    let mut remaining = dur;
    while remaining > Duration::ZERO {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let step = remaining.min(SLEEP_STEP);
        std::thread::sleep(step);
        remaining -= step;
    }
}

fn broadcast(socket: &UdpSocket, buf: &[u8], port: u16) {
    let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);
    let _ = socket.send_to(buf, dest);
}

fn send_entry(
    socket: &UdpSocket,
    packet_no: &AtomicU32,
    nick: &str,
    host: &str,
    port: u16,
    self_token: &str,
) {
    let packet = Packet {
        version: IPMSG_VERSION.to_string(),
        packet_no: next_packet_no(packet_no),
        sender: nick.to_string(),
        host: host.to_string(),
        command: command::BR_ENTRY,
        extra: entry_extra(nick, self_token),
    };
    broadcast(socket, &proto::encode(&packet), port);
}

/// 发送线程主循环:启动发一次 BR_ENTRY,之后每 ENTRY_INTERVAL 刷新一次。
fn send_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    packet_no: Arc<AtomicU32>,
    nick: String,
    host: String,
    port: u16,
    self_token: Arc<String>,
) {
    send_entry(&socket, &packet_no, &nick, &host, port, &self_token);
    loop {
        interruptible_sleep(&stop, ENTRY_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        send_entry(&socket, &packet_no, &nick, &host, port, &self_token);
    }
}

/// 收到报文后的处理结果:纯函数,便于脱离真实 socket 单元测试。
enum Action {
    /// 未知命令号(GETFILEDATA 等留给后续任务)或其它不需处理的情况:静默忽略。
    None,
    /// 直接上报事件,无需回包(ANSENTRY / BR_EXIT / 无回执要求的 SENDMSG)。
    Emit(IpmsgEvent),
    /// 单播回一个报文,并上报事件——BR_ENTRY→ANSENTRY+Online,
    /// 或 SENDMSG|SENDCHECKOPT→RECVMSG 回执+TextReceived。
    ReplyAndEmit(Packet, IpmsgEvent),
    /// 收到 RECVMSG 回执:从待回执表里摘掉这个 packet_no,不上报事件
    /// (M5 不做重发/超时,recv_loop 只需把它从 pending map 里移除)。
    Ack(u32),
}

/// 按 `Command(p.command).num()` 分派:BR_ENTRY → 回 ANSENTRY + Online;
/// ANSENTRY → Online;BR_EXIT → Offline;其它命令号静默忽略。
///
/// 自过滤:`extra` 携带自己的 `self_token` → 这是自己发出去、被 OS 广播回环
/// 反射回本机 recv 的报文(标准 UDP 广播行为),必须在分派前拦下——不回包、
/// 不上报事件,否则会把自己误判为新发现的对端(见任务说明)。真实对端
/// (无论是否 BigPaw)不会携带我方 token,不受影响。
fn dispatch(
    packet: Packet,
    src: SocketAddr,
    nick: &str,
    host: &str,
    packet_no: &AtomicU32,
    self_token: &str,
) -> Action {
    if packet.extra.contains(self_token) {
        return Action::None;
    }

    let key = format!("{}:{}", src.ip(), packet.host);
    let is_bigpaw = packet.extra.contains(BIGPAW_TAG);

    match Command(packet.command).num() {
        command::BR_ENTRY => {
            let reply = Packet {
                version: IPMSG_VERSION.to_string(),
                packet_no: next_packet_no(packet_no),
                sender: nick.to_string(),
                host: host.to_string(),
                command: command::ANSENTRY,
                extra: entry_extra(nick, self_token),
            };
            let online = IpmsgEvent::Online {
                key,
                nick: packet.sender,
                host: packet.host,
                addr: src,
                is_bigpaw,
            };
            Action::ReplyAndEmit(reply, online)
        }
        command::ANSENTRY => Action::Emit(IpmsgEvent::Online {
            key,
            nick: packet.sender,
            host: packet.host,
            addr: src,
            is_bigpaw,
        }),
        command::BR_EXIT => Action::Emit(IpmsgEvent::Offline { key }),
        command::SENDMSG => {
            let cmd = Command(packet.command);
            let event = if cmd.has_opt(command::FILEATTACHOPT) {
                let (_msg_body, files) = filexfer::parse_file_attach_extra(&packet.extra);
                IpmsgEvent::FileOffered {
                    key,
                    from: packet.sender.clone(),
                    packet_no: packet.packet_no,
                    files,
                }
            } else {
                IpmsgEvent::TextReceived {
                    key,
                    from: packet.sender.clone(),
                    body: packet.extra.clone(),
                }
            };
            if cmd.has_opt(command::SENDCHECKOPT) {
                let reply = Packet {
                    version: IPMSG_VERSION.to_string(),
                    packet_no: next_packet_no(packet_no),
                    sender: nick.to_string(),
                    host: host.to_string(),
                    command: command::RECVMSG,
                    // 回执 extra = 原始消息的 packet_no(十进制串),让发送方知道哪条消息被确认。
                    extra: packet.packet_no.to_string(),
                };
                Action::ReplyAndEmit(reply, event)
            } else {
                Action::Emit(event)
            }
        }
        // RECVMSG 的 extra 就是被确认消息的原始 packet_no;解析失败(畸形报文)静默忽略。
        command::RECVMSG => match packet.extra.parse::<u32>() {
            Ok(acked_no) => Action::Ack(acked_no),
            Err(_) => Action::None,
        },
        _ => Action::None,
    }
}

/// 接收线程主循环:recv_from → proto::decode(畸形报文静默丢弃)→ dispatch → 执行动作。
#[allow(clippy::too_many_arguments)]
fn recv_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    packet_no: Arc<AtomicU32>,
    nick: String,
    host: String,
    tx: Sender<IpmsgEvent>,
    self_token: Arc<String>,
    pending_acks: Arc<Mutex<HashMap<u32, Instant>>>,
) {
    let mut buf = [0u8; RECV_BUF_SIZE];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => {
                // 瞬时错误:短暂让步后重试,不 panic、不退出。
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let Some(packet) = proto::decode(&buf[..n]) else {
            continue; // decode None → 丢弃
        };

        match dispatch(packet, src, &nick, &host, &packet_no, &self_token) {
            Action::None => {}
            Action::Emit(ev) => {
                if tx.send(ev).is_err() {
                    return; // 接收端已销毁,退出线程
                }
            }
            Action::ReplyAndEmit(reply, ev) => {
                let _ = socket.send_to(&proto::encode(&reply), src);
                if tx.send(ev).is_err() {
                    return;
                }
            }
            Action::Ack(acked_no) => {
                // 短临界区:只是一次 HashMap::remove,绝不跨越阻塞 IO。
                pending_acks.lock().unwrap().remove(&acked_no);
            }
        }
    }
}

/// 进程唯一 token:纳秒级时间戳的十六进制串,埋进每个报文的 extra 尾部。
/// 用于在 recv 侧识别"这是自己发出去、被 OS 广播回环反射回本机的报文"
/// (标准 UDP 广播行为:发给 255.255.255.255 的包,内核会把它也送回本机
/// 自己的 recv socket)。原生发现层用 `fingerprint == self_fp` 做同样的事,
/// IPMsg 协议没有 fingerprint 字段,所以用这个 token 顶替。
fn new_self_token() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// 构造单文件 `SENDMSG|FILEATTACHOPT|SENDCHECKOPT` offer 报文;纯函数,`send_file`
/// 用它生成实际发送的 Packet,同时也是单测直接验证"command 位含 FILEATTACHOPT"
/// 的入口,不需要真的起网络服务。
#[allow(clippy::too_many_arguments)]
fn file_offer_packet(
    nick: &str,
    host: &str,
    packet_no: u32,
    file_id: u32,
    name: &str,
    size: u64,
    mtime: u64,
) -> Packet {
    Packet {
        version: IPMSG_VERSION.to_string(),
        packet_no,
        sender: nick.to_string(),
        host: host.to_string(),
        command: command::build(
            command::SENDMSG,
            &[command::FILEATTACHOPT, command::SENDCHECKOPT],
        ),
        extra: filexfer::build_file_offer_extra(
            "",
            file_id,
            name,
            size,
            mtime,
            filexfer::FILE_REGULAR,
        ),
    }
}

/// IPMsg 服务:UDP 2425 上的发现(BR_ENTRY/ANSENTRY/BR_EXIT)+ 文本
/// (SENDMSG/RECVMSG)+ 文件 offer(SENDMSG|FILEATTACHOPT),以及 TCP 2425 上的
/// GETFILEDATA 供给/拉取、GETDIRFILES 拉取(仅接收方向)。
/// 独立 crate:零 Tauri、零异步运行时,仅 std::net + socket2 线程模型。
pub struct IpmsgService {
    stop: Arc<AtomicBool>,
    socket: Arc<UdpSocket>,
    packet_no: Arc<AtomicU32>,
    nick: String,
    host: String,
    port: u16,
    self_token: Arc<String>,
    /// 已发出、待对端 RECVMSG 回执确认的 packet_no → 发送时刻。
    /// M5 不做重发/超时,Instant 目前只为将来扩展预留,收到 RECVMSG 即移除。
    pending_acks: Arc<Mutex<HashMap<u32, Instant>>>,
    /// 已通过 send_file 提供、允许对端用 GETFILEDATA 拉取的文件登记表
    /// (packet_no → file_id → 磁盘路径)。TCP 服务线程只应答这里登记过的文件。
    offered_files: OfferedFiles,
    send_handle: Option<JoinHandle<()>>,
    recv_handle: Option<JoinHandle<()>>,
    /// TCP GETFILEDATA 服务线程;若启动时 TCP `port` 绑定失败(None),则文件传输的
    /// "被拉取"一侧不可用,但不影响 UDP 发现/文本(见 `start` 里的处理)。
    tcp_handle: Option<JoinHandle<()>>,
}

impl IpmsgService {
    /// 绑定 UDP `0.0.0.0:port`(SO_REUSEADDR + SO_BROADCAST),起发送/接收线程。
    /// 端口被占用(如飞秋已在运行)返回 `IpmsgError::PortInUse`,不静默失败。
    pub fn start(
        nick: &str,
        host: &str,
        port: u16,
        tx: Sender<IpmsgEvent>,
    ) -> Result<IpmsgService, IpmsgError> {
        let socket = Arc::new(bind_socket(port)?);
        let stop = Arc::new(AtomicBool::new(false));
        let packet_no = Arc::new(AtomicU32::new(1));
        let self_token = Arc::new(new_self_token());
        let pending_acks: Arc<Mutex<HashMap<u32, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let offered_files: OfferedFiles = filexfer::new_offered_files();

        // TCP 侧 GETFILEDATA 供给:与 UDP 共用同一端口号,但这是完全独立的 TCP
        // 监听。绑定失败(如已有其它进程占了 TCP `port`)不应让整个服务起不来——
        // UDP 发现/文本仍应正常工作,只是"被拉取文件"这个方向暂不可用。
        let tcp_handle = match TcpListener::bind(("0.0.0.0", port)) {
            Ok(listener) => {
                let stop = Arc::clone(&stop);
                let offered = Arc::clone(&offered_files);
                Some(std::thread::spawn(move || {
                    filexfer::tcp_serve_loop(listener, stop, offered)
                }))
            }
            Err(e) => {
                eprintln!("ipmsg: TCP {port} 绑定失败,文件传输(GETFILEDATA 供给)暂不可用: {e}");
                None
            }
        };

        let send_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let packet_no = Arc::clone(&packet_no);
            let nick = nick.to_string();
            let host = host.to_string();
            let self_token = Arc::clone(&self_token);
            std::thread::spawn(move || {
                send_loop(socket, stop, packet_no, nick, host, port, self_token)
            })
        };

        let recv_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let packet_no = Arc::clone(&packet_no);
            let nick = nick.to_string();
            let host = host.to_string();
            let self_token = Arc::clone(&self_token);
            let pending_acks = Arc::clone(&pending_acks);
            std::thread::spawn(move || {
                recv_loop(
                    socket,
                    stop,
                    packet_no,
                    nick,
                    host,
                    tx,
                    self_token,
                    pending_acks,
                )
            })
        };

        Ok(IpmsgService {
            stop,
            socket,
            packet_no,
            nick: nick.to_string(),
            host: host.to_string(),
            port,
            self_token,
            pending_acks,
            offered_files,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
            tcp_handle,
        })
    }

    /// 单播发送一条 SENDMSG|SENDCHECKOPT 文本消息到 `addr`,body 走 GBK 编码。
    /// packet_no 记入待回执表(收到对端 RECVMSG 后由 recv_loop 摘除);
    /// M5 不做重发/超时,记录仅供将来扩展使用。
    pub fn send_text(&self, addr: SocketAddr, body: &str) -> Result<(), IpmsgError> {
        let packet_no = next_packet_no(&self.packet_no);
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no,
            sender: self.nick.clone(),
            host: self.host.clone(),
            command: command::build(command::SENDMSG, &[command::SENDCHECKOPT]),
            extra: body.to_string(),
        };
        self.socket.send_to(&proto::encode(&packet), addr)?;
        // 锁只覆盖这一次 insert,发送(阻塞 IO)已在上一行完成,不跨锁。
        self.pending_acks
            .lock()
            .unwrap()
            .insert(packet_no, Instant::now());
        Ok(())
    }

    /// 发送 `SENDMSG|FILEATTACHOPT|SENDCHECKOPT` 单文件 offer 到 `addr`,并把这个
    /// 文件登记进 `offered_files`,供对端稍后用 GETFILEDATA 通过 TCP 拉取
    /// (要求 TCP 监听已在 `start` 里成功绑定,否则对端连接会被拒绝——见 `start` 注释)。
    /// 文件夹发送**不支持**(设计文档 §6 冻结:文件夹仅接收),`path` 若是目录会报错。
    pub fn send_file(&self, addr: SocketAddr, path: &Path) -> Result<(), IpmsgError> {
        let meta = fs::metadata(path)?;
        if meta.is_dir() {
            return Err(IpmsgError::FolderSendUnsupported);
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(IpmsgError::BadName)?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // 单文件发送:一次 SENDMSG 只带一个文件条目,固定 file_id=0 即可
        // (唯一性只需要在这次 packet_no 的登记范围内成立)。
        const SINGLE_FILE_ID: u32 = 0;

        let packet_no = next_packet_no(&self.packet_no);
        let packet = file_offer_packet(
            &self.nick,
            &self.host,
            packet_no,
            SINGLE_FILE_ID,
            name,
            size,
            mtime,
        );
        self.socket.send_to(&proto::encode(&packet), addr)?;

        // 登记 + 待回执表:发送(阻塞 IO)已在上一行完成,锁只覆盖两次轻量插入。
        self.offered_files
            .lock()
            .unwrap()
            .entry(packet_no)
            .or_default()
            .insert(SINGLE_FILE_ID, path.to_path_buf());
        self.pending_acks
            .lock()
            .unwrap()
            .insert(packet_no, Instant::now());
        Ok(())
    }

    /// TCP 连 `sender_addr`(对端 IPMsg 端口,通常与 `packet.src` 相同),按
    /// `packetID:fileID:offset`(全十六进制)请求单个文件,读回 `size` 字节写入
    /// `save_path`(文件名会被 basename 化)。M5 不做断点续传,offset 固定 0。
    pub fn request_file(
        &self,
        sender_addr: SocketAddr,
        packet_no: u32,
        file_id: u32,
        size: u64,
        save_path: &Path,
    ) -> Result<PathBuf, IpmsgError> {
        let mut stream = TcpStream::connect(sender_addr)?;
        let my_packet_no = next_packet_no(&self.packet_no);
        filexfer::request_file_bytes(
            &mut stream,
            IPMSG_VERSION,
            my_packet_no,
            &self.nick,
            &self.host,
            packet_no,
            file_id,
            size,
            save_path,
        )
    }

    /// TCP 连 `sender_addr`,发 `GETDIRFILES`(extra=`packetID:fileID` 全十六进制)
    /// 请求一个文件夹,解析对端的目录流并落盘到 `save_dir`。仅接收方向
    /// (设计文档 §6 冻结:文件夹仅接收,本服务不响应对端的 GETDIRFILES 请求)。
    pub fn request_dir(
        &self,
        sender_addr: SocketAddr,
        packet_no: u32,
        file_id: u32,
        save_dir: &Path,
    ) -> Result<PathBuf, IpmsgError> {
        let mut stream = TcpStream::connect(sender_addr)?;
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: next_packet_no(&self.packet_no),
            sender: self.nick.clone(),
            host: self.host.clone(),
            command: command::GETDIRFILES,
            extra: format!("{packet_no:x}:{file_id:x}"),
        };
        stream.write_all(&proto::encode(&packet))?;
        stream.flush()?;
        let path = filexfer::receive_dir_stream(&mut stream, save_dir)?;
        Ok(path)
    }

    /// 广播 BR_EXIT,停线程,关闭 socket。
    pub fn shutdown(mut self) {
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: next_packet_no(&self.packet_no),
            sender: self.nick.clone(),
            host: self.host.clone(),
            command: command::BR_EXIT,
            extra: self.self_token.to_string(),
        };
        broadcast(&self.socket, &proto::encode(&packet), self.port);

        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.send_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.recv_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tcp_handle.take() {
            let _ = h.join();
        }
        // 所有线程已退出,socket/listener 随 self 一起 drop。
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn br_entry(sender: &str, host: &str, extra: &str) -> Packet {
        Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: 1,
            sender: sender.to_string(),
            host: host.to_string(),
            command: command::BR_ENTRY,
            extra: extra.to_string(),
        }
    }

    fn src_addr() -> SocketAddr {
        "192.168.1.42:2425".parse().unwrap()
    }

    /// dispatch 测试专用的"本机 token":不出现在下面任何测试报文的 extra 里,
    /// 确保现有的正常分派用例不会被自过滤逻辑误伤。
    const TEST_TOKEN: &str = "test-self-token-deadbeef";

    #[test]
    fn dispatch_br_entry_replies_ansentry_and_emits_online() {
        let counter = AtomicU32::new(1);
        let packet = br_entry("alice", "HOST-A", &entry_extra("alice", "peer-token"));
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(
                reply,
                IpmsgEvent::Online {
                    key,
                    nick,
                    host,
                    addr,
                    is_bigpaw,
                },
            ) => {
                assert_eq!(Command(reply.command).num(), command::ANSENTRY);
                assert_eq!(reply.sender, "me");
                assert_eq!(reply.host, "HOST-ME");
                assert!(reply.extra.contains(BIGPAW_TAG));
                assert_eq!(key, "192.168.1.42:HOST-A");
                assert_eq!(nick, "alice");
                assert_eq!(host, "HOST-A");
                assert_eq!(addr, src_addr());
                assert!(is_bigpaw);
            }
            _ => panic!("expected ReplyAndEmit"),
        }
    }

    #[test]
    fn dispatch_br_entry_from_real_feiq_is_not_bigpaw() {
        let counter = AtomicU32::new(1);
        // 真实飞秋不会带 BIGPAW_TAG。
        let packet = br_entry("feiq-user", "HOST-B", "");
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(_, IpmsgEvent::Online { is_bigpaw, .. }) => {
                assert!(!is_bigpaw);
            }
            _ => panic!("expected ReplyAndEmit"),
        }
    }

    #[test]
    fn dispatch_ansentry_emits_online_without_reply() {
        let counter = AtomicU32::new(1);
        let mut packet = br_entry("bob", "HOST-B", &entry_extra("bob", "peer-token"));
        packet.command = command::ANSENTRY;
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::Emit(IpmsgEvent::Online {
                key, nick, host, ..
            }) => {
                assert_eq!(key, "192.168.1.42:HOST-B");
                assert_eq!(nick, "bob");
                assert_eq!(host, "HOST-B");
            }
            _ => panic!("expected Emit(Online)"),
        }
    }

    #[test]
    fn dispatch_br_exit_emits_offline() {
        let counter = AtomicU32::new(1);
        let mut packet = br_entry("bob", "HOST-B", "");
        packet.command = command::BR_EXIT;
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::Emit(IpmsgEvent::Offline { key }) => {
                assert_eq!(key, "192.168.1.42:HOST-B");
            }
            _ => panic!("expected Emit(Offline)"),
        }
    }

    fn sendmsg_packet(sender: &str, host: &str, extra: &str, with_checkopt: bool) -> Packet {
        let command = if with_checkopt {
            command::build(command::SENDMSG, &[command::SENDCHECKOPT])
        } else {
            command::SENDMSG
        };
        Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: 7,
            sender: sender.to_string(),
            host: host.to_string(),
            command,
            extra: extra.to_string(),
        }
    }

    fn recvmsg_packet(sender: &str, host: &str, acked_no: &str) -> Packet {
        Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: 8,
            sender: sender.to_string(),
            host: host.to_string(),
            command: command::RECVMSG,
            extra: acked_no.to_string(),
        }
    }

    #[test]
    fn dispatch_sendmsg_with_checkopt_emits_text_and_replies_recvmsg() {
        let counter = AtomicU32::new(1);
        let packet = sendmsg_packet("alice", "HOST-A", "你好,BigPaw", true);
        let original_no = packet.packet_no;
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(reply, IpmsgEvent::TextReceived { key, from, body }) => {
                assert_eq!(Command(reply.command).num(), command::RECVMSG);
                assert_eq!(reply.extra, original_no.to_string());
                assert_eq!(reply.sender, "me");
                assert_eq!(reply.host, "HOST-ME");
                assert_eq!(key, "192.168.1.42:HOST-A");
                assert_eq!(from, "alice");
                assert_eq!(body, "你好,BigPaw");
            }
            _ => panic!("expected ReplyAndEmit(TextReceived)"),
        }
    }

    #[test]
    fn dispatch_sendmsg_without_checkopt_emits_text_without_reply() {
        let counter = AtomicU32::new(1);
        let packet = sendmsg_packet("bob", "HOST-B", "hello", false);
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::Emit(IpmsgEvent::TextReceived { key, from, body }) => {
                assert_eq!(key, "192.168.1.42:HOST-B");
                assert_eq!(from, "bob");
                assert_eq!(body, "hello");
            }
            _ => panic!("expected Emit(TextReceived) without reply"),
        }
    }

    #[test]
    fn dispatch_recvmsg_acks_original_packet_no() {
        let counter = AtomicU32::new(1);
        let packet = recvmsg_packet("alice", "HOST-A", "42");
        assert!(matches!(
            dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN),
            Action::Ack(42)
        ));
    }

    #[test]
    fn dispatch_recvmsg_with_garbage_extra_is_ignored() {
        let counter = AtomicU32::new(1);
        let packet = recvmsg_packet("alice", "HOST-A", "not-a-number");
        assert!(matches!(
            dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN),
            Action::None
        ));
    }

    /// 中文正文经 GBK 编解码往返后,dispatch 仍能还原出正确的 body
    /// (emoji 无 GBK 映射 → '?',符合 proto 层既有约定)。
    #[test]
    fn dispatch_sendmsg_chinese_body_roundtrips_through_wire() {
        let counter = AtomicU32::new(1);
        let packet = sendmsg_packet("alice", "HOST-A", "你好,世界🐾", true);
        let wire = proto::encode(&packet);
        let decoded = proto::decode(&wire).unwrap();
        match dispatch(decoded, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(_, IpmsgEvent::TextReceived { body, .. }) => {
                assert!(body.starts_with("你好,世界"));
                assert!(body.contains('?'));
            }
            _ => panic!("expected ReplyAndEmit(TextReceived)"),
        }
    }

    /// SENDMSG|FILEATTACHOPT → FileOffered,文件清单解析正确
    /// (packet_no 就是这条 SENDMSG 自身的 packet_no,供后续 GETFILEDATA 引用)。
    #[test]
    fn dispatch_sendmsg_with_fileattachopt_emits_file_offered() {
        let counter = AtomicU32::new(1);
        let extra =
            filexfer::build_file_offer_extra("", 0, "图片.png", 1000, 0, filexfer::FILE_REGULAR);
        let command = command::build(command::SENDMSG, &[command::FILEATTACHOPT]);
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: 99,
            sender: "alice".to_string(),
            host: "HOST-A".to_string(),
            command,
            extra,
        };
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::Emit(IpmsgEvent::FileOffered {
                key,
                from,
                packet_no,
                files,
            }) => {
                assert_eq!(key, "192.168.1.42:HOST-A");
                assert_eq!(from, "alice");
                assert_eq!(packet_no, 99);
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].name, "图片.png");
                assert_eq!(files[0].size, 1000);
                assert!(!files[0].is_dir);
            }
            _ => panic!("expected Emit(FileOffered)"),
        }
    }

    /// FILEATTACHOPT + SENDCHECKOPT 组合:仍然要回 RECVMSG 回执,同时上报 FileOffered
    /// (文件 offer 本质上还是一条 SENDMSG,回执行为不因为带了文件而改变)。
    #[test]
    fn dispatch_sendmsg_fileattachopt_with_checkopt_still_replies_recvmsg() {
        let counter = AtomicU32::new(1);
        let extra = filexfer::build_file_offer_extra(
            "看这个",
            3,
            "report.pdf",
            2048,
            0,
            filexfer::FILE_REGULAR,
        );
        let command = command::build(
            command::SENDMSG,
            &[command::FILEATTACHOPT, command::SENDCHECKOPT],
        );
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: 55,
            sender: "bob".to_string(),
            host: "HOST-B".to_string(),
            command,
            extra,
        };
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(
                reply,
                IpmsgEvent::FileOffered {
                    packet_no, files, ..
                },
            ) => {
                assert_eq!(Command(reply.command).num(), command::RECVMSG);
                assert_eq!(reply.extra, "55");
                assert_eq!(packet_no, 55);
                assert_eq!(files[0].name, "report.pdf");
            }
            _ => panic!("expected ReplyAndEmit(FileOffered)"),
        }
    }

    /// `send_file` 内部构造的 offer 报文:command 位必须含 FILEATTACHOPT,
    /// 且 extra 能被 parse_file_attach_extra 正确还原(纯函数级验证,不需要起网络服务)。
    #[test]
    fn file_offer_packet_has_fileattachopt_and_parses_back() {
        let p = file_offer_packet("me", "HOST-ME", 9, 0, "图片.png", 1000, 0);
        assert_eq!(Command(p.command).num(), command::SENDMSG);
        assert!(Command(p.command).has_opt(command::FILEATTACHOPT));
        assert!(Command(p.command).has_opt(command::SENDCHECKOPT));
        let (_body, files) = filexfer::parse_file_attach_extra(&p.extra);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "图片.png");
        assert_eq!(files[0].size, 1000);
        assert!(!files[0].is_dir);
    }

    #[test]
    fn dispatch_unknown_command_is_ignored() {
        let counter = AtomicU32::new(1);
        // GETFILEDATA/GETDIRFILES 是 TCP-only 命令(见 filexfer.rs),不会出现在
        // UDP dispatch 里;这里仍用它验证"未知于 UDP 分派的命令号"静默忽略的兜底分支。
        let mut packet = br_entry("bob", "HOST-B", "");
        packet.command = command::GETFILEDATA;
        assert!(matches!(
            dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN),
            Action::None
        ));
    }

    #[test]
    fn entry_extra_embeds_bigpaw_tag_and_self_token() {
        let extra = entry_extra("nick", "tok123");
        assert!(extra.starts_with("nick"));
        assert!(extra.contains(BIGPAW_TAG));
        assert!(extra.contains("tok123"));
    }

    /// 核心自过滤回归测试:一个带有本机 self_token 的报文(即自己的 BR_ENTRY/
    /// BR_EXIT 被 OS 广播回环反射回本机 recv 的场景)必须被 dispatch 拦下,
    /// 不回包、不上报任何事件——否则会把自己误判为新上线/下线的对端。
    #[test]
    fn dispatch_packet_with_own_self_token_is_ignored() {
        let counter = AtomicU32::new(1);
        let packet = br_entry("me", "HOST-ME", &entry_extra("me", TEST_TOKEN));
        assert!(matches!(
            dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN),
            Action::None
        ));
    }

    /// 同样的报文形状,但换成一个真实 BigPaw 对端的不同 token → 必须正常
    /// 分派为 Online,不能被误伤(否则就是把所有 BigPaw 对端都过滤掉了)。
    #[test]
    fn dispatch_packet_with_different_token_is_not_filtered() {
        let counter = AtomicU32::new(1);
        let packet = br_entry(
            "alice",
            "HOST-A",
            &entry_extra("alice", "a-different-token"),
        );
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter, TEST_TOKEN) {
            Action::ReplyAndEmit(_, IpmsgEvent::Online { is_bigpaw, .. }) => {
                assert!(is_bigpaw);
            }
            _ => panic!("expected ReplyAndEmit(Online) for a real peer with a different token"),
        }
    }

    /// 端口被占用必须明确报错,不能静默失败。
    /// 用一个不带 REUSEADDR 的普通 UdpSocket 先占住端口作为"对照组"。
    /// 注:若本机确有进程占用测试用端口(与对照组冲突),提前返回跳过——
    /// 该场景已在设计文档要求下改由人工验证(启动飞秋/feiq 后启动 BigPaw 观察报错)。
    #[test]
    fn start_returns_port_in_use_when_port_already_bound() {
        // 用高位临时端口而非 2425,避免和真实局域网 IPMsg 流量/其它测试抢占标准端口。
        const TEST_PORT: u16 = 22425;
        let guard = match std::net::UdpSocket::bind(("0.0.0.0", TEST_PORT)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("跳过:无法建立对照组 socket ({e}),疑似端口已被其它进程占用");
                return;
            }
        };

        let (tx, _rx) = std::sync::mpsc::channel();
        let result = IpmsgService::start("me", "HOST-ME", TEST_PORT, tx);
        drop(guard);

        match result {
            Err(IpmsgError::PortInUse) => {}
            Err(other) => panic!("expected PortInUse, got {other:?}"),
            Ok(svc) => {
                // 见任务说明:SO_REUSEADDR 在某些平台上可能允许重复 bind 成功。
                // 若发生这种情况,PortInUse 分支在本机无法通过纯单元测试验证,
                // 需要人工验证(两台机器/同机启动飞秋)确认 2425 占用报错行为。
                svc.shutdown();
                panic!("本机 SO_REUSEADDR 允许了重复 bind,PortInUse 分支需人工验证而非单测覆盖");
            }
        }
    }
}

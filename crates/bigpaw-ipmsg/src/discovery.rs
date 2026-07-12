//! IPMsg 发现层:BR_ENTRY/ANSENTRY/BR_EXIT over UDP 2425(设计文档 §6)。
//!
//! 零 Tauri、零异步运行时,仅线程 + std::net + socket2,不依赖 bigpaw-core。
//! 严格生成:仅发送标准的 BR_ENTRY/ANSENTRY/BR_EXIT 三种报文,其余命令号
//! (SENDMSG/RECVMSG/GETFILEDATA 等)留给后续任务分派,此处静默忽略。

use crate::command::{self, Command};
use crate::proto::{self, Packet, BIGPAW_TAG};
use socket2::{Domain, Protocol as SockProtocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
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
}

#[derive(Debug, Error)]
pub enum IpmsgError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// 2425 已被占用(常见于飞秋已在运行);必须明确报错,不能静默失败。
    #[error("port already in use")]
    PortInUse,
}

/// extra 尾部附带 BIGPAW_TAG,供对端识别我方为 BigPaw(飞秋会忽略这段附加数据)。
fn entry_extra(nick: &str) -> String {
    format!("{nick}{BIGPAW_TAG}")
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

fn send_entry(socket: &UdpSocket, packet_no: &AtomicU32, nick: &str, host: &str, port: u16) {
    let packet = Packet {
        version: IPMSG_VERSION.to_string(),
        packet_no: next_packet_no(packet_no),
        sender: nick.to_string(),
        host: host.to_string(),
        command: command::BR_ENTRY,
        extra: entry_extra(nick),
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
) {
    send_entry(&socket, &packet_no, &nick, &host, port);
    loop {
        interruptible_sleep(&stop, ENTRY_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        send_entry(&socket, &packet_no, &nick, &host, port);
    }
}

/// 收到报文后的处理结果:纯函数,便于脱离真实 socket 单元测试。
enum Action {
    /// 未知命令号(SENDMSG 等留给后续任务)或其它不需处理的情况:静默忽略。
    None,
    /// 直接上报事件,无需回包(ANSENTRY / BR_EXIT)。
    Emit(IpmsgEvent),
    /// 单播回一个 ANSENTRY 报文,并上报 Online 事件(收到对端 BR_ENTRY)。
    ReplyAndEmit(Packet, IpmsgEvent),
}

/// 按 `Command(p.command).num()` 分派:BR_ENTRY → 回 ANSENTRY + Online;
/// ANSENTRY → Online;BR_EXIT → Offline;其它命令号静默忽略。
fn dispatch(
    packet: Packet,
    src: SocketAddr,
    nick: &str,
    host: &str,
    packet_no: &AtomicU32,
) -> Action {
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
                extra: entry_extra(nick),
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
        _ => Action::None,
    }
}

/// 接收线程主循环:recv_from → proto::decode(畸形报文静默丢弃)→ dispatch → 执行动作。
fn recv_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    packet_no: Arc<AtomicU32>,
    nick: String,
    host: String,
    tx: Sender<IpmsgEvent>,
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

        match dispatch(packet, src, &nick, &host, &packet_no) {
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
        }
    }
}

/// IPMsg 发现服务:UDP 2425 上的 BR_ENTRY/ANSENTRY/BR_EXIT 收发。
/// 独立 crate:零 Tauri、零异步运行时,仅 std::net + socket2 线程模型。
pub struct IpmsgService {
    stop: Arc<AtomicBool>,
    socket: Arc<UdpSocket>,
    packet_no: Arc<AtomicU32>,
    nick: String,
    host: String,
    port: u16,
    send_handle: Option<JoinHandle<()>>,
    recv_handle: Option<JoinHandle<()>>,
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

        let send_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let packet_no = Arc::clone(&packet_no);
            let nick = nick.to_string();
            let host = host.to_string();
            std::thread::spawn(move || send_loop(socket, stop, packet_no, nick, host, port))
        };

        let recv_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let packet_no = Arc::clone(&packet_no);
            let nick = nick.to_string();
            let host = host.to_string();
            std::thread::spawn(move || recv_loop(socket, stop, packet_no, nick, host, tx))
        };

        Ok(IpmsgService {
            stop,
            socket,
            packet_no,
            nick: nick.to_string(),
            host: host.to_string(),
            port,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
        })
    }

    /// 广播 BR_EXIT,停线程,关闭 socket。
    pub fn shutdown(mut self) {
        let packet = Packet {
            version: IPMSG_VERSION.to_string(),
            packet_no: next_packet_no(&self.packet_no),
            sender: self.nick.clone(),
            host: self.host.clone(),
            command: command::BR_EXIT,
            extra: String::new(),
        };
        broadcast(&self.socket, &proto::encode(&packet), self.port);

        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.send_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.recv_handle.take() {
            let _ = h.join();
        }
        // 两条线程已退出,socket 随 self 一起 drop。
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

    #[test]
    fn dispatch_br_entry_replies_ansentry_and_emits_online() {
        let counter = AtomicU32::new(1);
        let packet = br_entry("alice", "HOST-A", &entry_extra("alice"));
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter) {
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
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter) {
            Action::ReplyAndEmit(_, IpmsgEvent::Online { is_bigpaw, .. }) => {
                assert!(!is_bigpaw);
            }
            _ => panic!("expected ReplyAndEmit"),
        }
    }

    #[test]
    fn dispatch_ansentry_emits_online_without_reply() {
        let counter = AtomicU32::new(1);
        let mut packet = br_entry("bob", "HOST-B", &entry_extra("bob"));
        packet.command = command::ANSENTRY;
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter) {
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
        match dispatch(packet, src_addr(), "me", "HOST-ME", &counter) {
            Action::Emit(IpmsgEvent::Offline { key }) => {
                assert_eq!(key, "192.168.1.42:HOST-B");
            }
            _ => panic!("expected Emit(Offline)"),
        }
    }

    #[test]
    fn dispatch_unknown_command_is_ignored() {
        let counter = AtomicU32::new(1);
        // SENDMSG 等留给后续任务,此阶段静默忽略。
        let mut packet = br_entry("bob", "HOST-B", "");
        packet.command = command::SENDMSG;
        assert!(matches!(
            dispatch(packet, src_addr(), "me", "HOST-ME", &counter),
            Action::None
        ));
    }

    #[test]
    fn entry_extra_embeds_bigpaw_tag() {
        let extra = entry_extra("nick");
        assert!(extra.starts_with("nick"));
        assert!(extra.contains(BIGPAW_TAG));
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

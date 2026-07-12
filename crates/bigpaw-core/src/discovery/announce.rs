//! UDP 宣告报文编解码 + 历史设备 IP 持久化 + 宣告收发服务(设计文档 §4)。
//! 报文严格 ≤ 1 个 MTU(防 IP 分片)。
//!
//! 网络友好铁律:
//! - 组播 TTL=1,报文绝不出本地网络;
//! - 应答只单播(防 N² 广播风暴),且对同一源限速;
//! - 启动快速宣告(2s/4s/8s 退避)后转周期(~25s),发送批次间隔 ≥1s。

use crate::identity::Identity;
use crate::roster::DiscoveryEvent;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol as SockProtocol, SockAddr, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;

/// 宣告服务默认端口(设计文档 §4)。
pub const DEFAULT_ANNOUNCE_PORT: u16 = 24916;
/// 组播组:仅限本地网络(TTL=1),绝不路由出局域网。
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 88);

const RECV_BUF_SIZE: usize = 2048;
/// recv_from 超时:让接收线程能定期醒来检查停止标志,而不是永久阻塞。
const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(500);
/// 同一源地址的单播应答限速,防止应答风暴。
const REPLY_RATE_LIMIT: Duration = Duration::from_secs(5);
/// 启动后的指数退避快速宣告(2s/4s/8s),随后转入周期宣告。
const STARTUP_BACKOFF: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];
const PERIODIC_INTERVAL: Duration = Duration::from_secs(25);
/// 全局发送批次最小间隔(令牌桶简化版):两次发送批次之间至少间隔这么久。
const MIN_SEND_BATCH_INTERVAL: Duration = Duration::from_secs(1);
/// 中断式休眠的步长,让停止标志能被及时观察到。
const SLEEP_STEP: Duration = Duration::from_millis(200);

/// 虚拟接口名关键字(隧道/网桥/虚拟网卡),这些不参与广播宣告。
const VIRTUAL_IFACE_HINTS: [&str; 5] = ["tun", "utun", "bridge", "vnic", "vmnet"];

const MAX_DATAGRAM: usize = 1400;
const MAX_NICK_BYTES: usize = 64;
const MAX_HISTORY: usize = 50;
const HISTORY_FILE: &str = "history_ips.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub v: u16,
    pub fp: String,
    pub nick: String,
    pub tport: u16,
    pub caps: String,
}

/// 昵称按 UTF-8 字节边界截断到 <= MAX_NICK_BYTES。
fn truncate_nick(nick: &str) -> String {
    if nick.len() <= MAX_NICK_BYTES {
        return nick.to_string();
    }
    let mut end = MAX_NICK_BYTES;
    while end > 0 && !nick.is_char_boundary(end) {
        end -= 1;
    }
    nick[..end].to_string()
}

pub fn encode(a: &Announcement) -> Vec<u8> {
    let safe = Announcement {
        nick: truncate_nick(&a.nick),
        ..a.clone()
    };
    let buf = serde_json::to_vec(&safe).unwrap_or_default();
    debug_assert!(buf.len() <= MAX_DATAGRAM);
    buf
}

pub fn decode(buf: &[u8]) -> Option<Announcement> {
    let a: Announcement = serde_json::from_slice(buf).ok()?;
    if a.fp.len() == 64 && a.v == 1 {
        Some(a)
    } else {
        None
    }
}

/// 历史设备 IP:去重、上限 50、LRU(最近记录的排前)、JSON 持久化。
pub struct HistoryStore {
    ips: VecDeque<IpAddr>,
}

impl HistoryStore {
    pub fn load(data_dir: &Path) -> Self {
        let ips = fs::read(data_dir.join(HISTORY_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<IpAddr>>(&b).ok())
            .unwrap_or_default();
        Self {
            ips: ips.into_iter().collect(),
        }
    }

    pub fn record(&mut self, ip: IpAddr) {
        self.ips.retain(|x| *x != ip);
        self.ips.push_front(ip);
        while self.ips.len() > MAX_HISTORY {
            self.ips.pop_back();
        }
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        self.ips.iter().copied().collect()
    }

    pub fn save(&self, data_dir: &Path) {
        if let Ok(b) = serde_json::to_vec(&self.ips()) {
            let _ = fs::write(data_dir.join(HISTORY_FILE), b);
        }
    }
}

#[derive(Debug, Error)]
pub enum AnnounceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// 判断接口名是否为虚拟/隧道类接口(不参与物理网段广播)。
fn is_virtual_iface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_IFACE_HINTS.iter().any(|hint| lower.contains(hint))
}

/// 枚举本机物理 IPv4 接口(跳过 loopback 与虚拟接口)。
fn physical_ipv4_interfaces() -> Vec<if_addrs::Ifv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !is_virtual_iface(&iface.name))
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) => Some(v4),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect()
}

/// 由 ip+netmask 计算定向广播地址(ip | !netmask)。
fn directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(netmask))
}

/// 绑定 0.0.0.0:port 的 UDP socket:REUSEADDR/REUSEPORT + BROADCAST,TTL=1,
/// 对每个物理接口尝试 join 组播组(失败的接口跳过,不影响其余接口)。
/// 返回 (socket, 实际 join 成功的接口 IP 列表) 供 shutdown 时对称 leave。
fn bind_socket(port: u16) -> Result<(UdpSocket, Vec<Ipv4Addr>), AnnounceError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    // TTL 失败不致命(极少数平台/权限限制),但仍应尽力设置以满足“绝不出局域网”铁律。
    let _ = socket.set_multicast_ttl_v4(1);

    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into();
    socket.bind(&SockAddr::from(bind_addr))?;

    let mut joined = Vec::new();
    for iface in physical_ipv4_interfaces() {
        if socket
            .join_multicast_v4(&MULTICAST_GROUP, &iface.ip)
            .is_ok()
        {
            joined.push(iface.ip);
        }
        // join 失败的接口直接跳过,不中断其余接口的尝试(铁律:单接口失败不影响整体)。
    }

    socket.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
    Ok((socket.into(), joined))
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

/// 向组播组 + 所有物理接口的定向广播地址双发同一份报文;单个目标发送失败不影响其余目标。
fn send_dual(socket: &UdpSocket, buf: &[u8], port: u16) {
    let _ = socket.send_to(buf, SocketAddrV4::new(MULTICAST_GROUP, port));
    for iface in physical_ipv4_interfaces() {
        let bcast = directed_broadcast(iface.ip, iface.netmask);
        let _ = socket.send_to(buf, SocketAddrV4::new(bcast, port));
    }
}

/// 发送线程主循环:启动 3 次指数退避快速宣告(2s/4s/8s),之后转周期宣告(~25s)。
/// 每次发送批次之间的全局最小间隔由退避/周期时长天然保证(均 ≥ MIN_SEND_BATCH_INTERVAL)。
fn send_loop(socket: Arc<UdpSocket>, stop: Arc<AtomicBool>, buf: Vec<u8>, port: u16) {
    debug_assert!(STARTUP_BACKOFF
        .iter()
        .all(|d| *d >= MIN_SEND_BATCH_INTERVAL));
    debug_assert!(PERIODIC_INTERVAL >= MIN_SEND_BATCH_INTERVAL);
    for delay in STARTUP_BACKOFF {
        interruptible_sleep(&stop, delay);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        send_dual(&socket, &buf, port);
    }
    loop {
        interruptible_sleep(&stop, PERIODIC_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        send_dual(&socket, &buf, port);
    }
}

/// 接收线程主循环:recv_from → decode(丢弃畸形报文)→ 过滤自己 fp → 上报 Seen →
/// 对源地址限速单播回应自己的宣告(防应答风暴)。
fn recv_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    self_fp: String,
    reply_buf: Vec<u8>,
    tx: Sender<DiscoveryEvent>,
) {
    let mut last_reply: HashMap<IpAddr, Instant> = HashMap::new();
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
                // 瞬时错误(如 ICMP unreachable 导致的 recv 报错):短暂让步后重试,不panic、不退出。
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        let Some(ann) = decode(&buf[..n]) else {
            continue; // 畸形报文静默丢弃
        };
        if ann.fp == self_fp {
            continue; // 自己的宣告(含本机多播回环),跳过
        }

        let src_ip = src.ip();
        let ev = DiscoveryEvent::Seen {
            fingerprint: ann.fp,
            nickname: ann.nick,
            addrs: vec![src_ip],
            port: ann.tport,
        };
        if tx.send(ev).is_err() {
            return; // 接收端已销毁,退出线程
        }

        let now = Instant::now();
        let should_reply = last_reply
            .get(&src_ip)
            .map(|last| now.duration_since(*last) >= REPLY_RATE_LIMIT)
            .unwrap_or(true);
        if should_reply {
            last_reply.insert(src_ip, now);
            // 应答只单播回对端的宣告 socket(收发同一 socket,src 即其宣告端口),防 N² 广播风暴。
            let _ = socket.send_to(&reply_buf, src);
        }
    }
}

/// UDP 宣告收发服务:组播+定向广播双发 + 单播限速应答(设计文档 §4)。
/// 零 Tauri、零异步运行时,仅线程 + std::net + socket2。
pub struct AnnounceService {
    stop: Arc<AtomicBool>,
    socket: Arc<UdpSocket>,
    joined: Vec<Ipv4Addr>,
    /// 预编码好的自身宣告报文,`poke` 复用它做定向单播(见下)。
    announce_buf: Vec<u8>,
    send_handle: Option<JoinHandle<()>>,
    recv_handle: Option<JoinHandle<()>>,
}

impl AnnounceService {
    /// 启动宣告收发服务:绑定 socket、加入组播组,并分别起发送/接收线程。
    pub fn start(
        identity: &Identity,
        nick: &str,
        tport: u16,
        port: u16,
        tx: Sender<DiscoveryEvent>,
    ) -> Result<AnnounceService, AnnounceError> {
        let (socket, joined) = bind_socket(port)?;
        let socket = Arc::new(socket);
        let stop = Arc::new(AtomicBool::new(false));

        let announcement = Announcement {
            v: 1,
            fp: identity.fingerprint.clone(),
            nick: nick.to_string(),
            tport,
            caps: "native".to_string(),
        };
        let buf = encode(&announcement);
        let self_fp = identity.fingerprint.clone();

        let send_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let buf = buf.clone();
            std::thread::spawn(move || send_loop(socket, stop, buf, port))
        };

        let recv_handle = {
            let socket = Arc::clone(&socket);
            let stop = Arc::clone(&stop);
            let buf = buf.clone();
            std::thread::spawn(move || recv_loop(socket, stop, self_fp, buf, tx))
        };

        Ok(AnnounceService {
            stop,
            socket,
            joined,
            announce_buf: buf,
            send_handle: Some(send_handle),
            recv_handle: Some(recv_handle),
        })
    }

    /// 对历史已知的单个 IP 发一份定向单播宣告(而非组播/广播),用来"唤醒"
    /// 一台 mDNS 因故听不到的历史设备——对方收到后走正常的宣告应答/mDNS
    /// 发现流程重新上线,本端不做端口扫描、不建立连接。
    ///
    /// 只发一个包,不在内部做节流:调用方(见 `Core::start` 的历史探测线程)
    /// 负责串行调用、每次间隔 ≥50ms,避免看起来像扫描而触发 IDS 告警。
    pub fn poke(&self, ip: IpAddr) {
        let target = SocketAddr::new(ip, DEFAULT_ANNOUNCE_PORT);
        let _ = self.socket.send_to(&self.announce_buf, target);
    }

    /// 停止两条线程、退出组播组并关闭 socket。
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.send_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.recv_handle.take() {
            let _ = h.join();
        }
        // 两条线程已退出,自己是唯一持有者:可安全拿回 socket 显式 leave_multicast。
        if let Ok(std_socket) = Arc::try_unwrap(self.socket) {
            let sock2 = Socket::from(std_socket);
            for ip in &self.joined {
                let _ = sock2.leave_multicast_v4(&MULTICAST_GROUP, ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ann() -> Announcement {
        Announcement {
            v: 1,
            fp: "a".repeat(64),
            nick: "alice".to_string(),
            tport: 24917,
            caps: "native".to_string(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let a = ann();
        let buf = encode(&a);
        assert!(buf.len() <= 1400);
        assert_eq!(decode(&buf), Some(a));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(decode(b"not json"), None);
        assert_eq!(decode(b"{}"), None); // 缺字段
        assert_eq!(decode(&[0xff, 0xfe]), None);
    }

    #[test]
    fn long_nick_is_truncated_to_fit_mtu() {
        let mut a = ann();
        a.nick = "长".repeat(500); // 远超 64 字节
        let buf = encode(&a);
        assert!(buf.len() <= 1400);
        let back = decode(&buf).unwrap();
        assert!(back.nick.len() <= 64);
    }

    #[test]
    fn history_dedup_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::load(dir.path());
        for i in 0..60u8 {
            h.record(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)));
        }
        h.record(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))); // 重复
        assert!(h.ips().len() <= 50, "上限 50");
        h.save(dir.path());
        let h2 = HistoryStore::load(dir.path());
        assert_eq!(h2.ips().len(), h.ips().len(), "重载一致");
    }
}

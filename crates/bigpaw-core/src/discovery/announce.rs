//! UDP 宣告报文编解码 + 历史设备 IP 持久化 + 宣告收发服务(设计文档 §4)。
//! 报文严格 ≤ 1 个 MTU(防 IP 分片)。
//!
//! 网络友好铁律:
//! - 组播 TTL=1,报文绝不出本地网络;
//! - 应答只单播(防 N² 广播风暴),且对同一源限速;
//! - 启动快速宣告(2s/4s/8s 退避)后转周期(~25s),发送批次间隔 ≥1s。

use crate::identity::Identity;
use crate::net_ifaces::{multicast_diff, send_targets, IfaceEntry, IfaceSnapshot};
use crate::roster::{DiscoveryEvent, Protocol};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol as SockProtocol, SockAddr, SockRef, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::watch;

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

/// 绑定 0.0.0.0:port 的 UDP socket:REUSEADDR/REUSEPORT + BROADCAST,TTL=1。
/// 不做任何组播 join——网卡选择已迁到 `net_ifaces::InterfaceRegistry`,组播
/// 成员关系改由 `sync_multicast` 按其发布的快照增量维护(见 `send_loop`),
/// 与"当前活跃网卡有哪些"这件事解耦,不再在绑定这一刻一次性枚举定死。
fn bind_socket(port: u16) -> Result<UdpSocket, AnnounceError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    // TTL 失败不致命(极少数平台/权限限制),但仍应尽力设置以满足“绝不出局域网”铁律。
    let _ = socket.set_multicast_ttl_v4(1);

    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into();
    socket.bind(&SockAddr::from(bind_addr))?;

    socket.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
    Ok(socket.into())
}

/// 按当前活跃网卡快照增量同步组播 join/leave 状态(`multicast_diff` 纯计算
/// 已在 `net_ifaces` 测过,这里只是把结果落到 std `UdpSocket` 自带的
/// `join_multicast_v4`/`leave_multicast_v4` 上)。全部容错(`let _`/
/// `is_ok()`):单张网卡 join/leave 失败不影响其余网卡,也不 panic——
/// `joined` 只记录"确认成功"的那些,失败的 join 不计入(下次快照不变时还会
/// 再尝试),leave 无论成败都从 `joined` 摘除(避免反复对一个已经不存在的
/// 接口发起 leave)。
fn sync_multicast(socket: &UdpSocket, joined: &mut Vec<Ipv4Addr>, entries: &[IfaceEntry]) {
    let (to_join, to_leave) = multicast_diff(joined, entries);
    for ip in &to_leave {
        let _ = socket.leave_multicast_v4(&MULTICAST_GROUP, ip);
    }
    joined.retain(|ip| !to_leave.contains(ip));
    for ip in to_join {
        if socket.join_multicast_v4(&MULTICAST_GROUP, &ip).is_ok() {
            joined.push(ip);
        }
    }
}

/// 向组播组 + 各子网定向广播地址双发同一份报文。先用 `send_targets` 做子网
/// 去重(同一子网多张网卡只发一次,防重复宣告/防飞秋对端列表重复),对每个
/// 目标临时借用 `socket2::SockRef` 把 `IP_MULTICAST_IF` 切到该网卡再发一次
/// 组播(否则组播出口网卡由系统路由表决定,不一定是我们想要的那张),随后
/// 发一次该子网的定向广播——组播+广播双通道兜底(部分交换机 IGMP snooping
/// 会让纯组播不可达)。`IP_MULTICAST_IF` 只影响组播发送方向,不影响本 socket
/// 的接收或 `poke` 用到的单播发送。
///
/// 门控范围只包住组播发送:`set_multicast_if_v4` 失败只应跳过"这张卡的组播"
/// 这一份,定向广播必须无条件照发——组播出口切换失败(权限/平台限制等)恰恰
/// 是广播兜底要发挥作用的场景,如果连广播也被一并跳过,这张卡就完全哑火了,
/// 违背"组播+广播双通道兜底"的设计初衷。单个目标的失败不影响其余目标
/// (铁律:单网卡失败不拖垮整轮)。`entries` 为空(用户排除了全部网卡)时
/// `send_targets` 返回空列表,本函数因此静默不发——即“全网隐身”。
fn send_dual(socket: &UdpSocket, buf: &[u8], port: u16, entries: &[IfaceEntry]) {
    for target in send_targets(entries) {
        if SockRef::from(socket)
            .set_multicast_if_v4(&target.iface_ip)
            .is_ok()
        {
            let _ = socket.send_to(buf, SocketAddrV4::new(MULTICAST_GROUP, port));
        }
        // 定向广播不依赖 IP_MULTICAST_IF,组播出口切换失败也照发。
        let _ = socket.send_to(buf, SocketAddrV4::new(target.broadcast, port));
    }
}

/// 统一的全局发送限速判定:距上次发送是否已过 `MIN_SEND_BATCH_INTERVAL`。
/// `sleep_and_watch_ifaces` 里的"网卡变化补发"与 `send_loop` 里的"边界发送"
/// 共用这一个判定(而不是各写一份 `elapsed() >= ...`),避免两处口径走样——
/// 后者正是曾经的 Critical bug:边界发送若不做同样的门控,变化补发和紧随其后
/// 的边界发送可能只隔一个 `SLEEP_STEP`(200ms),突破"报文速率不高于现状"
/// 铁律。抽成纯函数(接受显式 `now` 而非内部调用 `Instant::now()`)是为了能
/// 在不真实睡眠的情况下用构造出的时间点确定性单测。
fn send_allowed(last_send: Instant, now: Instant) -> bool {
    now.duration_since(last_send) >= MIN_SEND_BATCH_INTERVAL
}

/// 中断式休眠 + 网卡热变化响应:每 `SLEEP_STEP`(≤200ms)检查一次停止标志与
/// `ifaces_rx` 是否有新快照。快照变化时(网卡热插拔/用户改排除清单)立即按
/// 新快照 `sync_multicast` 并补发一批宣告,但受 `MIN_SEND_BATCH_INTERVAL`
/// 全局限速(避免抖动网卡触发发送风暴,不违反“报文速率不高于现状”铁律);
/// 不打断外层原有的退避/周期发送节奏,只是让"网卡变化秒级可见"。
/// 返回 `false` 表示被停止信号中断(调用方应立即退出线程)。
#[allow(clippy::too_many_arguments)]
fn sleep_and_watch_ifaces(
    stop: &AtomicBool,
    ifaces_rx: &mut watch::Receiver<IfaceSnapshot>,
    joined: &Mutex<Vec<Ipv4Addr>>,
    socket: &UdpSocket,
    buf: &[u8],
    port: u16,
    last_send: &mut Instant,
    dur: Duration,
) -> bool {
    let mut remaining = dur;
    while remaining > Duration::ZERO {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        if ifaces_rx.has_changed().unwrap_or(false) {
            let snapshot = ifaces_rx.borrow_and_update().clone();
            {
                let mut joined_guard = joined.lock().expect("joined lock");
                sync_multicast(socket, &mut joined_guard, &snapshot.entries);
            }
            if send_allowed(*last_send, Instant::now()) {
                send_dual(socket, buf, port, &snapshot.entries);
                *last_send = Instant::now();
            }
        }
        let step = remaining.min(SLEEP_STEP);
        std::thread::sleep(step);
        remaining -= step;
    }
    true
}

/// 发送线程主循环:启动 3 次指数退避快速宣告(2s/4s/8s),之后转周期宣告
/// (~25s)。每次发送批次之间的全局最小间隔由退避/周期时长天然保证(均 ≥
/// `MIN_SEND_BATCH_INTERVAL`),但 `sleep_and_watch_ifaces` 内部可能因网卡
/// 快照变化在等待窗口的任意时刻(包括临近结束时)已经补发过一批——因此每次
/// 睡眠结束后的"边界发送"仍需重新经过 `send_allowed` 门控,不能无条件发送,
/// 否则变化补发 + 边界发送可能只隔一个 `SLEEP_STEP`(200ms),突破"报文速率
/// 不高于现状"铁律。跳过边界
/// 发送不会饿死周期宣告:下一轮的等待时长(≥2s)本身就远大于
/// `MIN_SEND_BATCH_INTERVAL`(1s),届时必定又满足门槛。进循环前先按当前
/// 快照同步一次组播 join 状态(不发送,避免启动瞬间用空 `joined` 集合走一轮
/// "全部 to_join" 又立刻被 STARTUP_BACKOFF 的第一次发送重复触发)。
fn send_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    buf: Vec<u8>,
    port: u16,
    mut ifaces_rx: watch::Receiver<IfaceSnapshot>,
    joined: Arc<Mutex<Vec<Ipv4Addr>>>,
) {
    debug_assert!(STARTUP_BACKOFF
        .iter()
        .all(|d| *d >= MIN_SEND_BATCH_INTERVAL));
    debug_assert!(PERIODIC_INTERVAL >= MIN_SEND_BATCH_INTERVAL);

    {
        let snapshot = ifaces_rx.borrow_and_update().clone();
        let mut joined_guard = joined.lock().expect("joined lock");
        sync_multicast(&socket, &mut joined_guard, &snapshot.entries);
    }
    // 允许第一次退避发送不被“上次发送时间”误判为过近:初值刻意设在
    // MIN_SEND_BATCH_INTERVAL 之前。
    let mut last_send = Instant::now()
        .checked_sub(MIN_SEND_BATCH_INTERVAL)
        .unwrap_or_else(Instant::now);

    for delay in STARTUP_BACKOFF {
        if !sleep_and_watch_ifaces(
            &stop,
            &mut ifaces_rx,
            &joined,
            &socket,
            &buf,
            port,
            &mut last_send,
            delay,
        ) {
            return;
        }
        // 门控:睡眠期间可能已因网卡变化补发过一批,若距那次太近就跳过这次
        // 边界发送(见 send_allowed 注释),避免速率超出 MIN_SEND_BATCH_INTERVAL。
        if send_allowed(last_send, Instant::now()) {
            let entries = ifaces_rx.borrow().entries.clone();
            send_dual(&socket, &buf, port, &entries);
            last_send = Instant::now();
        }
    }
    loop {
        if !sleep_and_watch_ifaces(
            &stop,
            &mut ifaces_rx,
            &joined,
            &socket,
            &buf,
            port,
            &mut last_send,
            PERIODIC_INTERVAL,
        ) {
            return;
        }
        if send_allowed(last_send, Instant::now()) {
            let entries = ifaces_rx.borrow().entries.clone();
            send_dual(&socket, &buf, port, &entries);
            last_send = Instant::now();
        }
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
            protocol: Protocol::Native,
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
    /// 当前已 join 组播组的网卡 IP 集合。`Arc<Mutex<_>>` 是因为发送线程
    /// (`send_loop`/`sleep_and_watch_ifaces`)会在网卡快照变化时并发读写它,
    /// `shutdown` 时再借这把锁读出最终集合做对称 leave。
    joined: Arc<Mutex<Vec<Ipv4Addr>>>,
    /// 预编码好的自身宣告报文,`poke` 复用它做定向单播(见下)。
    announce_buf: Vec<u8>,
    send_handle: Option<JoinHandle<()>>,
    recv_handle: Option<JoinHandle<()>>,
}

impl AnnounceService {
    /// 启动宣告收发服务:绑定 socket,起发送/接收线程。组播 join/leave 不再
    /// 在这里一次性做——发送线程按 `ifaces_rx` 发布的活跃网卡快照增量维护
    /// (见 `send_loop`/`sync_multicast`),`ifaces_rx` 由调用方传入(通常是
    /// `net_ifaces::InterfaceRegistry::subscribe()`),本函数不关心它的来源。
    pub fn start(
        identity: &Identity,
        nick: &str,
        tport: u16,
        port: u16,
        tx: Sender<DiscoveryEvent>,
        ifaces_rx: watch::Receiver<IfaceSnapshot>,
    ) -> Result<AnnounceService, AnnounceError> {
        let socket = bind_socket(port)?;
        let socket = Arc::new(socket);
        let stop = Arc::new(AtomicBool::new(false));
        let joined: Arc<Mutex<Vec<Ipv4Addr>>> = Arc::new(Mutex::new(Vec::new()));

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
            let joined = Arc::clone(&joined);
            std::thread::spawn(move || send_loop(socket, stop, buf, port, ifaces_rx, joined))
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
            let joined = self.joined.lock().expect("joined lock").clone();
            for ip in &joined {
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

    // ---------- sync_multicast ----------

    fn test_entry(ip: Ipv4Addr) -> IfaceEntry {
        IfaceEntry {
            name: "test0".to_string(),
            ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(203, 0, 113, 255),
            is_virtual_hint: false,
        }
    }

    #[test]
    fn sync_multicast_does_not_record_failed_join() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut joined = Vec::new();
        // TEST-NET-3(RFC 5737)地址不属于任何本机网卡,join 必然失败——
        // 验证“单网卡失败不拖垮整轮”:失败的网卡不计入 joined。
        let entries = vec![test_entry(Ipv4Addr::new(203, 0, 113, 5))];
        sync_multicast(&socket, &mut joined, &entries);
        assert!(joined.is_empty(), "join 失败的网卡不应计入 joined");
    }

    #[test]
    fn sync_multicast_removes_ip_no_longer_in_snapshot() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        // 即使这个 IP 当初从未真正 join 成功(测试环境不持有它),leave 仍应
        // 尝试(容错)且无论成败都要把它从 joined 摘除,否则会无限重试。
        let mut joined = vec![Ipv4Addr::new(203, 0, 113, 5)];
        sync_multicast(&socket, &mut joined, &[]);
        assert!(joined.is_empty(), "快照中不再出现的 IP 应从 joined 摘除");
    }

    #[test]
    fn sync_multicast_is_a_no_op_when_already_in_sync() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut joined = Vec::new();
        sync_multicast(&socket, &mut joined, &[]);
        assert!(joined.is_empty());
    }

    // ---------- send_dual ----------

    #[test]
    fn send_dual_with_empty_entries_sends_nothing() {
        // 全部网卡被排除(entries 为空)= “全网隐身”:send_targets 返回空
        // 列表,send_dual 因此不应向任何地址发出报文。
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();

        send_dual(&socket, b"hello", port, &[]);

        let mut buf = [0u8; 16];
        assert!(
            receiver.recv_from(&mut buf).is_err(),
            "entries 为空时不应发送任何报文"
        );
    }

    #[test]
    fn send_dual_still_sends_broadcast_when_multicast_if_switch_fails() {
        // 回归测试(Critical 1):TEST-NET-3 地址不属于任何本机网卡,
        // set_multicast_if_v4 必然失败;门控只应挡住"这张卡的组播"一份,
        // 定向广播必须无条件照发——否则组播出口切换失败的那张卡就彻底哑火,
        // 违背"组播+广播双通道兜底"的设计初衷。
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();

        let mut entry = test_entry(Ipv4Addr::new(203, 0, 113, 5));
        entry.broadcast = Ipv4Addr::new(127, 0, 0, 1); // 指向本测试的接收端

        send_dual(&socket, b"hello", port, &[entry]);

        let mut buf = [0u8; 16];
        let (n, _src) = receiver
            .recv_from(&mut buf)
            .expect("组播出口切换失败时仍应发出定向广播");
        assert_eq!(&buf[..n], b"hello");
    }

    // ---------- send_allowed ----------

    #[test]
    fn send_allowed_is_false_within_the_min_interval() {
        // 回归测试(Critical 2):网卡变化触发的补发与紧随其后的边界发送必须
        // 共用同一个限速判定,否则两者可能只隔一个 SLEEP_STEP(200ms)。
        let last = Instant::now();
        assert!(
            !send_allowed(last, last + Duration::from_millis(200)),
            "200ms 远小于 MIN_SEND_BATCH_INTERVAL(1s),不应允许发送"
        );
        assert!(
            !send_allowed(last, last + Duration::from_millis(999)),
            "临界值之前 1ms 仍不应允许发送"
        );
    }

    #[test]
    fn send_allowed_is_true_at_and_after_the_min_interval() {
        let last = Instant::now();
        assert!(send_allowed(last, last + MIN_SEND_BATCH_INTERVAL));
        assert!(send_allowed(last, last + Duration::from_secs(2)));
    }
}

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
/// `joined` 只记录"确认成功"的那些,失败的 join 不计入;leave 无论成败都从
/// `joined` 摘除(避免反复对一个已经不存在的接口发起 leave)。
///
/// 调用方保证不只在快照变化时调用这个函数(Minor 4,最终评审修复):除了
/// `sleep_and_watch_ifaces` 在 `ifaces_rx` 变化时调用一次,`send_loop` 的
/// `resync_and_maybe_send` 在每个发送周期边界也无条件重新调用一次——
/// `multicast_diff` 本身是幂等 diff(已 join 的网卡这里是 no-op,零成本),
/// 所以一次瞬时 join 失败最坏只需等一个发送周期(退避阶段 ≤8s,进入周期
/// 阶段后 ≤`PERIODIC_INTERVAL`=25s)就会被重新尝试而自愈,不会像"只在快照
/// 变化时才 sync"那样,在网络长期稳定、快照再也不变的情况下无限期卡在失败
/// 状态。
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
/// 新快照 `sync_multicast` 并尝试补发一批宣告,但受 `MIN_SEND_BATCH_INTERVAL`
/// 全局限速(避免抖动网卡触发发送风暴,不违反"报文速率不高于现状"铁律);
/// 不打断外层原有的退避/周期发送节奏,只是让"网卡变化秒级可见"。
///
/// 限速跳过的补发不会被吞(Minor 3,最终评审修复):变化触发时若恰好撞上
/// `MIN_SEND_BATCH_INTERVAL` 限速窗口,`has_changed()` 已经被 `borrow_and_update`
/// 消费掉,不会再次为真——旧实现这里直接放弃这次补发,要等到本次休眠窗口
/// (`dur`,退避阶段 ≤8s、周期阶段 25s)结束时的边界发送才有机会重新尝试,
/// 最坏延迟 ~25s。这里改为记一个 `pending_send` 标志,后续每次 `SLEEP_STEP`
/// 迭代都重新判定 `send_allowed`,一旦限速窗口过去(至多 `MIN_SEND_BATCH_INTERVAL`
/// =1s 之后,远小于 `dur`)就立即补发,不需要等到新的 `has_changed()` 触发
/// (网络稳定时也不会再触发)。
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
    // 见函数文档注释"限速跳过的补发不会被吞":一旦某次网卡变化因限速被
    // 跳过,置位;之后每轮迭代限速一满足就立即补发并清位,不必等新变化。
    let mut pending_send = false;
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
                pending_send = false;
            } else {
                pending_send = true;
            }
        } else if pending_send && send_allowed(*last_send, Instant::now()) {
            // 之前被限速跳过的那批补发,现在限速窗口已过去,立即补上——
            // 用当前快照(不必是触发变化那一刻的快照,`ifaces_rx.borrow()`
            // 读最新值不消费变更标记,行为等价于"发最新状态",更准确)。
            let entries = ifaces_rx.borrow().entries.clone();
            send_dual(socket, buf, port, &entries);
            *last_send = Instant::now();
            pending_send = false;
        }
        let step = remaining.min(SLEEP_STEP);
        std::thread::sleep(step);
        remaining -= step;
    }
    true
}

/// 一个发送周期边界的固定动作(Minor 4,最终评审修复):无条件重新同步一次
/// 组播成员关系(见 `sync_multicast` 文档注释——诊断的是"瞬时 join 失败不
/// 自愈"缺口,`multicast_diff` 幂等、已同步的网卡这里是 no-op,零成本),
/// 随后仍按 `send_allowed` 门控决定是否真的发一批宣告。`STARTUP_BACKOFF`
/// 循环与周期循环各自调用一次,逻辑完全相同,抽出来避免两处漂移。
fn resync_and_maybe_send(
    socket: &UdpSocket,
    buf: &[u8],
    port: u16,
    ifaces_rx: &watch::Receiver<IfaceSnapshot>,
    joined: &Mutex<Vec<Ipv4Addr>>,
    last_send: &mut Instant,
) {
    let entries = ifaces_rx.borrow().entries.clone();
    {
        let mut joined_guard = joined.lock().expect("joined lock");
        sync_multicast(socket, &mut joined_guard, &entries);
    }
    if send_allowed(*last_send, Instant::now()) {
        send_dual(socket, buf, port, &entries);
        *last_send = Instant::now();
    }
}

/// 发送线程主循环:启动 3 次指数退避快速宣告(2s/4s/8s),之后转周期宣告
/// (~25s)。每次发送批次之间的全局最小间隔由退避/周期时长天然保证(均 ≥
/// `MIN_SEND_BATCH_INTERVAL`),但 `sleep_and_watch_ifaces` 内部可能因网卡
/// 快照变化在等待窗口的任意时刻(包括临近结束时)已经补发过一批——因此每次
/// 睡眠结束后的"边界发送"(`resync_and_maybe_send`)仍需重新经过
/// `send_allowed` 门控,不能无条件发送,否则变化补发 + 边界发送可能只隔一个
/// `SLEEP_STEP`(200ms),突破"报文速率不高于现状"铁律。跳过边界发送不会
/// 饿死周期宣告:下一轮的等待时长(≥2s)本身就远大于
/// `MIN_SEND_BATCH_INTERVAL`(1s),届时必定又满足门槛。`resync_and_maybe_send`
/// 里的组播同步则不受这个门控约束、每次边界都无条件执行(Minor 4,见该函数
/// 文档)。进循环前先按当前快照同步一次组播 join 状态(不发送,避免启动
/// 瞬间用空 `joined` 集合走一轮"全部 to_join" 又立刻被 STARTUP_BACKOFF 的
/// 第一次发送重复触发)。
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
        resync_and_maybe_send(&socket, &buf, port, &ifaces_rx, &joined, &mut last_send);
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
        resync_and_maybe_send(&socket, &buf, port, &ifaces_rx, &joined, &mut last_send);
    }
}

/// 接收线程主循环:recv_from → decode(丢弃畸形报文)→ 过滤自己 fp → 上报 Seen →
/// 对源地址限速单播回应自己的宣告(防应答风暴)。
///
/// `ifaces_rx`(Important 2,最终评审修复):接收侧隐身的低成本闭环——
/// entries 为空(用户排除了全部网卡,"全网隐身")时即使命中限速窗口也不
/// 单播回应。被动应答本身就是"暴露存在"的一种主动行为,与
/// `send_dual`/`send_targets` 在 entries 为空时"完全不主动宣告"的隐身语义
/// 保持一致,不能只堵住"我方主动说话"这一半,却留着"别人问我方就答"这一半
/// 敞开。
///
/// 已知局限(留 TODO,本期接受,与 `bigpaw_ipmsg::discovery::dispatch` 里
/// BR_ENTRY 分支的局限完全对应,复用同一条评审结论):这里只做"全排除时
/// 完全不回应"这个最低版本,不做按来源地址与当前网卡快照的同网段过滤——
/// `recv_loop` 绑定的是 0.0.0.0,不区分来源网卡是否在排除清单里,发送侧的
/// `send_dual`/`send_targets` 只控制"我方主动宣告发给谁",不控制"谁发来的
/// 宣告我方会限速单播回应"。所以只排除了部分网卡(而非全部)时,若被排除
/// 网段的对端仍能把宣告发到本机(例如同网段内广播),这里依旧会限速回应
/// ——即被排除网段对端的"看见我方"这半边,在"部分排除"场景下无法通过本次
/// 修复完全消除。真正做到双向隔离需要 `recv_loop` 也按来源地址与
/// `ifaces_rx` 快照做同网段过滤,留给后续任务。
fn recv_loop(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    self_fp: String,
    reply_buf: Vec<u8>,
    tx: Sender<DiscoveryEvent>,
    ifaces_rx: watch::Receiver<IfaceSnapshot>,
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
        // 全排除时不回应(Important 2b,见函数文档注释):`borrow()` 只读
        // 当前值、不消费变更标记,不影响 send_loop 那边的 has_changed 语义。
        if should_reply && !ifaces_rx.borrow().entries.is_empty() {
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
        // recv_loop 也要看当前网卡快照(Important 2b),独立克隆一份
        // `watch::Receiver`——两份各自维护自己的"已读"游标,recv_loop 这边
        // 只读 `borrow()`、从不 `borrow_and_update()`,不会影响 send_loop
        // 那边的 has_changed 语义(watch 的多订阅者互不干扰,标准用法)。
        let ifaces_rx_for_recv = ifaces_rx.clone();

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
            std::thread::spawn(move || {
                recv_loop(socket, stop, self_fp, buf, tx, ifaces_rx_for_recv)
            })
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

    // ---------- recv_loop:接收侧隐身闭环(Important 2b,最终评审修复) ----------

    /// 起一条 `recv_loop`,返回 (自己的监听地址, 停止信号, join handle, discovery
    /// 事件接收端)。`ifaces_rx` 由调用方传入,决定"全排除"与"未全排除"两种
    /// 场景。事件接收端必须由调用方一直持有到测试结束——`recv_loop` 每收到
    /// 一份宣告都会先 `tx.send(Seen 事件)`,一旦对端 rx 被提前丢弃(比如只在
    /// 本函数内部临时绑定、函数一返回就被析构),`tx.send` 会返回 `Err`,
    /// `recv_loop` 会在真正走到"限速单播回应"那一步之前就提前退出线程,
    /// 让测试断言"该不该收到回应"完全失去意义(误判为"不回应"其实是"线程已
    /// 经死了")。
    fn spawn_recv_loop(
        ifaces_rx: watch::Receiver<IfaceSnapshot>,
    ) -> (
        SocketAddr,
        Arc<AtomicBool>,
        JoinHandle<()>,
        std::sync::mpsc::Receiver<DiscoveryEvent>,
    ) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let socket = Arc::new(socket);
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let reply_buf = encode(&Announcement {
            v: 1,
            fp: "b".repeat(64),
            nick: "self".to_string(),
            tport: 1,
            caps: "native".to_string(),
        });
        let handle = {
            let socket = socket.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                recv_loop(socket, stop, "b".repeat(64), reply_buf, tx, ifaces_rx)
            })
        };
        (addr, stop, handle, rx)
    }

    #[test]
    fn recv_loop_does_not_reply_when_all_interfaces_excluded() {
        // entries 为空 = 用户排除了全部网卡("全网隐身")。旧实现只按
        // REPLY_RATE_LIMIT 限速,不看快照,仍会单播回应——回归此前的隐身
        // 缺口:此测试断言 recv_loop 现在完全不回应。
        let (_tx, ifaces_rx) = watch::channel(IfaceSnapshot {
            generation: 1,
            entries: vec![],
        });
        let (addr, stop, handle, _ev_rx) = spawn_recv_loop(ifaces_rx);

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let ann = encode(&ann());
        sender.send_to(&ann, addr).unwrap();

        let mut buf = [0u8; 512];
        assert!(
            sender.recv_from(&mut buf).is_err(),
            "全部网卡排除时不该单播回宣告"
        );

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn recv_loop_still_replies_when_not_all_interfaces_excluded() {
        // 回归防护:entries 非空(未全排除)时仍应保留旧的限速单播应答行为
        // ——本次修复只堵"全排除"这个最低版本缺口,不该连正常场景也一并
        // 挡住。
        let (_tx, ifaces_rx) = watch::channel(IfaceSnapshot {
            generation: 1,
            entries: vec![test_entry(Ipv4Addr::new(203, 0, 113, 5))],
        });
        let (addr, stop, handle, _ev_rx) = spawn_recv_loop(ifaces_rx);

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let ann = encode(&ann());
        sender.send_to(&ann, addr).unwrap();

        let mut buf = [0u8; 512];
        let (n, _src) = sender
            .recv_from(&mut buf)
            .expect("未全排除时仍应照常限速单播回宣告");
        assert!(decode(&buf[..n]).is_some(), "回应应是一份可解码的宣告报文");

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    // ---------- sleep_and_watch_ifaces:限速跳过的补发不被吞(Minor 3) ----------

    #[test]
    fn sleep_and_watch_ifaces_retries_skipped_resend_before_window_boundary() {
        // Minor 3 回归测试:网卡变化撞上 MIN_SEND_BATCH_INTERVAL 限速被跳过的
        // 补发,不该拖到 `dur` 窗口结束的边界发送才补上(本例 dur=3s,旧实现
        // 最坏要等到这 3s 结束)——应在限速窗口(1s)过去后的下一个
        // SLEEP_STEP(200ms)内就补发,远早于窗口边界。
        //
        // `sleep_and_watch_ifaces` 本身按设计要阻塞满整个 `dur`(中断式休眠
        // 骨架,靠内部 `SLEEP_STEP` 轮询,不是提前返回),所以不能在调用方
        // 所在线程里"调用后立即测耗时"——那样测到的永远是 `dur` 本身,量的
        // 是错误的东西。这里把它放到后台线程里跑,前台线程并发 `recv_from`,
        // 用"数据包多久后到达"而不是"函数多久后返回"来判定补发是否提前。
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();

        let mut entry = test_entry(Ipv4Addr::new(203, 0, 113, 5));
        entry.broadcast = Ipv4Addr::new(127, 0, 0, 1); // 指向接收端,便于断言收到

        let (tx, mut rx) = watch::channel(IfaceSnapshot::default());
        let joined = Mutex::new(Vec::new());
        let stop = AtomicBool::new(false);
        let buf = b"hello".to_vec();

        // 让 last_send 刚发生在 300ms 前:紧接着的网卡变化必然撞上 1s 限速
        // 窗口,制造"补发被跳过"的场景。
        let mut last_send = Instant::now() - Duration::from_millis(300);

        // 延迟 50ms 推送一次网卡变化,确保 sleep_and_watch_ifaces 已经进入
        // 循环开始轮询 has_changed。发送后必须让 `tx` 存活到测试结束,不能
        // 让它在这条线程退出时被 drop——tokio 的 `watch::Receiver::has_changed`
        // 一旦发现对端 `Sender` 已关闭就直接返回 `Err`(即使还有一份尚未被
        // `borrow_and_update` 消费的变更),优先级高于"是否有未读变更"的判断;
        // `sleep_and_watch_ifaces` 里 `.unwrap_or(false)` 会把这个 `Err` 当成
        // "没变化"处理,导致这条变更被整个错过(不是被测代码的 bug,是这里
        // 若不这样处理就会引入的测试假阳/假阴)。`mem::forget` 故意泄漏它,
        // 让 `tx` 活到进程退出——测试场景下无害。
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let _ = tx.send(IfaceSnapshot {
                generation: 1,
                entries: vec![entry],
            });
            std::mem::forget(tx);
        });

        let start = Instant::now();
        let bg = std::thread::spawn(move || {
            sleep_and_watch_ifaces(
                &stop,
                &mut rx,
                &joined,
                &socket,
                &buf,
                port,
                &mut last_send,
                Duration::from_secs(3),
            )
        });

        let mut recv_buf = [0u8; 16];
        let (n, _src) = receiver
            .recv_from(&mut recv_buf)
            .expect("被限速跳过的补发应该在窗口结束前就送达");
        let elapsed = start.elapsed();
        assert_eq!(&recv_buf[..n], b"hello");
        assert!(
            elapsed < Duration::from_secs(2),
            "补发不该拖到 dur=3s 窗口边界才发生,实际耗时 {elapsed:?}"
        );

        assert!(bg.join().unwrap(), "未被停止信号中断,应返回 true");
    }

    // ---------- resync_and_maybe_send:每周期无条件重同步(Minor 4) ----------

    #[test]
    fn resync_and_maybe_send_syncs_multicast_even_without_a_watch_change() {
        // Minor 4 回归测试:`resync_and_maybe_send` 不该像旧代码那样只在
        // `ifaces_rx.has_changed()` 为真时才 `sync_multicast`——这里构造一个
        // 从未 `send` 过的 watch::Receiver(entries 为空,has_changed 恒
        // 为 false),预先在 `joined` 里放一个"快照里已经不存在"的 IP,断言
        // 调用一次就被摘除。`sync_multicast` 的 leave 分支无论 socket 层面
        // 成功与否都会把它从 `joined` 摘除(见该函数文档),这个副作用不依赖
        // 真实网络接口/真实 join 成功与否,足以证明 sync_multicast 确实被
        // 无条件执行了,而不是被"没有变化"短路跳过。
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_tx, rx) = watch::channel(IfaceSnapshot::default());
        let joined = Mutex::new(vec![Ipv4Addr::new(203, 0, 113, 5)]);
        // last_send 设在很久以前,保证 send_allowed 恒真,不干扰本测试关注
        // 的 sync_multicast 部分。
        let mut last_send = Instant::now() - Duration::from_secs(10);

        resync_and_maybe_send(&socket, b"hello", 0, &rx, &joined, &mut last_send);

        assert!(
            joined.lock().unwrap().is_empty(),
            "即使 watch 从未变化,resync_and_maybe_send 也该无条件跑一次 \
             sync_multicast(leave 掉快照里已经不存在的陈旧 IP)"
        );
    }
}

//! 核心编排:identity + discovery + roster 串联,对壳层(src-tauri)暴露
//! 同步启动接口与 watch 快照订阅。零 Tauri、零异步运行时依赖。

use crate::discovery::announce::{
    AnnounceError, AnnounceService, HistoryStore, DEFAULT_ANNOUNCE_PORT,
};
use crate::discovery::Discovery;
use crate::identity::{Identity, IdentityError};
use crate::net_ifaces::{self, IfaceEntry, IfaceSnapshot, IfaceView, InterfaceRegistry};
use crate::roster::{DiscoveryEvent, Peer, PeerState, Protocol, Roster};
use crate::storage::Storage;
use crate::transport::manager::{
    MessageEvent, SentText, TransportError, TransportEvent, TransportManager, DEFAULT_PORT,
};
use bigpaw_ipmsg::discovery::{BroadcastTargets, IpmsgError, IpmsgEvent, IpmsgService};
use bigpaw_ipmsg::IPMSG_PORT;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::watch;

/// 历史 IP 单播"唤醒"宣告的发送间隔:串行、低速,不触发 IDS 扫描告警
/// (设计文档 §11),远高于 brief 要求的 ≥50ms 下限。
const HISTORY_WAKE_INTERVAL: Duration = Duration::from_millis(100);

/// roster 线程的过期扫描节奏(last-seen 超时判离线的采样粒度)。
/// 注意它不再是停止信号的响应延迟——那由 `ROSTER_POLL` 决定:早期两者
/// 共用一个值,导致无事件流入时(界面"正在搜索局域网设备…")退出 app
/// 要死等满 5s 才能 join 到该线程。
const ROSTER_TICK: Duration = Duration::from_secs(5);

/// roster 线程 `recv_timeout` 的轮询粒度 = `shutdown` 停止信号的最长响应
/// 延迟。与其余组件的中断步长同量级(announce/ipmsg 的 SLEEP_STEP=200ms)。
const ROSTER_POLL: Duration = Duration::from_millis(200);

/// 网卡快照的主动刷新节奏(设计文档:网卡选择,Step 7 热生效)。排除清单
/// 之外的系统级变化(拔插网线、切 Wi-Fi、VPN 连接/断开)不会主动通知我们
/// ——`InterfaceRegistry::refresh()` 靠 roster 线程按这个节奏定期轮询兜底
/// 感知。announce/transport 走 `watch` 订阅自动收到新快照;ipmsg 没有
/// watch 机制,变化时需要显式覆写 `Core::ipmsg_bcast` 里的 `Vec`(见
/// roster 线程实现;覆写经过 `IpmsgBcastGuard` 的 generation 守卫,防止
/// 这条定期刷新与 `apply_settings` 热生效路径并发时互相用 stale 快照覆盖,
/// 见该类型文档);mdns 的排除清单由 `apply_settings` 显式路径管理,
/// 这条定期刷新不碰它(daemon 自己每 5s 自查网卡 IP 变化,不需要我们管)。
///
/// 取值推导:30s = 6 × `ROSTER_TICK`(5s)。网卡枚举是本机系统调用,不像
/// 对端 `PEER_TIMEOUT` 那样受局域网抖动约束,没有必须匹配的外部节奏
/// ——选它的倍数只是为了刷新检查点能安全地挂在既有的 `ROSTER_TICK`/
/// `ROSTER_POLL` 轮询骨架上("检查点每 `ROSTER_POLL` 命中一次,真正执行
/// 只在到点时才做"的模式与过期扫描一致),而不是引入第二套独立定时器;
/// 6 倍留出足够余量,保证刷新频率明显低于过期扫描,不会成为新的热点。
const IFACE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// 对端超过这个时长未被任何发现通道(mDNS `Seen` 或 UDP 宣告 `Seen`)刷新,
/// 判定离线——mDNS/UDP 宣告周期通常 20-30s,60s ≈ 2-3 个漏掉的心跳周期,
/// 兼顾及时性与抖动容错(设计文档 §4 "心跳超时判离线")。这个阈值补的是
/// mDNS 被墙时的场景:UDP 宣告辅通道只在 `recv_loop` 里发 `Seen`,从不发
/// `Lost`,单靠它对端下线永远不会被判离线。
const PEER_TIMEOUT: Duration = Duration::from_secs(60);

/// 给定 last-seen 时间戳表、当前时刻、超时阈值,算出已过期(需要判离线)的
/// fingerprint 列表。抽成纯函数是为了不必真等 60s 就能确定性地单测扫描逻辑。
fn stale_fingerprints(
    last_seen: &HashMap<String, Instant>,
    now: Instant,
    timeout: Duration,
) -> Vec<String> {
    last_seen
        .iter()
        .filter(|(_, t)| now.duration_since(**t) > timeout)
        .map(|(fp, _)| fp.clone())
        .collect()
}

/// 探测成功后决定写入历史 IP 表的地址子集(设计文档:网卡选择,Step 7)。
/// `iface_entries` 非空时只记与本机某张网卡同网段的地址——跨网段地址多半
/// 是抖动/多网卡多路径解析出来的噪声,记它对"下次启动时单播唤醒"没有
/// 意义。`iface_entries` 为空(排除清单把所有网卡都排掉,或调用方还没
/// 来得及准备快照)时保持"全记"的旧行为,不做任何过滤——这是刻意的零
/// 语义漂移(3 处既有单测传 `vec![]` 无需改动预期)。抽成纯函数是为了不
/// 必起真实探测线程就能确定性单测这条过滤规则(镜像 `stale_fingerprints`
/// 的做法)。
fn addrs_to_record(addrs: &[IpAddr], iface_entries: &[IfaceEntry]) -> Vec<IpAddr> {
    if iface_entries.is_empty() {
        addrs.to_vec()
    } else {
        addrs
            .iter()
            .copied()
            .filter(|ip| net_ifaces::same_subnet(*ip, iface_entries))
            .collect()
    }
}

/// `Core::apply_settings` 的核心决策 + 副作用编排(设计文档:网卡选择,
/// Step 7)。抽成自由函数、把"清单变了怎么通知 mdns"外置成回调,是为了让
/// 行为测试不必起一个真实的 `Discovery`/mdns daemon 就能用合成的排除清单
/// (包括一个测试机上必然不存在的网卡名)确定性验证下面两条关键分离逻辑:
///
/// - ipmsg 定向广播目标表只在**快照**真的变化时才覆写(`registry.set_excluded`
///   已经用 `send_if_modified` 语义保证这一点,这里只是消费它的返回值);
/// - mdns 排除清单则要比较**清单本身**(`old_list != excluded`),而不是看
///   快照变没变——排除一个当前系统里根本不存在的网卡名时,快照不会变
///   (没有任何条目因此被滤掉),但 daemon 必须记住这个名字,不然它日后
///   插上来还是会被广播出去。
fn apply_excluded_interfaces(
    registry: &InterfaceRegistry,
    ipmsg_bcast: &IpmsgBcastGuard,
    excluded: &[String],
    mut on_list_changed: impl FnMut(&[String], &[String]),
) {
    let (old_list, new_snapshot) = registry.set_excluded(excluded.to_vec());

    if let Some(snapshot) = &new_snapshot {
        ipmsg_bcast.apply_if_newer(snapshot);
    }

    if old_list != excluded {
        on_list_changed(excluded, &old_list);
    }
}

/// ipmsg 定向广播目标表的写入守卫(Important 1,最终评审修复;经复审指出
/// 首版用 `AtomicU64::fetch_max` 做"两段式" check-then-write 仍有竞态窗口
/// 后,改成本版的单锁临界区实现)。
///
/// 背景:`apply_settings` 热生效路径(`InterfaceRegistry::set_excluded`)与
/// roster 线程按 `IFACE_REFRESH_INTERVAL` 的定期 `refresh()` 都可能产生一份
/// 新快照,两者各自在拿到快照**之后**(已经离开 registry 内部的 `excluded`
/// 锁)才去锁 `ipmsg_bcast` 并覆写它的 `Vec`——这一步不受 `excluded` 锁保护。
/// 若线程调度恰好让"读到旧快照的一方"晚于"读到新快照的一方"执行这个覆写
/// (例如 roster 线程的 refresh() 在 apply_settings 发布新排除清单**之前**
/// 就已经算完自己的旧快照,但因为被抢占,直到 apply_settings 写完之后才
/// 轮到它执行覆写),就会用 stale 数据把刚生效的新排除清单覆盖回去——而
/// ipmsg 没有 watch 机制感知这个错误,这个 stale 状态会无限期留存(直到
/// 下一次快照内容碰巧真的变化),持续向已排除的网段发送 BR_ENTRY。
///
/// 首版实现的问题(复审指出):用独立的 `AtomicU64` 配 `fetch_max` 只能保证
/// "谁先执行 fetch_max,谁的 generation 先被原子地记录"，不能保证"记录
/// generation"与"覆写 targets"这两步对多个线程而言是同一个原子操作——两者
/// 之间存在一个可被抢占的窗口:线程 B(旧 generation)的 `fetch_max` 检查
/// 通过后,若在它真正执行 `targets.lock()` 写入之前被调度器换出,线程 A
/// (新 generation)完整跑完"fetch_max 检查 + 写入"并释放锁,B 恢复执行后
/// 仍会无条件地把自己更早读到的旧数据写回,覆盖 A 刚写完的新数据。
///
/// 现在的修法:不用独立的原子量做"预检",而是把 generation 与
/// "覆写 targets"这两步收进**同一把锁(`applied_gen: Mutex<u64>`)的临界
/// 区**——`apply_if_newer` 先锁 `applied_gen`,在**持有它的整个临界区内**
/// 完成"读 generation → 判断 → 覆写 targets → 更新 generation"全部四步才
/// 释放锁。固定锁序为"先锁 `applied_gen`,临界区内再锁 `targets`",三个
/// 调用点(`apply_excluded_interfaces`、roster 线程两处 `refresh` 覆写)
/// 全部只通过这一个方法接触 `targets`,不存在任何绕开 `applied_gen` 锁直接
/// 覆写 `targets` 的路径——因此 `apply_if_newer` 的调用之间是完全互斥的,
/// check 和 write 之间不再有可被插入的窗口,不需要把覆写挪进 registry 内部
/// 改成回调(那样要给 registry 加 ipmsg 相关依赖,改动面更大)。
struct IpmsgBcastGuard {
    targets: BroadcastTargets,
    applied_gen: Mutex<u64>,
}

impl IpmsgBcastGuard {
    /// `initial_gen` 传调用方构造 `targets` 时所依据的那份快照的 generation
    /// (`Core::start` 里是 `registry.snapshot().generation`),避免后续一份
    /// generation 相同(理论上不会,但严谨起见)或更旧的快照被误判为"更新"。
    fn new(targets: BroadcastTargets, initial_gen: u64) -> Self {
        Self {
            targets,
            applied_gen: Mutex::new(initial_gen),
        }
    }

    /// check-and-write 在 `applied_gen` 这一把锁的临界区内原子完成(见类型
    /// 文档"现在的修法"):持锁期间做完"判断 generation → 覆写 targets →
    /// 更新已应用 generation"三件事才放锁,调用者之间因此完全互斥——不存在
    /// 让另一个调用者在"判断"和"写入"之间插进来的窗口。收到一份 stale 快照
    /// (generation 不大于已应用值)时静默跳过,不覆写。
    fn apply_if_newer(&self, snapshot: &IfaceSnapshot) {
        let mut applied = self.applied_gen.lock().expect("applied gen lock");
        if snapshot.generation > *applied {
            *self.targets.lock().expect("ipmsg bcast lock") =
                net_ifaces::broadcast_targets(&snapshot.entries);
            *applied = snapshot.generation;
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("mdns: {0}")]
    Mdns(#[from] mdns_sd::Error),
    #[error("announce: {0}")]
    Announce(#[from] AnnounceError),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("ipmsg: {0}")]
    Ipmsg(#[from] IpmsgError),
    #[error("IPMsg 兼容层未启用(2425 端口被占用,可能本机在跑飞秋)")]
    IpmsgUnavailable,
    #[error("对端不在线或未知")]
    UnknownPeer,
    #[error("storage: {0}")]
    Storage(#[from] crate::storage::StorageError),
}

pub struct CoreConfig {
    pub data_dir: PathBuf,
    /// None 时用主机名(去 .local 后缀)
    pub nickname: Option<String>,
}

pub struct Core {
    identity: Arc<Identity>,
    /// 当前生效昵称。Mutex 因 apply_settings 热改名(昵称热生效)与读取并发。
    nickname: Mutex<String>,
    roster_rx: watch::Receiver<Vec<Peer>>,
    roster_handle: Arc<Mutex<Roster>>,
    discovery: std::sync::Mutex<Option<Discovery>>,
    /// `Arc` 包裹是因为启动时的历史 IP 唤醒线程也要短暂借用它调用
    /// `poke`(见 `Core::start`);`shutdown` 时 `.take()` 拿到唯一所有权后
    /// 按值传给 `AnnounceService::shutdown`,与 `discovery` 字段同样的幂等模式。
    announce: Arc<Mutex<Option<AnnounceService>>>,
    transport: Arc<TransportManager>,
    /// 活跃网卡快照的唯一真源(Step 7 编排):announce/transport 在
    /// `Core::start` 里各自 `subscribe()` 了一份 watch 句柄,自动感知后续
    /// 变化;mdns 没有 watch 机制,排除清单的变更走 `apply_settings` 里的
    /// 显式 `discovery.apply_exclusions` 调用。roster 线程按
    /// `IFACE_REFRESH_INTERVAL` 定期 `refresh()`,兜底感知排除清单之外的
    /// 系统级网卡变化(拔插网线等)。
    registry: Arc<InterfaceRegistry>,
    events_rx: Mutex<Option<std::sync::mpsc::Receiver<TransportEvent>>>,
    /// `events_rx` 那条 `TransportEvent` 通道的发送端克隆:`respond_file_ipmsg`
    /// 起的后台下载线程要在完成/失败时上报 `FileDone`/`FileFailed`,复用与
    /// 原生文件传输相同的事件形状与转发路径(见 `take_events` 消费方)。
    events_tx: Sender<TransportEvent>,
    /// roster 消费线程的停止信号:`recv_timeout` 每 `ROSTER_TICK` 醒一次
    /// 检查它,`shutdown` 靠它让线程可终止,不必等 `rx` 断开(见线程内自
    /// 持的 `tx` 克隆——那把克隆本身就保证了 `rx.recv()` 永不返回 `Err`)。
    roster_stop: Arc<AtomicBool>,
    /// `shutdown` 时 `.take()` 拿到唯一所有权后 `join`,与 `discovery`/
    /// `announce` 字段一致的幂等模式:重复调用第二次拿到 `None` 直接跳过。
    roster_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// IPMsg 兼容层(M5):`Arc` 包裹是因为 `send_text`/`offer_file`/
    /// `respond_file` 处理 ipmsg 对端时都要用它做阻塞网络 IO——克隆一份
    /// `Arc` 后立即释放这把锁,不能让锁跨越网络调用(参见 `ipmsg_handle`)。
    /// `None` 表示 2425 端口被占用(通常是本机在跑飞秋),兼容层已禁用,
    /// 但不影响原生栈(见 `Core::start` 里的处理)。
    ipmsg: Mutex<Option<Arc<IpmsgService>>>,
    /// 启动时 IPMsg 兼容层是否成功启用,供壳层 `ipmsg_status()` 命令查询,
    /// 让前端能提示"IPMsg 兼容层未启用(2425 被占用)"。启动后固定不变。
    ipmsg_available: bool,
    /// ipmsg 兼容层的定向广播目标表(`Arc<Mutex<Vec<Ipv4Addr>>>`,Step 7)。
    /// `IpmsgService`(若启用)内部克隆了同一份底层 `Arc`,这里包一层
    /// `IpmsgBcastGuard` 用于热更新:排除清单变化后原地覆写内部 `Vec`,
    /// `IpmsgService` 下次 BR_ENTRY/BR_EXIT 发送时自动感知新目标表,不需要
    /// 重启服务。兼容层未启用时这份表仍然存在、仍然会被覆写,只是没有人读
    /// 它,无害。`IpmsgBcastGuard` 的 generation 守卫防止 `apply_settings`
    /// 热生效路径与 roster 线程定期 `refresh()` 并发覆写时互相用 stale
    /// 快照覆盖对方(Important 1,最终评审修复,见该类型文档)。
    ipmsg_bcast: Arc<IpmsgBcastGuard>,
    /// 对端(ipmsg 协议)通过 `SENDMSG|FILEATTACHOPT` 报价的文件:
    /// 本地生成的 `xfer_id -> (packet_no, file_id, 文件名, 大小)` 登记表,
    /// 供 `respond_file` 决定接受时反查、发起 `IpmsgService::request_file`。
    ipmsg_offers: Arc<Mutex<HashMap<String, IpmsgOffer>>>,
    /// SQLite 持久化(M6):持久化泵线程、send_text/offer_file 落库、壳层
    /// 历史查询命令共用。`Arc` 是因为泵线程与查询命令并发使用。
    storage: Arc<Storage>,
}

/// 一条待决的 ipmsg 文件报价(见 `Core::ipmsg_offers` 字段注释)。
struct IpmsgOffer {
    /// 报价方的伪 fingerprint(`ipmsg:<key>`),接受时要反查 roster 拿地址。
    peer_fp: String,
    packet_no: u32,
    file_id: u32,
    /// 已在 `bigpaw_ipmsg::filexfer::parse_one_file_entry` 净化过的安全
    /// basename,可以直接 `download_dir.join(name)`,不需要再次净化。
    name: String,
    size: u64,
    /// 这条报价是文件夹还是单文件(`IpmsgFileEntry::is_dir`);
    /// `respond_file_ipmsg` 据此分派 `request_file` 还是 `request_dir`。
    is_dir: bool,
}

impl Core {
    pub fn start(cfg: CoreConfig) -> Result<Self, CoreError> {
        let identity = Arc::new(Identity::load_or_create(&cfg.data_dir)?);
        let storage = Arc::new(Storage::open(&cfg.data_dir)?);
        let settings = crate::settings::load(&cfg.data_dir);
        let nickname = cfg
            .nickname
            .or_else(|| settings.nickname.clone())
            .unwrap_or_else(default_nickname);

        // 网卡选择(Step 7 编排):registry 是 announce/mdns/ipmsg/transport
        // 共用的活跃网卡快照唯一真源。建在读 settings 之后、transport 起动
        // 之前(与其它组件一样以 registry 为准起步),subscribe() 句柄随后
        // 分发给 transport/announce/ipmsg 各自的接线点。
        let registry = InterfaceRegistry::new(settings.excluded_interfaces.clone());

        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        // 留一份克隆给 IPMsg 兼容层的事件转发线程(见下):TextReceived/
        // FileOffered 复用与原生传输层相同的 TransportEvent 转发路径。
        let events_tx = msg_tx.clone();
        let transport = TransportManager::start(identity.clone(), DEFAULT_PORT, msg_tx)?;
        // set_iface_rx 在 transport 起动后立即接线——后续每次拨号前都会
        // 按最新快照做同网段亲和排序(Step 6 机制)。
        transport.set_iface_rx(registry.subscribe());

        // IPMsg/飞秋兼容层(M5,设计文档 §6):独立 crate,启动失败(最常见
        // 是 2425 已被占用,比如本机在跑飞秋)绝不能让 Core::start 整体失败
        // ——原生栈已经就绪,只是"旧协议兼容"这一层降级为不可用,记一个
        // 标志供 `ipmsg_available()`/壳层 `ipmsg_status()` 命令查询。
        let (ipmsg_evt_tx, ipmsg_evt_rx) = std::sync::mpsc::channel::<IpmsgEvent>();
        let ipmsg_host = hostname_no_local();
        // 定向广播目标表(Step 7):由 registry 当前快照算出,排除清单已经
        // 生效。底层 `Arc<Mutex<Vec<_>>>` 另克隆一份原样交给 `IpmsgService`
        // 持有(它读、我们写);`Core::ipmsg_bcast` 上保留的是包了一层
        // generation 守卫的 `IpmsgBcastGuard`(Important 1,最终评审修复),
        // 供 `apply_settings`/roster 线程的定期刷新原地覆写内部 `Vec`——
        // `IpmsgService` 自己另持有底层 `Arc` 的克隆,下次 BR_ENTRY/BR_EXIT
        // 发送时自动感知,不需要重启服务。
        let init_snapshot = registry.snapshot();
        let ipmsg_bcast_targets: BroadcastTargets = Arc::new(Mutex::new(
            net_ifaces::broadcast_targets(&init_snapshot.entries),
        ));
        let ipmsg_bcast = Arc::new(IpmsgBcastGuard::new(
            ipmsg_bcast_targets.clone(),
            init_snapshot.generation,
        ));
        let (ipmsg_service, ipmsg_available) = if settings.ipmsg_enabled {
            match IpmsgService::start(
                &nickname,
                &ipmsg_host,
                IPMSG_PORT,
                ipmsg_evt_tx,
                ipmsg_bcast_targets.clone(),
            ) {
                Ok(svc) => (Some(Arc::new(svc)), true),
                Err(e) => {
                    eprintln!("ipmsg: {IPMSG_PORT} 端口不可用({e}),兼容层已禁用(原生栈不受影响)");
                    (None, false)
                }
            }
        } else {
            (None, false) // 用户在设置里关闭了兼容层
        };
        let ipmsg_offers: Arc<Mutex<HashMap<String, IpmsgOffer>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // discovery 事件通道:mDNS 发现线程通过 tx 送 Seen/Lost;下面同一个
        // 线程里为新对端起的回连探测线程也复用这条通道的克隆,把探测结论
        // (Registered/Unreachable)回灌给 roster——两类事件因此天然串行化,
        // 不需要额外同步。
        let (tx, rx) = std::sync::mpsc::channel();
        // 真实端口进 SRV
        let mut discovery = Discovery::start(&identity, &nickname, transport.port(), tx.clone())?;
        // 网卡排除清单初始提交(Step 5):prev=[] 表示"还没提交过任何清单",
        // 清单非空时才会真正 disable + unregister/re-register;为空时是
        // no-op,不会多余重建 mDNS 服务。热生效(设置变更时再次调用)走
        // `apply_settings`,这里只做启动时这一次。
        discovery.apply_exclusions(&settings.excluded_interfaces, &[])?;

        // UDP 宣告辅通道(设计文档 §4):与 mDNS 共用同一个 tx,两类事件天然
        // 串行喂给下面的 roster 线程,fingerprint 去重由 Roster::apply 保证。
        let announce_service = AnnounceService::start(
            &identity,
            &nickname,
            transport.port(),
            DEFAULT_ANNOUNCE_PORT,
            tx.clone(),
            registry.subscribe(),
        )?;
        let announce = Arc::new(Mutex::new(Some(announce_service)));

        // IPMsg 事件 → roster/transport 事件转发线程:只在兼容层真正启用时
        // 才起(未启用时 ipmsg_evt_tx 已在 start() 失败分支里被丢弃,
        // ipmsg_evt_rx.recv() 会立刻返回 Err,起了也是白起)。
        if ipmsg_available {
            let disc_tx = tx.clone();
            let msg_tx_for_ipmsg = events_tx.clone();
            let offers_for_thread = ipmsg_offers.clone();
            std::thread::spawn(move || {
                while let Ok(ev) = ipmsg_evt_rx.recv() {
                    forward_ipmsg_event(ev, &disc_tx, &msg_tx_for_ipmsg, &offers_for_thread);
                }
            });
        }

        let mut roster_init = Roster::new(identity.fingerprint.clone());
        match storage.known_peers() {
            Ok(known) => roster_init.seed_offline(
                known
                    .into_iter()
                    .map(|k| Peer {
                        fingerprint: k.fingerprint,
                        nickname: k.nickname,
                        addrs: k
                            .last_addr
                            .and_then(|a| a.parse().ok())
                            .into_iter()
                            .collect(),
                        port: 0,
                        protocol: if k.protocol == "ipmsg" {
                            Protocol::Ipmsg
                        } else {
                            Protocol::Native
                        },
                        state: PeerState::Offline,
                    })
                    .collect(),
            ),
            Err(e) => eprintln!("storage: 读取已知 peer 失败(跳过预热): {e}"),
        }
        let initial_snapshot = roster_init.snapshot();
        let roster_handle = Arc::new(Mutex::new(roster_init));
        let (watch_tx, watch_rx) = watch::channel(initial_snapshot);
        let roster_for_thread = roster_handle.clone();
        let history = Arc::new(Mutex::new(HistoryStore::load(&cfg.data_dir)));

        // 历史 IP 单播唤醒(M4 简化版双向注册):对已知历史设备逐个发一份
        // 单播宣告,串行、间隔 ≥50ms,让对方回连/回宣告,走正常发现流程
        // 重新进入 roster——不做端口扫描、不直接建连接。
        //
        // 已知局限(留 TODO,本期接受,镜像
        // `bigpaw_ipmsg::discovery::dispatch` 里 BR_ENTRY 分支、以及
        // `announce::recv_loop` 的同一条局限——见后者注释):`AnnounceService::poke`
        // 直接对给定 IP 发一份定向单播,不看当前网卡快照/排除清单——即使用户
        // 已经把这个历史 IP 所在的网段整张网卡都排除掉("隐身"=不主动宣告),
        // 这条唤醒线程仍会向它发一个单播包,是"隐身"语义里尚未堵上的一个
        // 缺口。之所以本期不修:`poke` 不经过 `send_targets`/`send_dual` 的
        // 网卡枚举路径,要按来源网卡过滤就要么给它传网卡快照做同网段判断,
        // 要么整条唤醒线程感知 registry——影响面超出本轮 Important 2 的最低
        // 版本(被动应答/接收侧隐身)范围,留给后续任务按来源子网过滤时一并
        // 处理。
        {
            let announce_for_wake = announce.clone();
            let wake_ips = history.lock().expect("history lock").ips();
            std::thread::spawn(move || {
                for ip in wake_ips {
                    if let Some(a) = announce_for_wake.lock().expect("announce lock").as_ref() {
                        a.poke(ip);
                    }
                    std::thread::sleep(HISTORY_WAKE_INTERVAL);
                }
            });
        }
        // 正在探测中的 fingerprint 集合:防止同一对端因为重复的 Seen 宣告
        // (mDNS 周期重宣告、多网卡多次解析)并发起多条探测线程(探测风暴)。
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let data_dir = cfg.data_dir.clone();
        let transport_for_thread = transport.clone();
        let roster_stop = Arc::new(AtomicBool::new(false));
        let roster_stop_for_thread = roster_stop.clone();
        let storage_for_roster = storage.clone();
        let registry_for_thread = registry.clone();
        let ipmsg_bcast_for_thread = ipmsg_bcast.clone();
        let roster_thread = std::thread::spawn(move || {
            let transport = transport_for_thread;
            // last-seen 时间戳(不进 roster,保持 roster 纯状态机):任一
            // 通道的 Seen 刷新它;超过 PEER_TIMEOUT 未刷新则判离线(见下)。
            let mut last_seen: HashMap<String, Instant> = HashMap::new();
            // 过期扫描按 ROSTER_TICK 节奏;recv 轮询按 ROSTER_POLL 粒度。
            // 两者解耦:停止信号 200ms 内可见,扫描频率不因此提高 25 倍。
            let mut last_scan = Instant::now();
            // 网卡快照的主动刷新节奏(IFACE_REFRESH_INTERVAL=30s,Step 7)。
            // `Instant` 比较零成本,检查点放在 Timeout 分支和 Ok(ev) 分支
            // 尾部各一份——只放 Timeout 分支的话,持续有事件流入(mDNS/UDP
            // 宣告频繁)时 recv_timeout 会一直命中 Ok(ev) 而不是 Timeout,
            // 30s 刷新会被无限期饿死。
            let mut last_iface_refresh = Instant::now();
            loop {
                match rx.recv_timeout(ROSTER_POLL) {
                    Ok(ev) => {
                        if let DiscoveryEvent::Seen {
                            fingerprint,
                            nickname,
                            addrs,
                            protocol,
                            ..
                        } = &ev
                        {
                            last_seen.insert(fingerprint.clone(), Instant::now());
                            let proto = match protocol {
                                Protocol::Native => "native",
                                Protocol::Ipmsg => "ipmsg",
                            };
                            let addr = addrs.first().map(|a| a.to_string());
                            if let Err(e) = storage_for_roster.upsert_peer(
                                fingerprint,
                                nickname,
                                proto,
                                addr.as_deref(),
                                crate::transport::proto::now_ms() as i64,
                            ) {
                                eprintln!("storage: peer 回写失败: {e}");
                            }
                        }
                        // Seen 事件在被 apply 消费掉之前,先取出探测需要的字段。
                        // 只对 Native 协议做回连探测:ipmsg 对端的 TCP 2425 说的是
                        // GETFILEDATA 而不是原生 TLS 握手,拿 probe_reachable 去拨
                        // 只会误判 Unreachable,没有意义(见 protocol 字段注释)。
                        let probe_target = match &ev {
                            DiscoveryEvent::Seen {
                                fingerprint,
                                addrs,
                                port,
                                protocol: Protocol::Native,
                                ..
                            } => Some((fingerprint.clone(), addrs.clone(), *port)),
                            _ => None,
                        };

                        let mut roster = roster_for_thread.lock().expect("roster lock");
                        let changed = roster.apply(ev);
                        let snapshot = roster.snapshot();
                        drop(roster); // 探测线程的起线程动作不需要跨这把锁

                        let already_reachable = probe_target.as_ref().is_some_and(|(fp, _, _)| {
                            snapshot
                                .iter()
                                .any(|p| p.fingerprint == *fp && p.state == PeerState::Reachable)
                        });

                        if changed && watch_tx.send(snapshot).is_err() {
                            break; // 订阅端全部销毁
                        }

                        if let Some((fp, addrs, port)) = probe_target {
                            if !already_reachable {
                                spawn_probe(
                                    &transport,
                                    &tx,
                                    &in_flight,
                                    &history,
                                    &data_dir,
                                    registry_for_thread.snapshot().entries,
                                    fp,
                                    addrs,
                                    port,
                                );
                            }
                        }

                        // 停止信号也在这里检查,不只是在 Timeout 分支:如果
                        // 同进程里还有别的 Core 实例在真实网络上持续
                        // mDNS/UDP 宣告(测试并发场景下常见),recv_timeout
                        // 会不断命中 Ok(ev) 而不是 Timeout,单靠 Timeout 分支
                        // 判断会让 shutdown 被这些不相关的事件流无限期拖住。
                        if roster_stop_for_thread.load(Ordering::Relaxed) {
                            break;
                        }

                        // 网卡快照刷新检查(见 last_iface_refresh 声明处注释):
                        // 持续有事件流入时也不能让 30s 刷新被无限期饿死。
                        if last_iface_refresh.elapsed() >= IFACE_REFRESH_INTERVAL {
                            last_iface_refresh = Instant::now();
                            if let Some(snapshot) = registry_for_thread.refresh() {
                                // 经 generation 守卫覆写(Important 1):若这份
                                // 快照因线程调度延迟到达,已经被 apply_settings
                                // 发布的更新一代覆盖过,这里会被识别为 stale 而
                                // 静默跳过,不会覆写回旧的广播目标表。
                                ipmsg_bcast_for_thread.apply_if_newer(&snapshot);
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if roster_stop_for_thread.load(Ordering::Relaxed) {
                            break;
                        }
                        // 网卡快照刷新检查(与 Ok(ev) 分支尾部同一份逻辑):
                        // 放在 last_scan 的 `continue` 之前,避免"未到扫描
                        // 节奏就 continue"顺带把这个检查点也跳过。
                        if last_iface_refresh.elapsed() >= IFACE_REFRESH_INTERVAL {
                            last_iface_refresh = Instant::now();
                            if let Some(snapshot) = registry_for_thread.refresh() {
                                // 经 generation 守卫覆写(Important 1):若这份
                                // 快照因线程调度延迟到达,已经被 apply_settings
                                // 发布的更新一代覆盖过,这里会被识别为 stale 而
                                // 静默跳过,不会覆写回旧的广播目标表。
                                ipmsg_bcast_for_thread.apply_if_newer(&snapshot);
                            }
                        }
                        // 未到扫描节奏就继续轮询:这个分支现在每 ROSTER_POLL
                        // (200ms)就会命中一次,扫描本身仍按 ROSTER_TICK 执行。
                        if last_scan.elapsed() < ROSTER_TICK {
                            continue;
                        }
                        last_scan = Instant::now();
                        // 过期扫描:超过 PEER_TIMEOUT 未再被任何通道 Seen 的
                        // 对端 → Lost(→Offline)。这是 UDP 宣告通道(mDNS 被
                        // 墙时唯一存活的通道)从不发 Lost 的唯一兜底。
                        let now = Instant::now();
                        let stale = stale_fingerprints(&last_seen, now, PEER_TIMEOUT);
                        if !stale.is_empty() {
                            let mut roster = roster_for_thread.lock().expect("roster lock");
                            let mut any = false;
                            for fp in &stale {
                                if roster.apply(DiscoveryEvent::Lost {
                                    fingerprint: fp.clone(),
                                }) {
                                    any = true;
                                }
                            }
                            let snapshot = roster.snapshot();
                            drop(roster);
                            for fp in stale {
                                last_seen.remove(&fp); // 已判离线,别反复触发
                            }
                            if any && watch_tx.send(snapshot).is_err() {
                                break;
                            }
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        // 持久化泵(M6):transport/ipmsg 的事件先写库、再转发给壳层。
        // take_events() 对外签名不变——壳层拿到的是泵的出口端。
        let (pump_tx, pump_rx) = std::sync::mpsc::channel();
        let storage_for_pump = storage.clone();
        std::thread::spawn(move || {
            while let Ok(ev) = msg_rx.recv() {
                persist_event(&storage_for_pump, &ev);
                if pump_tx.send(ev).is_err() {
                    break; // 消费端已销毁
                }
            }
        });

        Ok(Self {
            identity,
            nickname: Mutex::new(nickname),
            roster_rx: watch_rx,
            roster_handle,
            discovery: std::sync::Mutex::new(Some(discovery)),
            announce,
            transport,
            registry,
            events_rx: Mutex::new(Some(pump_rx)),
            events_tx,
            roster_stop,
            roster_thread: Mutex::new(Some(roster_thread)),
            ipmsg: Mutex::new(ipmsg_service),
            ipmsg_available,
            ipmsg_bcast,
            ipmsg_offers,
            storage,
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.identity.fingerprint
    }

    pub fn nickname(&self) -> String {
        self.nickname.lock().expect("nickname lock").clone()
    }

    pub fn roster_snapshot(&self) -> Vec<Peer> {
        self.roster_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<Vec<Peer>> {
        self.roster_rx.clone()
    }

    /// 从 roster 当前快照查一个对端的完整记录:M5 起 send_text/offer_file
    /// 除了地址/端口,还要看 `protocol` 决定走原生传输还是 IPMsg 兼容层。
    fn find_peer(&self, peer_fp: &str) -> Result<Peer, CoreError> {
        let roster = self.roster_handle.lock().expect("roster lock");
        roster
            .snapshot()
            .into_iter()
            .find(|p| p.fingerprint == peer_fp)
            .ok_or(CoreError::UnknownPeer)
    }

    /// 给对端发文本;按 `peer.protocol` 分派到原生传输或 IPMsg 兼容层,
    /// 调用方(壳层命令)不需要关心协议差异。
    pub fn send_text(&self, peer_fp: &str, body: &str) -> Result<SentText, CoreError> {
        let peer = self.find_peer(peer_fp)?;
        let sent = match peer.protocol {
            Protocol::Native => self
                .transport
                .send_text(peer_fp, &peer.addrs, peer.port, body)?,
            Protocol::Ipmsg => self.send_text_ipmsg(&peer, body)?,
        };
        if let Err(e) =
            self.storage
                .insert_message(&sent.id, peer_fp, "out", body, sent.ts_ms as i64)
        {
            eprintln!("storage: 出站消息落库失败: {e}");
        }
        Ok(sent)
    }

    /// 给对端发起一次文件传输报价;同样按 `peer.protocol` 分派。原生一侧
    /// 返回 xfer_id,后续的 FileOffered/FileProgress/FileDone/FileFailed
    /// 事件都带着它,供调用方关联;ipmsg 一侧见 `offer_file_ipmsg` 注释。
    pub fn offer_file(&self, peer_fp: &str, path: &Path) -> Result<String, CoreError> {
        let peer = self.find_peer(peer_fp)?;
        let xfer_id = match peer.protocol {
            Protocol::Native => {
                self.transport
                    .offer_file(peer_fp, &peer.addrs, peer.port, path)?
                    .xfer_id
            }
            Protocol::Ipmsg => self.offer_file_ipmsg(&peer, path)?,
        };
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let size = std::fs::metadata(path).map(|m| m.len() as i64).unwrap_or(0);
        if let Err(e) = self.storage.insert_transfer(
            &xfer_id,
            peer_fp,
            "out",
            &name,
            size,
            false,
            "active",
            crate::transport::proto::now_ms() as i64,
        ) {
            eprintln!("storage: 出站文件记录落库失败: {e}");
        }
        Ok(xfer_id)
    }

    /// 接收方对一个待决的文件报价做出决定(接受/拒绝)。先查 `ipmsg_offers`
    /// (M5 新增):命中说明这是一条 ipmsg 报价,走 `respond_file_ipmsg`;
    /// 否则落回原生 `TransportManager::respond_file`(未知 xfer_id 时它自己
    /// 静默忽略,保持既有的幂等语义)。
    pub fn respond_file(
        &self,
        xfer_id: &str,
        accept: bool,
        download_dir: &Path,
    ) -> Result<(), CoreError> {
        let ipmsg_offer = self
            .ipmsg_offers
            .lock()
            .expect("ipmsg offers lock")
            .remove(xfer_id);
        let route_result = match ipmsg_offer {
            Some(offer) => self.respond_file_ipmsg(xfer_id, offer, accept, download_dir),
            None => Ok(self.transport.respond_file(xfer_id, accept, download_dir)?),
        };
        if route_result.is_ok() {
            let status = if accept { "active" } else { "rejected" };
            if let Err(e) = self.storage.update_transfer(xfer_id, status, None) {
                eprintln!("storage: 传输状态落库失败: {e}");
            }
        }
        route_result
    }

    /// 短暂持锁克隆出一份 `Arc<IpmsgService>` 立即释放锁——`send_text`/
    /// `send_file`/`request_file` 都是阻塞网络 IO,绝不能让它们跨越这把锁
    /// (否则同时互相排队,还会拖住 `shutdown` 的 `.take()`)。
    /// 兼容层未启用(2425 被占用)时返回 `IpmsgUnavailable`。
    fn ipmsg_handle(&self) -> Result<Arc<IpmsgService>, CoreError> {
        self.ipmsg
            .lock()
            .expect("ipmsg lock")
            .clone()
            .ok_or(CoreError::IpmsgUnavailable)
    }

    /// ipmsg 对端只有一个来源地址(发现时的 UDP 源地址),`port` 也就是它的
    /// IPMsg 监听端口(UDP/TCP 同号)。
    fn ipmsg_socket_addr(peer: &Peer) -> Result<SocketAddr, CoreError> {
        let ip = peer.addrs.first().copied().ok_or(CoreError::UnknownPeer)?;
        Ok(SocketAddr::new(ip, peer.port))
    }

    fn send_text_ipmsg(&self, peer: &Peer, body: &str) -> Result<SentText, CoreError> {
        let addr = Self::ipmsg_socket_addr(peer)?;
        let svc = self.ipmsg_handle()?;
        svc.send_text(addr, body)?;
        // IPMsg 协议本身没有给调用方回一个 id/时间戳;本地生成,和原生一侧
        // 的 SentText 同形状,壳层命令因此不需要区分协议来源。
        Ok(SentText {
            id: crate::transport::proto::new_id(),
            ts_ms: crate::transport::proto::now_ms(),
        })
    }

    /// M5 冻结范围:单文件发送。发出 offer 后本端观察不到对端何时/是否真的
    /// 用 GETFILEDATA 拉取——这是 IPMsg 协议本身的性质(报价即忘),真实
    /// 飞秋客户端同样不会给发送方任何完成回执,因此这里只生成一个本地
    /// xfer_id 供 UI 记账,不会再有后续的 FileDone/FileFailed 事件。
    fn offer_file_ipmsg(&self, peer: &Peer, path: &Path) -> Result<String, CoreError> {
        let addr = Self::ipmsg_socket_addr(peer)?;
        let svc = self.ipmsg_handle()?;
        svc.send_file(addr, path)?;
        Ok(crate::transport::proto::new_id())
    }

    /// 接受/拒绝一条 ipmsg 文件报价(单文件或文件夹)。拒绝:IPMsg 协议没有
    /// "我拒绝了"的回执,不请求就是拒绝,静默即可。接受:反查 roster 拿地址,
    /// 后台线程按 `offer.is_dir` 分派发起 `IpmsgService::request_file`(单文件)
    /// 或 `request_dir`(文件夹,GETDIRFILES,整棵树落到 `download_dir/<name>`
    /// 下——`receive_dir_stream` 内部只按流里的相对路径写子项,不会自己重建
    /// 顶层文件夹名,因此这里必须显式 `join` 一次)。两者都是阻塞网络 IO,
    /// 不能占着调用方线程——与原生 `offer_file` 的 `await_offer_reply` 后台
    /// 线程同一个道理,完成/失败时复用原生一致的
    /// `TransportEvent::FileDone`/`FileFailed` 上报(文件夹场景下 `FileDone`
    /// 的 `path` 就是这个新建的顶层文件夹路径)。
    fn respond_file_ipmsg(
        &self,
        xfer_id: &str,
        offer: IpmsgOffer,
        accept: bool,
        download_dir: &Path,
    ) -> Result<(), CoreError> {
        if !accept {
            return Ok(());
        }
        let peer = self.find_peer(&offer.peer_fp)?;
        let addr = Self::ipmsg_socket_addr(&peer)?;
        let save_path = download_dir.join(&offer.name);
        let svc = self.ipmsg_handle()?;
        let events = self.events_tx.clone();
        let xfer_id = xfer_id.to_string();
        std::thread::spawn(move || {
            let result = if offer.is_dir {
                svc.request_dir(addr, offer.packet_no, offer.file_id, &save_path)
            } else {
                svc.request_file(addr, offer.packet_no, offer.file_id, offer.size, &save_path)
            };
            match result {
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
        });
        Ok(())
    }

    /// 取走事件接收端(只能取一次,由壳层的事件循环消费)。
    pub fn take_events(&self) -> Option<std::sync::mpsc::Receiver<TransportEvent>> {
        self.events_rx.lock().expect("events lock").take()
    }

    /// 持久化层句柄:壳层历史查询/搜索/清空命令直接用它,不经过 Core 转发。
    pub fn storage(&self) -> Arc<Storage> {
        self.storage.clone()
    }

    pub fn port(&self) -> u16 {
        self.transport.port()
    }

    /// IPMsg 兼容层是否已启用(启动时 2425 端口绑定成功)。供壳层
    /// `ipmsg_status()` 命令查询,让前端能提示"2425 被占用,可能本机在跑
    /// 飞秋"。启动后固定不变。
    pub fn ipmsg_available(&self) -> bool {
        self.ipmsg_available
    }

    /// 网卡排除清单热生效入口(设计文档:网卡选择,Step 7)。壳层设置页保存
    /// 新的 `Settings`(已经 `settings::save` 落盘)后调用它,让运行中的
    /// announce/transport/ipmsg/mdns 全部感知新的排除清单,不需要重启 app。
    ///
    /// 实际决策逻辑在自由函数 `apply_excluded_interfaces` 里(TDD 友好:
    /// 测试可以注入一个 spy 闭包代替真实 `discovery.apply_exclusions`,
    /// 不需要起真实 mDNS daemon)。这里只负责提供"清单变了该怎么通知 mdns"
    /// 这一步真实的副作用实现:持 `discovery` 锁调用 `apply_exclusions`
    /// 是安全的——Step 5 已经把它做成非阻塞的投递式调用(内部先做纯函数
    /// diff,只在结果非空时才触碰 daemon,且 `disable_interface`/
    /// `enable_interface`/`re_register` 都是非阻塞 API),不会让这把锁跨越
    /// 真正的网络 IO;若此刻 `discovery` 已经是 `None`(`shutdown` 之后),
    /// 静默跳过。
    pub fn apply_settings(&self, s: &crate::settings::Settings) {
        apply_excluded_interfaces(
            &self.registry,
            &self.ipmsg_bcast,
            &s.excluded_interfaces,
            |new, old| {
                let mut discovery = self.discovery.lock().expect("discovery lock poisoned");
                if let Some(d) = discovery.as_mut() {
                    if let Err(e) = d.apply_exclusions(new, old) {
                        eprintln!("mdns: 排除清单热生效失败: {e}");
                    }
                }
            },
        );

        // 昵称热生效:diff 归一化后的新旧值,变了才逐路通知(幂等,未变零成本)。
        let new_nick = effective_nickname(s);
        let changed = {
            let mut cur = self.nickname.lock().expect("nickname lock");
            if *cur != new_nick {
                *cur = new_nick.clone();
                true
            } else {
                false
            }
        };
        if changed {
            // 本方法依赖调用方(壳层 set_settings)串行调用:diff-and-set 在
            // `nickname` 锁内原子完成,但下面三路通知用的是锁外局部变量
            // `new_nick`,并发调用间无互斥——若未来把 set_settings 改成 async
            // 并允许并发调用,两次改名可能在这里乱序执行,导致 mdns/announce/
            // ipmsg 三路里注册的值和内存里的 `self.nickname` 不一致,且不会自愈。
            {
                let mut discovery = self.discovery.lock().expect("discovery lock poisoned");
                if let Some(d) = discovery.as_mut() {
                    if let Err(e) = d.set_nickname(&new_nick) {
                        eprintln!("mdns: 昵称热生效失败: {e}");
                    }
                }
            }
            {
                let announce = self.announce.lock().expect("announce lock poisoned");
                if let Some(a) = announce.as_ref() {
                    a.set_nick(&new_nick); // 纯内存换 buf,持锁无 IO
                }
            }
            // ipmsg 锁只用于克隆 Arc,set_nick 的 BR_ENTRY 补发在锁外(锁纪律)。
            let ipmsg = self.ipmsg.lock().expect("ipmsg lock poisoned").clone();
            if let Some(svc) = ipmsg {
                svc.set_nick(&new_nick);
            }
        }
    }

    /// 列出全部网卡(不滤排除项),标注 excluded 状态,供壳层设置页展示。
    pub fn list_interfaces(&self) -> Vec<IfaceView> {
        self.registry.list_all()
    }

    /// 主动下线:注销 mDNS(发 goodbye)+ 停止 UDP 宣告收发,对端立刻收到
    /// Lost 而不是等 TTL 过期;随后停掉 roster 消费线程并 join 它,确保
    /// `shutdown` 返回时线程已经真正退出(不是"发个信号就当作已停")。
    /// 三路都幂等(`Mutex<Option<_>>::take` 保证重复调用时第二次拿到
    /// `None`,直接跳过)。
    ///
    /// roster 线程最长在一个 `ROSTER_POLL`(200ms)内响应停止信号并退出;
    /// 加上 mDNS goodbye(≤1s)与 announce/ipmsg 的 join(各 ≤~0.7s),
    /// 本方法整体亚秒~2s 量级返回,不会永久挂起,也不再出现"无联系人时
    /// 退出 app 卡 5s"(旧行为:停止信号要等满一个 ROSTER_TICK 才被看到)。
    pub fn shutdown(&self) {
        let discovery = self
            .discovery
            .lock()
            .expect("discovery lock poisoned")
            .take();
        if let Some(d) = discovery {
            d.shutdown();
        }

        let announce = self.announce.lock().expect("announce lock poisoned").take();
        if let Some(a) = announce {
            a.shutdown();
        }

        // IPMsg 兼容层:同样"take 拿唯一所有权再 shutdown"的幂等模式,但
        // 这里存的是 `Arc`(供 send_text_ipmsg/offer_file_ipmsg/
        // respond_file_ipmsg 在锁外并发使用,见 `ipmsg` 字段注释),
        // `IpmsgService::shutdown` 又要求按值消费 self。若此刻仍有并发的
        // 后台线程(比如一次 respond_file_ipmsg 正在跑的 request_file)持有
        // 克隆,`Arc::try_unwrap` 会失败——这种情况下放弃优雅关闭(不广播
        // BR_EXIT、不 join 内部线程),而不是阻塞 shutdown 等一个时长未知的
        // 下载完成:与 roster 线程"最长阻塞一个 ROSTER_TICK"的既有承诺一致,
        // shutdown 不应该被网络 IO 无限期拖住。
        let ipmsg = self.ipmsg.lock().expect("ipmsg lock poisoned").take();
        if let Some(arc) = ipmsg {
            if let Ok(svc) = Arc::try_unwrap(arc) {
                svc.shutdown();
            }
        }

        self.roster_stop.store(true, Ordering::Relaxed);
        let roster_thread = self
            .roster_thread
            .lock()
            .expect("roster thread lock poisoned")
            .take();
        if let Some(h) = roster_thread {
            let _ = h.join();
        }
    }
}

/// 事件落库(M6 持久化泵)。写失败不阻断消息流(spec §6):实时聊天的
/// 可用性优先于持久化,但必须 eprintln 留痕。FileProgress 太密,不落库。
fn persist_event(storage: &Storage, ev: &TransportEvent) {
    let result = match ev {
        TransportEvent::Message(m) => {
            storage.insert_message(&m.id, &m.peer_fp, "in", &m.body, m.ts_ms as i64)
        }
        TransportEvent::FileOffered {
            xfer_id,
            peer_fp,
            name,
            size,
            is_dir,
        } => storage.insert_transfer(
            xfer_id,
            peer_fp,
            "in",
            name,
            *size as i64,
            *is_dir,
            "offered",
            crate::transport::proto::now_ms() as i64,
        ),
        TransportEvent::FileDone { xfer_id, path } => {
            storage.update_transfer(xfer_id, "done", Some(&path.to_string_lossy()))
        }
        TransportEvent::FileFailed { xfer_id, .. } => {
            storage.update_transfer(xfer_id, "failed", None)
        }
        TransportEvent::FileProgress { .. } => Ok(()),
    };
    if let Err(e) = result {
        eprintln!("storage: 事件落库失败(不阻断消息流): {e}");
    }
}

/// 双向注册(M4):对一个刚被 `Seen`、且当前不是 `Reachable` 的对端,起一条
/// 独立线程做回连探测(`TransportManager::probe_reachable`),据结果把
/// `Registered`/`Unreachable` 事件回灌进 discovery 事件通道(见调用处注释,
/// 与 mDNS 发现共用同一条通道,天然串行化地喂给 roster)。
///
/// 锁纪律:`in_flight` 只在起线程前后各持有一次短锁(登记/摘除),`history`
/// 只在探测成功后短暂持有(record + save),两者都不跨越 `probe_reachable`
/// 内部的阻塞网络 IO——这把锁如果跨了阻塞拨号,会让同一 fp 的所有后续
/// Seen 事件在等这次探测期间被迫串行阻塞在锁上,而 `in_flight` 集合本身
/// 已经足够防止探测风暴,不需要用锁再多做这件事。
///
/// `iface_entries`(Step 7):探测成功后决定记入历史 IP 表的地址子集,
/// 实际过滤逻辑在纯函数 `addrs_to_record` 里——非空时只记同网段地址,
/// 为空时保持全记(零语义漂移,见该函数注释)。
#[allow(clippy::too_many_arguments)]
fn spawn_probe(
    transport: &Arc<TransportManager>,
    discovery_tx: &Sender<DiscoveryEvent>,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    history: &Arc<Mutex<HistoryStore>>,
    data_dir: &Path,
    iface_entries: Vec<IfaceEntry>,
    fingerprint: String,
    addrs: Vec<IpAddr>,
    port: u16,
) {
    {
        let mut set = in_flight.lock().expect("in-flight lock");
        if !set.insert(fingerprint.clone()) {
            return; // 同一 fp 已有一条探测在飞,不重复起线程
        }
    }

    let transport = transport.clone();
    let discovery_tx = discovery_tx.clone();
    let in_flight = in_flight.clone();
    let history = history.clone();
    let data_dir = data_dir.to_path_buf();
    std::thread::spawn(move || {
        let ok = transport.probe_reachable(&fingerprint, &addrs, port);
        let result_ev = if ok {
            // 回连成功:这几个地址里至少一个确实可达,记入历史 IP(供将来
            // mDNS 不可用时的单播兜底探测使用)——具体记哪些见
            // `addrs_to_record` 注释。
            let mut h = history.lock().expect("history lock");
            for ip in addrs_to_record(&addrs, &iface_entries) {
                h.record(ip);
            }
            h.save(&data_dir);
            drop(h);
            DiscoveryEvent::Registered {
                fingerprint: fingerprint.clone(),
            }
        } else {
            DiscoveryEvent::Unreachable {
                fingerprint: fingerprint.clone(),
            }
        };
        let _ = discovery_tx.send(result_ev);
        in_flight
            .lock()
            .expect("in-flight lock")
            .remove(&fingerprint);
    });
}

/// 去掉 `.local` 后缀的真实主机名。既用作 `nickname` 的默认值(用户可覆盖),
/// 也用作 IPMsg 报文里的 `host` 字段(设计上恒为真实机器名,不随
/// `CoreConfig::nickname` 覆盖而变化——两者语义不同:nickname 是"顶给别人
/// 看的昵称",host 是"这台机器叫什么")。
fn hostname_no_local() -> String {
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    host.trim_end_matches(".local").to_string()
}

fn default_nickname() -> String {
    hostname_no_local()
}

/// 设置里的昵称归一化:None/空白 → 主机名默认值(与 UI 侧 trim+空值回退
/// 的语义对齐)。壳层 CoreConfig::nickname 恒为 None,热生效路径只看 settings。
fn effective_nickname(s: &crate::settings::Settings) -> String {
    s.nickname
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .unwrap_or_else(default_nickname)
}

/// IPMsg 事件 → roster/transport 事件的映射(M5,设计文档 §6):
/// - `Online`:**自动升级去重**——`is_bigpaw=true` 说明对端也是 BigPaw,
///   原生发现层(mDNS/UDP 宣告)迟早会(或已经)发现同一台设备并注册为
///   `Protocol::Native` 联系人,这里直接跳过、不注入 ipmsg 联系人,否则同
///   一对端会在联系人列表里出现两次。转成 roster 的 `Seen` 时用伪指纹
///   `ipmsg:<key>`(ipmsg 对端没有真实指纹),`protocol: Ipmsg`。
/// - `Offline`:转成 `Lost`;若这个伪指纹从未被 `Seen` 加入过(比如它当初
///   因为 `is_bigpaw=true` 被跳过),`Roster::apply` 本身对未知 fingerprint
///   就是无操作,这里不需要额外判断。
/// - `TextReceived`/`FileOffered`:转成与原生传输层同形状的
///   `TransportEvent`,复用既有的 `message://received`/`file://offered`
///   转发路径,UI 不需要区分协议来源。文件/文件夹 offer 都顺带把
///   `(peer_fp, packet_no, file_id, name, size, is_dir)` 登记进 `offers`,供
///   `Core::respond_file` 决定接受时反查、按 `is_dir` 分派
///   `request_file`/`request_dir`(文件夹仅接收,§6 冻结范围——发送文件夹
///   仍不支持,但接收侧不再过滤掉目录条目)。
fn forward_ipmsg_event(
    ev: IpmsgEvent,
    disc_tx: &Sender<DiscoveryEvent>,
    msg_tx: &Sender<TransportEvent>,
    offers: &Mutex<HashMap<String, IpmsgOffer>>,
) {
    match ev {
        IpmsgEvent::Online {
            key,
            nick,
            addr,
            is_bigpaw,
            ..
        } => {
            if is_bigpaw {
                return; // 自动升级:交给原生发现层,不重复注入联系人
            }
            let _ = disc_tx.send(DiscoveryEvent::Seen {
                fingerprint: format!("ipmsg:{key}"),
                nickname: nick,
                addrs: vec![addr.ip()],
                port: addr.port(),
                protocol: Protocol::Ipmsg,
            });
        }
        IpmsgEvent::Offline { key } => {
            let _ = disc_tx.send(DiscoveryEvent::Lost {
                fingerprint: format!("ipmsg:{key}"),
            });
        }
        IpmsgEvent::TextReceived { key, body, .. } => {
            let _ = msg_tx.send(TransportEvent::Message(MessageEvent {
                peer_fp: format!("ipmsg:{key}"),
                id: crate::transport::proto::new_id(),
                body,
                ts_ms: crate::transport::proto::now_ms(),
            }));
        }
        IpmsgEvent::FileOffered {
            key,
            packet_no,
            files,
            ..
        } => {
            let peer_fp = format!("ipmsg:{key}");
            for f in files {
                let xfer_id = crate::transport::proto::new_id();
                offers.lock().expect("ipmsg offers lock").insert(
                    xfer_id.clone(),
                    IpmsgOffer {
                        peer_fp: peer_fp.clone(),
                        packet_no,
                        file_id: f.file_id,
                        name: f.name.clone(),
                        size: f.size,
                        is_dir: f.is_dir,
                    },
                );
                let _ = msg_tx.send(TransportEvent::FileOffered {
                    xfer_id,
                    peer_fp: peer_fp.clone(),
                    name: f.name,
                    size: f.size,
                    is_dir: f.is_dir,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn spawn_probe_reports_registered_and_records_history() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(dir_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(dir_b.path()).unwrap());
        let (msg_tx_a, _msg_rx_a) = std::sync::mpsc::channel();
        let (msg_tx_b, _msg_rx_b) = std::sync::mpsc::channel();
        let transport_a = TransportManager::start(id_a, 0, msg_tx_a).unwrap();
        let transport_b = TransportManager::start(id_b.clone(), 0, msg_tx_b).unwrap();

        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let history_dir = tempfile::tempdir().unwrap();
        let history = Arc::new(Mutex::new(HistoryStore::load(history_dir.path())));
        let local = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];

        spawn_probe(
            &transport_a,
            &disc_tx,
            &in_flight,
            &history,
            history_dir.path(),
            vec![], // entries 为空:零语义漂移,保持"全记"旧行为
            id_b.fingerprint.clone(),
            local.clone(),
            transport_b.port(),
        );

        match disc_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            DiscoveryEvent::Registered { fingerprint } => {
                assert_eq!(fingerprint, id_b.fingerprint)
            }
            other => panic!("期望 Registered,却收到 {other:?}"),
        }
        assert!(
            in_flight.lock().unwrap().is_empty(),
            "探测结束后应从 in-flight 集合摘除"
        );
        assert!(
            HistoryStore::load(history_dir.path())
                .ips()
                .contains(&local[0]),
            "回连成功应记入历史 IP 并落盘"
        );
    }

    #[test]
    fn spawn_probe_reports_unreachable_for_dead_port() {
        let dir_a = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(dir_a.path()).unwrap());
        let (msg_tx_a, _msg_rx_a) = std::sync::mpsc::channel();
        let transport_a = TransportManager::start(id_a, 0, msg_tx_a).unwrap();

        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let history_dir = tempfile::tempdir().unwrap();
        let history = Arc::new(Mutex::new(HistoryStore::load(history_dir.path())));
        let dead_fp = "0".repeat(64);

        spawn_probe(
            &transport_a,
            &disc_tx,
            &in_flight,
            &history,
            history_dir.path(),
            vec![], // entries 为空:零语义漂移,保持"全记"旧行为
            dead_fp.clone(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            1, // 无人监听
        );

        match disc_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            DiscoveryEvent::Unreachable { fingerprint } => assert_eq!(fingerprint, dead_fp),
            other => panic!("期望 Unreachable,却收到 {other:?}"),
        }
        assert!(in_flight.lock().unwrap().is_empty());
    }

    #[test]
    fn spawn_probe_skips_when_already_in_flight() {
        let dir_a = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(dir_a.path()).unwrap());
        let (msg_tx_a, _msg_rx_a) = std::sync::mpsc::channel();
        let transport_a = TransportManager::start(id_a, 0, msg_tx_a).unwrap();

        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        in_flight.lock().unwrap().insert("bbbb".to_string());
        let history_dir = tempfile::tempdir().unwrap();
        let history = Arc::new(Mutex::new(HistoryStore::load(history_dir.path())));

        spawn_probe(
            &transport_a,
            &disc_tx,
            &in_flight,
            &history,
            history_dir.path(),
            vec![], // entries 为空:零语义漂移,保持"全记"旧行为
            "bbbb".to_string(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            1,
        );

        // 已在飞:不该起新线程探测,也就不该有事件送回。
        assert!(disc_rx.recv_timeout(Duration::from_millis(300)).is_err());
        assert_eq!(
            in_flight.lock().unwrap().len(),
            1,
            "已在飞的标记不该被这次跳过的调用误摘除"
        );
    }

    #[test]
    fn start_creates_identity_and_empty_roster() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        assert_eq!(core.fingerprint().len(), 64);
        assert_eq!(core.nickname(), "tester");
        assert!(core.roster_snapshot().is_empty());
        assert!(dir.path().join("identity.key.der").exists());
    }

    #[test]
    fn default_nickname_is_hostname_without_local_suffix() {
        let n = default_nickname();
        assert!(!n.is_empty());
        assert!(!n.ends_with(".local"));
    }

    #[test]
    fn shutdown_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        core.shutdown();
        core.shutdown(); // 第二次调用不得 panic
    }

    #[test]
    fn shutdown_joins_roster_thread_without_hanging() {
        // roster 消费线程从阻塞 recv 换成 recv_timeout(ROSTER_TICK=5s)+
        // stop 标志后,shutdown 必须真正 join 到它、而不是发个信号就返回。
        // 用耗时上限断言防止回归成"发信号但不 join"或"join 却永久挂起"。
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        let start = Instant::now();
        core.shutdown();
        // 3s = 各组件优雅关闭上界之和(mDNS goodbye ≤1s + announce join ≤0.7s
        // + ipmsg join ≤0.7s)留出余量;关键是它显著小于 ROSTER_TICK(5s),
        // 若 roster 线程回归成"死等满一个 tick 才看停止标志",此断言必失败。
        // 用户可感知的现象即"无联系人(无事件流)时退出 app 卡 ~5s"。
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "shutdown 应亚秒级响应停止信号(轮询粒度与过期扫描节奏解耦),\
             实际耗时 {:?}(说明 roster 线程在死等 recv_timeout 满 ROSTER_TICK)",
            start.elapsed()
        );
    }

    #[test]
    fn stale_fingerprints_finds_only_expired_entries() {
        // 纯函数单测:不必真等 PEER_TIMEOUT(60s),用人为构造的时间戳即可
        // 确定性地验证过期判定逻辑——这也是它被抽出来独立于线程之外的原因。
        let now = Instant::now();
        let mut last_seen: HashMap<String, Instant> = HashMap::new();
        last_seen.insert("fresh".to_string(), now);
        last_seen.insert(
            "stale".to_string(),
            now.checked_sub(Duration::from_secs(120))
                .expect("测试机器已启动超过 120s"),
        );

        let stale = stale_fingerprints(&last_seen, now, Duration::from_secs(60));
        assert_eq!(stale, vec!["stale".to_string()]);
    }

    #[test]
    fn stale_fingerprints_empty_when_nothing_expired() {
        let now = Instant::now();
        let mut last_seen: HashMap<String, Instant> = HashMap::new();
        last_seen.insert("fresh".to_string(), now);
        assert!(stale_fingerprints(&last_seen, now, Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn stale_fingerprints_boundary_is_strictly_greater_than_timeout() {
        // 恰好等于超时阈值不算过期(用 `>` 而不是 `>=`),避免在超时边界
        // 上因为调用时机的微小抖动而误判——只有真正超过才判离线。
        let now = Instant::now();
        let mut last_seen: HashMap<String, Instant> = HashMap::new();
        last_seen.insert(
            "exactly-at-boundary".to_string(),
            now.checked_sub(Duration::from_secs(60))
                .expect("测试机器已启动超过 60s"),
        );
        assert!(stale_fingerprints(&last_seen, now, Duration::from_secs(60)).is_empty());
    }

    // ---- addrs_to_record:spawn_probe 的历史 IP 过滤规则(Step 7) ----

    fn iface_entry(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> IfaceEntry {
        IfaceEntry {
            name: name.to_string(),
            ip,
            netmask,
            broadcast: net_ifaces::directed_broadcast(ip, netmask),
            is_virtual_hint: false,
        }
    }

    #[test]
    fn addrs_to_record_keeps_all_when_entries_empty() {
        // entries 为空(全排除/尚未初始化)保持"全记"的旧行为——现有 3 处
        // spawn_probe 单测传 vec![] 正是依赖这条零语义漂移保证。
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9)),
        ];
        assert_eq!(addrs_to_record(&addrs, &[]), addrs);
    }

    #[test]
    fn addrs_to_record_filters_to_same_subnet_when_entries_present() {
        let entries = vec![iface_entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),   // 不同网段:该被滤掉
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9)), // 同网段:该保留
        ];
        assert_eq!(
            addrs_to_record(&addrs, &entries),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9))]
        );
    }

    #[test]
    fn addrs_to_record_empty_result_when_no_addr_matches_any_entry() {
        let entries = vec![iface_entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))];
        assert!(addrs_to_record(&addrs, &entries).is_empty());
    }

    // ---- apply_excluded_interfaces:apply_settings 的核心决策(Step 7) ----
    //
    // 用真实 InterfaceRegistry(网卡枚举依赖真实主机,没有 mock 钩子),但
    // mdns 一侧换成记录调用参数的 spy 闭包,不必起真实 Discovery/mdns
    // daemon——这是"清单变化 → registry 快照变化 → ipmsg targets 被覆写"
    // 这条编排逻辑可确定性单测的关键(与 brief 要求的"合成数据"对应:
    // 一个测试机上必然不存在的网卡名,以及测试机当前真实的网卡名清单)。

    /// 测试用:构造一份底层目标表 + generation=0 起步的 `IpmsgBcastGuard`,
    /// 返回两者供测试既能调用 `apply_excluded_interfaces`,又能直接读底层
    /// `BroadcastTargets` 断言写入结果。
    fn new_bcast_guard() -> (BroadcastTargets, IpmsgBcastGuard) {
        let targets: BroadcastTargets = bigpaw_ipmsg::discovery::default_broadcast_targets();
        let guard = IpmsgBcastGuard::new(targets.clone(), 0);
        (targets, guard)
    }

    #[test]
    fn apply_excluded_interfaces_skips_mdns_callback_when_list_unchanged() {
        let registry = InterfaceRegistry::new(vec!["already-excluded".to_string()]);
        let (_targets, ipmsg_bcast) = new_bcast_guard();
        let mut calls = 0;
        apply_excluded_interfaces(
            &registry,
            &ipmsg_bcast,
            &["already-excluded".to_string()],
            |_, _| calls += 1,
        );
        assert_eq!(calls, 0, "清单没变不该触碰 mdns");
    }

    #[test]
    fn apply_excluded_interfaces_notifies_mdns_for_nonexistent_iface_name_even_if_snapshot_unchanged(
    ) {
        // 关键分离逻辑:排除一个当前系统里根本不存在的网卡名——快照不会
        // 变(没有任何条目因此被滤掉),但 daemon 必须记住这个名字(不然它
        // 日后插上来还是会被广播出去),所以 mdns 回调仍然必须被调用。
        let registry = InterfaceRegistry::new(vec![]);
        let (targets, ipmsg_bcast) = new_bcast_guard();
        let before_snapshot = registry.snapshot();
        let before_bcast = targets.lock().unwrap().clone();

        let fake_name = "definitely-not-a-real-iface-zzz".to_string();
        let mut calls: Vec<(Vec<String>, Vec<String>)> = Vec::new();
        apply_excluded_interfaces(
            &registry,
            &ipmsg_bcast,
            std::slice::from_ref(&fake_name),
            |new, old| {
                calls.push((new.to_vec(), old.to_vec()));
            },
        );

        assert_eq!(calls, vec![(vec![fake_name], vec![])], "清单变了必须通知 mdns");
        assert_eq!(
            registry.snapshot().entries,
            before_snapshot.entries,
            "不存在的网卡名不该改变快照"
        );
        assert_eq!(
            *targets.lock().unwrap(),
            before_bcast,
            "快照没变,ipmsg 目标表不该被覆写"
        );
    }

    #[test]
    fn apply_excluded_interfaces_overwrites_ipmsg_bcast_when_snapshot_changes() {
        let registry = InterfaceRegistry::new(vec![]);
        let names: Vec<String> = registry.list_all().into_iter().map(|v| v.name).collect();
        if names.is_empty() {
            eprintln!("测试机无非回环网卡,跳过(快照永远不会因排除清单而变化)");
            return;
        }
        let (targets, ipmsg_bcast) = new_bcast_guard();

        let mut calls = 0;
        apply_excluded_interfaces(&registry, &ipmsg_bcast, &names, |_, _| calls += 1);

        assert_eq!(calls, 1, "清单从空变成非空,必须通知 mdns");
        let expected = net_ifaces::broadcast_targets(&registry.snapshot().entries);
        assert_eq!(
            *targets.lock().unwrap(),
            expected,
            "快照真的变了,ipmsg 目标表必须原地覆写成新快照算出的广播地址"
        );
    }

    // ---- IpmsgBcastGuard:generation 守卫堵 stale 覆写竞态(Important 1,
    // 最终评审修复)----
    //
    // `apply_settings`(set_excluded)与 roster 线程定期 `refresh()` 并发时,
    // 真实的交错时序依赖线程调度、无法在单测里可靠复现;能确定性验证的是
    // 修复所依赖的结构保证本身——generation 更旧的写入,无论它在时间线上
    // 排在 generation 更新的写入*之后*才执行到覆写这一步,都必须被识别为
    // stale 并跳过。下面直接构造"新写入先发生、旧写入后到达"的交错顺序
    // (对应评审描述的竞态:roster 线程 refresh() 发布 gen N 后被抢占,
    // apply_settings 发布 gen N+1 并写 bcast,roster 恢复后用 gen N 覆写
    // 回去),断言最终状态是新写入的结果、没有被旧写入覆盖。

    #[test]
    fn ipmsg_bcast_guard_rejects_stale_generation_applied_after_newer_one() {
        let targets: BroadcastTargets = bigpaw_ipmsg::discovery::default_broadcast_targets();
        let guard = IpmsgBcastGuard::new(targets.clone(), 0);

        // "旧"快照:对应 roster 线程 refresh() 在 apply_settings 之前读到的
        // 那份(排除生效之前,en0 仍在),generation=1。
        let stale_entries = vec![iface_entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let stale = IfaceSnapshot {
            generation: 1,
            entries: stale_entries,
        };

        // "新"快照:对应 apply_settings 里 set_excluded 排除掉 en0 之后发布的
        // 那份,generation=2(严格新于 stale)。
        let fresh_entries = vec![iface_entry(
            "en1",
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(255, 0, 0, 0),
        )];
        let fresh = IfaceSnapshot {
            generation: 2,
            entries: fresh_entries.clone(),
        };

        // 交错顺序:新的先落地(apply_settings 抢先执行完覆写),旧的因为
        // 线程调度延迟,后落地(roster 线程恢复执行、试图覆写回去)。
        guard.apply_if_newer(&fresh);
        guard.apply_if_newer(&stale);

        assert_eq!(
            *targets.lock().unwrap(),
            net_ifaces::broadcast_targets(&fresh_entries),
            "generation 更旧的写入即使后执行到覆写这一步,也不该覆盖更新一代的结果"
        );
    }

    #[test]
    fn ipmsg_bcast_guard_applies_when_generation_arrives_in_order() {
        // 正常顺序(无竞态)下,新一代快照仍应正确覆写——防止守卫逻辑矫枉
        // 过正,把所有写入都挡住。
        let targets: BroadcastTargets = bigpaw_ipmsg::discovery::default_broadcast_targets();
        let guard = IpmsgBcastGuard::new(targets.clone(), 0);

        let e1 = vec![iface_entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        guard.apply_if_newer(&IfaceSnapshot {
            generation: 1,
            entries: e1,
        });

        let e2 = vec![iface_entry(
            "en1",
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(255, 0, 0, 0),
        )];
        guard.apply_if_newer(&IfaceSnapshot {
            generation: 2,
            entries: e2.clone(),
        });

        assert_eq!(*targets.lock().unwrap(), net_ifaces::broadcast_targets(&e2));
    }

    #[test]
    fn ipmsg_bcast_guard_same_generation_reapplied_is_a_harmless_noop() {
        // 同一代重复应用(两个调用方都读到了同一份最新快照)不该 panic,
        // 第二次是 no-op(条件是严格大于,不是大于等于)。
        let targets: BroadcastTargets = bigpaw_ipmsg::discovery::default_broadcast_targets();
        let guard = IpmsgBcastGuard::new(targets.clone(), 0);
        let entries = vec![iface_entry(
            "en0",
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(255, 255, 255, 0),
        )];
        let snapshot = IfaceSnapshot {
            generation: 1,
            entries: entries.clone(),
        };

        guard.apply_if_newer(&snapshot);
        guard.apply_if_newer(&snapshot);

        assert_eq!(
            *targets.lock().unwrap(),
            net_ifaces::broadcast_targets(&entries)
        );
    }

    #[test]
    fn ipmsg_bcast_guard_concurrent_interleaved_generations_converge_to_the_max() {
        // 多线程压力测试(复审要求):同线程顺序调用只能验证"逻辑上旧的不该
        // 覆盖新的",验证不了"check 和 write 之间是否真的不可被抢占插入"这个
        // 并发属性本身——两条线程各 1000 次交替以递增 generation 调用
        // `apply_if_newer`,制造大量"新旧交错"的真实调度机会。这类压力测试
        // 不能穷尽所有调度顺序,但配合 `apply_if_newer` 的锁序论证(见类型
        // 文档"现在的修法":check-and-write 在同一把 `applied_gen` 锁的临界
        // 区内原子完成,调用者之间完全互斥)已经足够——现在的实现下这个
        // 断言应当 100% 确定性成立(不是"大概率成立"),因为整把锁序保证了
        // "最终状态 = 出现过的最高 generation"这一收敛性质,与线程调度顺序
        // 无关;首版 `fetch_max` 两段式实现在这个测试上并不保证必然失败
        // (窗口很窄,压力测试可能撞不上),这正是复审指出"结构性论证"比
        // "跑几次不挂"更重要的原因——本测试是锁序论证之外的补充信心,不是
        // 唯一证据。
        let targets: BroadcastTargets = bigpaw_ipmsg::discovery::default_broadcast_targets();
        let guard = Arc::new(IpmsgBcastGuard::new(targets.clone(), 0));

        const ITERS: u64 = 1000;
        fn entries_for_gen(gen: u64) -> Vec<IfaceEntry> {
            vec![iface_entry(
                "en0",
                Ipv4Addr::new(10, 0, ((gen >> 8) & 0xff) as u8, (gen & 0xff) as u8),
                Ipv4Addr::new(255, 255, 255, 0),
            )]
        }

        let barrier = Arc::new(std::sync::Barrier::new(2));

        // 线程 A:偶数代 2, 4, ..., 2*ITERS(全局最高的一代 2*ITERS 出自这里)。
        let guard_a = guard.clone();
        let barrier_a = barrier.clone();
        let handle_a = std::thread::spawn(move || {
            barrier_a.wait(); // 尽量让两条线程同时起跑,加大交错概率
            for i in 1..=ITERS {
                let gen = i * 2;
                guard_a.apply_if_newer(&IfaceSnapshot {
                    generation: gen,
                    entries: entries_for_gen(gen),
                });
            }
        });

        // 线程 B:奇数代 1, 3, ..., 2*ITERS-1——每一个都紧跟在线程 A 同轮次
        // 的偶数代之后一个整数,专门制造"旧的紧跟在新的后面尝试覆写"的场景。
        let guard_b = guard.clone();
        let barrier_b = barrier.clone();
        let handle_b = std::thread::spawn(move || {
            barrier_b.wait();
            for i in 1..=ITERS {
                let gen = i * 2 - 1;
                guard_b.apply_if_newer(&IfaceSnapshot {
                    generation: gen,
                    entries: entries_for_gen(gen),
                });
            }
        });

        handle_a.join().unwrap();
        handle_b.join().unwrap();

        // 两条线程整个压力测试期间出现过的全局最高 generation 是 2*ITERS
        // (线程 A 的最后一次调用)。无论实际调度交错成什么顺序,最终状态都
        // 必须与它一致——不能被任何一次更旧 generation 的调用事后覆盖。
        let max_gen = ITERS * 2;
        assert_eq!(
            *targets.lock().unwrap(),
            net_ifaces::broadcast_targets(&entries_for_gen(max_gen)),
            "两线程 {ITERS} 次交替 apply 之后,最终 targets 必须与压力测试中\
             出现过的最高 generation({max_gen})一致,不能被更旧的 generation \
             事后覆盖"
        );
    }

    // ---- forward_ipmsg_event:IPMsg → roster/transport 事件映射(M5) ----

    fn ipmsg_online(key: &str, is_bigpaw: bool) -> IpmsgEvent {
        IpmsgEvent::Online {
            key: key.to_string(),
            nick: "bob-feiq".to_string(),
            host: "HOST-B".to_string(),
            addr: "192.168.1.9:2425".parse().unwrap(),
            is_bigpaw,
        }
    }

    #[test]
    fn forward_ipmsg_event_online_becomes_seen_with_ipmsg_protocol() {
        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, _msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            ipmsg_online("192.168.1.9:HOST-B", false),
            &disc_tx,
            &msg_tx,
            &offers,
        );

        match disc_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            DiscoveryEvent::Seen {
                fingerprint,
                protocol,
                addrs,
                port,
                ..
            } => {
                assert_eq!(fingerprint, "ipmsg:192.168.1.9:HOST-B");
                assert_eq!(protocol, Protocol::Ipmsg);
                assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9))]);
                assert_eq!(port, 2425);
            }
            other => panic!("期望 Seen,却收到 {other:?}"),
        }
    }

    #[test]
    fn forward_ipmsg_event_skips_bigpaw_peer_for_auto_upgrade() {
        // 自动升级去重:对端也是 BigPaw 时不注入 ipmsg 联系人,原生发现层接管。
        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, _msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            ipmsg_online("192.168.1.9:HOST-B", true),
            &disc_tx,
            &msg_tx,
            &offers,
        );

        assert!(
            disc_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "is_bigpaw=true 不该注入 ipmsg 联系人"
        );
    }

    #[test]
    fn forward_ipmsg_event_offline_becomes_lost() {
        let (disc_tx, disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, _msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            IpmsgEvent::Offline {
                key: "192.168.1.9:HOST-B".to_string(),
            },
            &disc_tx,
            &msg_tx,
            &offers,
        );

        match disc_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            DiscoveryEvent::Lost { fingerprint } => {
                assert_eq!(fingerprint, "ipmsg:192.168.1.9:HOST-B")
            }
            other => panic!("期望 Lost,却收到 {other:?}"),
        }
    }

    #[test]
    fn forward_ipmsg_event_text_received_becomes_message() {
        let (disc_tx, _disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            IpmsgEvent::TextReceived {
                key: "192.168.1.9:HOST-B".to_string(),
                from: "bob".to_string(),
                body: "你好".to_string(),
            },
            &disc_tx,
            &msg_tx,
            &offers,
        );

        match msg_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            TransportEvent::Message(m) => {
                assert_eq!(m.peer_fp, "ipmsg:192.168.1.9:HOST-B");
                assert_eq!(m.body, "你好");
            }
            other => panic!("期望 Message,却收到 {other:?}"),
        }
    }

    #[test]
    fn forward_ipmsg_event_file_offered_registers_offer_and_emits_event() {
        let (disc_tx, _disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            IpmsgEvent::FileOffered {
                key: "192.168.1.9:HOST-B".to_string(),
                from: "bob".to_string(),
                packet_no: 42,
                files: vec![bigpaw_ipmsg::filexfer::IpmsgFileEntry {
                    file_id: 0,
                    name: "report.pdf".to_string(),
                    size: 2048,
                    is_dir: false,
                }],
            },
            &disc_tx,
            &msg_tx,
            &offers,
        );

        let xfer_id = match msg_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            TransportEvent::FileOffered {
                xfer_id,
                peer_fp,
                name,
                size,
                is_dir,
            } => {
                assert_eq!(peer_fp, "ipmsg:192.168.1.9:HOST-B");
                assert_eq!(name, "report.pdf");
                assert_eq!(size, 2048);
                assert!(!is_dir);
                xfer_id
            }
            other => panic!("期望 FileOffered,却收到 {other:?}"),
        };

        let table = offers.lock().unwrap();
        let registered = table.get(&xfer_id).expect("offer 应已登记");
        assert_eq!(registered.peer_fp, "ipmsg:192.168.1.9:HOST-B");
        assert_eq!(registered.packet_no, 42);
        assert_eq!(registered.file_id, 0);
        assert_eq!(registered.name, "report.pdf");
        assert_eq!(registered.size, 2048);
        assert!(!registered.is_dir);
    }

    #[test]
    fn forward_ipmsg_event_file_offered_surfaces_dir_entries() {
        // M5 folder-receive:目录条目不再被过滤——必须像文件一样生成 xfer_id、
        // 登记进 offers(带 is_dir=true),并上报 FileOffered 供 UI 展示成
        // 可接受的"文件夹"offer(回归此前 filter(|f| !f.is_dir) 丢弃目录的 bug)。
        let (disc_tx, _disc_rx) = std::sync::mpsc::channel();
        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        let offers: Mutex<HashMap<String, IpmsgOffer>> = Mutex::new(HashMap::new());

        forward_ipmsg_event(
            IpmsgEvent::FileOffered {
                key: "192.168.1.9:HOST-B".to_string(),
                from: "bob".to_string(),
                packet_no: 1,
                files: vec![bigpaw_ipmsg::filexfer::IpmsgFileEntry {
                    file_id: 0,
                    name: "照片".to_string(),
                    size: 0,
                    is_dir: true,
                }],
            },
            &disc_tx,
            &msg_tx,
            &offers,
        );

        let xfer_id = match msg_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            TransportEvent::FileOffered {
                xfer_id,
                name,
                is_dir,
                ..
            } => {
                assert_eq!(name, "照片");
                assert!(is_dir, "目录条目应带 is_dir=true 上报,不再被过滤");
                xfer_id
            }
            other => panic!("期望 FileOffered(目录),却收到 {other:?}"),
        };

        let table = offers.lock().unwrap();
        let registered = table
            .get(&xfer_id)
            .expect("目录 offer 也应登记,供 respond 时反查");
        assert!(registered.is_dir);
    }

    /// respond 路由回归:接受一条 `is_dir=true` 的 ipmsg offer 必须真的调用
    /// `IpmsgService::request_dir`(走 GETDIRFILES),而不是 `request_file`
    /// (GETFILEDATA)。用一个裸 TCP 监听器充当"对端"——它不实现真正的
    /// GETDIRFILES 响应协议,只读出客户端发来的请求报文并解码,断言其
    /// `command` 字段确实是 `GETDIRFILES`(直接读 header-size 时遇到 EOF,
    /// `receive_dir_stream` 视作"干净的空目录流"返回 Ok,不算错误)。
    #[test]
    fn respond_file_routes_dir_offer_to_request_dir_over_tcp() {
        use std::io::Read;
        use std::net::TcpListener;

        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        if !core.ipmsg_available() {
            eprintln!("2425 端口不可用(可能被其它进程/测试占用),跳过本测试");
            return;
        }

        // 裸 TCP "假对端":接受一条连接,读出请求报文的 command 字段后立即关闭
        // (不回任何目录流字节),验证发起方发的是 GETDIRFILES。
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let fake_peer_addr = listener.local_addr().unwrap();
        let received_command = Arc::new(Mutex::new(None::<u32>));
        let received_command_for_server = received_command.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                if let Some(packet) = bigpaw_ipmsg::proto::decode(&buf[..n]) {
                    *received_command_for_server.lock().unwrap() =
                        Some(bigpaw_ipmsg::command::Command(packet.command).num());
                }
            }
            // 故意不发任何目录流字节就断开连接:receive_dir_stream 在
            // header-size 阶段读到 EOF 视为"干净结束",返回 Ok(空目录)。
        });

        // 手工把这个"假对端"注入 roster(伪 fingerprint,Protocol::Ipmsg)和
        // ipmsg_offers(is_dir=true),模拟 forward_ipmsg_event 本该做的登记——
        // 跳过真实 UDP 发现,只测 respond_file 的路由决策本身。
        let peer_fp = "ipmsg:test-dir-peer".to_string();
        core.roster_handle
            .lock()
            .unwrap()
            .apply(DiscoveryEvent::Seen {
                fingerprint: peer_fp.clone(),
                nickname: "fake-feiq".to_string(),
                addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                port: fake_peer_addr.port(),
                protocol: Protocol::Ipmsg,
            });
        let xfer_id = "test-xfer-dir".to_string();
        core.ipmsg_offers.lock().unwrap().insert(
            xfer_id.clone(),
            IpmsgOffer {
                peer_fp,
                packet_no: 7,
                file_id: 0,
                name: "照片".to_string(),
                size: 0,
                is_dir: true,
            },
        );

        let events_rx = core.take_events().expect("events_rx 应可取走");
        core.respond_file(&xfer_id, true, dir.path()).unwrap();

        // respond_file_ipmsg 的后台线程完成(对端立刻断连,Ok(空目录))后应
        // 上报 FileDone;这就是"确实沿着目录路径完整跑完一次 request_dir"的
        // 端到端证明,而不仅仅是路由决策本身。
        let done = events_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        match done {
            TransportEvent::FileDone { xfer_id: got, .. } => assert_eq!(got, xfer_id),
            other => panic!("期望 FileDone,却收到 {other:?}"),
        }

        server.join().unwrap();
        assert_eq!(
            *received_command.lock().unwrap(),
            Some(bigpaw_ipmsg::command::GETDIRFILES),
            "接受目录 offer 必须发 GETDIRFILES,而不是 GETFILEDATA"
        );

        core.shutdown();
    }

    // ---- 持久化泵(M6):事件先写库、再转发 ----

    #[test]
    fn pump_persists_incoming_message_before_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        let rx = core.take_events().expect("events_rx");
        // 直接从内部发送端注入(与 respond_file_ipmsg 上报同一条路径)
        core.events_tx
            .send(TransportEvent::Message(MessageEvent {
                peer_fp: "peerX".to_string(),
                id: "id1".to_string(),
                body: "你好".to_string(),
                ts_ms: 1234,
            }))
            .unwrap();
        // 事件到达消费端时,数据库必须已经写入(先写库、再转发)
        match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
            TransportEvent::Message(m) => assert_eq!(m.id, "id1"),
            other => panic!("期望 Message,得到 {other:?}"),
        }
        let items = core.storage().history("peerX", None, 10).unwrap();
        assert_eq!(items.len(), 1, "转发之前应已落库");
        core.shutdown();
    }

    #[test]
    fn pump_records_file_offer_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        let rx = core.take_events().expect("events_rx");
        core.events_tx
            .send(TransportEvent::FileOffered {
                xfer_id: "x1".to_string(),
                peer_fp: "peerX".to_string(),
                name: "a.zip".to_string(),
                size: 2048,
                is_dir: false,
            })
            .unwrap();
        core.events_tx
            .send(TransportEvent::FileDone {
                xfer_id: "x1".to_string(),
                path: PathBuf::from("/tmp/a.zip"),
            })
            .unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let items = core.storage().history("peerX", None, 10).unwrap();
        assert_eq!(items.len(), 1);
        match &items[0] {
            crate::storage::HistoryItem::File { status, path, .. } => {
                assert_eq!(status, "done");
                assert_eq!(path.as_deref(), Some("/tmp/a.zip"));
            }
            other => panic!("期望 File,得到 {other:?}"),
        }
        core.shutdown();
    }

    // ---- 启动预热/settings 接入(M6 task6) ----

    #[test]
    fn start_seeds_offline_peers_from_storage() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            s.upsert_peer("fpZ", "zoe", "native", Some("192.168.1.7"), 123)
                .unwrap();
        }
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        let snap = core.roster_snapshot();
        let zoe = snap
            .iter()
            .find(|p| p.fingerprint == "fpZ")
            .expect("已知 peer 应预热进 roster");
        assert_eq!(zoe.state, PeerState::Offline);
        assert_eq!(zoe.nickname, "zoe");
        assert_eq!(zoe.addrs, vec!["192.168.1.7".parse::<IpAddr>().unwrap()]);
        core.shutdown();
    }

    #[test]
    fn effective_nickname_falls_back_to_hostname_when_unset_or_blank() {
        let unset = crate::settings::Settings::default();
        assert_eq!(effective_nickname(&unset), default_nickname());

        let blank = crate::settings::Settings {
            nickname: Some("   ".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_nickname(&blank), default_nickname());

        let set = crate::settings::Settings {
            nickname: Some("大脚猫".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_nickname(&set), "大脚猫");
    }

    #[test]
    fn apply_settings_hot_renames_nickname() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("旧名".to_string()),
        })
        .unwrap();
        assert_eq!(core.nickname(), "旧名");

        core.apply_settings(&crate::settings::Settings {
            nickname: Some("新名".to_string()),
            ..Default::default()
        });
        assert_eq!(core.nickname(), "新名", "改名应即时反映在 nickname() 上");

        // 清空昵称 = 回退主机名默认值
        core.apply_settings(&crate::settings::Settings::default());
        assert_eq!(core.nickname(), default_nickname());
        core.shutdown();
    }

    #[test]
    fn start_uses_nickname_from_settings_when_cfg_is_none() {
        let dir = tempfile::tempdir().unwrap();
        crate::settings::save(
            dir.path(),
            &crate::settings::Settings {
                nickname: Some("设置里的名字".to_string()),
                group: None,
                download_dir: None,
                ipmsg_enabled: true,
                excluded_interfaces: Vec::new(),
            },
        )
        .unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: None,
        })
        .unwrap();
        assert_eq!(core.nickname(), "设置里的名字");
        core.shutdown();
    }

    #[test]
    fn start_skips_ipmsg_when_disabled_in_settings() {
        let dir = tempfile::tempdir().unwrap();
        crate::settings::save(
            dir.path(),
            &crate::settings::Settings {
                nickname: None,
                group: None,
                download_dir: None,
                ipmsg_enabled: false,
                excluded_interfaces: Vec::new(),
            },
        )
        .unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        assert!(!core.ipmsg_available(), "设置关闭时兼容层不启动");
        core.shutdown();
    }
}

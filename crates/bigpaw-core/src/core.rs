//! 核心编排:identity + discovery + roster 串联,对壳层(src-tauri)暴露
//! 同步启动接口与 watch 快照订阅。零 Tauri、零异步运行时依赖。

use crate::discovery::announce::{
    AnnounceError, AnnounceService, HistoryStore, DEFAULT_ANNOUNCE_PORT,
};
use crate::discovery::Discovery;
use crate::identity::{Identity, IdentityError};
use crate::roster::{DiscoveryEvent, Peer, PeerState, Protocol, Roster};
use crate::transport::manager::{
    MessageEvent, SentText, TransportError, TransportEvent, TransportManager, DEFAULT_PORT,
};
use bigpaw_ipmsg::discovery::{IpmsgError, IpmsgEvent, IpmsgService};
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

/// roster 消费线程从阻塞 `recv` 换成 `recv_timeout` 后的轮询间隔:既是
/// `shutdown` 停止信号的最长响应延迟上限,也是过期扫描的采样粒度。
const ROSTER_TICK: Duration = Duration::from_secs(5);

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
}

pub struct CoreConfig {
    pub data_dir: PathBuf,
    /// None 时用主机名(去 .local 后缀)
    pub nickname: Option<String>,
}

pub struct Core {
    identity: Arc<Identity>,
    nickname: String,
    roster_rx: watch::Receiver<Vec<Peer>>,
    roster_handle: Arc<Mutex<Roster>>,
    discovery: std::sync::Mutex<Option<Discovery>>,
    /// `Arc` 包裹是因为启动时的历史 IP 唤醒线程也要短暂借用它调用
    /// `poke`(见 `Core::start`);`shutdown` 时 `.take()` 拿到唯一所有权后
    /// 按值传给 `AnnounceService::shutdown`,与 `discovery` 字段同样的幂等模式。
    announce: Arc<Mutex<Option<AnnounceService>>>,
    transport: Arc<TransportManager>,
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
    /// 对端(ipmsg 协议)通过 `SENDMSG|FILEATTACHOPT` 报价的文件:
    /// 本地生成的 `xfer_id -> (packet_no, file_id, 文件名, 大小)` 登记表,
    /// 供 `respond_file` 决定接受时反查、发起 `IpmsgService::request_file`。
    ipmsg_offers: Arc<Mutex<HashMap<String, IpmsgOffer>>>,
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
}

impl Core {
    pub fn start(cfg: CoreConfig) -> Result<Self, CoreError> {
        let identity = Arc::new(Identity::load_or_create(&cfg.data_dir)?);
        let nickname = cfg.nickname.unwrap_or_else(default_nickname);

        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        // 留一份克隆给 IPMsg 兼容层的事件转发线程(见下):TextReceived/
        // FileOffered 复用与原生传输层相同的 TransportEvent 转发路径。
        let events_tx = msg_tx.clone();
        let transport = TransportManager::start(identity.clone(), DEFAULT_PORT, msg_tx)?;

        // IPMsg/飞秋兼容层(M5,设计文档 §6):独立 crate,启动失败(最常见
        // 是 2425 已被占用,比如本机在跑飞秋)绝不能让 Core::start 整体失败
        // ——原生栈已经就绪,只是"旧协议兼容"这一层降级为不可用,记一个
        // 标志供 `ipmsg_available()`/壳层 `ipmsg_status()` 命令查询。
        let (ipmsg_evt_tx, ipmsg_evt_rx) = std::sync::mpsc::channel::<IpmsgEvent>();
        let ipmsg_host = hostname_no_local();
        let (ipmsg_service, ipmsg_available) =
            match IpmsgService::start(&nickname, &ipmsg_host, IPMSG_PORT, ipmsg_evt_tx) {
                Ok(svc) => (Some(Arc::new(svc)), true),
                Err(e) => {
                    eprintln!("ipmsg: {IPMSG_PORT} 端口不可用({e}),兼容层已禁用(原生栈不受影响)");
                    (None, false)
                }
            };
        let ipmsg_offers: Arc<Mutex<HashMap<String, IpmsgOffer>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // discovery 事件通道:mDNS 发现线程通过 tx 送 Seen/Lost;下面同一个
        // 线程里为新对端起的回连探测线程也复用这条通道的克隆,把探测结论
        // (Registered/Unreachable)回灌给 roster——两类事件因此天然串行化,
        // 不需要额外同步。
        let (tx, rx) = std::sync::mpsc::channel();
        // 真实端口进 SRV
        let discovery = Discovery::start(&identity, &nickname, transport.port(), tx.clone())?;
        // UDP 宣告辅通道(设计文档 §4):与 mDNS 共用同一个 tx,两类事件天然
        // 串行喂给下面的 roster 线程,fingerprint 去重由 Roster::apply 保证。
        let announce_service = AnnounceService::start(
            &identity,
            &nickname,
            transport.port(),
            DEFAULT_ANNOUNCE_PORT,
            tx.clone(),
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

        let roster_handle = Arc::new(Mutex::new(Roster::new(identity.fingerprint.clone())));
        let (watch_tx, watch_rx) = watch::channel(Vec::new());
        let roster_for_thread = roster_handle.clone();
        let history = Arc::new(Mutex::new(HistoryStore::load(&cfg.data_dir)));

        // 历史 IP 单播唤醒(M4 简化版双向注册):对已知历史设备逐个发一份
        // 单播宣告,串行、间隔 ≥50ms,让对方回连/回宣告,走正常发现流程
        // 重新进入 roster——不做端口扫描、不直接建连接。
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
        let roster_thread = std::thread::spawn(move || {
            let transport = transport_for_thread;
            // last-seen 时间戳(不进 roster,保持 roster 纯状态机):任一
            // 通道的 Seen 刷新它;超过 PEER_TIMEOUT 未刷新则判离线(见下)。
            let mut last_seen: HashMap<String, Instant> = HashMap::new();
            loop {
                match rx.recv_timeout(ROSTER_TICK) {
                    Ok(ev) => {
                        if let DiscoveryEvent::Seen { fingerprint, .. } = &ev {
                            last_seen.insert(fingerprint.clone(), Instant::now());
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
                                    &transport, &tx, &in_flight, &history, &data_dir, fp, addrs,
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
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if roster_stop_for_thread.load(Ordering::Relaxed) {
                            break;
                        }
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

        Ok(Self {
            identity,
            nickname,
            roster_rx: watch_rx,
            roster_handle,
            discovery: std::sync::Mutex::new(Some(discovery)),
            announce,
            transport,
            events_rx: Mutex::new(Some(msg_rx)),
            events_tx,
            roster_stop,
            roster_thread: Mutex::new(Some(roster_thread)),
            ipmsg: Mutex::new(ipmsg_service),
            ipmsg_available,
            ipmsg_offers,
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.identity.fingerprint
    }

    pub fn nickname(&self) -> &str {
        &self.nickname
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
        match peer.protocol {
            Protocol::Native => {
                Ok(self
                    .transport
                    .send_text(peer_fp, &peer.addrs, peer.port, body)?)
            }
            Protocol::Ipmsg => self.send_text_ipmsg(&peer, body),
        }
    }

    /// 给对端发起一次文件传输报价;同样按 `peer.protocol` 分派。原生一侧
    /// 返回 xfer_id,后续的 FileOffered/FileProgress/FileDone/FileFailed
    /// 事件都带着它,供调用方关联;ipmsg 一侧见 `offer_file_ipmsg` 注释。
    pub fn offer_file(&self, peer_fp: &str, path: &Path) -> Result<String, CoreError> {
        let peer = self.find_peer(peer_fp)?;
        match peer.protocol {
            Protocol::Native => {
                let handle = self
                    .transport
                    .offer_file(peer_fp, &peer.addrs, peer.port, path)?;
                Ok(handle.xfer_id)
            }
            Protocol::Ipmsg => self.offer_file_ipmsg(&peer, path),
        }
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
        match ipmsg_offer {
            Some(offer) => self.respond_file_ipmsg(xfer_id, offer, accept, download_dir),
            None => Ok(self.transport.respond_file(xfer_id, accept, download_dir)?),
        }
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

    /// 接受/拒绝一条 ipmsg 文件报价。拒绝:IPMsg 协议没有"我拒绝了"的回执,
    /// 不请求就是拒绝,静默即可。接受:反查 roster 拿地址,后台线程发起
    /// `IpmsgService::request_file`(阻塞网络 IO,不能占着调用方线程——与
    /// 原生 `offer_file` 的 `await_offer_reply` 后台线程同一个道理),完成/
    /// 失败时复用原生一致的 `TransportEvent::FileDone`/`FileFailed` 上报。
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
            match svc.request_file(addr, offer.packet_no, offer.file_id, offer.size, &save_path) {
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

    pub fn port(&self) -> u16 {
        self.transport.port()
    }

    /// IPMsg 兼容层是否已启用(启动时 2425 端口绑定成功)。供壳层
    /// `ipmsg_status()` 命令查询,让前端能提示"2425 被占用,可能本机在跑
    /// 飞秋"。启动后固定不变。
    pub fn ipmsg_available(&self) -> bool {
        self.ipmsg_available
    }

    /// 主动下线:注销 mDNS(发 goodbye)+ 停止 UDP 宣告收发,对端立刻收到
    /// Lost 而不是等 TTL 过期;随后停掉 roster 消费线程并 join 它,确保
    /// `shutdown` 返回时线程已经真正退出(不是"发个信号就当作已停")。
    /// 三路都幂等(`Mutex<Option<_>>::take` 保证重复调用时第二次拿到
    /// `None`,直接跳过)。
    ///
    /// roster 线程最长在一个 `ROSTER_TICK`(5s)内响应停止信号并退出,
    /// 因此本方法最长阻塞 ~5s,而不会永久挂起。
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
#[allow(clippy::too_many_arguments)]
fn spawn_probe(
    transport: &Arc<TransportManager>,
    discovery_tx: &Sender<DiscoveryEvent>,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    history: &Arc<Mutex<HistoryStore>>,
    data_dir: &Path,
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
            // mDNS 不可用时的单播兜底探测使用)。
            let mut h = history.lock().expect("history lock");
            for ip in &addrs {
                h.record(*ip);
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
///   转发路径,UI 不需要区分协议来源。文件 offer 顺带把
///   `(peer_fp, packet_no, file_id, name, size)` 登记进 `offers`,供
///   `Core::respond_file` 决定接受时反查、发起 `request_file`;目录条目
///   (`is_dir`)跳过——M5 冻结范围只接单文件。
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
            for f in files.into_iter().filter(|f| !f.is_dir) {
                let xfer_id = crate::transport::proto::new_id();
                offers.lock().expect("ipmsg offers lock").insert(
                    xfer_id.clone(),
                    IpmsgOffer {
                        peer_fp: peer_fp.clone(),
                        packet_no,
                        file_id: f.file_id,
                        name: f.name.clone(),
                        size: f.size,
                    },
                );
                let _ = msg_tx.send(TransportEvent::FileOffered {
                    xfer_id,
                    peer_fp: peer_fp.clone(),
                    name: f.name,
                    size: f.size,
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
        assert!(
            start.elapsed() < ROSTER_TICK + Duration::from_secs(2),
            "shutdown 应在一个 ROSTER_TICK 内 join 到 roster 线程并返回,\
             实际耗时 {:?}(说明线程没被真正停止/join,或者 join 挂住了)",
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
            } => {
                assert_eq!(peer_fp, "ipmsg:192.168.1.9:HOST-B");
                assert_eq!(name, "report.pdf");
                assert_eq!(size, 2048);
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
    }

    #[test]
    fn forward_ipmsg_event_file_offered_skips_dir_entries() {
        // M5 冻结范围只接单文件:目录条目跳过,不生成 xfer_id、不登记。
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

        assert!(
            msg_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "目录条目应跳过,不上报 FileOffered"
        );
        assert!(offers.lock().unwrap().is_empty());
    }
}

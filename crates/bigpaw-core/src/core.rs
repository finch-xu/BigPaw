//! 核心编排:identity + discovery + roster 串联,对壳层(src-tauri)暴露
//! 同步启动接口与 watch 快照订阅。零 Tauri、零异步运行时依赖。

use crate::discovery::announce::{
    AnnounceError, AnnounceService, HistoryStore, DEFAULT_ANNOUNCE_PORT,
};
use crate::discovery::Discovery;
use crate::identity::{Identity, IdentityError};
use crate::roster::{DiscoveryEvent, Peer, PeerState, Roster};
use crate::transport::manager::{
    SentText, TransportError, TransportEvent, TransportManager, DEFAULT_PORT,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::watch;

/// 历史 IP 单播"唤醒"宣告的发送间隔:串行、低速,不触发 IDS 扫描告警
/// (设计文档 §11),远高于 brief 要求的 ≥50ms 下限。
const HISTORY_WAKE_INTERVAL: Duration = Duration::from_millis(100);

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
}

impl Core {
    pub fn start(cfg: CoreConfig) -> Result<Self, CoreError> {
        let identity = Arc::new(Identity::load_or_create(&cfg.data_dir)?);
        let nickname = cfg.nickname.unwrap_or_else(default_nickname);

        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        let transport = TransportManager::start(identity.clone(), DEFAULT_PORT, msg_tx)?;

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
        std::thread::spawn(move || {
            let transport = transport_for_thread;
            while let Ok(ev) = rx.recv() {
                // Seen 事件在被 apply 消费掉之前,先取出探测需要的字段。
                let probe_target = match &ev {
                    DiscoveryEvent::Seen {
                        fingerprint,
                        addrs,
                        port,
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
                            &transport, &tx, &in_flight, &history, &data_dir, fp, addrs, port,
                        );
                    }
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

    /// 从 roster 当前快照查一个对端的地址与端口(send_text/offer_file 共用)。
    fn peer_addr(&self, peer_fp: &str) -> Result<(Vec<std::net::IpAddr>, u16), CoreError> {
        let roster = self.roster_handle.lock().expect("roster lock");
        let peer = roster
            .snapshot()
            .into_iter()
            .find(|p| p.fingerprint == peer_fp)
            .ok_or(CoreError::UnknownPeer)?;
        Ok((peer.addrs, peer.port))
    }

    /// 给对端发文本。地址与端口取自 roster 当前快照。
    pub fn send_text(&self, peer_fp: &str, body: &str) -> Result<SentText, CoreError> {
        let (addrs, port) = self.peer_addr(peer_fp)?;
        Ok(self.transport.send_text(peer_fp, &addrs, port, body)?)
    }

    /// 给对端发起一次文件传输报价。地址与端口同 send_text,取自 roster 当前快照。
    /// 返回 xfer_id,后续的 FileOffered/FileProgress/FileDone/FileFailed
    /// 事件都带着它,供调用方关联。
    pub fn offer_file(&self, peer_fp: &str, path: &Path) -> Result<String, CoreError> {
        let (addrs, port) = self.peer_addr(peer_fp)?;
        let handle = self.transport.offer_file(peer_fp, &addrs, port, path)?;
        Ok(handle.xfer_id)
    }

    /// 接收方对一个待决的文件报价做出决定(接受/拒绝)。
    pub fn respond_file(
        &self,
        xfer_id: &str,
        accept: bool,
        download_dir: &Path,
    ) -> Result<(), CoreError> {
        Ok(self.transport.respond_file(xfer_id, accept, download_dir)?)
    }

    /// 取走事件接收端(只能取一次,由壳层的事件循环消费)。
    pub fn take_events(&self) -> Option<std::sync::mpsc::Receiver<TransportEvent>> {
        self.events_rx.lock().expect("events lock").take()
    }

    pub fn port(&self) -> u16 {
        self.transport.port()
    }

    /// 主动下线:注销 mDNS(发 goodbye)+ 停止 UDP 宣告收发,对端立刻收到
    /// Lost 而不是等 TTL 过期。两路都幂等(`Mutex<Option<_>>::take` 保证
    /// 重复调用时第二次拿到 `None`,直接跳过)。
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

fn default_nickname() -> String {
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    host.trim_end_matches(".local").to_string()
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
}

//! 双实例 UDP 宣告互发现。绑定临时端口避免与真实 24916 冲突/多测试并发干扰。

use bigpaw_core::discovery::announce::{AnnounceService, DEFAULT_ANNOUNCE_PORT};
use bigpaw_core::identity::Identity;
use bigpaw_core::net_ifaces::InterfaceRegistry;
use bigpaw_core::roster::DiscoveryEvent;
use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

fn wait_seen(rx: &Receiver<DiscoveryEvent>, want_fp: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(DiscoveryEvent::Seen { fingerprint, .. }) =
            rx.recv_timeout(Duration::from_secs(1))
        {
            if fingerprint == want_fp {
                return true;
            }
        }
    }
    false
}

#[test]
#[ignore = "需要支持组播/广播的网络接口"]
fn two_instances_announce_and_discover() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Identity::load_or_create(da.path()).unwrap();
    let idb = Identity::load_or_create(db.path()).unwrap();
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    // 用同一个非默认端口,两实例在同机通过组播互听
    let port = 24916;
    let _a = AnnounceService::start(
        &ida,
        "alice",
        None,
        24917,
        port,
        txa,
        InterfaceRegistry::new(vec![]).subscribe(),
    )
    .unwrap();
    let _b = AnnounceService::start(
        &idb,
        "bob",
        None,
        24918,
        port,
        txb,
        InterfaceRegistry::new(vec![]).subscribe(),
    )
    .unwrap();
    assert!(wait_seen(&rxa, &idb.fingerprint, 15), "A 应发现 B");
    assert!(wait_seen(&rxb, &ida.fingerprint, 15), "B 应发现 A");
}

#[test]
#[ignore = "需要真实网络接口,且会短暂占用默认宣告端口 24916"]
fn poke_wakes_peer_via_unicast_announcement() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Identity::load_or_create(da.path()).unwrap();
    let idb = Identity::load_or_create(db.path()).unwrap();
    let (txa, _rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    // 历史唤醒场景里 poke 的目标端口固定是 DEFAULT_ANNOUNCE_PORT,所以两端都绑真实端口。
    let a = AnnounceService::start(
        &ida,
        "alice",
        None,
        24917,
        DEFAULT_ANNOUNCE_PORT,
        txa,
        InterfaceRegistry::new(vec![]).subscribe(),
    )
    .unwrap();
    let _b = AnnounceService::start(
        &idb,
        "bob",
        None,
        24918,
        DEFAULT_ANNOUNCE_PORT,
        txb,
        InterfaceRegistry::new(vec![]).subscribe(),
    )
    .unwrap();
    // 消耗掉双方启动时的快速组播/广播宣告可能带来的 Seen,避免和下面的断言混淆。
    let _ = wait_seen(&rxb, &ida.fingerprint, 3);
    a.poke(Ipv4Addr::LOCALHOST.into());
    assert!(
        wait_seen(&rxb, &ida.fingerprint, 5),
        "b 应通过单播 poke 收到 a 的宣告"
    );
}

/// 网络范围限定(严格隐身):A 的允许范围不含本机任何地址 → A 不向本机子网
/// 广播/组播(计划为 Silent/Unicast 到范围内主机),也不回应 B 的宣告;B 因此
/// 在整个观察窗口内看不到 A。B 不限制,仍照常宣告——但 A 的接收侧按范围
/// 过滤,同样看不到 B。
#[test]
#[ignore = "需要支持组播/广播的网络接口"]
fn scoped_instance_is_invisible_to_out_of_scope_peer() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Identity::load_or_create(da.path()).unwrap();
    let idb = Identity::load_or_create(db.path()).unwrap();
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let port = 24916;
    // TEST-NET-3:不落在任何本机子网,也不是本机地址
    let scope = std::sync::Arc::new(
        bigpaw_core::net_scope::NetScope::parse(&["203.0.113.7".to_string()]).unwrap(),
    );
    let _a = AnnounceService::start(
        &ida,
        "alice",
        None,
        24917,
        port,
        txa,
        InterfaceRegistry::new_with_scope(vec![], scope).subscribe(),
    )
    .unwrap();
    let _b = AnnounceService::start(
        &idb,
        "bob",
        None,
        24918,
        port,
        txb,
        InterfaceRegistry::new(vec![]).subscribe(),
    )
    .unwrap();
    assert!(!wait_seen(&rxb, &ida.fingerprint, 12), "B 不该看到限定范围外的 A");
    assert!(!wait_seen(&rxa, &idb.fingerprint, 3), "A 的接收侧应过滤掉范围外的 B");
}

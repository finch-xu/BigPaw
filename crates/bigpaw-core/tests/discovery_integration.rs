//! 双实例互发现集成测试。依赖本机有支持组播的网络接口,默认 ignored。
//! 本地运行: cargo test -p bigpaw-core --test discovery_integration -- --ignored

use bigpaw_core::discovery::Discovery;
use bigpaw_core::identity::Identity;
use bigpaw_core::roster::DiscoveryEvent;
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

fn wait_lost(rx: &Receiver<DiscoveryEvent>, want_fp: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(DiscoveryEvent::Lost { fingerprint }) = rx.recv_timeout(Duration::from_secs(1)) {
            if fingerprint == want_fp {
                return true;
            }
        }
    }
    false
}

#[test]
#[ignore = "需要支持组播的真实网络接口"]
fn two_instances_discover_and_lose_each_other() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let id_a = Identity::load_or_create(dir_a.path()).unwrap();
    let id_b = Identity::load_or_create(dir_b.path()).unwrap();
    let (tx_a, rx_a) = std::sync::mpsc::channel();
    let (tx_b, rx_b) = std::sync::mpsc::channel();

    let _disc_a = Discovery::start(&id_a, "alice", 0, tx_a).unwrap();
    let disc_b = Discovery::start(&id_b, "bob", 0, tx_b).unwrap();

    assert!(
        wait_seen(&rx_a, &id_b.fingerprint, 15),
        "A 应在 15s 内发现 B"
    );
    assert!(
        wait_seen(&rx_b, &id_a.fingerprint, 15),
        "B 应在 15s 内发现 A"
    );

    disc_b.shutdown();
    assert!(
        wait_lost(&rx_a, &id_b.fingerprint, 15),
        "B 注销后 A 应收到 Lost"
    );
}

/// `apply_exclusions` 的 daemon 交互(disable_interface/unregister+re-register)
/// 单测无法覆盖——需要真实网络守护验证 re_register 不破坏已建立的发现关系。
/// 排除一个不存在的网卡名:`disable_interface` 对它是 no-op,但清单从空变
/// 非空仍应触发 re_register(见 mdns.rs `apply_exclusions` 文档),验证这一步
/// 不会让已经互相发现的两端失联。
#[test]
#[ignore = "需要支持组播的真实网络接口"]
fn apply_exclusions_re_register_keeps_peers_discoverable() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let id_a = Identity::load_or_create(dir_a.path()).unwrap();
    let id_b = Identity::load_or_create(dir_b.path()).unwrap();
    let (tx_a, rx_a) = std::sync::mpsc::channel();
    let (tx_b, rx_b) = std::sync::mpsc::channel();

    let mut disc_a = Discovery::start(&id_a, "alice", 0, tx_a).unwrap();
    let _disc_b = Discovery::start(&id_b, "bob", 0, tx_b).unwrap();

    assert!(wait_seen(&rx_b, &id_a.fingerprint, 15), "B 应先发现 A");

    disc_a
        .apply_exclusions(&["definitely-not-a-real-iface".to_string()], &[])
        .unwrap();

    assert!(
        wait_seen(&rx_b, &id_a.fingerprint, 15),
        "re_register 后 B 应仍能(重新)发现 A"
    );

    let _ = rx_a;
}

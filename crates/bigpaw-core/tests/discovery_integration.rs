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

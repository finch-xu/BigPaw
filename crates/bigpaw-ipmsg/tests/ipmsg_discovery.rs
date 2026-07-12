//! 双 IpmsgService 互发现。#[ignore](需广播网络);端口 2425 固定。

use bigpaw_ipmsg::discovery::{IpmsgEvent, IpmsgService};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

fn wait_online(rx: &Receiver<IpmsgEvent>, want_host: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(IpmsgEvent::Online { host, .. }) = rx.recv_timeout(Duration::from_secs(1)) {
            if host == want_host {
                return true;
            }
        }
    }
    false
}

#[test]
#[ignore = "需要广播网络且 2425 空闲"]
fn two_ipmsg_instances_discover() {
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let a = IpmsgService::start("alice", "HOST-A", 2425, txa).unwrap();
    // 同机两实例共用 2425 需 SO_REUSEPORT/REUSEADDR;若不行本测试跳过
    let b = IpmsgService::start("bob", "HOST-B", 2425, txb);
    if b.is_err() {
        eprintln!("2425 单机双绑不支持,跳过(真实场景是两台机器)");
        return;
    }
    let _b = b.unwrap();
    assert!(wait_online(&rxa, "HOST-B", 10) || wait_online(&rxb, "HOST-A", 10));
    let _ = a;
}

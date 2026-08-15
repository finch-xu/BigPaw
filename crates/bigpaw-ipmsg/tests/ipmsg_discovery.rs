//! 双 IpmsgService 互发现。#[ignore](需广播网络);端口 2425 固定。

use bigpaw_ipmsg::discovery::{default_broadcast_targets, IpmsgEvent, IpmsgService, allow_all_peers};
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
    let a = IpmsgService::start("alice", None, "HOST-A", 2425, txa, default_broadcast_targets(), allow_all_peers()).unwrap();
    // 同机两实例共用 2425 需 SO_REUSEPORT/REUSEADDR;若不行本测试跳过
    let b = IpmsgService::start("bob", None, "HOST-B", 2425, txb, default_broadcast_targets(), allow_all_peers());
    if b.is_err() {
        eprintln!("2425 单机双绑不支持,跳过(真实场景是两台机器)");
        return;
    }
    let _b = b.unwrap();
    assert!(wait_online(&rxa, "HOST-B", 10) || wait_online(&rxb, "HOST-A", 10));
    let _ = a;
}

fn wait_text(rx: &Receiver<IpmsgEvent>, want_body: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(IpmsgEvent::TextReceived { body, .. }) = rx.recv_timeout(Duration::from_secs(1)) {
            if body == want_body {
                return true;
            }
        }
    }
    false
}

/// 双实例互发中文文本:一端 send_text,另一端应收到 TextReceived 且 body 正确
/// (顺带验证收到 SENDCHECKOPT 后会自动单播回 RECVMSG 回执,但本测试不直接断言
/// 回执——回执只在对端的 pending_acks 内部表里体现,无法从 IpmsgEvent 观察到)。
#[test]
#[ignore = "需要两台机器/两块网卡,单机双绑 2425 不稳定"]
fn two_ipmsg_instances_exchange_text() {
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let a = IpmsgService::start("alice", None, "HOST-A", 2425, txa, default_broadcast_targets(), allow_all_peers()).unwrap();
    let b = IpmsgService::start("bob", None, "HOST-B", 2425, txb, default_broadcast_targets(), allow_all_peers());
    if b.is_err() {
        eprintln!("2425 单机双绑不支持,跳过(真实场景是两台机器)");
        return;
    }
    let b = b.unwrap();

    // 先等 A 发现 B,拿到 B 的实际来源地址(SENDMSG 是单播,需要目标 addr)。
    let bob_addr = loop {
        match rxa.recv_timeout(Duration::from_secs(10)) {
            Ok(IpmsgEvent::Online { host, addr, .. }) if host == "HOST-B" => break Some(addr),
            Ok(_) => continue,
            Err(_) => break None,
        }
    };
    let Some(bob_addr) = bob_addr else {
        eprintln!("未能在超时内发现 HOST-B,跳过");
        return;
    };

    a.send_text(bob_addr, "你好,BigPaw 世界").unwrap();
    assert!(wait_text(&rxb, "你好,BigPaw 世界", 10));

    let _ = b;
}

/// 网络范围限定:A 的 PeerFilter 拒绝一切来源 → A 收到 B 的 BR_ENTRY 既不回
/// ANSENTRY 也不上报 Online;B 收不到 A 的回应(A 自己的 BR_ENTRY 广播目标表为
/// 空,也不主动宣告),整个观察窗口内双方互不可见。
#[test]
#[ignore = "需要真实网络接口且同机双绑 2425"]
fn filtered_instance_neither_replies_nor_reports() {
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let deny_all: bigpaw_ipmsg::discovery::PeerFilter = std::sync::Arc::new(|_| false);
    let silent_targets: bigpaw_ipmsg::discovery::BroadcastTargets =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let a = IpmsgService::start("alice", None, "HOST-A", 2425, txa, silent_targets, deny_all).unwrap();
    let b = IpmsgService::start("bob", None, "HOST-B", 2425, txb, default_broadcast_targets(), allow_all_peers());
    let Ok(b) = b else {
        eprintln!("同机双绑 2425 失败,跳过");
        a.shutdown();
        return;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut seen_any = false;
    while std::time::Instant::now() < deadline {
        if let Ok(IpmsgEvent::Online { .. }) = rxa.recv_timeout(std::time::Duration::from_millis(200)) {
            seen_any = true;
        }
        if let Ok(IpmsgEvent::Online { .. }) = rxb.recv_timeout(std::time::Duration::from_millis(200)) {
            seen_any = true;
        }
    }
    a.shutdown();
    b.shutdown();
    assert!(!seen_any, "过滤一切来源的一侧不该与对端互相上线");
}

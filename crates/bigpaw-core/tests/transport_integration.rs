//! 双 manager 环回:双向文本 + 断线重连。纯 localhost,无 mDNS,默认运行。

use bigpaw_core::identity::Identity;
use bigpaw_core::transport::manager::{MessageEvent, TransportEvent, TransportManager};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

const LOCAL: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::LOCALHOST)];

// M3:events channel 从只发 MessageEvent 改为发 TransportEvent(见 manager.rs)。
// 这两个既有测试只关心文本消息,所以只需在这里解一层 TransportEvent::Message。
fn recv_text(rx: &Receiver<TransportEvent>, secs: u64) -> MessageEvent {
    match rx
        .recv_timeout(Duration::from_secs(secs))
        .expect("应收到消息")
    {
        TransportEvent::Message(m) => m,
        other => panic!("期望 Message 事件,却收到 {other:?}"),
    }
}

#[test]
fn bidirectional_text_and_reconnect() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Arc::new(Identity::load_or_create(da.path()).unwrap());
    let idb = Arc::new(Identity::load_or_create(db.path()).unwrap());
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();

    let ma = TransportManager::start(ida.clone(), 0, txa).unwrap();
    let mb = TransportManager::start(idb.clone(), 0, txb).unwrap();

    // A → B
    let sent = ma
        .send_text(&idb.fingerprint, &LOCAL, mb.port(), "你好 B")
        .unwrap();
    let got = recv_text(&rxb, 10);
    assert_eq!(got.body, "你好 B");
    assert_eq!(got.peer_fp, ida.fingerprint);
    assert_eq!(got.id, sent.id);

    // B → A(独立拨号,证明双向)
    mb.send_text(&ida.fingerprint, &LOCAL, ma.port(), "你好 A")
        .unwrap();
    assert_eq!(recv_text(&rxa, 10).body, "你好 A");

    // 断线重连:B 整个重启(旧连接全断,端口换新)
    let bport_old = mb.port();
    drop(mb);
    std::thread::sleep(Duration::from_millis(200));
    let (txb2, rxb2) = std::sync::mpsc::channel();
    let mb2 = TransportManager::start(idb.clone(), 0, txb2).unwrap();
    assert_ne!(mb2.port(), 0);
    let _ = bport_old;

    // A 向新端口发送:必须成功(缓存的旧连接失效→重拨新地址)
    ma.send_text(&idb.fingerprint, &LOCAL, mb2.port(), "重连后")
        .unwrap();
    assert_eq!(recv_text(&rxb2, 10).body, "重连后");
}

#[test]
fn send_to_dead_port_errors() {
    let d = tempfile::tempdir().unwrap();
    let id = Arc::new(Identity::load_or_create(d.path()).unwrap());
    let (tx, _rx) = std::sync::mpsc::channel();
    let m = TransportManager::start(id, 0, tx).unwrap();
    let err = m.send_text(&"0".repeat(64), &LOCAL, 1, "x"); // 端口 1 无人监听
    assert!(err.is_err());
}

// M4:双向注册回连探测——probe_reachable 只做"拨号+握手+写 Hello",不应
// 在对端产生消息事件,也不该污染发送方的 outbound 缓存/后续 send_text。
#[test]
fn probe_reachable_succeeds_without_polluting_message_path() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Arc::new(Identity::load_or_create(da.path()).unwrap());
    let idb = Arc::new(Identity::load_or_create(db.path()).unwrap());
    let (txa, _rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();

    let ma = TransportManager::start(ida.clone(), 0, txa).unwrap();
    let mb = TransportManager::start(idb.clone(), 0, txb).unwrap();

    assert!(ma.probe_reachable(&idb.fingerprint, &LOCAL, mb.port()));
    // 探测连接只写 Hello,不应让 B 产生任何 TransportEvent(尤其不是消息事件)。
    assert!(rxb.recv_timeout(Duration::from_millis(500)).is_err());

    // 探测不应污染 outbound 缓存:后续真实发消息仍必须正常工作(独立重拨)。
    ma.send_text(&idb.fingerprint, &LOCAL, mb.port(), "探测之后")
        .unwrap();
    assert_eq!(recv_text(&rxb, 10).body, "探测之后");
}

#[test]
fn probe_reachable_fails_for_dead_port() {
    let d = tempfile::tempdir().unwrap();
    let id = Arc::new(Identity::load_or_create(d.path()).unwrap());
    let (tx, _rx) = std::sync::mpsc::channel();
    let m = TransportManager::start(id, 0, tx).unwrap();
    assert!(!m.probe_reachable(&"0".repeat(64), &LOCAL, 1)); // 端口 1 无人监听
}

//! 双 manager 环回:双向文本 + 断线重连。纯 localhost,无 mDNS,默认运行。

use bigpaw_core::identity::Identity;
use bigpaw_core::transport::manager::{MessageEvent, TransportManager};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

const LOCAL: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::LOCALHOST)];

fn recv_text(rx: &Receiver<MessageEvent>, secs: u64) -> MessageEvent {
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("应收到消息")
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

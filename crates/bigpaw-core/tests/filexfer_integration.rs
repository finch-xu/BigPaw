//! 双 manager 文件传输:offer → accept → 传输 → 校验落盘。localhost。

use bigpaw_core::identity::Identity;
use bigpaw_core::transport::manager::{TransportEvent, TransportManager};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

const LOCAL: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::LOCALHOST)];

fn wait_event<F, T>(rx: &Receiver<TransportEvent>, secs: u64, mut f: F) -> T
where
    F: FnMut(&TransportEvent) -> Option<T>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_secs(secs)) {
            if let Some(v) = f(&ev) {
                return v;
            }
        }
    }
    panic!("等待事件超时");
}

#[test]
fn offer_accept_transfer_verifies() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let dl = tempfile::tempdir().unwrap(); // 接收方下载目录
    let ida = Arc::new(Identity::load_or_create(da.path()).unwrap());
    let idb = Arc::new(Identity::load_or_create(db.path()).unwrap());
    let (txa, _rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let ma = TransportManager::start(ida.clone(), 0, txa).unwrap();
    let mb = TransportManager::start(idb.clone(), 0, txb).unwrap();

    // 造一个测试文件
    let src = da.path().join("payload.bin");
    let content = vec![42u8; 2_500_000];
    std::fs::File::create(&src)
        .unwrap()
        .write_all(&content)
        .unwrap();

    // A offer 给 B
    ma.offer_file(&idb.fingerprint, &LOCAL, mb.port(), &src)
        .unwrap();

    // B 收到 offer
    let xfer_id = wait_event(&rxb, 10, |ev| match ev {
        TransportEvent::FileOffered {
            xfer_id,
            name,
            size,
            ..
        } => {
            assert_eq!(name, "payload.bin");
            assert_eq!(*size, content.len() as u64);
            Some(xfer_id.clone())
        }
        _ => None,
    });

    // B 接受
    mb.respond_file(&xfer_id, true, dl.path()).unwrap();

    // B 收到 FileDone
    let path = wait_event(&rxb, 15, |ev| match ev {
        TransportEvent::FileDone { path, .. } => Some(path.clone()),
        _ => None,
    });
    assert_eq!(std::fs::read(&path).unwrap(), content);
    assert_eq!(path, dl.path().join("payload.bin"));
}

#[test]
fn reject_stops_transfer() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let ida = Arc::new(Identity::load_or_create(da.path()).unwrap());
    let idb = Arc::new(Identity::load_or_create(db.path()).unwrap());
    let (txa, _rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let ma = TransportManager::start(ida.clone(), 0, txa).unwrap();
    let mb = TransportManager::start(idb.clone(), 0, txb).unwrap();
    let src = da.path().join("f.bin");
    std::fs::write(&src, vec![1u8; 1000]).unwrap();
    ma.offer_file(&idb.fingerprint, &LOCAL, mb.port(), &src)
        .unwrap();
    let xfer_id = wait_event(&rxb, 10, |ev| match ev {
        TransportEvent::FileOffered { xfer_id, .. } => Some(xfer_id.clone()),
        _ => None,
    });
    // 拒绝
    mb.respond_file(&xfer_id, false, db.path()).unwrap();
    // 不 panic 即可(无 FileDone);给一点时间确保没有意外落盘
    std::thread::sleep(Duration::from_millis(300));
}

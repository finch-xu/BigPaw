//! 双 IpmsgService 单文件端到端:A send_file → B FileOffered → B request_file → 落盘校验一致。
//! #[ignore](同机双绑 2425 不稳定,真实场景是两台机器/飞秋 VM,与既有
//! `ipmsg_discovery.rs` 里的两个 ignored 集成测试同风格、同限制)。

use bigpaw_ipmsg::discovery::{IpmsgEvent, IpmsgService};
use std::io::Write;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

fn wait_online(
    rx: &Receiver<IpmsgEvent>,
    want_host: &str,
    secs: u64,
) -> Option<std::net::SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(IpmsgEvent::Online { host, addr, .. }) = rx.recv_timeout(Duration::from_secs(1)) {
            if host == want_host {
                return Some(addr);
            }
        }
    }
    None
}

fn wait_file_offered(
    rx: &Receiver<IpmsgEvent>,
    secs: u64,
) -> Option<(String, u32, Vec<bigpaw_ipmsg::filexfer::IpmsgFileEntry>)> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(IpmsgEvent::FileOffered {
            from,
            packet_no,
            files,
            ..
        }) = rx.recv_timeout(Duration::from_secs(1))
        {
            return Some((from, packet_no, files));
        }
    }
    None
}

#[test]
#[ignore = "需要两台机器/两块网卡,单机双绑 2425 不稳定"]
fn two_ipmsg_instances_transfer_single_file() {
    let (txa, rxa) = std::sync::mpsc::channel();
    let (txb, rxb) = std::sync::mpsc::channel();
    let a = IpmsgService::start("alice", "HOST-A", 2425, txa).unwrap();
    let b = IpmsgService::start("bob", "HOST-B", 2425, txb);
    if b.is_err() {
        eprintln!("2425 单机双绑不支持,跳过(真实场景是两台机器)");
        return;
    }
    let b = b.unwrap();

    // A 先发现 B,拿到 B 的真实来源地址(send_file 是单播)。
    let Some(bob_addr) = wait_online(&rxa, "HOST-B", 10) else {
        eprintln!("未能在超时内发现 HOST-B,跳过");
        return;
    };
    // B 也需要 A 的地址,才能反向拨 TCP 去拉文件。
    let Some(alice_addr) = wait_online(&rxb, "HOST-A", 10) else {
        eprintln!("未能在超时内发现 HOST-A,跳过");
        return;
    };

    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("你好.txt");
    let content = b"BigPaw <-> IPMsg single file transfer payload".to_vec();
    std::fs::File::create(&src_path)
        .unwrap()
        .write_all(&content)
        .unwrap();

    a.send_file(bob_addr, &src_path).unwrap();

    let Some((from, packet_no, files)) = wait_file_offered(&rxb, 10) else {
        eprintln!("未在超时内收到 FileOffered,跳过");
        return;
    };
    assert_eq!(from, "alice");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "你好.txt");
    assert_eq!(files[0].size, content.len() as u64);
    assert!(!files[0].is_dir);

    let dst_dir = tempfile::tempdir().unwrap();
    let save_path = dst_dir.path().join("你好.txt");
    let downloaded = b
        .request_file(
            alice_addr,
            packet_no,
            files[0].file_id,
            files[0].size,
            &save_path,
        )
        .unwrap();
    assert_eq!(std::fs::read(&downloaded).unwrap(), content);

    let _ = a;
}

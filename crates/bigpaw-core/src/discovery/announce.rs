//! UDP 宣告报文编解码 + 历史设备 IP 持久化。报文严格 ≤ 1 个 MTU(防 IP 分片)。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

const MAX_DATAGRAM: usize = 1400;
const MAX_NICK_BYTES: usize = 64;
const MAX_HISTORY: usize = 50;
const HISTORY_FILE: &str = "history_ips.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub v: u16,
    pub fp: String,
    pub nick: String,
    pub tport: u16,
    pub caps: String,
}

/// 昵称按 UTF-8 字节边界截断到 <= MAX_NICK_BYTES。
fn truncate_nick(nick: &str) -> String {
    if nick.len() <= MAX_NICK_BYTES {
        return nick.to_string();
    }
    let mut end = MAX_NICK_BYTES;
    while end > 0 && !nick.is_char_boundary(end) {
        end -= 1;
    }
    nick[..end].to_string()
}

pub fn encode(a: &Announcement) -> Vec<u8> {
    let safe = Announcement {
        nick: truncate_nick(&a.nick),
        ..a.clone()
    };
    let buf = serde_json::to_vec(&safe).unwrap_or_default();
    debug_assert!(buf.len() <= MAX_DATAGRAM);
    buf
}

pub fn decode(buf: &[u8]) -> Option<Announcement> {
    let a: Announcement = serde_json::from_slice(buf).ok()?;
    if a.fp.len() == 64 && a.v == 1 {
        Some(a)
    } else {
        None
    }
}

/// 历史设备 IP:去重、上限 50、LRU(最近记录的排前)、JSON 持久化。
pub struct HistoryStore {
    ips: VecDeque<IpAddr>,
}

impl HistoryStore {
    pub fn load(data_dir: &Path) -> Self {
        let ips = fs::read(data_dir.join(HISTORY_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<IpAddr>>(&b).ok())
            .unwrap_or_default();
        Self {
            ips: ips.into_iter().collect(),
        }
    }

    pub fn record(&mut self, ip: IpAddr) {
        self.ips.retain(|x| *x != ip);
        self.ips.push_front(ip);
        while self.ips.len() > MAX_HISTORY {
            self.ips.pop_back();
        }
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        self.ips.iter().copied().collect()
    }

    pub fn save(&self, data_dir: &Path) {
        if let Ok(b) = serde_json::to_vec(&self.ips()) {
            let _ = fs::write(data_dir.join(HISTORY_FILE), b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ann() -> Announcement {
        Announcement {
            v: 1,
            fp: "a".repeat(64),
            nick: "alice".to_string(),
            tport: 24917,
            caps: "native".to_string(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let a = ann();
        let buf = encode(&a);
        assert!(buf.len() <= 1400);
        assert_eq!(decode(&buf), Some(a));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(decode(b"not json"), None);
        assert_eq!(decode(b"{}"), None); // 缺字段
        assert_eq!(decode(&[0xff, 0xfe]), None);
    }

    #[test]
    fn long_nick_is_truncated_to_fit_mtu() {
        let mut a = ann();
        a.nick = "长".repeat(500); // 远超 64 字节
        let buf = encode(&a);
        assert!(buf.len() <= 1400);
        let back = decode(&buf).unwrap();
        assert!(back.nick.len() <= 64);
    }

    #[test]
    fn history_dedup_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::load(dir.path());
        for i in 0..60u8 {
            h.record(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)));
        }
        h.record(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))); // 重复
        assert!(h.ips().len() <= 50, "上限 50");
        h.save(dir.path());
        let h2 = HistoryStore::load(dir.path());
        assert_eq!(h2.ips().len(), h.ips().len(), "重载一致");
    }
}

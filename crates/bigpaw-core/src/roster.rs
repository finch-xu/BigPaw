//! 统一用户列表状态机(设计文档 §7):按 fingerprint 去重、防自发现。
//! M1 仅 Discovered/Offline 两态;Reachable/Unreachable 随 M4 双向注册引入。

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Native,
    Ipmsg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Discovered,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Peer {
    pub fingerprint: String,
    pub nickname: String,
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PeerState,
}

/// 发现层喂给 roster 的事件。
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Seen {
        fingerprint: String,
        nickname: String,
        addrs: Vec<IpAddr>,
        port: u16,
    },
    Lost {
        fingerprint: String,
    },
}

pub struct Roster {
    self_fingerprint: String,
    peers: HashMap<String, Peer>,
}

impl Roster {
    pub fn new(self_fingerprint: String) -> Self {
        Self {
            self_fingerprint,
            peers: HashMap::new(),
        }
    }

    /// 应用事件;返回 true 表示列表有实际变化(调用方据此决定是否推送快照)。
    pub fn apply(&mut self, ev: DiscoveryEvent) -> bool {
        match ev {
            DiscoveryEvent::Seen {
                fingerprint,
                nickname,
                mut addrs,
                port,
            } => {
                if fingerprint == self.self_fingerprint {
                    return false;
                }
                addrs.sort();
                let peer = Peer {
                    fingerprint: fingerprint.clone(),
                    nickname,
                    addrs,
                    port,
                    protocol: Protocol::Native,
                    state: PeerState::Discovered,
                };
                match self.peers.get(&fingerprint) {
                    Some(existing) if *existing == peer => false,
                    _ => {
                        self.peers.insert(fingerprint, peer);
                        true
                    }
                }
            }
            DiscoveryEvent::Lost { fingerprint } => match self.peers.get_mut(&fingerprint) {
                Some(p) if p.state != PeerState::Offline => {
                    p.state = PeerState::Offline;
                    true
                }
                _ => false,
            },
        }
    }

    pub fn snapshot(&self) -> Vec<Peer> {
        let mut v: Vec<Peer> = self.peers.values().cloned().collect();
        v.sort_by(|a, b| {
            a.nickname
                .cmp(&b.nickname)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const SELF_FP: &str = "aaaa";
    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }
    fn seen(fp: &str, nick: &str) -> DiscoveryEvent {
        DiscoveryEvent::Seen {
            fingerprint: fp.to_string(),
            nickname: nick.to_string(),
            addrs: vec![ip(5)],
            port: 0,
        }
    }

    #[test]
    fn seen_adds_peer_and_reports_change() {
        let mut r = Roster::new(SELF_FP.to_string());
        assert!(r.apply(seen("bbbb", "bob")));
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].nickname, "bob");
        assert_eq!(snap[0].state, PeerState::Discovered);
    }

    #[test]
    fn own_fingerprint_is_filtered() {
        let mut r = Roster::new(SELF_FP.to_string());
        assert!(!r.apply(seen(SELF_FP, "me")));
        assert!(r.snapshot().is_empty());
    }

    #[test]
    fn duplicate_seen_reports_no_change() {
        let mut r = Roster::new(SELF_FP.to_string());
        assert!(r.apply(seen("bbbb", "bob")));
        assert!(!r.apply(seen("bbbb", "bob")), "内容相同的重复宣告不算变化");
        assert!(r.apply(seen("bbbb", "bob-renamed")), "昵称变了算变化");
    }

    #[test]
    fn lost_marks_offline_and_keeps_record() {
        let mut r = Roster::new(SELF_FP.to_string());
        r.apply(seen("bbbb", "bob"));
        assert!(r.apply(DiscoveryEvent::Lost {
            fingerprint: "bbbb".to_string()
        }));
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1, "离线保留记录(M4 单播探测需要)");
        assert_eq!(snap[0].state, PeerState::Offline);
        assert!(
            !r.apply(DiscoveryEvent::Lost {
                fingerprint: "bbbb".to_string()
            }),
            "重复 Lost 不算变化"
        );
        assert!(
            !r.apply(DiscoveryEvent::Lost {
                fingerprint: "cccc".to_string()
            }),
            "未知 fingerprint 的 Lost 忽略"
        );
    }

    #[test]
    fn snapshot_sorted_by_nickname_then_fingerprint() {
        let mut r = Roster::new(SELF_FP.to_string());
        r.apply(seen("cccc", "zoe"));
        r.apply(seen("bbbb", "amy"));
        let snap = r.snapshot();
        assert_eq!(snap[0].nickname, "amy");
        assert_eq!(snap[1].nickname, "zoe");
    }

    #[test]
    fn peer_serializes_with_lowercase_enums() {
        let mut r = Roster::new(SELF_FP.to_string());
        r.apply(seen("bbbb", "bob"));
        let json = serde_json::to_string(&r.snapshot()).unwrap();
        assert!(json.contains("\"native\""), "{json}");
        assert!(json.contains("\"discovered\""), "{json}");
        assert!(json.contains("192.168.1.5"), "{json}");
    }
}

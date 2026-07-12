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

/// 状态优先级(高→低):`Reachable` > `Discovered` > `Unreachable` > `Offline`。
/// - `Reachable`:回连探测(TCP+TLS 握手)成功过,视为双向可达。
/// - `Discovered`:仅收到过发现层宣告(mDNS/UDP),尚未/无需回连验证。
/// - `Unreachable`:收到过宣告,但回连探测失败(比如对端在防火墙后单向广播)。
/// - `Offline`:发现层判定对方已离线(mDNS TTL 过期/goodbye)。
///
/// 这个优先级只体现在"谁能盖过谁"的转移规则里(见 `Roster::apply`),不是
/// 一个可比较的 `Ord`:比如 `Unreachable` 不会被 `Offline` 覆盖(`Lost` 只针对
/// 仍在线的记录打标),`Reachable` 不会被重复的 `Seen` 或单次探测失败打回去。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Discovered,
    Offline,
    Reachable,
    Unreachable,
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
        /// 发现来源:mDNS/UDP 宣告(原生栈)恒为 `Native`;IPMsg 兼容层(M5)
        /// 喂入的 Seen 恒为 `Ipmsg`,让 roster 记录下这个对端走哪条协议栈。
        protocol: Protocol,
    },
    Lost {
        fingerprint: String,
    },
    /// 回连探测(见 `TransportManager::probe_reachable`)成功。
    Registered {
        fingerprint: String,
    },
    /// 回连探测失败。
    Unreachable {
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
                protocol,
            } => {
                if fingerprint == self.self_fingerprint {
                    return false;
                }
                addrs.sort();
                // 状态优先级:Reachable/Unreachable 是回连探测的结论,不该被一条
                // 单纯的重复宣告(Seen)打回 Discovered——否则 UI 会在"已验证可达"
                // 和"刚发现"之间抖动。只有 Offline(此前判定离线)在重新收到宣告
                // 时才应该回到 Discovered:这代表对方重新上线了,旧的可达性结论
                // 已经过时,需要新一轮探测重新验证。
                let state = match self.peers.get(&fingerprint) {
                    Some(existing) => match existing.state {
                        PeerState::Offline => PeerState::Discovered,
                        kept => kept,
                    },
                    None => PeerState::Discovered,
                };
                let peer = Peer {
                    fingerprint: fingerprint.clone(),
                    nickname,
                    addrs,
                    port,
                    protocol,
                    state,
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
            DiscoveryEvent::Registered { fingerprint } => {
                match self.peers.get_mut(&fingerprint) {
                    Some(p) if p.state != PeerState::Reachable => {
                        p.state = PeerState::Reachable;
                        true
                    }
                    _ => false, // 未知 fp 或已是 Reachable:忽略
                }
            }
            DiscoveryEvent::Unreachable { fingerprint } => {
                match self.peers.get_mut(&fingerprint) {
                    // 单次探测失败不打断已确认可达的连接;Discovered/Offline 才
                    // 会被标记为 Unreachable(已是 Unreachable 则无变化)。
                    Some(p)
                        if p.state != PeerState::Reachable && p.state != PeerState::Unreachable =>
                    {
                        p.state = PeerState::Unreachable;
                        true
                    }
                    _ => false,
                }
            }
        }
    }

    /// 启动预热(M6):把持久化的已知 peer 以 Offline 态注入,让 UI 一打开
    /// 就能看到历史联系人并查其聊天记录。不覆盖已存在的记录(发现层可能
    /// 已抢先注册),不注入自己。port=0/addrs 可能为空:离线记录本来就
    /// 不可直连,重新被发现时 Seen 会带来新地址并整体覆盖。
    pub fn seed_offline(&mut self, peers: Vec<Peer>) {
        for mut p in peers {
            if p.fingerprint == self.self_fingerprint {
                continue;
            }
            p.state = PeerState::Offline;
            self.peers.entry(p.fingerprint.clone()).or_insert(p);
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
            protocol: Protocol::Native,
        }
    }

    fn seen_ipmsg(fp: &str, nick: &str) -> DiscoveryEvent {
        DiscoveryEvent::Seen {
            fingerprint: fp.to_string(),
            nickname: nick.to_string(),
            addrs: vec![ip(9)],
            port: 2425,
            protocol: Protocol::Ipmsg,
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

    #[test]
    fn reachable_and_unreachable_serialize_lowercase() {
        assert_eq!(
            serde_json::to_string(&PeerState::Reachable).unwrap(),
            "\"reachable\""
        );
        assert_eq!(
            serde_json::to_string(&PeerState::Unreachable).unwrap(),
            "\"unreachable\""
        );
    }

    #[test]
    fn reachable_upgrades_from_discovered() {
        let mut r = Roster::new("aaaa".to_string());
        r.apply(seen("bbbb", "bob"));
        assert_eq!(r.snapshot()[0].state, PeerState::Discovered);
        assert!(r.apply(DiscoveryEvent::Registered {
            fingerprint: "bbbb".to_string()
        }));
        assert_eq!(r.snapshot()[0].state, PeerState::Reachable);
    }

    #[test]
    fn unreachable_marks_but_keeps_peer() {
        let mut r = Roster::new("aaaa".to_string());
        r.apply(seen("bbbb", "bob"));
        assert!(r.apply(DiscoveryEvent::Unreachable {
            fingerprint: "bbbb".to_string()
        }));
        assert_eq!(r.snapshot()[0].state, PeerState::Unreachable);
    }

    #[test]
    fn seen_does_not_downgrade_reachable() {
        let mut r = Roster::new("aaaa".to_string());
        r.apply(seen("bbbb", "bob"));
        r.apply(DiscoveryEvent::Registered {
            fingerprint: "bbbb".to_string(),
        });
        // 再次收到宣告(Seen)不应把 Reachable 打回 Discovered
        r.apply(seen("bbbb", "bob"));
        assert_eq!(r.snapshot()[0].state, PeerState::Reachable);
    }

    #[test]
    fn registered_for_unknown_peer_is_ignored() {
        let mut r = Roster::new("aaaa".to_string());
        assert!(!r.apply(DiscoveryEvent::Registered {
            fingerprint: "zzzz".to_string()
        }));
    }

    #[test]
    fn unreachable_does_not_demote_reachable() {
        let mut r = Roster::new("aaaa".to_string());
        r.apply(seen("bbbb", "bob"));
        r.apply(DiscoveryEvent::Registered {
            fingerprint: "bbbb".to_string(),
        });
        assert!(!r.apply(DiscoveryEvent::Unreachable {
            fingerprint: "bbbb".to_string()
        }));
        assert_eq!(r.snapshot()[0].state, PeerState::Reachable);
    }

    #[test]
    fn seen_with_ipmsg_protocol_records_ipmsg_peer() {
        // M5:IPMsg 兼容层喂入的 Seen 带 protocol=Ipmsg,伪 fingerprint 形如
        // `ipmsg:<key>`——roster 应如实记录 protocol,而不是硬编码成 Native。
        let mut r = Roster::new(SELF_FP.to_string());
        assert!(r.apply(seen_ipmsg("ipmsg:192.168.1.9:HOST-B", "bob-feiq")));
        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].protocol, Protocol::Ipmsg);
        assert_eq!(snap[0].port, 2425);
    }

    #[test]
    fn offline_peer_seen_again_returns_to_discovered() {
        let mut r = Roster::new("aaaa".to_string());
        r.apply(seen("bbbb", "bob"));
        r.apply(DiscoveryEvent::Lost {
            fingerprint: "bbbb".to_string(),
        });
        assert_eq!(r.snapshot()[0].state, PeerState::Offline);
        assert!(r.apply(seen("bbbb", "bob")));
        assert_eq!(r.snapshot()[0].state, PeerState::Discovered);
    }

    #[test]
    fn seed_offline_injects_known_peers_as_offline() {
        let mut r = Roster::new(SELF_FP.to_string());
        r.apply(seen("bbbb", "bob")); // 已在线的不该被预热覆盖
        r.seed_offline(vec![
            Peer {
                fingerprint: "bbbb".to_string(),
                nickname: "bob-old".to_string(),
                addrs: vec![],
                port: 0,
                protocol: Protocol::Native,
                state: PeerState::Discovered, // seed 强制改为 Offline
            },
            Peer {
                fingerprint: "cccc".to_string(),
                nickname: "carol".to_string(),
                addrs: vec![ip(7)],
                port: 0,
                protocol: Protocol::Native,
                state: PeerState::Discovered,
            },
            Peer {
                fingerprint: SELF_FP.to_string(),
                nickname: "me".to_string(),
                addrs: vec![],
                port: 0,
                protocol: Protocol::Native,
                state: PeerState::Discovered,
            },
        ]);
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2, "自己不注入");
        let bob = snap.iter().find(|p| p.fingerprint == "bbbb").unwrap();
        assert_eq!(bob.state, PeerState::Discovered, "在线记录不被预热覆盖");
        assert_eq!(bob.nickname, "bob", "昵称保持在线版本");
        let carol = snap.iter().find(|p| p.fingerprint == "cccc").unwrap();
        assert_eq!(carol.state, PeerState::Offline);
    }
}

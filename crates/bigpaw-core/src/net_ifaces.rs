//! 网卡选择功能的唯一真源(设计文档:网卡选择)。
//!
//! 维护"活跃网卡快照"(`IfaceSnapshot`):枚举系统 IPv4 接口、滤 loopback、
//! 滤用户排除清单,通过 `watch` 通道发布给 announce/mdns/ipmsg/transport 订阅。
//! 本模块不做任何网络 IO,只做枚举 + 纯计算,保持可测试。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// 虚拟接口名关键字提示(隧道/网桥/虚拟网卡)。仅作标注供上层决策(发送代表选择、
/// UI 展示)参考,本模块不据此强制过滤——是否参与发送由排除清单决定。
const VIRTUAL_IFACE_HINTS: [&str; 5] = ["tun", "utun", "bridge", "vnic", "vmnet"];

/// 判断接口名是否命中虚拟网卡关键字提示(大小写不敏感、子串匹配)。
pub fn is_virtual_hint(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_IFACE_HINTS.iter().any(|hint| lower.contains(hint))
}

/// 由 ip+netmask 计算定向广播地址(ip | !netmask)。
pub fn directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(netmask))
}

/// 单张网卡的一条 IPv4 地址快照条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceEntry {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub is_virtual_hint: bool,
}

/// 某一时刻的活跃网卡快照。`generation` 单调递增;`Default`(generation=0)
/// 表示"尚未枚举",与 `InterfaceRegistry::new()` 产出的首个快照(generation=1)
/// 严格区分,订阅者可用它判断是否已收到过真实数据。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfaceSnapshot {
    pub generation: u64,
    pub entries: Vec<IfaceEntry>,
}

/// UI 用的网卡视图:不滤排除项,带 excluded 标记,供设置页展示全量网卡。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceView {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub is_virtual_hint: bool,
    pub excluded: bool,
}

/// 由 `(ip & netmask, netmask)` 分组后选出的子网发送目标:同一子网只保留一个代表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendTarget {
    pub iface_ip: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

/// 由原始枚举结果构建快照条目:
/// - 滤 loopback;
/// - 只留 IPv4(IPv6 地址直接丢弃,不参与广播宣告);
/// - 按网卡名精确等值滤排除清单(不做前缀/模式匹配);
/// - 广播地址优先取系统上报字段,缺失时由 ip+netmask 现算;
/// - 按 (name, ip) 排序,保证多次枚举结果可稳定对比(顺序不因系统返回顺序抖动而误判"变化")。
pub fn build_entries(ifaces: &[if_addrs::Interface], excluded: &[String]) -> Vec<IfaceEntry> {
    let mut entries: Vec<IfaceEntry> = ifaces
        .iter()
        .filter(|iface| !iface.is_loopback())
        .filter(|iface| !excluded.iter().any(|ex| ex == &iface.name))
        .filter_map(|iface| match &iface.addr {
            if_addrs::IfAddr::V4(v4) => Some(IfaceEntry {
                name: iface.name.clone(),
                ip: v4.ip,
                netmask: v4.netmask,
                broadcast: v4
                    .broadcast
                    .unwrap_or_else(|| directed_broadcast(v4.ip, v4.netmask)),
                is_virtual_hint: is_virtual_hint(&iface.name),
            }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    entries.sort_by(|a, b| (a.name.as_str(), a.ip).cmp(&(b.name.as_str(), b.ip)));
    entries
}

/// 判断地址是否与条目集合中的任一网卡同网段。条目全为 IPv4,故传入 IPv6 地址恒返回
/// false(不 panic),不代表"精确排除",只是"这条地址与本机没有已知同网段网卡"。
pub fn same_subnet(addr: IpAddr, entries: &[IfaceEntry]) -> bool {
    let IpAddr::V4(addr) = addr else {
        return false;
    };
    entries.iter().any(|e| {
        (u32::from(addr) & u32::from(e.netmask)) == (u32::from(e.ip) & u32::from(e.netmask))
    })
}

/// 按亲和度稳定排序:与本机任一网卡同网段的地址排到前面(拨号顺序优化,Step 6 消费)。
/// `bool` 的 `Ord` 满足 false < true,故 `!same_subnet` 为 false(即同网段)的排前。
pub fn sort_by_affinity(addrs: &mut [IpAddr], entries: &[IfaceEntry]) {
    addrs.sort_by_key(|a| !same_subnet(*a, entries));
}

/// 组播 join/leave 增量。`joined` 为当前已 join 的网卡 IP 集合,`entries` 为期望活跃
/// 的网卡快照条目(已滤排除清单)。返回 (需新 join 的 IP, 需 leave 的 IP)。
/// 接收方向不做子网去重——重复收包由上层 fingerprint/roster 幂等吸收。
pub fn multicast_diff(
    joined: &[Ipv4Addr],
    entries: &[IfaceEntry],
) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let desired: Vec<Ipv4Addr> = entries.iter().map(|e| e.ip).collect();
    let to_join = desired
        .iter()
        .filter(|ip| !joined.contains(ip))
        .copied()
        .collect();
    let to_leave = joined
        .iter()
        .filter(|ip| !desired.contains(ip))
        .copied()
        .collect();
    (to_join, to_leave)
}

/// 子网去重(防重复宣告/防飞秋列表重复):按 `(ip & netmask, netmask)` 分组,每个子网
/// 只保留一张代表网卡——代表优先选非虚拟(`is_virtual_hint == false`),同级按网卡名
/// 排序取首,保证源 IP 稳定(IPMsg 身份含源 IP,代表漂移会导致对端列表分裂)。
/// 输出按 `iface_ip` 排序,与输入顺序无关,保证代表选择的确定性。
pub fn send_targets(entries: &[IfaceEntry]) -> Vec<SendTarget> {
    let mut groups: HashMap<(u32, u32), Vec<&IfaceEntry>> = HashMap::new();
    for e in entries {
        let network = u32::from(e.ip) & u32::from(e.netmask);
        groups
            .entry((network, u32::from(e.netmask)))
            .or_default()
            .push(e);
    }

    let mut targets: Vec<SendTarget> = groups
        .into_values()
        .filter_map(|mut group| {
            group.sort_by(|a, b| {
                a.is_virtual_hint
                    .cmp(&b.is_virtual_hint)
                    .then_with(|| a.name.cmp(&b.name))
            });
            group.first().map(|rep| SendTarget {
                iface_ip: rep.ip,
                broadcast: rep.broadcast,
            })
        })
        .collect();
    targets.sort_by_key(|t| t.iface_ip);
    targets
}

/// 供 ipmsg 使用的定向广播地址清单,基于 `send_targets` 取 broadcast 字段(天然去重)。
pub fn broadcast_targets(entries: &[IfaceEntry]) -> Vec<Ipv4Addr> {
    send_targets(entries)
        .into_iter()
        .map(|t| t.broadcast)
        .collect()
}

/// 活跃网卡快照的唯一真源。持有当前排除清单与 watch 发布通道,供
/// announce/mdns/ipmsg/transport 订阅;排除清单变更后自动 refresh。
pub struct InterfaceRegistry {
    excluded: Mutex<Vec<String>>,
    tx: watch::Sender<IfaceSnapshot>,
}

impl InterfaceRegistry {
    /// 创建并做一次同步初始枚举。首个快照 generation 无条件为 1(不与
    /// `IfaceSnapshot::default()` 的空快照比较——即使当前恰好没有物理网卡,
    /// 首个快照也代表"已完成一次真实枚举",区别于"尚未枚举")。
    pub fn new(excluded: Vec<String>) -> Arc<Self> {
        let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
        let entries = build_entries(&ifaces, &excluded);
        let (tx, _rx) = watch::channel(IfaceSnapshot {
            generation: 1,
            entries,
        });
        Arc::new(Self {
            excluded: Mutex::new(excluded),
            tx,
        })
    }

    /// 订阅快照变更;订阅者可在收到通知时读取最新值,也可随时 `snapshot()` 主动拉取。
    pub fn subscribe(&self) -> watch::Receiver<IfaceSnapshot> {
        self.tx.subscribe()
    }

    /// 读取当前快照(不阻塞、不触发枚举)。
    pub fn snapshot(&self) -> IfaceSnapshot {
        self.tx.borrow().clone()
    }

    /// 重新枚举系统网卡并原子对比发布。数据未变化时不触发订阅者唤醒(`send_if_modified`
    /// 语义),避免 announce/mdns 等下游做无意义的重建。
    pub fn refresh(&self) -> Option<IfaceSnapshot> {
        let excluded = self.excluded.lock().expect("excluded lock").clone();
        let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
        let entries = build_entries(&ifaces, &excluded);
        self.apply_entries(entries)
    }

    /// 把已构建好的条目原子对比发布进快照(不做系统枚举)。抽出这一层是为了让 diff/
    /// 幂等逻辑可以直接喂数据测试,不必 mock `if_addrs::get_if_addrs()`。
    fn apply_entries(&self, entries: Vec<IfaceEntry>) -> Option<IfaceSnapshot> {
        let mut published = None;
        self.tx.send_if_modified(|snapshot| {
            if snapshot.entries == entries {
                return false;
            }
            snapshot.generation += 1;
            snapshot.entries = entries.clone();
            published = Some(snapshot.clone());
            true
        });
        published
    }

    /// 更新排除清单并立即 refresh。返回 (旧清单, 若快照因此变化则为新快照)。
    /// 旧清单供 mdns 侧做 enable/disable diff(哪些名字从排除变为放行、反之)。
    pub fn set_excluded(&self, names: Vec<String>) -> (Vec<String>, Option<IfaceSnapshot>) {
        let old = {
            let mut guard = self.excluded.lock().expect("excluded lock");
            std::mem::replace(&mut *guard, names)
        };
        let new_snapshot = self.refresh();
        (old, new_snapshot)
    }

    /// 列出全部网卡(不滤排除项),标注 excluded 状态,供 UI 展示设置页。
    /// 仍滤 loopback/IPv6——它们从不构成一个可选的网卡条目。
    pub fn list_all(&self) -> Vec<IfaceView> {
        let excluded = self.excluded.lock().expect("excluded lock").clone();
        let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
        let mut views: Vec<IfaceView> = ifaces
            .iter()
            .filter(|iface| !iface.is_loopback())
            .filter_map(|iface| match &iface.addr {
                if_addrs::IfAddr::V4(v4) => Some(IfaceView {
                    name: iface.name.clone(),
                    ip: v4.ip,
                    netmask: v4.netmask,
                    is_virtual_hint: is_virtual_hint(&iface.name),
                    excluded: excluded.iter().any(|ex| ex == &iface.name),
                }),
                if_addrs::IfAddr::V6(_) => None,
            })
            .collect();
        views.sort_by(|a, b| (a.name.as_str(), a.ip).cmp(&(b.name.as_str(), b.ip)));
        views
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// 构造测试用 `if_addrs::Interface`(IPv4)。`adapter_name` 字段仅 Windows 有,
    /// 用 cfg 分支处理,保证测试在两个平台都能编译。
    #[cfg(not(windows))]
    fn v4_iface(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        broadcast: Option<Ipv4Addr>,
    ) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.to_string(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask,
                prefixlen: 24,
                broadcast,
            }),
            index: None,
        }
    }

    #[cfg(windows)]
    fn v4_iface(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        broadcast: Option<Ipv4Addr>,
    ) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.to_string(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask,
                prefixlen: 24,
                broadcast,
            }),
            index: None,
            adapter_name: String::new(),
        }
    }

    fn loopback_iface() -> if_addrs::Interface {
        v4_iface("lo0", v4(127, 0, 0, 1), v4(255, 0, 0, 0), None)
    }

    #[cfg(not(windows))]
    fn v6_iface(name: &str) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.to_string(),
            addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                ip: Ipv6Addr::LOCALHOST,
                netmask: Ipv6Addr::from(u128::MAX),
                prefixlen: 128,
                broadcast: None,
            }),
            index: None,
        }
    }

    #[cfg(windows)]
    fn v6_iface(name: &str) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.to_string(),
            addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                ip: Ipv6Addr::LOCALHOST,
                netmask: Ipv6Addr::from(u128::MAX),
                prefixlen: 128,
                broadcast: None,
            }),
            index: None,
            adapter_name: String::new(),
        }
    }

    fn entry(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, is_virtual_hint: bool) -> IfaceEntry {
        IfaceEntry {
            name: name.to_string(),
            ip,
            netmask,
            broadcast: directed_broadcast(ip, netmask),
            is_virtual_hint,
        }
    }

    // ---------- directed_broadcast ----------

    #[test]
    fn directed_broadcast_slash_24() {
        assert_eq!(
            directed_broadcast(v4(192, 168, 1, 42), v4(255, 255, 255, 0)),
            v4(192, 168, 1, 255)
        );
    }

    #[test]
    fn directed_broadcast_slash_8() {
        assert_eq!(
            directed_broadcast(v4(10, 1, 2, 3), v4(255, 0, 0, 0)),
            v4(10, 255, 255, 255)
        );
    }

    #[test]
    fn directed_broadcast_slash_32_equals_ip_itself() {
        assert_eq!(
            directed_broadcast(v4(172, 16, 5, 9), v4(255, 255, 255, 255)),
            v4(172, 16, 5, 9)
        );
    }

    // ---------- is_virtual_hint ----------

    #[test]
    fn is_virtual_hint_matches_known_keywords_case_insensitive() {
        for name in ["utun0", "tun0", "bridge100", "vnic1", "vmnet8", "UTUN3"] {
            assert!(is_virtual_hint(name), "{name} 应命中虚拟网卡提示");
        }
    }

    #[test]
    fn is_virtual_hint_does_not_match_physical_names() {
        for name in ["en0", "eth0", "wlan0", "Wi-Fi"] {
            assert!(!is_virtual_hint(name), "{name} 不应命中虚拟网卡提示");
        }
    }

    // ---------- build_entries ----------

    #[test]
    fn build_entries_filters_loopback() {
        let ifaces = vec![
            loopback_iface(),
            v4_iface("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), None),
        ];
        let entries = build_entries(&ifaces, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "en0");
    }

    #[test]
    fn build_entries_filters_excluded_by_exact_name_match() {
        let ifaces = vec![
            v4_iface("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), None),
            v4_iface("en1", v4(192, 168, 2, 10), v4(255, 255, 255, 0), None),
        ];
        // 精确等值匹配:"en" 不应前缀匹配掉 en0/en1。
        let entries = build_entries(&ifaces, &["en0".to_string(), "en".to_string()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "en1");
    }

    #[test]
    fn build_entries_filters_ipv6_addresses() {
        let ifaces = vec![
            v6_iface("en0"),
            v4_iface("en1", v4(10, 0, 0, 5), v4(255, 0, 0, 0), None),
        ];
        let entries = build_entries(&ifaces, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "en1");
    }

    #[test]
    fn build_entries_prefers_system_broadcast_field() {
        let ifaces = vec![v4_iface(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            Some(v4(192, 168, 1, 200)), // 非常规值,验证优先取系统字段而非现算
        )];
        let entries = build_entries(&ifaces, &[]);
        assert_eq!(entries[0].broadcast, v4(192, 168, 1, 200));
    }

    #[test]
    fn build_entries_computes_broadcast_when_system_field_missing() {
        let ifaces = vec![v4_iface(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            None,
        )];
        let entries = build_entries(&ifaces, &[]);
        assert_eq!(entries[0].broadcast, v4(192, 168, 1, 255));
    }

    #[test]
    fn build_entries_marks_virtual_hint() {
        let ifaces = vec![
            v4_iface("utun3", v4(10, 8, 0, 2), v4(255, 255, 255, 0), None),
            v4_iface("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), None),
        ];
        let entries = build_entries(&ifaces, &[]);
        let utun = entries.iter().find(|e| e.name == "utun3").unwrap();
        let en0 = entries.iter().find(|e| e.name == "en0").unwrap();
        assert!(utun.is_virtual_hint);
        assert!(!en0.is_virtual_hint);
    }

    #[test]
    fn build_entries_sorted_by_name_then_ip_regardless_of_input_order() {
        let ifaces = vec![
            v4_iface("en1", v4(192, 168, 2, 10), v4(255, 255, 255, 0), None),
            v4_iface("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), None),
        ];
        let entries = build_entries(&ifaces, &[]);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["en0", "en1"]);
    }

    // ---------- same_subnet ----------

    #[test]
    fn same_subnet_true_when_addr_shares_network_with_an_entry() {
        let entries = vec![entry(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            false,
        )];
        assert!(same_subnet(IpAddr::V4(v4(192, 168, 1, 200)), &entries));
    }

    #[test]
    fn same_subnet_false_when_no_entry_shares_network() {
        let entries = vec![entry(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            false,
        )];
        assert!(!same_subnet(IpAddr::V4(v4(10, 0, 0, 5)), &entries));
    }

    #[test]
    fn same_subnet_ipv6_addr_never_panics_and_returns_false() {
        let entries = vec![entry(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            false,
        )];
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!same_subnet(v6, &entries));
    }

    // ---------- sort_by_affinity ----------

    #[test]
    fn sort_by_affinity_puts_same_subnet_addrs_first_stably() {
        let entries = vec![entry(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            false,
        )];
        let mut addrs = vec![
            IpAddr::V4(v4(8, 8, 8, 8)),      // 远端,不同网段
            IpAddr::V4(v4(192, 168, 1, 50)), // 同网段 #1
            IpAddr::V4(v4(1, 1, 1, 1)),      // 远端
            IpAddr::V4(v4(192, 168, 1, 99)), // 同网段 #2
        ];
        sort_by_affinity(&mut addrs, &entries);
        assert_eq!(
            addrs,
            vec![
                IpAddr::V4(v4(192, 168, 1, 50)),
                IpAddr::V4(v4(192, 168, 1, 99)),
                IpAddr::V4(v4(8, 8, 8, 8)),
                IpAddr::V4(v4(1, 1, 1, 1)),
            ],
            "同网段地址应前置,且组内保持原有相对顺序(稳定排序)"
        );
    }

    // ---------- multicast_diff ----------

    #[test]
    fn multicast_diff_computes_join_and_leave() {
        let entries = vec![
            entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false),
            entry("en1", v4(192, 168, 2, 10), v4(255, 255, 255, 0), false),
        ];
        let joined = vec![v4(192, 168, 1, 10), v4(10, 0, 0, 1)]; // en0 已 join,10.0.0.1 已不在快照里
        let (to_join, to_leave) = multicast_diff(&joined, &entries);
        assert_eq!(to_join, vec![v4(192, 168, 2, 10)]);
        assert_eq!(to_leave, vec![v4(10, 0, 0, 1)]);
    }

    #[test]
    fn multicast_diff_empty_when_already_in_sync() {
        let entries = vec![entry(
            "en0",
            v4(192, 168, 1, 10),
            v4(255, 255, 255, 0),
            false,
        )];
        let joined = vec![v4(192, 168, 1, 10)];
        let (to_join, to_leave) = multicast_diff(&joined, &entries);
        assert!(to_join.is_empty());
        assert!(to_leave.is_empty());
    }

    // ---------- send_targets / broadcast_targets ----------

    #[test]
    fn send_targets_dedups_same_subnet_and_prefers_physical_representative() {
        // 桥接虚拟网卡与物理卡同子网 → 合并为一次发送,代表为物理卡。
        let entries = vec![
            entry("bridge0", v4(192, 168, 1, 20), v4(255, 255, 255, 0), true),
            entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false),
        ];
        let targets = send_targets(&entries);
        assert_eq!(targets.len(), 1, "同子网只应产生一个发送目标");
        assert_eq!(targets[0].iface_ip, v4(192, 168, 1, 10), "代表应为物理卡");
    }

    #[test]
    fn send_targets_nat_subnet_is_independent_target() {
        // NAT 虚拟网卡自带独立子网 → 不与物理卡合并,独立成一个目标。
        let entries = vec![
            entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false),
            entry("vmnet8", v4(172, 16, 5, 1), v4(255, 255, 255, 0), true),
        ];
        let targets = send_targets(&entries);
        assert_eq!(targets.len(), 2, "两个不同子网应各自独立成目标");
        let ips: Vec<Ipv4Addr> = targets.iter().map(|t| t.iface_ip).collect();
        assert!(ips.contains(&v4(192, 168, 1, 10)));
        assert!(ips.contains(&v4(172, 16, 5, 1)));
    }

    #[test]
    fn send_targets_representative_choice_is_stable_regardless_of_input_order() {
        let a = entry("bridge0", v4(192, 168, 1, 20), v4(255, 255, 255, 0), true);
        let b = entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false);

        let forward = send_targets(&[a.clone(), b.clone()]);
        let backward = send_targets(&[b, a]);

        assert_eq!(forward, backward, "乱序输入不应改变代表选择结果");
        assert_eq!(forward[0].iface_ip, v4(192, 168, 1, 10));
    }

    #[test]
    fn send_targets_tie_break_by_name_when_both_physical_or_both_virtual() {
        // 同为物理卡的场景(极罕见但需确定性):按网卡名排序取首。
        let a = entry("en1", v4(192, 168, 1, 20), v4(255, 255, 255, 0), false);
        let b = entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false);
        let targets = send_targets(&[a, b]);
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].iface_ip,
            v4(192, 168, 1, 10),
            "同级按名称排序,en0 在前"
        );
    }

    #[test]
    fn broadcast_targets_derived_from_send_targets_broadcast_field() {
        let entries = vec![
            entry("bridge0", v4(192, 168, 1, 20), v4(255, 255, 255, 0), true),
            entry("en0", v4(192, 168, 1, 10), v4(255, 255, 255, 0), false),
            entry("vmnet8", v4(172, 16, 5, 1), v4(255, 255, 255, 0), true),
        ];
        let broadcasts = broadcast_targets(&entries);
        assert_eq!(broadcasts.len(), 2, "两个子网,天然去重");
        assert!(broadcasts.contains(&v4(192, 168, 1, 255)));
        assert!(broadcasts.contains(&v4(172, 16, 5, 255)));
    }

    // ---------- InterfaceRegistry ----------

    #[test]
    fn new_registry_initial_snapshot_generation_is_one() {
        let registry = InterfaceRegistry::new(vec![]);
        assert_eq!(registry.snapshot().generation, 1);
    }

    #[test]
    fn default_snapshot_generation_is_zero_meaning_not_yet_enumerated() {
        assert_eq!(IfaceSnapshot::default().generation, 0);
    }

    #[test]
    fn apply_entries_idempotent_no_notify_when_data_unchanged() {
        let registry = InterfaceRegistry::new(vec![]);
        // 用现实中不可能存在的地址(TEST-NET-3, RFC 5737)确保与宿主机真实网卡不重合。
        let entries = vec![entry(
            "biguniquetest0",
            v4(203, 0, 113, 5),
            v4(255, 255, 255, 0),
            false,
        )];

        let first = registry.apply_entries(entries.clone());
        assert!(first.is_some(), "首次写入不同数据应产生新快照");
        let gen_after_first = first.unwrap().generation;

        let second = registry.apply_entries(entries);
        assert!(second.is_none(), "相同数据二次 apply 不应产生新快照/通知");
        assert_eq!(
            registry.snapshot().generation,
            gen_after_first,
            "generation 不应因无变化的 apply 而递增"
        );
    }

    #[test]
    fn apply_entries_bumps_generation_when_data_changes() {
        let registry = InterfaceRegistry::new(vec![]);
        let e1 = vec![entry(
            "biguniquetest0",
            v4(203, 0, 113, 5),
            v4(255, 255, 255, 0),
            false,
        )];
        let e2 = vec![entry(
            "biguniquetest0",
            v4(203, 0, 113, 6),
            v4(255, 255, 255, 0),
            false,
        )];

        let first = registry.apply_entries(e1).unwrap();
        let second = registry.apply_entries(e2).unwrap();
        assert_eq!(second.generation, first.generation + 1);
    }

    #[test]
    fn set_excluded_returns_previous_list() {
        let registry = InterfaceRegistry::new(vec!["a".to_string()]);
        let (old, _new_snapshot) = registry.set_excluded(vec!["b".to_string()]);
        assert_eq!(old, vec!["a".to_string()]);
    }
}

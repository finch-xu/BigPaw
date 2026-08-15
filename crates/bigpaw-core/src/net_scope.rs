//! 网络范围限定(允许网段清单)的唯一真源:纯计算、零 IO。
//!
//! 语义借鉴 Syncthing `allowedNetworks`:范围指**对端地址**;清单为空 =
//! 不限制(默认,行为与改造前逐字节等价)。三种条目格式:
//! - 单 IP        `192.168.1.10`
//! - CIDR         `192.168.1.0/24`(主机位非零时自动归零)
//! - 闭区间       `192.168.1.10-192.168.1.50`
//!
//! 内部把所有条目归并成排序、不重叠的 u32 闭区间列表,`allows`/
//! `covers_subnet`/主机枚举全部基于它——不遍历子网,整数区间运算。
//! 不引入 `ipnet`:它不支持区间格式,而我们只需要 u32 闭区间。

use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

/// 清单条目上限(防止手改配置塞进离谱数量)。
pub const MAX_ENTRIES: usize = 256;
/// 单播枚举上限:一张网卡(或跨网段池)每轮宣告最多单播这么多台主机。
/// 1024 pkt / 25s 远低于 IDS 扫描阈值;超限截断并由发布点记一次日志。
pub const MAX_UNICAST_HOSTS: usize = 1024;

/// 单条范围条目,保留用户输入形态供 UI 回显。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    Single(Ipv4Addr),
    Cidr { network: Ipv4Addr, prefix: u8 },
    Range { start: Ipv4Addr, end: Ipv4Addr },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScopeParseError {
    #[error("第 {line} 行:无法解析 IPv4 地址 `{text}`")]
    BadIp { line: usize, text: String },
    #[error("第 {line} 行:CIDR 前缀长度非法 `{text}`(应为 0-32)")]
    BadPrefix { line: usize, text: String },
    #[error("第 {line} 行:区间起点大于终点 `{text}`")]
    ReversedRange { line: usize, text: String },
    #[error("第 {line} 行:格式无法识别 `{text}`")]
    Malformed { line: usize, text: String },
    #[error("条目过多({0} > {MAX_ENTRIES})")]
    TooMany(usize),
}

/// 主机枚举结果:`truncated` 表示达到 cap 被截断;`skipped_entries` 为
/// 因过大而整体跳过的条目(canonical 形式,供日志)。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostList {
    pub hosts: Vec<Ipv4Addr>,
    pub truncated: bool,
    pub skipped_entries: Vec<String>,
}

/// 允许的对端地址范围。空清单 = 不限制。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetScope {
    entries: Vec<ScopeEntry>,
    /// 归并后的有序不重叠闭区间。
    merged: Vec<(u32, u32)>,
}

impl ScopeEntry {
    /// 解析单条(已 trim 的)文本。`line` 只用于错误报告(1-based)。
    pub fn parse(text: &str, line: usize) -> Result<Self, ScopeParseError> {
        let text = text.trim();
        let bad_ip = || ScopeParseError::BadIp {
            line,
            text: text.to_string(),
        };
        if let Some((addr, prefix)) = text.split_once('/') {
            let ip: Ipv4Addr = addr.trim().parse().map_err(|_| bad_ip())?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .ok()
                .filter(|p| *p <= 32)
                .ok_or(ScopeParseError::BadPrefix {
                    line,
                    text: text.to_string(),
                })?;
            let mask = prefix_mask(prefix);
            return Ok(Self::Cidr {
                network: Ipv4Addr::from(u32::from(ip) & mask),
                prefix,
            });
        }
        if let Some((a, b)) = text.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| bad_ip())?;
            let end: Ipv4Addr = b.trim().parse().map_err(|_| bad_ip())?;
            if start > end {
                return Err(ScopeParseError::ReversedRange {
                    line,
                    text: text.to_string(),
                });
            }
            return Ok(Self::Range { start, end });
        }
        match text.parse::<Ipv4Addr>() {
            Ok(ip) => Ok(Self::Single(ip)),
            // 形似地址(有点或冒号)但解析失败 → BadIp;完全不像 → Malformed
            Err(_) if text.contains('.') || text.contains(':') => Err(bad_ip()),
            Err(_) => Err(ScopeParseError::Malformed {
                line,
                text: text.to_string(),
            }),
        }
    }

    /// 闭区间 [start, end](u32)。
    pub fn bounds(&self) -> (u32, u32) {
        match self {
            Self::Single(ip) => (u32::from(*ip), u32::from(*ip)),
            Self::Cidr { network, prefix } => {
                let start = u32::from(*network);
                (start, start | !prefix_mask(*prefix))
            }
            Self::Range { start, end } => (u32::from(*start), u32::from(*end)),
        }
    }

    /// 覆盖的地址数。
    pub fn size(&self) -> u64 {
        let (s, e) = self.bounds();
        u64::from(e) - u64::from(s) + 1
    }

    /// 归一化文本(CIDR 主机位归零后的形式)。
    pub fn canonical(&self) -> String {
        match self {
            Self::Single(ip) => ip.to_string(),
            Self::Cidr { network, prefix } => format!("{network}/{prefix}"),
            Self::Range { start, end } => format!("{start}-{end}"),
        }
    }
}

impl NetScope {
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// 严格解析:任一行出错即整体失败(`set_settings` 权威校验用)。
    /// 空行/纯空白行跳过。
    pub fn parse(lines: &[String]) -> Result<Self, ScopeParseError> {
        let mut entries = Vec::new();
        for (idx, raw) in lines.iter().enumerate() {
            let text = raw.trim();
            if text.is_empty() {
                continue;
            }
            entries.push(ScopeEntry::parse(text, idx + 1)?);
        }
        if entries.len() > MAX_ENTRIES {
            return Err(ScopeParseError::TooMany(entries.len()));
        }
        Ok(Self::from_entries(entries))
    }

    /// 宽松解析:跳过坏行并把错误返回给调用方记日志(启动读手改过的
    /// settings.json 用)。全部坏行 → unrestricted + 全部错误。
    pub fn parse_lenient(lines: &[String]) -> (Self, Vec<ScopeParseError>) {
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for (idx, raw) in lines.iter().enumerate() {
            let text = raw.trim();
            if text.is_empty() {
                continue;
            }
            match ScopeEntry::parse(text, idx + 1) {
                Ok(e) => entries.push(e),
                Err(e) => errors.push(e),
            }
        }
        if entries.len() > MAX_ENTRIES {
            errors.push(ScopeParseError::TooMany(entries.len()));
            entries.truncate(MAX_ENTRIES);
        }
        (Self::from_entries(entries), errors)
    }

    fn from_entries(entries: Vec<ScopeEntry>) -> Self {
        let merged = merge_ranges(entries.iter().map(ScopeEntry::bounds));
        Self { entries, merged }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }

    /// 对端地址是否在范围内。unrestricted → true;IPv6 → false(项目 IPv4-only)。
    pub fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.allows_v4(v4),
            IpAddr::V6(_) => self.is_unrestricted(),
        }
    }

    pub fn allows_v4(&self, ip: Ipv4Addr) -> bool {
        self.is_unrestricted() || self.containing_range(u32::from(ip)).is_some()
    }

    /// 二分查找包含 `x` 的归并区间。
    fn containing_range(&self, x: u32) -> Option<(u32, u32)> {
        // partition_point 给出首个 start > x 的下标,候选即其前一个。
        let idx = self.merged.partition_point(|(s, _)| *s <= x);
        idx.checked_sub(1)
            .map(|i| self.merged[i])
            .filter(|(_, e)| x <= *e)
    }

    /// 归并后是否有单个区间完全覆盖 `[network, broadcast]`。unrestricted → true。
    pub fn covers_subnet(&self, ip: Ipv4Addr, netmask: Ipv4Addr) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        let (network, broadcast) = subnet_bounds(ip, netmask);
        self.containing_range(network)
            .is_some_and(|(_, end)| end >= broadcast)
    }

    /// 清单 ∩ 子网 的主机地址枚举(升序,去重):子网主机区间为
    /// `[network+1, broadcast-1]`(prefix ≥ 31 时为 `[network, broadcast]`),
    /// 再减去 `exclude`(本机在该子网上的全部 IP);最多 `cap` 个,超限截断并
    /// 置 `truncated`。unrestricted → 空(不该被调用,防御性返回)。
    pub fn hosts_within(
        &self,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        exclude: &[Ipv4Addr],
        cap: usize,
    ) -> HostList {
        let mut out = HostList::default();
        if self.is_unrestricted() {
            return out;
        }
        let (network, broadcast) = subnet_bounds(ip, netmask);
        // 主机区间:常规子网去掉网络地址与广播地址;/31、/32(区间宽度 < 2 个
        // 可去除的端点)两端都算主机(RFC 3021 点对点链路)。
        let (host_lo, host_hi) = if broadcast - network < 2 {
            (network, broadcast)
        } else {
            (network + 1, broadcast - 1)
        };
        // 与归并区间逐一求交:merged 有序不重叠,交集自然升序、无重复。
        let pieces: Vec<(u32, u32)> = self
            .merged
            .iter()
            .map(|(s, e)| ((*s).max(host_lo), (*e).min(host_hi)))
            .filter(|(lo, hi)| lo <= hi)
            .collect();
        collect_hosts(pieces, exclude, cap, &mut out);
        out
    }

    /// 清单中不落在任何给定子网内的地址(跨网段直连单播用)。只对
    /// `size() <= cap` 的条目做子网减法枚举;超大条目整体跳过并记入
    /// `skipped_entries`(`10.0.0.0/8` 这类显然是过滤意图,逐台单播像扫描)。
    /// 总数仍受 `cap` 截断。
    pub fn hosts_outside(&self, subnets: &[(Ipv4Addr, Ipv4Addr)], cap: usize) -> HostList {
        let mut out = HostList::default();
        if self.is_unrestricted() {
            return out;
        }
        let local: Vec<(u32, u32)> = subnets
            .iter()
            .map(|(ip, mask)| subnet_bounds(*ip, *mask))
            .collect();
        // 逐条目做子网减法后收集,最后按归并去重(条目之间可能重叠)。
        let mut pieces: Vec<(u32, u32)> = Vec::new();
        for entry in &self.entries {
            if entry.size() > cap as u64 {
                out.skipped_entries.push(entry.canonical());
                continue;
            }
            let mut remaining = vec![entry.bounds()];
            for sub in &local {
                remaining = remaining
                    .into_iter()
                    .flat_map(|r| subtract_range(r, *sub))
                    .collect();
            }
            pieces.extend(remaining);
        }
        collect_hosts(merge_ranges(pieces.into_iter()), &[], cap, &mut out);
        out
    }
}

/// prefix → 子网掩码(u32);prefix=0 → 0。
fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// `(network, broadcast)` 闭区间。
fn subnet_bounds(ip: Ipv4Addr, netmask: Ipv4Addr) -> (u32, u32) {
    let mask = u32::from(netmask);
    let network = u32::from(ip) & mask;
    (network, network | !mask)
}

/// 归并成有序、不重叠、不相邻的闭区间列表。
fn merge_ranges(ranges: impl Iterator<Item = (u32, u32)>) -> Vec<(u32, u32)> {
    let mut v: Vec<(u32, u32)> = ranges.collect();
    v.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match merged.last_mut() {
            // 重叠或相邻(last.1 + 1 == s)都并入;用 u64 防 u32::MAX 溢出。
            Some(last) if u64::from(s) <= u64::from(last.1) + 1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// 闭区间减法 `a \ b`,结果 0~2 段。
fn subtract_range(a: (u32, u32), b: (u32, u32)) -> Vec<(u32, u32)> {
    if b.1 < a.0 || b.0 > a.1 {
        return vec![a];
    }
    let mut out = Vec::with_capacity(2);
    if b.0 > a.0 {
        out.push((a.0, b.0 - 1));
    }
    if b.1 < a.1 {
        out.push((b.1 + 1, a.1));
    }
    out
}

/// 把有序不重叠区间展开为主机地址,跳过 `exclude`,最多 `cap` 个;超限置
/// `truncated`。展开前先做整数区间运算,这里只遍历真正会被输出的地址。
fn collect_hosts(ranges: Vec<(u32, u32)>, exclude: &[Ipv4Addr], cap: usize, out: &mut HostList) {
    for (s, e) in ranges {
        let mut x = u64::from(s);
        while x <= u64::from(e) {
            let ip = Ipv4Addr::from(x as u32);
            if !exclude.contains(&ip) {
                if out.hosts.len() >= cap {
                    out.truncated = true;
                    return;
                }
                out.hosts.push(ip);
            }
            x += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn scope(v: &[&str]) -> NetScope {
        NetScope::parse(&lines(v)).unwrap()
    }
    const MASK24: &str = "255.255.255.0";

    // ---------- ScopeEntry::parse ----------

    #[test]
    fn parse_single_ip() {
        assert_eq!(
            ScopeEntry::parse("192.168.1.10", 1).unwrap(),
            ScopeEntry::Single(ip("192.168.1.10"))
        );
    }

    #[test]
    fn parse_cidr_zeroes_host_bits() {
        assert_eq!(
            ScopeEntry::parse("192.168.1.77/24", 1).unwrap(),
            ScopeEntry::Cidr {
                network: ip("192.168.1.0"),
                prefix: 24
            }
        );
    }

    #[test]
    fn parse_range() {
        assert_eq!(
            ScopeEntry::parse("192.168.1.10-192.168.1.50", 1).unwrap(),
            ScopeEntry::Range {
                start: ip("192.168.1.10"),
                end: ip("192.168.1.50")
            }
        );
    }

    #[test]
    fn parse_range_tolerates_spaces_around_dash() {
        assert_eq!(
            ScopeEntry::parse("192.168.1.10 - 192.168.1.50", 3).unwrap(),
            ScopeEntry::Range {
                start: ip("192.168.1.10"),
                end: ip("192.168.1.50")
            }
        );
    }

    #[test]
    fn parse_errors_carry_line_numbers() {
        assert_eq!(
            ScopeEntry::parse("300.1.1.1", 2),
            Err(ScopeParseError::BadIp {
                line: 2,
                text: "300.1.1.1".into()
            })
        );
        assert_eq!(
            ScopeEntry::parse("10.0.0.0/33", 4),
            Err(ScopeParseError::BadPrefix {
                line: 4,
                text: "10.0.0.0/33".into()
            })
        );
        assert_eq!(
            ScopeEntry::parse("10.0.0.9-10.0.0.1", 5),
            Err(ScopeParseError::ReversedRange {
                line: 5,
                text: "10.0.0.9-10.0.0.1".into()
            })
        );
        assert_eq!(
            ScopeEntry::parse("hello", 6),
            Err(ScopeParseError::Malformed {
                line: 6,
                text: "hello".into()
            })
        );
        // IPv6 属于"无法解析 IPv4"
        assert!(matches!(
            ScopeEntry::parse("fe80::1", 7),
            Err(ScopeParseError::BadIp { line: 7, .. })
        ));
    }

    #[test]
    fn bounds_size_and_canonical() {
        let single = ScopeEntry::parse("10.0.0.5", 1).unwrap();
        assert_eq!(single.bounds(), (u32::from(ip("10.0.0.5")), u32::from(ip("10.0.0.5"))));
        assert_eq!(single.size(), 1);
        assert_eq!(single.canonical(), "10.0.0.5");

        let cidr = ScopeEntry::parse("10.0.0.99/24", 1).unwrap();
        assert_eq!(cidr.bounds(), (u32::from(ip("10.0.0.0")), u32::from(ip("10.0.0.255"))));
        assert_eq!(cidr.size(), 256);
        assert_eq!(cidr.canonical(), "10.0.0.0/24");

        let all = ScopeEntry::parse("1.2.3.4/0", 1).unwrap();
        assert_eq!(all.bounds(), (0, u32::MAX));
        assert_eq!(all.size(), 1 << 32);
        assert_eq!(all.canonical(), "0.0.0.0/0");

        let host = ScopeEntry::parse("10.0.0.7/32", 1).unwrap();
        assert_eq!(host.size(), 1);

        let range = ScopeEntry::parse("10.0.0.1-10.0.0.3", 1).unwrap();
        assert_eq!(range.size(), 3);
        assert_eq!(range.canonical(), "10.0.0.1-10.0.0.3");
    }

    // ---------- NetScope::parse ----------

    #[test]
    fn empty_lines_are_unrestricted() {
        let s = NetScope::parse(&lines(&["", "   "])).unwrap();
        assert!(s.is_unrestricted());
        assert_eq!(s, NetScope::unrestricted());
        assert!(s.allows("8.8.8.8".parse().unwrap()));
        assert!(s.allows("fe80::1".parse().unwrap()));
    }

    #[test]
    fn strict_parse_fails_on_any_bad_line() {
        let err = NetScope::parse(&lines(&["10.0.0.1", "bad", "10.0.0.2"])).unwrap_err();
        assert_eq!(
            err,
            ScopeParseError::Malformed {
                line: 2,
                text: "bad".into()
            }
        );
    }

    #[test]
    fn strict_parse_rejects_too_many_entries() {
        let many: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("10.0.{}.1", i % 250)).collect();
        assert_eq!(
            NetScope::parse(&many),
            Err(ScopeParseError::TooMany(MAX_ENTRIES + 1))
        );
    }

    #[test]
    fn lenient_parse_skips_bad_lines_and_reports_them() {
        let (s, errs) = NetScope::parse_lenient(&lines(&["10.0.0.1", "bad", "10.0.0.0/33"]));
        assert_eq!(s.entries().len(), 1);
        assert_eq!(errs.len(), 2);
        assert!(s.allows_v4(ip("10.0.0.1")));
        assert!(!s.allows_v4(ip("10.0.0.2")));
    }

    #[test]
    fn lenient_parse_all_bad_is_unrestricted() {
        let (s, errs) = NetScope::parse_lenient(&lines(&["bad", "worse"]));
        assert!(s.is_unrestricted());
        assert_eq!(errs.len(), 2);
    }

    // ---------- allows ----------

    #[test]
    fn allows_respects_all_three_formats_and_boundaries() {
        let s = scope(&["192.168.1.10", "10.0.0.0/24", "172.16.0.5-172.16.0.9"]);
        assert!(s.allows_v4(ip("192.168.1.10")));
        assert!(!s.allows_v4(ip("192.168.1.11")));
        assert!(s.allows_v4(ip("10.0.0.0")));
        assert!(s.allows_v4(ip("10.0.0.255")));
        assert!(!s.allows_v4(ip("10.0.1.0")));
        assert!(s.allows_v4(ip("172.16.0.5")));
        assert!(s.allows_v4(ip("172.16.0.9")));
        assert!(!s.allows_v4(ip("172.16.0.4")));
        assert!(!s.allows_v4(ip("172.16.0.10")));
    }

    #[test]
    fn restricted_scope_rejects_ipv6() {
        let s = scope(&["10.0.0.0/8"]);
        assert!(!s.allows("fe80::1".parse().unwrap()));
        assert!(s.allows("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn overlapping_and_adjacent_entries_merge() {
        // 两条相邻区间归并成一条,才能"覆盖"一整段 /24
        let s = scope(&["10.0.0.0-10.0.0.127", "10.0.0.128/25"]);
        assert!(s.covers_subnet(ip("10.0.0.5"), ip(MASK24)));
        // 重叠归并
        let s2 = scope(&["10.0.0.0/25", "10.0.0.100-10.0.0.255"]);
        assert!(s2.covers_subnet(ip("10.0.0.5"), ip(MASK24)));
    }

    // ---------- covers_subnet ----------

    #[test]
    fn covers_subnet_semantics() {
        assert!(NetScope::unrestricted().covers_subnet(ip("10.0.0.5"), ip(MASK24)));
        let s = scope(&["10.0.0.0/24", "192.168.0.0/16"]);
        assert!(s.covers_subnet(ip("10.0.0.5"), ip(MASK24)));
        assert!(s.covers_subnet(ip("192.168.7.9"), ip(MASK24)));
        // 只覆盖一半 → false
        let half = scope(&["10.0.0.0/25"]);
        assert!(!half.covers_subnet(ip("10.0.0.5"), ip(MASK24)));
        // 单 IP 不覆盖 /24
        assert!(!scope(&["10.0.0.5"]).covers_subnet(ip("10.0.0.5"), ip(MASK24)));
        // /32 网卡(点对点)被同地址单 IP 条目覆盖
        assert!(scope(&["10.8.0.2"]).covers_subnet(ip("10.8.0.2"), ip("255.255.255.255")));
        // 不相干网段
        assert!(!s.covers_subnet(ip("172.16.0.1"), ip(MASK24)));
    }

    // ---------- hosts_within ----------

    #[test]
    fn hosts_within_intersects_and_strips_network_broadcast_and_self() {
        let s = scope(&["10.0.0.0-10.0.0.5", "10.0.0.250-10.0.1.3"]);
        let hl = s.hosts_within(ip("10.0.0.7"), ip(MASK24), &[ip("10.0.0.7"), ip("10.0.0.3")], 1024);
        // 0 是网络地址、255 是广播地址、3 是本机 → 去掉;10.0.1.x 不在子网内
        assert_eq!(
            hl.hosts,
            vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.4"), ip("10.0.0.5"),
                 ip("10.0.0.250"), ip("10.0.0.251"), ip("10.0.0.252"), ip("10.0.0.253"), ip("10.0.0.254")]
        );
        assert!(!hl.truncated);
        assert!(hl.skipped_entries.is_empty());
    }

    #[test]
    fn hosts_within_no_intersection_is_empty() {
        let s = scope(&["172.16.0.0/16"]);
        let hl = s.hosts_within(ip("10.0.0.7"), ip(MASK24), &[], 1024);
        assert!(hl.hosts.is_empty());
        assert!(!hl.truncated);
    }

    #[test]
    fn hosts_within_truncates_at_cap_in_ascending_order() {
        let s = scope(&["10.0.0.0/24"]);
        let hl = s.hosts_within(ip("10.0.0.7"), ip(MASK24), &[ip("10.0.0.7")], 5);
        assert_eq!(
            hl.hosts,
            vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3"), ip("10.0.0.4"), ip("10.0.0.5")]
        );
        assert!(hl.truncated);
    }

    #[test]
    fn hosts_within_full_subnet_excludes_only_edges_and_self() {
        let s = scope(&["10.0.0.0/24"]);
        let hl = s.hosts_within(ip("10.0.0.7"), ip(MASK24), &[ip("10.0.0.7")], 1024);
        assert_eq!(hl.hosts.len(), 254 - 1);
        assert!(!hl.truncated);
    }

    #[test]
    fn hosts_within_handles_31_and_32_prefixes() {
        // /31:两端都是主机
        let s = scope(&["10.0.0.0/24"]);
        let hl = s.hosts_within(ip("10.0.0.4"), ip("255.255.255.254"), &[ip("10.0.0.4")], 10);
        assert_eq!(hl.hosts, vec![ip("10.0.0.5")]);
        // /32:只有自己,排除后为空
        let hl32 = s.hosts_within(ip("10.0.0.4"), ip("255.255.255.255"), &[ip("10.0.0.4")], 10);
        assert!(hl32.hosts.is_empty());
    }

    #[test]
    fn hosts_within_unrestricted_is_empty() {
        let hl = NetScope::unrestricted().hosts_within(ip("10.0.0.7"), ip(MASK24), &[], 10);
        assert!(hl.hosts.is_empty());
    }

    // ---------- hosts_outside ----------

    #[test]
    fn hosts_outside_subtracts_local_subnets() {
        let s = scope(&["10.0.0.5", "10.0.0.6", "192.168.9.1-192.168.9.3", "172.16.0.0/30"]);
        let hl = s.hosts_outside(&[(ip("10.0.0.7"), ip(MASK24))], 1024);
        assert_eq!(
            hl.hosts,
            vec![ip("172.16.0.0"), ip("172.16.0.1"), ip("172.16.0.2"), ip("172.16.0.3"),
                 ip("192.168.9.1"), ip("192.168.9.2"), ip("192.168.9.3")]
        );
        assert!(!hl.truncated);
        assert!(hl.skipped_entries.is_empty());
    }

    #[test]
    fn hosts_outside_skips_oversized_entries_and_reports_them() {
        let s = scope(&["10.0.0.0/8", "192.168.9.1"]);
        let hl = s.hosts_outside(&[], 1024);
        assert_eq!(hl.hosts, vec![ip("192.168.9.1")]);
        assert_eq!(hl.skipped_entries, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn hosts_outside_truncates_total_at_cap() {
        // 每条都不超 cap(不会被 skipped),但总数超 cap → 按升序截断
        let s = scope(&["192.168.9.4", "192.168.9.1-192.168.9.2", "192.168.9.3"]);
        let hl = s.hosts_outside(&[], 3);
        assert_eq!(hl.hosts, vec![ip("192.168.9.1"), ip("192.168.9.2"), ip("192.168.9.3")]);
        assert!(hl.truncated);
        assert!(hl.skipped_entries.is_empty());
    }

    #[test]
    fn hosts_outside_unrestricted_is_empty() {
        assert!(NetScope::unrestricted().hosts_outside(&[], 10).hosts.is_empty());
    }
}

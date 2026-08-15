//! mDNS 发现主通道(设计文档 §4):应用内自带协议栈,不依赖系统 Bonjour。
//! 注册 `_bigpaw._tcp.local.`,TXT 携带 fingerprint/昵称/能力位/协议版本;
//! 浏览同类型服务,解析出的对端转成 DiscoveryEvent 发往 roster。
//!
//! ## 网卡排除清单同步(Step 5,设计文档:网卡选择)
//!
//! mdns-sd 0.13.11(源码已核对 `service_daemon.rs`)提供
//! `daemon.disable_interface(if_kind)` / `enable_interface`,`IfKind::Name`
//! 按网卡名字符串匹配。关键事实:
//! - name selection 对**未来同名网卡持久生效**(比如网卡先拔后插,或系统
//!   重新枚举出同名接口),不需要我们在热插拔时重新提交;
//! - daemon 内部每 5s 自查一次 IP 变化,热插拔场景本身也不需要我们管;
//! - selection 列表是**追加式**的(`apply_intf_selections`),重复提交同一
//!   个名字会无界增长,所以 `set_disabled_interfaces` 内部按 `applied_disabled`
//!   做 diff,只在集合**真的变了**时才提交——调用方(`Core::start`、
//!   `apply_settings`、roster 线程的定期刷新)可以幂等地重复调用。
//! - 期望禁用集合 = 用户排除清单 ∪ 网络范围限定下"未被整段覆盖"的网卡
//!   (严格隐身:该网卡不再做 mDNS 宣告/浏览,改由 UDP 单播宣告承担发现),
//!   由 `net_ifaces::desired_mdns_disabled` 计算,本模块只管提交。
//!
//! 已确认的坑:`disable_interface` 只摘除该网卡对应的 socket/收包缓存,
//! **不清理 `enable_addr_auto` 服务在 A 记录里已缓存的旧 IP**(源码
//! `apply_intf_selections` 第 1227-1240 行,没有调用 `del_addr_in_my_services`)。
//! 也就是说:仅 disable 网卡,自身广播出去的服务记录里还会残留被排除网卡的
//! IP。对策:清单真变化后额外 unregister + re-register 一次,靠重新构建
//! `ServiceInfo`(`enable_addr_auto` 会按当前活跃网卡重新收集地址)清空这份
//! 残留。为此 `Discovery` 需要存下重建 `ServiceInfo` 的全部参数
//! (fingerprint/nickname/port/instance/host)。

use crate::identity::Identity;
use crate::roster::{DiscoveryEvent, Protocol};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::mpsc::Sender;

pub const SERVICE_TYPE: &str = "_bigpaw._tcp.local.";

pub struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
    // 以下字段只为 `re_register`(排除清单变更后重建 ServiceInfo)存在,
    // 发现/浏览逻辑本身不需要它们。
    /// 本机身份指纹,写进 TXT 的 "fp" 字段。
    fingerprint: String,
    /// 当前昵称,写进 TXT 的 "nick" 字段。
    nickname: String,
    /// 当前工作组名(M7a),写进 TXT 的 "group" 字段(无值写空串)。
    group: Option<String>,
    /// 注册用的服务端口(真实监听端口,非 mDNS 自身端口)。
    port: u16,
    /// 实例名(fp 前 16 位),ServiceInfo 的 instance 参数。
    instance: String,
    /// 主机名(`{instance}.local.`),ServiceInfo 的 host 参数。
    host: String,
    /// 已提交给 daemon 的禁用网卡名集合(排序去重),`set_disabled_interfaces`
    /// 据此做 diff,保证 selection 只在真变化时追加。
    applied_disabled: Vec<String>,
}

/// 由重建参数构建一份新的 `ServiceInfo`。抽出来是因为初次注册(`start`)与
/// 排除清单变更后的 `re_register` 需要用同一套参数重建——`ServiceInfo`
/// 按值被 `daemon.register()` 消费,旧实例不能重复使用。
fn build_service_info(
    instance: &str,
    host: &str,
    fingerprint: &str,
    nickname: &str,
    group: Option<&str>,
    port: u16,
) -> Result<ServiceInfo, mdns_sd::Error> {
    // group 无值时写空串占位:TXT 字段固定存在,解析侧空串→None(M7a)。
    let props = [
        ("v", "1"),
        ("fp", fingerprint),
        ("nick", nickname),
        ("group", group.unwrap_or("")),
        ("caps", "native"),
    ];
    Ok(ServiceInfo::new(SERVICE_TYPE, instance, host, "", port, &props[..])?.enable_addr_auto())
}

/// 计算排除清单从 `prev` 变为 `next` 的增量:新纳入排除的网卡名、重新放行
/// 的网卡名。纯函数、不接触 daemon,供下方单测覆盖全部 diff 场景
/// (新增/移除/无变化/首次提交)。
fn exclusion_diff(prev: &[String], next: &[String]) -> (Vec<String>, Vec<String>) {
    let newly_excluded: Vec<String> = next
        .iter()
        .filter(|name| !prev.contains(name))
        .cloned()
        .collect();
    let re_enabled: Vec<String> = prev
        .iter()
        .filter(|name| !next.contains(name))
        .cloned()
        .collect();
    (newly_excluded, re_enabled)
}

impl Discovery {
    /// 注册自身并开始浏览。解析到的对端(按 fp 过滤自己)发 Seen;服务消失发 Lost。
    pub fn start(
        identity: &Identity,
        nickname: &str,
        group: Option<&str>,
        port: u16,
        tx: Sender<DiscoveryEvent>,
    ) -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        // 实例名用 fp 前 16 位:稳定、可辨识、避免昵称冲突/非法字符
        let instance = identity
            .fingerprint
            .get(..16)
            .ok_or_else(|| mdns_sd::Error::Msg("fingerprint 短于 16 字符".into()))?
            .to_string();
        let host = format!("{instance}.local.");
        let fingerprint = identity.fingerprint.clone();
        let nickname_owned = nickname.to_string();
        let group_owned = group.map(str::to_string);
        let info = build_service_info(
            &instance,
            &host,
            &fingerprint,
            &nickname_owned,
            group_owned.as_deref(),
            port,
        )?;
        let fullname = info.get_fullname().to_string();
        daemon.register(info)?;

        let receiver = daemon.browse(SERVICE_TYPE)?;
        let self_fp = identity.fingerprint.clone();
        std::thread::spawn(move || {
            // fullname -> fp:ServiceRemoved 只给 fullname,在 Resolved 时记映射
            let mut known: HashMap<String, String> = HashMap::new();
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let fp = info
                            .get_property_val_str("fp")
                            .unwrap_or_default()
                            .to_string();
                        if fp.is_empty() || fp == self_fp {
                            continue;
                        }
                        known.insert(info.get_fullname().to_string(), fp.clone());
                        let nickname = info.get_property_val_str("nick").unwrap_or("?").to_string();
                        // TXT "group" 空串占位 → None(M7a,与 build_service_info 对称)
                        let group = info
                            .get_property_val_str("group")
                            .filter(|g| !g.is_empty())
                            .map(str::to_string);
                        let addrs = info.get_addresses().iter().copied().collect();
                        if tx
                            .send(DiscoveryEvent::Seen {
                                fingerprint: fp,
                                nickname,
                                addrs,
                                port: info.get_port(),
                                protocol: Protocol::Native,
                                group,
                            })
                            .is_err()
                        {
                            break; // 接收端已销毁,退出线程
                        }
                    }
                    ServiceEvent::ServiceRemoved(_ty, fullname) => {
                        if let Some(fp) = known.remove(&fullname) {
                            if tx.send(DiscoveryEvent::Lost { fingerprint: fp }).is_err() {
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            daemon,
            fullname,
            fingerprint,
            nickname: nickname_owned,
            group: group_owned,
            port,
            instance,
            host,
            applied_disabled: Vec::new(),
        })
    }

    /// 提交"期望禁用的网卡名集合"(设计文档:网卡选择 Step 5 + 网络范围限定)。
    /// 幂等:内部用 `exclusion_diff(&self.applied_disabled, desired)` 算增量,
    /// 无变化直接返回 `Ok(false)`、不碰 daemon(见文件头注释,selection
    /// 是追加式的);有变化则:
    /// 1. 分别 `disable_interface`/`enable_interface`(按名字 selection,对
    ///    未来同名网卡持久生效,热插拔由 daemon 自查,不需要我们管);
    /// 2. 再 `re_register` 一次:disable 不清 addr_auto 服务 A 记录里的旧
    ///    IP(文件头坑位),必须靠重建 ServiceInfo 才能让残留 IP 消失;
    /// 3. 记录新的已提交集合,返回 `Ok(true)`。
    pub fn set_disabled_interfaces(&mut self, desired: &[String]) -> Result<bool, mdns_sd::Error> {
        let mut desired: Vec<String> = desired.to_vec();
        desired.sort();
        desired.dedup();
        let (newly_disabled, re_enabled) = exclusion_diff(&self.applied_disabled, &desired);
        if newly_disabled.is_empty() && re_enabled.is_empty() {
            return Ok(false);
        }
        if !newly_disabled.is_empty() {
            let names: Vec<&str> = newly_disabled.iter().map(String::as_str).collect();
            self.daemon.disable_interface(names)?;
        }
        if !re_enabled.is_empty() {
            let names: Vec<&str> = re_enabled.iter().map(String::as_str).collect();
            self.daemon.enable_interface(names)?;
        }
        self.re_register()?;
        self.applied_disabled = desired;
        Ok(true)
    }

    /// 当前已提交给 daemon 的禁用集合(排序去重)。
    pub fn applied_disabled(&self) -> &[String] {
        &self.applied_disabled
    }

    /// 运行时改名(昵称热生效):更新自持昵称后走既有 `re_register`
    /// (unregister + 以新 TXT 重新 register,fire-and-forget,见其文档注释)。
    /// BigPaw 对端通过 TXT 变更即时看到新名字。
    pub fn set_nickname(&mut self, nickname: &str) -> Result<(), mdns_sd::Error> {
        self.nickname = nickname.to_string();
        self.re_register()
    }

    /// 运行时改组名(M7a 热生效):更新自持组名后走既有 `re_register`,
    /// 对端通过 TXT "group" 变更即时看到新分组。模式同 `set_nickname`。
    pub fn set_group(&mut self, group: Option<&str>) -> Result<(), mdns_sd::Error> {
        self.group = group.map(str::to_string);
        self.re_register()
    }

    /// unregister 旧实例、register 一份新构建的 ServiceInfo,重建
    /// `enable_addr_auto` 的地址集合(只在 `apply_exclusions` 确认清单真变化
    /// 后调用,见其文档注释与文件头坑位说明)。instance/host 不变,
    /// fullname 理论上应保持一致,这里仍从新 `ServiceInfo` 重新取一次,
    /// 不假设 mdns-sd 内部实现细节。
    ///
    /// 注意:这里**不**像 `shutdown` 那样同步等 unregister 的
    /// `Receiver<UnregisterStatus>`——`shutdown` 是一次性终局关停,阻塞
    /// ≤1s 换确定性划算;`apply_exclusions`/`re_register` 是运行期热路径
    /// (Step 7 会在持有 `Core::discovery` 的 `Mutex` 时调用它),同步等待
    /// 会变成"锁内阻塞网络 IO"——正是这个代码库刻意避免的反模式(见
    /// `core.rs` 里 `ipmsg` 字段的锁使用注释)。安全性依据:mdns-sd 的
    /// daemon 命令由其内部线程按队列顺序串行处理,`unregister` 与紧随其后
    /// 的 `register` 的先后顺序由这个队列保证,调用方不需要同步等待
    /// unregister 处理完才能提交 register。
    fn re_register(&mut self) -> Result<(), mdns_sd::Error> {
        // fire-and-forget:只投递命令,不等结果(见上方注释)。
        let _ = self.daemon.unregister(&self.fullname);
        let info = build_service_info(
            &self.instance,
            &self.host,
            &self.fingerprint,
            &self.nickname,
            self.group.as_deref(),
            self.port,
        )?;
        self.fullname = info.get_fullname().to_string();
        self.daemon.register(info)?;
        Ok(())
    }

    /// 主动注销(发 mDNS goodbye)并停掉守护。
    pub fn shutdown(self) {
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            // 等 goodbye 真正处理完,上限 1s,比盲睡 200ms 更确定
            let _ = rx.recv_timeout(std::time::Duration::from_secs(1));
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_diff_first_submission_excludes_all() {
        // Core::start 的初始接线:prev=[](还没提交过任何清单)。
        let (newly_excluded, re_enabled) =
            exclusion_diff(&[], &["eth0".to_string(), "wlan0".to_string()]);
        assert_eq!(
            newly_excluded,
            vec!["eth0".to_string(), "wlan0".to_string()]
        );
        assert!(re_enabled.is_empty());
    }

    #[test]
    fn exclusion_diff_no_change_is_a_noop() {
        let prev = vec!["eth0".to_string()];
        let (newly_excluded, re_enabled) = exclusion_diff(&prev, &prev.clone());
        assert!(newly_excluded.is_empty());
        assert!(re_enabled.is_empty());
    }

    #[test]
    fn exclusion_diff_detects_added_and_removed_names() {
        let prev = vec!["eth0".to_string(), "wlan0".to_string()];
        let next = vec!["wlan0".to_string(), "utun3".to_string()];
        let (newly_excluded, re_enabled) = exclusion_diff(&prev, &next);
        assert_eq!(newly_excluded, vec!["utun3".to_string()]);
        assert_eq!(re_enabled, vec!["eth0".to_string()]);
    }

    #[test]
    fn exclusion_diff_empty_to_empty_is_a_noop() {
        let (newly_excluded, re_enabled) = exclusion_diff(&[], &[]);
        assert!(newly_excluded.is_empty());
        assert!(re_enabled.is_empty());
    }

    #[test]
    fn exclusion_diff_clearing_the_list_re_enables_everything() {
        let prev = vec!["eth0".to_string(), "wlan0".to_string()];
        let (newly_excluded, re_enabled) = exclusion_diff(&prev, &[]);
        assert!(newly_excluded.is_empty());
        assert_eq!(re_enabled, vec!["eth0".to_string(), "wlan0".to_string()]);
    }

    /// `set_disabled_interfaces` 内部按 `applied_disabled` 做 diff:同一期望
    /// 集合重复提交不再触碰 daemon(返回 false),集合变化才提交(返回 true)。
    /// 起一个真实 daemon(不依赖组播可达性,只验证本地状态推进)。
    #[test]
    fn set_disabled_interfaces_is_idempotent_and_tracks_applied_set() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(dir.path()).unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut d = Discovery::start(&id, "n", None, 0, tx).unwrap();
        assert!(d.applied_disabled().is_empty());

        let want = vec!["not-a-real-iface".to_string()];
        assert!(d.set_disabled_interfaces(&want).unwrap(), "首次提交应触碰 daemon");
        assert_eq!(d.applied_disabled(), want.as_slice());
        assert!(!d.set_disabled_interfaces(&want).unwrap(), "同一集合重复提交应为 no-op");

        assert!(d.set_disabled_interfaces(&[]).unwrap(), "清空应重新放行");
        assert!(d.applied_disabled().is_empty());
        d.shutdown();
    }

    #[test]
    fn build_service_info_embeds_nickname_in_txt() {
        let info = build_service_info(
            "abcdef0123456789",
            "abcdef0123456789.local.",
            &"a".repeat(64),
            "新昵称",
            None,
            4600,
        )
        .unwrap();
        assert_eq!(info.get_property_val_str("nick"), Some("新昵称"));
    }

    /// M7a:TXT 携带 group 字段;无组名写空串占位(解析侧空串→None)。
    #[test]
    fn build_service_info_embeds_group_in_txt() {
        let info = build_service_info(
            "abcdef0123456789",
            "abcdef0123456789.local.",
            &"a".repeat(64),
            "昵称",
            Some("研发部"),
            4600,
        )
        .unwrap();
        assert_eq!(info.get_property_val_str("group"), Some("研发部"));
        let info2 = build_service_info(
            "abcdef0123456789",
            "abcdef0123456789.local.",
            &"a".repeat(64),
            "昵称",
            None,
            4600,
        )
        .unwrap();
        assert_eq!(info2.get_property_val_str("group"), Some(""), "无组名写空串占位");
    }
}

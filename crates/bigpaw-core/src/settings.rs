//! 用户设置(M6):`data_dir/settings.json`。昵称/IPMsg 开关在 Core::start
//! 时读取(重启后生效);下载目录由壳层命令即时读取。

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub nickname: Option<String>,
    /// 自我归属分组(M7a):单层组名,None=未设置。广播给全网对端(含飞秋)。
    pub group: Option<String>,
    pub download_dir: Option<String>,
    pub ipmsg_enabled: bool,
    pub excluded_interfaces: Vec<String>,
    /// 允许的对端地址范围清单(网络范围限定):每项为单 IP / CIDR / 起-止
    /// 区间文本,由 `net_scope::NetScope::parse` 解析;空 = 不限制。
    pub allowed_networks: Vec<String>,
    /// 全局通知开关(M8)。关闭后不弹系统通知,但托盘红点仍更新
    /// ——关通知 ≠ 关未读指示。
    pub notify_enabled: bool,
    /// 提示音开关(M8)。语义见 notify.rs 的 sound_name():
    /// 插件的 sound 是「显式指定音源」而非开关。
    pub notify_sound: bool,
    /// 通知正文是否显示消息内容(M8)。关闭后正文固定为「发来一条新消息」,
    /// 用于投屏、共享桌面等场合。
    pub notify_show_preview: bool,
    /// 已静音的会话 id(M8):单聊=对端指纹,群聊=groupId。
    /// 用 Vec 而非 map,与 excluded_interfaces / allowed_networks 保持一致。
    pub muted_conversations: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            nickname: None,
            group: None,
            download_dir: None,
            ipmsg_enabled: true, // 与 M5 现状一致:默认尝试启用兼容层
            excluded_interfaces: Vec::new(),
            allowed_networks: Vec::new(),
            notify_enabled: true,
            notify_sound: true,
            notify_show_preview: true,
            muted_conversations: Vec::new(),
        }
    }
}

/// 读不到/解析失败一律回退默认值:设置文件损坏不该让 app 起不来。
pub fn load(data_dir: &Path) -> Settings {
    std::fs::read_to_string(data_dir.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(data_dir: &Path, settings: &Settings) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(settings).expect("settings 可序列化");
    std::fs::write(data_dir.join("settings.json"), json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let s = load(dir.path());
        assert_eq!(s, Settings::default());
        assert!(s.ipmsg_enabled, "IPMsg 默认开启(与现状一致)");
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        // 这里**故意**穷举全部字段、不写 `..Settings::default()`:它是一根绊线。
        // 新增字段时本测试会编译失败,提醒开发者回头检查所有消费点
        // (Core::apply_settings、壳层命令、Notifier 的设置缓存、前端 Settings
        // 接口与设置页)。本文件其余测试保持 spread 写法,只有这一处担此职责,
        // 所以**不要**给它补 spread。
        let s = Settings {
            nickname: Some("大脚猫".to_string()),
            group: None,
            download_dir: Some("/tmp/dl".to_string()),
            ipmsg_enabled: false,
            excluded_interfaces: Vec::new(),
            allowed_networks: Vec::new(),
            notify_enabled: false,
            notify_sound: false,
            notify_show_preview: false,
            muted_conversations: vec!["abc123".to_string()],
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()), s);
    }

    #[test]
    fn load_corrupt_file_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{oops").unwrap();
        assert_eq!(load(dir.path()), Settings::default());
    }

    #[test]
    fn excluded_interfaces_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings {
            nickname: Some("大脚猫".to_string()),
            group: None,
            download_dir: Some("/tmp/dl".to_string()),
            ipmsg_enabled: false,
            excluded_interfaces: vec!["eth0".to_string(), "wlan0".to_string()],
            allowed_networks: Vec::new(),
            ..Settings::default()
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()), s);
    }

    #[test]
    fn group_roundtrip_and_old_json_compat() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings {
            group: Some("研发部".to_string()),
            ..Settings::default()
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()).group, Some("研发部".to_string()));
        // 旧配置无 group 字段 → None
        let old: Settings = serde_json::from_str(r#"{"nickname":"旧"}"#).unwrap();
        assert_eq!(old.group, None);
    }

    #[test]
    fn allowed_networks_roundtrip_and_old_json_compat() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings {
            allowed_networks: vec!["192.168.1.0/24".to_string(), "10.0.0.5".to_string()],
            ..Settings::default()
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()).allowed_networks, s.allowed_networks);
        // 旧配置无 allowedNetworks 字段 → 空清单(不限制)
        let old: Settings = serde_json::from_str(r#"{"nickname":"旧"}"#).unwrap();
        assert!(old.allowed_networks.is_empty());
        // 序列化键名为 camelCase
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"allowedNetworks\""));
    }

    #[test]
    fn old_json_without_excluded_interfaces_deserializes_to_empty_list() {
        let old_json = r#"{"nickname":"旧配置","ipMsgEnabled":true}"#;
        let s: Settings = serde_json::from_str(old_json).unwrap();
        assert_eq!(s.nickname, Some("旧配置".to_string()));
        assert!(s.ipmsg_enabled);
        assert_eq!(s.excluded_interfaces, Vec::<String>::new());
    }

    #[test]
    fn notify_fields_default_to_on() {
        let s = Settings::default();
        assert!(s.notify_enabled, "默认开启通知");
        assert!(s.notify_sound, "默认开启提示音");
        assert!(s.notify_show_preview, "默认显示消息内容");
        assert!(s.muted_conversations.is_empty(), "默认没有静音会话");
    }

    #[test]
    fn notify_fields_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings {
            notify_enabled: false,
            notify_sound: false,
            notify_show_preview: false,
            muted_conversations: vec!["abc123".to_string(), "group-1".to_string()],
            ..Settings::default()
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()), s);
    }

    #[test]
    fn old_json_without_notify_fields_defaults_to_on() {
        // 旧配置文件没有这些字段:三个开关都必须回退为 true,静音清单为空。
        // 若回退成 false,老用户升级后会「静悄悄地」收不到任何通知。
        let old: Settings = serde_json::from_str(r#"{"nickname":"旧配置"}"#).unwrap();
        assert!(old.notify_enabled);
        assert!(old.notify_sound);
        assert!(old.notify_show_preview);
        assert!(old.muted_conversations.is_empty());

        let json = serde_json::to_string(&Settings::default()).unwrap();
        assert!(json.contains("\"notifyEnabled\""));
        assert!(json.contains("\"notifySound\""));
        assert!(json.contains("\"notifyShowPreview\""));
        assert!(json.contains("\"mutedConversations\""));
    }
}

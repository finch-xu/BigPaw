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
        let s = Settings {
            nickname: Some("大脚猫".to_string()),
            group: None,
            download_dir: Some("/tmp/dl".to_string()),
            ipmsg_enabled: false,
            excluded_interfaces: Vec::new(),
            allowed_networks: Vec::new(),
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
}

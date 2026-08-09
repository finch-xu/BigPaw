//! 用户设置(M6):`data_dir/settings.json`。昵称/IPMsg 开关在 Core::start
//! 时读取(重启后生效);下载目录由壳层命令即时读取。

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub nickname: Option<String>,
    pub download_dir: Option<String>,
    pub ipmsg_enabled: bool,
    pub excluded_interfaces: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            nickname: None,
            download_dir: None,
            ipmsg_enabled: true, // 与 M5 现状一致:默认尝试启用兼容层
            excluded_interfaces: Vec::new(),
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
            download_dir: Some("/tmp/dl".to_string()),
            ipmsg_enabled: false,
            excluded_interfaces: Vec::new(),
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
            download_dir: Some("/tmp/dl".to_string()),
            ipmsg_enabled: false,
            excluded_interfaces: vec!["eth0".to_string(), "wlan0".to_string()],
        };
        save(dir.path(), &s).unwrap();
        assert_eq!(load(dir.path()), s);
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

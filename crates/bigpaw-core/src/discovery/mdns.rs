//! mDNS 发现主通道(设计文档 §4):应用内自带协议栈,不依赖系统 Bonjour。
//! 注册 `_bigpaw._tcp.local.`,TXT 携带 fingerprint/昵称/能力位/协议版本;
//! 浏览同类型服务,解析出的对端转成 DiscoveryEvent 发往 roster。

use crate::identity::Identity;
use crate::roster::DiscoveryEvent;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::mpsc::Sender;

pub const SERVICE_TYPE: &str = "_bigpaw._tcp.local.";

pub struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Discovery {
    /// 注册自身并开始浏览。解析到的对端(按 fp 过滤自己)发 Seen;服务消失发 Lost。
    pub fn start(
        identity: &Identity,
        nickname: &str,
        port: u16,
        tx: Sender<DiscoveryEvent>,
    ) -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        // 实例名用 fp 前 16 位:稳定、可辨识、避免昵称冲突/非法字符
        let instance = identity
            .fingerprint
            .get(..16)
            .ok_or_else(|| mdns_sd::Error::Msg("fingerprint 短于 16 字符".into()))?;
        let host = format!("{instance}.local.");
        let props = [
            ("v", "1"),
            ("fp", identity.fingerprint.as_str()),
            ("nick", nickname),
            ("caps", "native"),
        ];
        let info = ServiceInfo::new(SERVICE_TYPE, instance, &host, "", port, &props[..])?
            .enable_addr_auto();
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
                        let addrs = info.get_addresses().iter().copied().collect();
                        if tx
                            .send(DiscoveryEvent::Seen {
                                fingerprint: fp,
                                nickname,
                                addrs,
                                port: info.get_port(),
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

        Ok(Self { daemon, fullname })
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

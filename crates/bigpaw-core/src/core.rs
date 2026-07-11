//! 核心编排:identity + discovery + roster 串联,对壳层(src-tauri)暴露
//! 同步启动接口与 watch 快照订阅。零 Tauri、零异步运行时依赖。

use crate::discovery::Discovery;
use crate::identity::{Identity, IdentityError};
use crate::roster::{Peer, Roster};
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::watch;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("mdns: {0}")]
    Mdns(#[from] mdns_sd::Error),
}

pub struct CoreConfig {
    pub data_dir: PathBuf,
    /// None 时用主机名(去 .local 后缀)
    pub nickname: Option<String>,
}

pub struct Core {
    identity: Identity,
    nickname: String,
    roster_rx: watch::Receiver<Vec<Peer>>,
    discovery: std::sync::Mutex<Option<Discovery>>,
}

impl Core {
    pub fn start(cfg: CoreConfig) -> Result<Self, CoreError> {
        let identity = Identity::load_or_create(&cfg.data_dir)?;
        let nickname = cfg.nickname.unwrap_or_else(default_nickname);

        let (tx, rx) = std::sync::mpsc::channel();
        let discovery = Discovery::start(&identity, &nickname, 0, tx)?;

        let (watch_tx, watch_rx) = watch::channel(Vec::new());
        let mut roster = Roster::new(identity.fingerprint.clone());
        std::thread::spawn(move || {
            while let Ok(ev) = rx.recv() {
                if roster.apply(ev) && watch_tx.send(roster.snapshot()).is_err() {
                    break; // 订阅端全部销毁
                }
            }
        });

        Ok(Self {
            identity,
            nickname,
            roster_rx: watch_rx,
            discovery: std::sync::Mutex::new(Some(discovery)),
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.identity.fingerprint
    }

    pub fn nickname(&self) -> &str {
        &self.nickname
    }

    pub fn roster_snapshot(&self) -> Vec<Peer> {
        self.roster_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<Vec<Peer>> {
        self.roster_rx.clone()
    }

    /// 主动下线:注销 mDNS(发 goodbye),对端立刻收到 Lost 而不是等 TTL 过期。幂等。
    pub fn shutdown(&self) {
        let discovery = self
            .discovery
            .lock()
            .expect("discovery lock poisoned")
            .take();
        if let Some(d) = discovery {
            d.shutdown();
        }
    }
}

fn default_nickname() -> String {
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    host.trim_end_matches(".local").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_creates_identity_and_empty_roster() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        assert_eq!(core.fingerprint().len(), 64);
        assert_eq!(core.nickname(), "tester");
        assert!(core.roster_snapshot().is_empty());
        assert!(dir.path().join("identity.key.der").exists());
    }

    #[test]
    fn default_nickname_is_hostname_without_local_suffix() {
        let n = default_nickname();
        assert!(!n.is_empty());
        assert!(!n.ends_with(".local"));
    }

    #[test]
    fn shutdown_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::start(CoreConfig {
            data_dir: dir.path().to_path_buf(),
            nickname: Some("tester".to_string()),
        })
        .unwrap();
        core.shutdown();
        core.shutdown(); // 第二次调用不得 panic
    }
}

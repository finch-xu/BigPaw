//! 长期身份:自签证书 + 私钥,fingerprint = 证书 DER 的 SHA-256(小写 hex 64 字符)。
//! fingerprint 用于发现去重、防自发现、记住设备,并在 M2 绑定 TLS 加密信道(设计文档 §4)。

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("证书生成失败: {0}")]
    Rcgen(#[from] rcgen::Error),
}

pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub fingerprint: String,
}

impl Identity {
    /// 从 data_dir 加载身份;不存在则生成并落盘(identity.cert.der / identity.key.der,私钥 0600)。
    pub fn load_or_create(data_dir: &Path) -> Result<Self, IdentityError> {
        let cert_path = data_dir.join("identity.cert.der");
        let key_path = data_dir.join("identity.key.der");
        if cert_path.exists() && key_path.exists() {
            return Ok(Self::from_parts(
                fs::read(&cert_path)?,
                fs::read(&key_path)?,
            ));
        }
        fs::create_dir_all(data_dir)?;
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["bigpaw".to_string()])?;
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        fs::write(&cert_path, &cert_der)?;
        Self::write_key_owner_only(&key_path, &key_der)?;
        Ok(Self::from_parts(cert_der, key_der))
    }

    /// 私钥文件必须从创建那一刻起就是 0600,不能先写后收权限(TOCTOU)。
    fn write_key_owner_only(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(data)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            // Windows 无 POSIX 位;密钥位于用户 AppData,由账户 ACL 保护(M6 再评估 DPAPI)
            fs::write(path, data)
        }
    }

    fn from_parts(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        let fingerprint = hex::encode(Sha256::digest(&cert_der));
        Self {
            cert_der,
            key_der,
            fingerprint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(dir.path()).unwrap();
        let b = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint, "重载后 fingerprint 必须不变");
        assert_eq!(a.fingerprint.len(), 64);
        assert!(a
            .fingerprint
            .chars()
            .all(|c: char| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn distinct_dirs_get_distinct_identities() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(d1.path()).unwrap();
        let b = Identity::load_or_create(d2.path()).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        Identity::load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("identity.key.der"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "私钥必须 0600");
    }
}

//! 原生传输层(设计文档 §5):TLS 1.3 + 长度前缀 JSON 帧,同步 IO + 线程。

pub mod filexfer;
pub mod manager;
pub mod proto;
pub mod tls;

pub use tls::TlsError;

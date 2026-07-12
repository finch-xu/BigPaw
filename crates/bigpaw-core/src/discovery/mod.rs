//! 发现层:mDNS 主通道 + UDP 宣告辅通道 + 单播探测兜底(设计文档 §4)。

pub mod announce;
pub mod mdns;

// 保持对外 API 兼容:原 discovery::Discovery / SERVICE_TYPE 仍可用
pub use mdns::{Discovery, SERVICE_TYPE};

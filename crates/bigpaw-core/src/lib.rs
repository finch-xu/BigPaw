//! BigPaw 核心：identity / discovery / transport / roster。
//! 铁律：本 crate 零 Tauri 依赖，全部网络与磁盘 IO 在此闭环。

/// 原生协议版本，握手帧携带（设计文档 §5.2）。
pub const PROTOCOL_VERSION: u16 = 1;

pub mod identity;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}

//! IPMsg/飞秋兼容层。范围冻结（设计文档 §6）：仅标准命令集，不做方言扩展。

/// IPMsg 标准端口（UDP 与 TCP 同号）。
pub const IPMSG_PORT: u16 = 2425;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipmsg_port_is_2425() {
        assert_eq!(IPMSG_PORT, 2425);
    }
}

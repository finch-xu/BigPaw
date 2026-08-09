//! IPMsg 报文:`版本:包编号:发送者:主机名:命令字:附加数据`,GBK 编码。
//! 严格生成、宽容解析(版本字段不透明,未知命令交上层忽略)。

use encoding_rs::GBK;

/// 埋在 extra 尾部的自有标识,飞秋会忽略;用于识别对端为本 app。
pub const BIGPAW_TAG: &str = "\u{0}BIGPAW";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub version: String,
    pub packet_no: u32,
    pub sender: String,
    pub host: String,
    pub command: u32,
    pub extra: String,
}

/// GBK 编码;不可映射字符替换为 '?'(不是 encoding_rs 默认的 HTML 实体)。
pub fn gbk_encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let mut buf = [0u8; 4];
        let piece = ch.encode_utf8(&mut buf);
        let (cow, _, had_errors) = GBK.encode(piece);
        if had_errors {
            out.push(b'?');
        } else {
            out.extend_from_slice(&cow);
        }
    }
    out
}

pub fn gbk_decode(b: &[u8]) -> String {
    let (cow, _, _) = GBK.decode(b);
    cow.into_owned()
}

/// wire 报文以 `\0` 结尾:飞鸽/飞秋参考实现按 `strlen(buf)+1` 发送(C 字符串
/// 语义),对端也按 C 字符串解析——缺了这个字节,真实飞秋可能解析失败
/// (实测症状:TCP GETFILEDATA 请求发过去后对端不回数据,读超时"接收失败")。
pub fn encode(p: &Packet) -> Vec<u8> {
    let s = format!(
        "{}:{}:{}:{}:{}:{}",
        p.version, p.packet_no, p.sender, p.host, p.command, p.extra
    );
    let mut out = gbk_encode(&s);
    out.push(0);
    out
}

pub fn decode(buf: &[u8]) -> Option<Packet> {
    // 剥掉 C 实现的尾部 NUL(可能不止一个:有实现按固定缓冲区补零)。只剥
    // **结尾**,extra 内部的 `\0`(FILEATTACHOPT 正文/清单分隔、BIGPAW_TAG)
    // 必须原样保留。不剥的话,extra 最后一个字段会带 `\0`,下游严格 hex
    // 解析(如 GETFILEDATA 的 offset)直接失败。
    let mut end = buf.len();
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    let buf = &buf[..end];
    if buf.is_empty() {
        return None;
    }
    let s = gbk_decode(buf);
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() < 6 {
        return None;
    }
    Some(Packet {
        version: parts[0].to_string(),
        packet_no: parts[1].parse().ok()?,
        sender: parts[2].to_string(),
        host: parts[3].to_string(),
        command: parts[4].parse().ok()?,
        extra: parts[5].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbk_roundtrip_chinese() {
        let s = "你好世界";
        let b = gbk_encode(s);
        assert_eq!(gbk_decode(&b), s);
        // GBK 不是 UTF-8:中文应该是 2 字节/字
        assert_eq!(b.len(), 8);
    }

    #[test]
    fn gbk_unmappable_becomes_question_mark() {
        let s = "hi🐾"; // emoji 无 GBK 映射
        let b = gbk_encode(s);
        let back = gbk_decode(&b);
        assert!(back.starts_with("hi"));
        assert!(back.contains('?'));
    }

    #[test]
    fn packet_roundtrip() {
        let p = Packet {
            version: "1".to_string(),
            packet_no: 12345,
            sender: "张三".to_string(),
            host: "PC-01".to_string(),
            command: 0x20,
            extra: "你好".to_string(),
        };
        let buf = encode(&p);
        let back = decode(&buf).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn decode_treats_version_as_opaque() {
        // 飞秋的私有版本串不能导致丢包
        let raw = gbk_encode("1_lbt6_8#998#abc:100:feiq:HOST:32:hello");
        let p = decode(&raw).unwrap();
        assert_eq!(p.version, "1_lbt6_8#998#abc");
        assert_eq!(p.packet_no, 100);
        assert_eq!(p.command, 32);
        assert_eq!(p.extra, "hello");
    }

    #[test]
    fn extra_may_contain_colons() {
        let raw = gbk_encode("1:5:me:HOST:32:a:b:c");
        let p = decode(&raw).unwrap();
        assert_eq!(p.extra, "a:b:c"); // 只按前 5 个冒号分割
    }

    #[test]
    fn decode_garbage_is_none() {
        assert!(decode(b"").is_none());
        assert!(decode(&gbk_encode("only:three:fields")).is_none());
    }

    /// 互通关键(飞秋对拍修复):飞鸽/飞秋参考实现发包长度为 `strlen(buf)+1`,
    /// 即报文自带尾部 `\0`。decode 必须把**结尾**的 NUL 剥掉,否则 extra 的最后
    /// 一个字段会带着 `\0`(例如 GETFILEDATA 的 offset 字段变成 `"0\0"`),
    /// 严格 hex 解析直接失败 → 飞秋侧表现为"传输失败"。
    #[test]
    fn decode_strips_trailing_nul_from_c_implementations() {
        let raw = gbk_encode("1:100:feiq:HOST:96:abc:0:0\u{0}");
        let p = decode(&raw).unwrap();
        assert_eq!(p.extra, "abc:0:0", "尾部 \\0 必须被剥掉");

        // 多个尾部 NUL 也要容忍(有实现按固定缓冲区补零)。
        let raw2 = gbk_encode("1:5:me:HOST:32:hello\u{0}\u{0}\u{0}");
        assert_eq!(decode(&raw2).unwrap().extra, "hello");
    }

    /// 尾部剥离绝不能伤及 extra **内部**的 NUL——FILEATTACHOPT 的正文/清单
    /// 分隔符、BIGPAW_TAG 都依赖内部 `\0`。
    #[test]
    fn decode_keeps_interior_nul_intact() {
        let raw = gbk_encode("1:7:me:HOST:2097184:正文\u{0}0:a.txt:5:0:1:\u{0}");
        let p = decode(&raw).unwrap();
        assert_eq!(p.extra, "正文\u{0}0:a.txt:5:0:1:");
    }

    /// 对称面:我方发出的报文也要带尾部 `\0`(参考实现 `strlen+1` 语义),
    /// 否则飞秋按 C 字符串解析我方 TCP GETFILEDATA 请求时可能失败,
    /// 表现为对端永不回数据、我方 read 超时"接收失败"。
    #[test]
    fn encode_appends_trailing_nul() {
        let p = Packet {
            version: "1".to_string(),
            packet_no: 1,
            sender: "me".to_string(),
            host: "H".to_string(),
            command: 0x60,
            extra: "a:0:0".to_string(),
        };
        let buf = encode(&p);
        assert_eq!(buf.last(), Some(&0u8), "wire 报文必须以 \\0 结尾");
        // 且 encode→decode 往返仍然无损(decode 会剥掉这个 NUL)。
        assert_eq!(decode(&buf).unwrap(), p);
    }
}

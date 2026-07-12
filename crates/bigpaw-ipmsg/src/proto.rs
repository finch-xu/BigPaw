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

pub fn encode(p: &Packet) -> Vec<u8> {
    let s = format!(
        "{}:{}:{}:{}:{}:{}",
        p.version, p.packet_no, p.sender, p.host, p.command, p.extra
    );
    gbk_encode(&s)
}

pub fn decode(buf: &[u8]) -> Option<Packet> {
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
}

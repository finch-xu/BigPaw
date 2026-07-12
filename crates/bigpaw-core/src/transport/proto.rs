//! 消息帧:[4B BE 总长(类型+payload)][1B 类型][JSON payload]。
//! 上限 1MiB;超限/未知类型 = InvalidData(严格生成、宽容解析只适用 IPMsg 层,原生层收到坏帧断连)。

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_FRAME: usize = 1024 * 1024;
pub const PROTO_V: u16 = 1;

const T_HELLO: u8 = 1;
const T_TEXT: u8 = 2;
const T_FILE_OFFER: u8 = 3;
const T_FILE_ACCEPT: u8 = 4;
const T_FILE_REJECT: u8 = 5;
const T_FILE_START: u8 = 6;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Msg {
    Hello {
        v: u16,
    },
    Text {
        id: String,
        body: String,
        ts_ms: u64,
    },
    FileOffer {
        xfer_id: String,
        name: String,
        size: u64,
        blake3: String,
    },
    FileAccept {
        xfer_id: String,
        offset: u64,
    },
    FileReject {
        xfer_id: String,
    },
    FileStart {
        xfer_id: String,
        offset: u64,
    },
}

impl Msg {
    fn type_byte(&self) -> u8 {
        match self {
            Msg::Hello { .. } => T_HELLO,
            Msg::Text { .. } => T_TEXT,
            Msg::FileOffer { .. } => T_FILE_OFFER,
            Msg::FileAccept { .. } => T_FILE_ACCEPT,
            Msg::FileReject { .. } => T_FILE_REJECT,
            Msg::FileStart { .. } => T_FILE_START,
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn write_msg(w: &mut impl Write, msg: &Msg) -> io::Result<()> {
    // 序列化 payload:去掉外层枚举标签,只留字段对象
    let payload = match msg {
        Msg::Hello { v } => serde_json::json!({ "v": v }),
        Msg::Text { id, body, ts_ms } => {
            serde_json::json!({ "id": id, "body": body, "ts_ms": ts_ms })
        }
        Msg::FileOffer {
            xfer_id,
            name,
            size,
            blake3,
        } => serde_json::json!({
            "xfer_id": xfer_id,
            "name": name,
            "size": size,
            "blake3": blake3
        }),
        Msg::FileAccept { xfer_id, offset } => {
            serde_json::json!({ "xfer_id": xfer_id, "offset": offset })
        }
        Msg::FileReject { xfer_id } => serde_json::json!({ "xfer_id": xfer_id }),
        Msg::FileStart { xfer_id, offset } => {
            serde_json::json!({ "xfer_id": xfer_id, "offset": offset })
        }
    };
    let bytes = serde_json::to_vec(&payload)?;
    let total = bytes.len() + 1;
    if total > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(total as u32).to_be_bytes())?;
    w.write_all(&[msg.type_byte()])?;
    w.write_all(&bytes)?;
    w.flush()
}

pub fn read_msg(r: &mut impl Read) -> io::Result<Msg> {
    let mut len4 = [0u8; 4];
    r.read_exact(&mut len4)?;
    let total = u32::from_be_bytes(len4) as usize;
    if total == 0 || total > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame size out of range",
        ));
    }
    let mut ty = [0u8; 1];
    r.read_exact(&mut ty)?;
    let mut payload = vec![0u8; total - 1];
    r.read_exact(&mut payload)?;
    let val: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    match ty[0] {
        T_HELLO => Ok(Msg::Hello {
            v: val.get("v").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
        }),
        T_TEXT => Ok(Msg::Text {
            id: val
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            body: val
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            ts_ms: val.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        }),
        T_FILE_OFFER => Ok(Msg::FileOffer {
            xfer_id: val
                .get("xfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            name: val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            size: val.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            blake3: val
                .get("blake3")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        T_FILE_ACCEPT => Ok(Msg::FileAccept {
            xfer_id: val
                .get("xfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            offset: val.get("offset").and_then(|v| v.as_u64()).unwrap_or(0),
        }),
        T_FILE_REJECT => Ok(Msg::FileReject {
            xfer_id: val
                .get("xfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        T_FILE_START => Ok(Msg::FileStart {
            xfer_id: val
                .get("xfer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            offset: val.get("offset").and_then(|v| v.as_u64()).unwrap_or(0),
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown frame type",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_hello_and_text() {
        let msgs = vec![
            Msg::Hello { v: 1 },
            Msg::Text {
                id: new_id(),
                body: "你好 BigPaw🐾".to_string(),
                ts_ms: now_ms(),
            },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_msg(&mut buf, m).unwrap();
        }
        let mut r = Cursor::new(buf);
        for m in &msgs {
            assert_eq!(&read_msg(&mut r).unwrap(), m);
        }
    }

    #[test]
    fn oversize_frame_is_rejected_without_allocation() {
        // 手工构造超限长度头
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        buf.push(2);
        let err = read_msg(&mut Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn unknown_type_is_invalid_data() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.push(99);
        buf.extend_from_slice(b"{}");
        let err = read_msg(&mut Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn file_control_frames_roundtrip() {
        let msgs = vec![
            Msg::FileOffer {
                xfer_id: new_id(),
                name: "报告.pdf".to_string(),
                size: 10_485_760,
                blake3: "a".repeat(64),
            },
            Msg::FileAccept {
                xfer_id: new_id(),
                offset: 1_048_576,
            },
            Msg::FileReject { xfer_id: new_id() },
            Msg::FileStart {
                xfer_id: new_id(),
                offset: 0,
            },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_msg(&mut buf, m).unwrap();
        }
        let mut r = Cursor::new(buf);
        for m in &msgs {
            assert_eq!(&read_msg(&mut r).unwrap(), m);
        }
    }
}

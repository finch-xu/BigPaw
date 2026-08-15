//! IPMsg 文件传输(设计文档 §6):`SENDMSG|FILEATTACHOPT` 文件清单编解码 +
//! TCP `GETFILEDATA` 请求/供给的字节级实现 + `GETDIRFILES` 目录流**仅接收**解析。
//!
//! 报文格式依据 IPMsg 协议 Draft-10(<https://github.com/shirouzu/ipmsg/blob/master/prot-eng.txt>):
//! - 文件清单:`msgbody` + `\0` + `fileID:filename:size:mtime:fileattr[:extend-attr=...]:`,
//!   多个文件条目以 `\a`(0x07,BEL)分隔;size/mtime/fileattr 为十六进制;
//!   文件名中的 `:` 需转义为 `::`。
//! - `GETFILEDATA` 请求 extra:`packetID:fileID:offset`,全部十六进制;响应为裸字节流,无信封。
//! - `GETDIRFILES` 目录流:`header-size:filename:file-size:fileattr[...]:` + 紧跟的
//!   `file-size` 字节内容,连续多条;`header-size` 是从本条目起始到"内容前最后一个冒号"
//!   (含该冒号)的字节数,用于在文件名可能含转义冒号时仍能无歧义地找到头部终点。
//!   `fileattr` 低 8 位为 `FILE_DIR`(进入子目录,无内容)或 `FILE_RETPARENT`(文件名固定为
//!   `"."`,返回上级目录)。
//!
//! 本 crate 独立(不依赖 bigpaw-core),`safe_basename` 从 M3
//! (`bigpaw-core/src/transport/filexfer.rs`)复制而来,保持同等的路径穿越/
//! Windows 危险名防护。

use crate::command::{self, Command};
use crate::discovery::IpmsgError;
use crate::proto::{self, Packet};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// fileattr 低 8 位取值(IPMsg 协议 Draft-10 §1.4,是一组互斥的类型枚举,不是位标志)。
pub const FILE_REGULAR: u32 = 0x01;
pub const FILE_DIR: u32 = 0x02;
pub const FILE_RETPARENT: u32 = 0x03;

/// 一次 `SENDMSG|FILEATTACHOPT` 清单里的单个文件/目录条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpmsgFileEntry {
    pub file_id: u32,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

/// `packet_no -> file_id -> 磁盘路径` 的已提供文件登记表:TCP 侧只应答已登记的
/// (packet_no, file_id) 组合,防止 GETFILEDATA 被用来读任意路径。
pub type OfferedFiles = Arc<Mutex<HashMap<u32, HashMap<u32, PathBuf>>>>;

pub fn new_offered_files() -> OfferedFiles {
    Arc::new(Mutex::new(HashMap::new()))
}

/// 文件名里的 `:` 转义为 `::`(IPMsg 规范:冒号是清单/目录流的字段分隔符)。
fn escape_colon(s: &str) -> String {
    s.replace(':', "::")
}

/// 按 IPMsg 转义规则切分字段:单个 `:` 是分隔符,`::` 是字段内字面 `:`。
fn split_escaped_fields(s: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' {
            if chars.peek() == Some(&':') {
                chars.next();
                current.push(':');
            } else {
                fields.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    fields.push(current);
    fields
}

/// 构造单文件 offer 的 extra(M5 单文件发送:一次 SENDMSG 只带一个文件条目)。
pub fn build_file_offer_extra(
    msg_body: &str,
    file_id: u32,
    name: &str,
    size: u64,
    mtime: u64,
    fileattr: u32,
) -> String {
    format!(
        "{msg_body}\u{0}{file_id:x}:{}:{size:x}:{mtime:x}:{fileattr:x}:",
        escape_colon(name)
    )
}

/// 解析 `SENDMSG|FILEATTACHOPT` 的 extra → (消息正文, 文件清单)。
/// 纯函数,不做 IO;畸形条目(hex 解析失败/字段不足)静默跳过,不 panic、不影响其余条目。
pub fn parse_file_attach_extra(extra: &str) -> (String, Vec<IpmsgFileEntry>) {
    let Some(nul_pos) = extra.find('\u{0}') else {
        return (extra.to_string(), Vec::new());
    };
    let msg_body = extra[..nul_pos].to_string();
    let rest = &extra[nul_pos + 1..];
    let files = rest
        .split('\u{7}')
        .filter(|chunk| !chunk.is_empty())
        .filter_map(parse_one_file_entry)
        .collect();
    (msg_body, files)
}

fn parse_one_file_entry(chunk: &str) -> Option<IpmsgFileEntry> {
    let fields = split_escaped_fields(chunk);
    if fields.len() < 5 {
        return None;
    }
    let file_id = u32::from_str_radix(&fields[0], 16).ok()?;
    // 安全关键:对端可在清单里塞任意字符串当文件名(协议本身不禁止 `/`/`..`)。
    // 在这里就用 safe_basename 净化——非法(路径穿越/Windows 危险名/空)则整条丢弃,
    // 这样 IpmsgFileEntry.name 从构造起就是一个安全 basename,FileOffered
    // 事件永远不会携带危险文件名往下游传播(见 request_file_bytes 的第二层净化)。
    let name = safe_basename(&fields[1])?;
    let size = u64::from_str_radix(&fields[2], 16).ok()?;
    let _mtime = u64::from_str_radix(&fields[3], 16).ok()?;
    let fileattr = u32::from_str_radix(&fields[4], 16).ok()?;
    let is_dir = (fileattr & 0xff) == FILE_DIR;
    Some(IpmsgFileEntry {
        file_id,
        name,
        size,
        is_dir,
    })
}

/// `GETFILEDATA` 请求 extra:`packetID:fileID:offset`,全部十六进制(规范原文
/// "Use all hex format")。
pub fn build_getfiledata_extra(target_packet_no: u32, file_id: u32, offset: u64) -> String {
    format!("{target_packet_no:x}:{file_id:x}:{offset:x}")
}

/// 解析失败(字段不足/非十六进制)→ None,不 panic。
pub fn parse_getfiledata_extra(extra: &str) -> Option<(u32, u32, u64)> {
    let parts: Vec<&str> = extra.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let packet_no = u32::from_str_radix(parts[0], 16).ok()?;
    let file_id = u32::from_str_radix(parts[1], 16).ok()?;
    let offset = u64::from_str_radix(parts[2], 16).ok()?;
    Some((packet_no, file_id, offset))
}

// ---- safe_basename:从 bigpaw-core M3 `transport/filexfer.rs` 复制,保持 crate 独立 ----

/// Windows 保留设备名(不区分大小写,只匹配第一个 '.' 之前的 stem)。
const WINDOWS_RESERVED_STEMS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 含 Unicode 双向/格式控制字符(RTLO 等仿冒手法)。
fn contains_bidi_control(name: &str) -> bool {
    name.chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
}

/// 只取文件名部分,拒绝任何含路径分隔符/父目录/绝对路径的名字,
/// 以及会在 Windows 上引发问题的名字(保留设备名、尾部点/空格、NTFS ADS、双向控制字符仿冒)。
pub fn safe_basename(name: &str) -> Option<String> {
    if name.is_empty() || name == ".." || name == "." {
        return None;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return None;
    }
    if name.contains(':') {
        return None; // NTFS 备用数据流(ADS)
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return None; // Windows 会静默去除尾部点/空格,导致名字实际所指发生偏移
    }
    if contains_bidi_control(name) {
        return None; // RTLO 等仿冒扩展名攻击
    }
    let stem = name.split('.').next().unwrap_or(name);
    if WINDOWS_RESERVED_STEMS
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return None;
    }
    Some(name.to_string())
}

// ---- TCP GETFILEDATA:服务端(供给) ----

/// 处理一条入站 TCP 连接的单次 GETFILEDATA 请求:一次性读入请求报文(足够小,
/// 单次 read 视为完整请求——与 UDP recv_from 同样的简化,亦是 IPMsg 原始实现的
/// 行为,规范原文"send the specified data (no format)"意味着协议本身就没有为
/// 请求/响应设计额外的长度前缀信封)。只应答 `offered` 表里登记过的
/// (packet_no, file_id),未登记 → 静默关闭连接,不回一个字节(防任意路径读取)。
pub fn serve_getfiledata_request(
    stream: &mut (impl Read + Write),
    offered: &OfferedFiles,
) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let Some(packet) = proto::decode(&buf[..n]) else {
        return Ok(());
    };
    if Command(packet.command).num() != command::GETFILEDATA {
        return Ok(());
    }
    let Some((target_packet_no, file_id, offset)) = parse_getfiledata_extra(&packet.extra) else {
        return Ok(());
    };
    let path = {
        // 短临界区:只做一次查表,文件 IO(阻塞)在锁释放之后才发生。
        let guard = offered.lock().unwrap();
        guard
            .get(&target_packet_no)
            .and_then(|m| m.get(&file_id))
            .cloned()
    };
    let Some(path) = path else {
        return Ok(()); // 未登记 → 拒绝,静默关闭
    };
    let mut file = File::open(&path)?;
    io::Seek::seek(&mut file, io::SeekFrom::Start(offset))?;
    io::copy(&mut file, stream)?;
    Ok(())
}

/// TCP 监听主循环:accept 一条连接就起一个短生命周期线程处理,非阻塞 accept +
/// 轮询停止标志(与 discovery.rs 里 UDP recv_loop 的中断式设计一致)。
///
/// `peer_filter`(网络范围限定):accept 后先按对端地址过滤,范围外的连接直接
/// 丢弃(drop 即关闭),不读请求、不回数据。
pub fn tcp_serve_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    offered: OfferedFiles,
    peer_filter: crate::discovery::PeerFilter,
) {
    let _ = listener.set_nonblocking(true);
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((_stream, peer)) if !peer_filter(peer.ip()) => {
                // 范围外对端:drop 关闭连接。
            }
            Ok((mut stream, _peer)) => {
                let offered = Arc::clone(&offered);
                std::thread::spawn(move || {
                    // BSD/macOS 上 accept 出的 socket 会继承监听 socket 的非阻塞
                    // 标志,首次 read 立刻 WouldBlock 就把连接关了(对端请求稍晚
                    // 到达即失败)。显式切回阻塞,让下面的 10s 读超时真正生效。
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = serve_getfiledata_request(&mut stream, &offered);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

// ---- TCP GETFILEDATA:客户端(拉取) ----

/// 已连上对端 2425 的 TCP 流上:发送 GETFILEDATA 请求 + 读回 `size` 字节落盘。
/// `save_path` 的文件名部分会被 basename 化(拒绝穿越/危险名),且整条路径不允许
/// 出现任何 `..` 段(见 `sanitize_save_path`);最终写入路径为
/// `save_path 所在目录 / 净化后的文件名`。offset 固定为 0(M5 不做断点续传)。
#[allow(clippy::too_many_arguments)]
pub fn request_file_bytes(
    stream: &mut (impl Read + Write),
    version: &str,
    my_packet_no: u32,
    my_name: &str,
    my_host: &str,
    target_packet_no: u32,
    file_id: u32,
    size: u64,
    save_path: &Path,
) -> Result<PathBuf, IpmsgError> {
    let final_path = sanitize_save_path(save_path)?;

    let packet = Packet {
        version: version.to_string(),
        packet_no: my_packet_no,
        sender: my_name.to_string(),
        host: my_host.to_string(),
        command: command::GETFILEDATA,
        extra: build_getfiledata_extra(target_packet_no, file_id, 0),
    };
    stream.write_all(&proto::encode(&packet))?;
    stream.flush()?;

    let mut file = File::create(&final_path)?;
    let mut remaining = size;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        stream.read_exact(&mut buf[..want])?;
        file.write_all(&buf[..want])?;
        remaining -= want as u64;
    }
    file.flush()?;
    Ok(final_path)
}

/// `save_path` 的文件名部分 basename 化;目录部分按需创建。落盘文件名安全性的
/// 最后一道防线(不完全信任调用方已经净化过)。
///
/// 安全关键(纵深防御第二层):`IpmsgFileEntry.name`(唯一的不可信输入来源)
/// 已经在解析层(`parse_one_file_entry`)被 `safe_basename` 净化,不可能再带
/// `/`/`\`/`..`,所以正常的 `download_dir.join(&entry.name)` 不会产生穿越路径。
/// 但这里仍不完全信任调用方——如果 `save_path` 途中**任何一段**是 `..`
/// (`Component::ParentDir`),整条直接拒绝,而不是像旧实现那样只检查最后一段
/// (`file_name()`)、对 `parent()` 里可能残留的穿越段视而不见:那样的话,一旦
/// 调用方在解析层被绕过之前就拼出 `download_dir.join("../../../tmp/evil.txt")`
/// 这样的路径,`file_name()` 只会看到末尾的 `evil.txt`(能通过 basename 校验),
/// `parent()` 却仍然带着中间的 `..` 段,写盘时会被 OS 解析到 `download_dir`
/// 之外。这一层检查不额外校验 `save_path` 的合法目录名部分(避免对真实存在、
/// 恰好撞上 Windows 保留名/尾随空格等规则的合法目录名造成误伤),只专门堵
/// `..` 这一个逃逸向量,与解析层的 `safe_basename` 校验相互独立、互为冗余。
fn sanitize_save_path(save_path: &Path) -> Result<PathBuf, IpmsgError> {
    if save_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(IpmsgError::BadName);
    }
    let file_name = save_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(IpmsgError::BadName)?;
    let safe_name = safe_basename(file_name).ok_or(IpmsgError::BadName)?;
    let dir = match save_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir)?;
    Ok(dir.join(safe_name))
}

// ---- GETDIRFILES:仅接收方向 ----

/// 解析对端 GETDIRFILES 目录流并落盘,返回目标根目录(设计冻结 §6:文件夹**仅接收**,
/// 不实现发送/服务端)。流位置必须严格按各条目声明的字节数消费,否则会与对端失步;
/// 因此即使某个文件名不安全(basename 化失败),也要把它的内容字节读掉再继续下一条,
/// 只是不写盘、不在磁盘上创建对应目录。
pub fn receive_dir_stream(reader: &mut impl Read, dest_root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dest_root)?;
    let mut stack: Vec<PathBuf> = vec![dest_root.to_path_buf()];

    loop {
        let Some((header_size, consumed)) = read_header_size(reader)? else {
            break; // 干净的流结束(下一条目起点恰好 EOF)
        };
        if header_size < consumed {
            break; // 畸形 header-size,停止解析(不 panic)
        }
        let remaining = (header_size - consumed) as usize;
        let mut header_buf = vec![0u8; remaining];
        reader.read_exact(&mut header_buf)?;
        // 目录流头部与其余 IPMsg 报文一样走 GBK,支持中文文件/目录名。
        let header_str = proto::gbk_decode(&header_buf);
        let fields = split_escaped_fields(&header_str);
        if fields.len() < 3 {
            break; // 畸形,停止(不 panic)
        }
        let name = fields[0].clone();
        let Ok(file_size) = u64::from_str_radix(&fields[1], 16) else {
            break;
        };
        let Ok(fileattr) = u32::from_str_radix(&fields[2], 16) else {
            break;
        };
        let low = fileattr & 0xff;

        if low == FILE_RETPARENT {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }

        if low == FILE_DIR {
            let current = stack.last().unwrap().clone();
            match safe_basename(&name) {
                Some(safe_name) => {
                    let sub = current.join(safe_name);
                    fs::create_dir_all(&sub)?;
                    stack.push(sub);
                }
                None => {
                    // 非法目录名:仍压栈占位以维持 RETPARENT 出栈配平,但不在磁盘上创建。
                    stack.push(current);
                }
            }
            continue;
        }

        // 普通文件条目:必须精确消费 file_size 字节维持流同步,无论文件名是否安全。
        let current = stack.last().unwrap().clone();
        match safe_basename(&name) {
            Some(safe_name) => {
                let mut out = File::create(current.join(safe_name))?;
                copy_exact(reader, &mut out, file_size)?;
            }
            None => {
                copy_exact(reader, &mut io::sink(), file_size)?;
            }
        }
    }
    Ok(dest_root.to_path_buf())
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, size: u64) -> io::Result<()> {
    let mut remaining = size;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        reader.read_exact(&mut buf[..want])?;
        writer.write_all(&buf[..want])?;
        remaining -= want as u64;
    }
    Ok(())
}

/// 读取 `header-size`(十六进制,直到遇到 `:`)。返回 `(数值, 已消耗字节数含冒号)`;
/// 流已在干净边界结束(未读到任何字节即 EOF)→ `Ok(None)`。
fn read_header_size(reader: &mut impl Read) -> io::Result<Option<(u64, u64)>> {
    let mut digits = String::new();
    let mut one = [0u8; 1];
    loop {
        let n = reader.read(&mut one)?;
        if n == 0 {
            return if digits.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "目录流在 header-size 中截断",
                ))
            };
        }
        let c = one[0] as char;
        if c == ':' {
            return match u64::from_str_radix(&digits, 16) {
                Ok(v) => Ok(Some((v, digits.len() as u64 + 1))),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header-size 非十六进制",
                )),
            };
        }
        digits.push(c);
        if digits.len() > 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header-size 字段过长",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{TcpListener, TcpStream};

    // ---- TCP 监听的来源过滤(网络范围限定) ----

    /// 起 tcp_serve_loop,用给定过滤器;客户端连上后立即 read:
    /// 被拒绝 → 服务端 drop,客户端读到 EOF(Ok(0));
    /// 被放行 → 服务端在等请求(10s 读超时),客户端 read 在 500ms 内超时。
    fn accept_outcome(filter: crate::discovery::PeerFilter) -> std::io::Result<usize> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || tcp_serve_loop(listener, stop, new_offered_files(), filter))
        };
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut buf = [0u8; 8];
        let outcome = std::io::Read::read(&mut client, &mut buf);
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        outcome
    }

    #[test]
    fn tcp_serve_loop_drops_connections_from_filtered_peers() {
        let deny_all: crate::discovery::PeerFilter = Arc::new(|_| false);
        assert!(
            matches!(accept_outcome(deny_all), Ok(0)),
            "范围外对端的连接应被立即关闭(读到 EOF)"
        );
    }

    #[test]
    fn tcp_serve_loop_keeps_allowed_connections_open() {
        let out = accept_outcome(crate::discovery::allow_all_peers());
        assert!(
            matches!(out, Err(ref e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
            "对照组:放行的连接应保持打开等待请求,得到 {out:?}"
        );
    }

    // ---- 文件清单编解码 ----

    #[test]
    fn parse_file_attach_extra_single_file_chinese_name() {
        let extra = build_file_offer_extra("你好", 0, "图片.png", 1000, 0, FILE_REGULAR);
        let (body, files) = parse_file_attach_extra(&extra);
        assert_eq!(body, "你好");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, 0);
        assert_eq!(files[0].name, "图片.png");
        assert_eq!(files[0].size, 1000);
        assert!(!files[0].is_dir);
    }

    #[test]
    fn parse_file_attach_extra_multiple_files() {
        let e1 = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            0u32, "a.txt", 10u64, 0u64, FILE_REGULAR
        );
        let e2 = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            1u32, "b.zip", 20u64, 0u64, FILE_REGULAR
        );
        let extra = format!("hi\u{0}{e1}\u{7}{e2}");
        let (body, files) = parse_file_attach_extra(&extra);
        assert_eq!(body, "hi");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a.txt");
        assert_eq!(files[0].size, 10); // 10u64 -> hex "a" -> 十六进制解析回 10
        assert_eq!(files[1].name, "b.zip");
        assert_eq!(files[1].size, 20); // 20u64 -> hex "14" -> 十六进制解析回 20
    }

    #[test]
    fn parse_file_attach_extra_dir_entry_marks_is_dir() {
        let extra = build_file_offer_extra("", 2, "照片文件夹", 0, 0, FILE_DIR);
        let (_, files) = parse_file_attach_extra(&extra);
        assert_eq!(files.len(), 1);
        assert!(files[0].is_dir);
    }

    #[test]
    fn parse_file_attach_extra_malformed_hex_entry_is_skipped_not_panic() {
        let extra = "msg\u{0}zzz:name.txt:notafhex:0:1:";
        let (body, files) = parse_file_attach_extra(extra);
        assert_eq!(body, "msg");
        assert!(files.is_empty());
    }

    #[test]
    fn parse_file_attach_extra_no_nul_returns_body_only() {
        let (body, files) = parse_file_attach_extra("just a normal text message");
        assert_eq!(body, "just a normal text message");
        assert!(files.is_empty());
    }

    #[test]
    fn parse_file_attach_extra_second_bad_entry_does_not_drop_first_good_one() {
        let good = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            0u32, "ok.txt", 5u64, 0u64, FILE_REGULAR
        );
        let extra = format!("m\u{0}{good}\u{7}bad:entry");
        let (_, files) = parse_file_attach_extra(&extra);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "ok.txt");
    }

    /// 安全回归:恶意对端在清单里塞一个路径穿越文件名(如 `../../../etc/passwd`),
    /// 该条目必须在解析阶段就被整条丢弃(不出现在返回的 files 里),绝不能作为
    /// `IpmsgFileEntry.name` 流向下游、被某个调用方 `download_dir.join(name)` 后
    /// 逃出下载目录。同批次里的合法中文文件名条目仍应正常解析,证明畸形条目
    /// 不会连累其余条目(与既有的"坏 hex 条目不影响好条目"同一模式)。
    #[test]
    fn parse_file_attach_extra_drops_traversal_entry_name() {
        let evil = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            0u32, "../../../etc/passwd", 10u64, 0u64, FILE_REGULAR
        );
        let good = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            1u32, "你好.txt", 5u64, 0u64, FILE_REGULAR
        );
        let extra = format!("m\u{0}{evil}\u{7}{good}");
        let (_, files) = parse_file_attach_extra(&extra);
        assert_eq!(files.len(), 1, "穿越文件名条目必须被丢弃,只剩合法的那条");
        assert_eq!(files[0].name, "你好.txt");
        assert!(files.iter().all(|f| !f.name.contains('/')));
    }

    /// 同上,但穿越 payload 用反斜杠(Windows 风格)——同样必须被丢弃。
    #[test]
    fn parse_file_attach_extra_drops_backslash_traversal_entry_name() {
        let evil = format!(
            "{:x}:{}:{:x}:{:x}:{:x}:",
            0u32, "..\\..\\evil.txt", 4u64, 0u64, FILE_REGULAR
        );
        let extra = format!("m\u{0}{evil}");
        let (_, files) = parse_file_attach_extra(&extra);
        assert!(files.is_empty());
    }

    /// 转义机制本身(`escape_colon`/`split_escaped_fields`)必须正确处理字段内
    /// 字面 `:` 与分隔符 `:` 的区别——这是清单里所有 `:` 分隔字段共享的机制,不是
    /// 文件名专属。刻意在字段拆分这一层验证,避免跟 `safe_basename` 的"文件名
    /// 不允许出现 `:`(NTFS 备用数据流防护)"规则的断言混在一起。
    #[test]
    fn colon_escaping_roundtrips_at_the_field_splitting_level() {
        let escaped = escape_colon("10:30 会议记录");
        assert_eq!(escaped, "10::30 会议记录");
        let fields = split_escaped_fields(&format!("{escaped}:next"));
        assert_eq!(
            fields,
            vec!["10:30 会议记录".to_string(), "next".to_string()]
        );
    }

    /// Fix 1 的直接后果:文件名里若真的带 `:`,即使 wire 上转义/反转义完全正确
    /// (上一条测试已证明),`parse_one_file_entry` 也必须把整条目丢弃——
    /// `IpmsgFileEntry.name` 必须始终是 `safe_basename` 认可的安全 basename,
    /// 不允许把 NTFS 备用数据流风险的名字传播到 FileOffered 事件里。
    #[test]
    fn parse_file_attach_extra_drops_colon_in_filename_entry() {
        let extra = build_file_offer_extra("", 0, "10:30 会议记录.txt", 5, 0, FILE_REGULAR);
        assert!(extra.contains("10::30")); // wire 上确实转义成了 "::"
        let (_, files) = parse_file_attach_extra(&extra);
        assert!(
            files.is_empty(),
            "文件名含 ':' 必须被拒绝,不能作为安全 basename 往下游传播"
        );
    }

    // ---- GETFILEDATA extra ----

    #[test]
    fn getfiledata_extra_roundtrips_hex() {
        let extra = build_getfiledata_extra(0xABCD, 0x7, 0x1000);
        assert_eq!(extra, "abcd:7:1000");
        assert_eq!(parse_getfiledata_extra(&extra), Some((0xABCD, 0x7, 0x1000)));
    }

    #[test]
    fn getfiledata_extra_malformed_is_none() {
        assert_eq!(parse_getfiledata_extra("only:two"), None);
        assert_eq!(parse_getfiledata_extra("zz:1:2"), None);
    }

    // ---- safe_basename(与 M3 同等防护,拷贝自 bigpaw-core) ----

    #[test]
    fn safe_basename_rejects_traversal_and_hazards() {
        assert_eq!(safe_basename("report.pdf"), Some("report.pdf".to_string()));
        assert_eq!(safe_basename("图片.png"), Some("图片.png".to_string()));
        assert_eq!(safe_basename("../etc/passwd"), None);
        assert_eq!(safe_basename("a/b.txt"), None);
        assert_eq!(safe_basename("a\\b.txt"), None);
        assert_eq!(safe_basename("/abs"), None);
        assert_eq!(safe_basename(".."), None);
        assert_eq!(safe_basename(""), None);
        assert_eq!(safe_basename("CON"), None);
        assert_eq!(safe_basename("con.txt"), None);
        assert_eq!(safe_basename("a."), None);
        assert_eq!(safe_basename("x:hidden"), None);
        assert_eq!(safe_basename("a\u{202E}txt.exe"), None);
    }

    // ---- TCP GETFILEDATA 请求/响应字节级framing(EPHEMERAL 端口,不占 2425) ----

    #[test]
    fn getfiledata_request_response_roundtrips_over_ephemeral_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("source.bin");
        let content = b"hello bigpaw ipmsg file transfer payload".to_vec();
        fs::write(&src_path, &content).unwrap();

        let offered = new_offered_files();
        offered
            .lock()
            .unwrap()
            .entry(42)
            .or_default()
            .insert(7, src_path.clone());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let offered_srv = Arc::clone(&offered);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_getfiledata_request(&mut stream, &offered_srv).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let save_path = dir.path().join("downloaded.bin");
        let result = request_file_bytes(
            &mut client,
            "1",
            1,
            "bob",
            "HOST-B",
            42,
            7,
            content.len() as u64,
            &save_path,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(result, save_path);
        assert_eq!(fs::read(&result).unwrap(), content);
    }

    /// 飞秋对拍回归:真实飞秋(C++ 实现)发的 GETFILEDATA 请求带尾部 `\0`
    /// (参考实现 `strlen+1` 发送语义)。修复前 `parse_getfiledata_extra` 拿到的
    /// offset 字段是 `"0\0"`,hex 解析失败 → 静默拒绝 → 飞秋显示"传输失败"。
    /// 这里直接用手工拼的飞秋风格原始字节(私有版本串 + 尾部 NUL)回归。
    #[test]
    fn serve_getfiledata_accepts_feiq_style_nul_terminated_request() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("feiq.bin");
        let content = b"feiq interop payload".to_vec();
        fs::write(&src_path, &content).unwrap();

        let offered = new_offered_files();
        offered
            .lock()
            .unwrap()
            .entry(0x2a)
            .or_default()
            .insert(0, src_path);

        // 飞秋风格:私有版本串、GETFILEDATA(0x60=96)、extra 全 hex、结尾 \0。
        let raw = proto::gbk_encode("1_lbt6_8#998#abc:7:feiq:FEIQ-HOST:96:2a:0:0\u{0}");
        let mut wire = raw.clone();
        let mut response = Vec::new();
        let mut stream = DuplexBuf {
            read: Cursor::new(&mut wire),
            write: &mut response,
        };
        serve_getfiledata_request(&mut stream, &offered).unwrap();
        assert_eq!(response, content, "带尾部 \\0 的请求必须被正常供给");
    }

    /// 极简双工桩:读侧回放请求字节,写侧收集响应。
    struct DuplexBuf<'a> {
        read: Cursor<&'a mut Vec<u8>>,
        write: &'a mut Vec<u8>,
    }
    impl Read for DuplexBuf<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }
    impl Write for DuplexBuf<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn getfiledata_request_for_unregistered_file_id_is_refused() {
        let offered = new_offered_files(); // 空表:什么都没登记过

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let offered_srv = Arc::clone(&offered);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_getfiledata_request(&mut stream, &offered_srv).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let save_path = dir.path().join("should-not-exist.bin");
        // 服务端会静默关闭连接、不回任何字节;客户端期望 size 字节会得到 UnexpectedEof。
        let result = request_file_bytes(
            &mut client,
            "1",
            1,
            "bob",
            "HOST-B",
            999,
            999,
            10,
            &save_path,
        );
        server.join().unwrap();

        assert!(
            result.is_err(),
            "未登记的 packet_no/file_id 必须被拒绝,而不是读到任意文件"
        );
    }

    #[test]
    fn request_file_bytes_sanitizes_save_path_basename() {
        let dir = tempfile::tempdir().unwrap();
        let bad_path = dir.path().join("..");
        // file_name() 对 ".." 返回 None → sanitize 阶段就应该失败,不会真的去 connect。
        let mut fake = Vec::<u8>::new(); // 不会被用到:sanitize 在网络 IO 之前发生
        let result = request_file_bytes(
            &mut Cursor::new(&mut fake),
            "1",
            1,
            "bob",
            "HOST-B",
            1,
            1,
            0,
            &bad_path,
        );
        assert!(matches!(result, Err(IpmsgError::BadName)));
    }

    /// 安全回归(Fix 1 第二层,纵深防御):即使某个调用方按最自然的写法
    /// `download_dir.join(&entry.name)` 拼出 `save_path`(而不是分别传入受信目录
    /// 与不可信文件名),只要拼接结果里任何一段是 `..`,`request_file_bytes` 也
    /// 必须拒绝并且**不写任何字节**——既不写到 tmpdir 之外,也不在 tmpdir 内留下
    /// 任何文件(sanitize 在打开文件之前就失败了)。这一层不依赖解析层
    /// (`parse_one_file_entry`)是否已经净化过 `entry.name`,是独立的第二道防线。
    #[test]
    fn request_file_bytes_rejects_traversal_save_path_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        // 模拟调用方对未净化文件名做 `download_dir.join(&entry.name)` 的经典穿越写法。
        let malicious_name = "../../evil-traversal-test.bin";
        let save_path = dir.path().join(malicious_name);
        let escaping_target = dir.path().join("..").join("evil-traversal-test.bin");
        let mut fake = Vec::<u8>::new(); // 不会被用到:sanitize 在网络 IO 之前发生
        let result = request_file_bytes(
            &mut Cursor::new(&mut fake),
            "1",
            1,
            "bob",
            "HOST-B",
            1,
            1,
            0,
            &save_path,
        );
        assert!(matches!(result, Err(IpmsgError::BadName)));
        assert!(
            !escaping_target.exists(),
            "净化必须在任何落盘发生前失败,tmpdir 之外不应出现文件"
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "tmpdir 内也不应留下任何文件"
        );
    }

    // ---- GETDIRFILES 接收方向解析 ----

    /// 构造一条目录流条目的字节:header-size 从本条目"数字起点"算起,含终止冒号。
    fn dir_entry_bytes(name: &str, size_or_zero: u64, fileattr: u32, content: &[u8]) -> Vec<u8> {
        let name_wire = proto::gbk_encode(&escape_colon(name));
        // header = "<name>:<size(hex)>:<fileattr(hex)>:" (GBK 编码后的字节)
        let mut header_tail = Vec::new();
        header_tail.extend_from_slice(&name_wire);
        header_tail.extend_from_slice(format!(":{size_or_zero:x}:{fileattr:x}:").as_bytes());

        // header-size = header_tail 的字节数 + header-size 数字本身的字节数 + 1(冒号)。
        // 需要迭代求解(数字位数会影响自身长度),位数很小几次就能收敛。
        let mut hs_digits = 1usize;
        loop {
            let total = hs_digits + 1 + header_tail.len();
            let hex_len = format!("{total:x}").len();
            if hex_len == hs_digits {
                let mut out = format!("{total:x}:").into_bytes();
                out.extend_from_slice(&header_tail);
                out.extend_from_slice(content);
                return out;
            }
            hs_digits = hex_len;
        }
    }

    #[test]
    fn receive_dir_stream_flat_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = Vec::new();
        wire.extend(dir_entry_bytes("a.txt", 5, FILE_REGULAR, b"hello"));
        wire.extend(dir_entry_bytes(
            "图片.png",
            3,
            FILE_REGULAR,
            b"\x01\x02\x03",
        ));

        let mut cursor = Cursor::new(wire);
        let root = receive_dir_stream(&mut cursor, dir.path()).unwrap();
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(root.join("图片.png")).unwrap(), b"\x01\x02\x03");
    }

    #[test]
    fn receive_dir_stream_nested_directory_with_retparent() {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = Vec::new();
        wire.extend(dir_entry_bytes("sub", 0, FILE_DIR, b""));
        wire.extend(dir_entry_bytes("inner.txt", 5, FILE_REGULAR, b"world"));
        wire.extend(dir_entry_bytes(".", 0, FILE_RETPARENT, b""));
        wire.extend(dir_entry_bytes("top.txt", 3, FILE_REGULAR, b"top"));

        let mut cursor = Cursor::new(wire);
        let root = receive_dir_stream(&mut cursor, dir.path()).unwrap();
        assert_eq!(
            fs::read(root.join("sub").join("inner.txt")).unwrap(),
            b"world"
        );
        assert_eq!(fs::read(root.join("top.txt")).unwrap(), b"top");
    }

    #[test]
    fn receive_dir_stream_rejects_traversal_but_stays_in_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = Vec::new();
        wire.extend(dir_entry_bytes("../evil.txt", 4, FILE_REGULAR, b"evil"));
        wire.extend(dir_entry_bytes("safe.txt", 4, FILE_REGULAR, b"safe"));

        let mut cursor = Cursor::new(wire);
        let root = receive_dir_stream(&mut cursor, dir.path()).unwrap();
        assert!(!dir.path().join("../evil.txt").exists());
        assert!(!root.join("evil.txt").exists());
        // 第一条被拒但流没有失步:第二条仍正确落盘。
        assert_eq!(fs::read(root.join("safe.txt")).unwrap(), b"safe");
    }

    #[test]
    fn receive_dir_stream_over_tcp_stream() {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = Vec::new();
        wire.extend(dir_entry_bytes("a.txt", 5, FILE_REGULAR, b"hello"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&wire).unwrap();
            // 主动关闭写方向,让客户端读到 EOF 从而结束目录流解析。
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let root = receive_dir_stream(&mut client, dir.path()).unwrap();
        server.join().unwrap();
        assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello");
    }
}

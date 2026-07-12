//! 文件接收:落盘到 <name>.bigpaw-part,累积 blake3,完成后原子 rename。
//! 断点续传:已有 part 的字节数即 offset。安全:文件名 basename 化防穿越。

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const PART_SUFFIX: &str = ".bigpaw-part";
const CHUNK: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum XferError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("非法文件名(可能路径穿越)")]
    BadName,
    #[error("blake3 校验失败:期望 {expected}, 实际 {actual}")]
    Checksum { expected: String, actual: String },
}

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

pub fn part_path(download_dir: &Path, name: &str) -> PathBuf {
    download_dir.join(format!("{name}{PART_SUFFIX}"))
}

/// 部分文件当前字节数(续传起点);无则 0。
pub fn existing_offset(download_dir: &Path, name: &str) -> u64 {
    fs::metadata(part_path(download_dir, name))
        .map(|m| m.len())
        .unwrap_or(0)
}

/// 从 offset 起接收 size-offset 字节写入 part,累积校验全文件 blake3,成功后 rename 去后缀。
pub fn receive_into(
    download_dir: &Path,
    name: &str,
    size: u64,
    offset: u64,
    expected_blake3: &str,
    reader: &mut impl Read,
    on_progress: &mut dyn FnMut(u64),
) -> Result<PathBuf, XferError> {
    let name = safe_basename(name).ok_or(XferError::BadName)?;
    fs::create_dir_all(download_dir)?;
    let part = part_path(download_dir, &name);

    let mut hasher = blake3::Hasher::new();
    // 续传:先把已落盘的部分喂进 hasher
    let mut file = if offset > 0 && part.exists() {
        let mut existing = fs::File::open(&part)?;
        let mut buf = vec![0u8; CHUNK];
        let mut fed = 0u64;
        while fed < offset {
            let want = CHUNK.min((offset - fed) as usize);
            existing.read_exact(&mut buf[..want])?;
            hasher.update(&buf[..want]);
            fed += want as u64;
        }
        let mut f = OpenOptions::new().write(true).open(&part)?;
        // 截断掉 offset 之后的垃圾尾巴(旧 part 可能比 offset 大),
        // 否则续传写入后成品会比 size 更长,导致 rename 出一个超长且哈希不符的"成品"。
        f.set_len(offset)?;
        f.seek(SeekFrom::Start(offset))?;
        f
    } else {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part)?
    };

    let mut done = offset;
    let mut buf = vec![0u8; CHUNK];
    while done < size {
        let want = CHUNK.min((size - done) as usize);
        reader.read_exact(&mut buf[..want])?;
        file.write_all(&buf[..want])?;
        hasher.update(&buf[..want]);
        done += want as u64;
        on_progress(done);
    }
    file.flush()?;

    let actual = hasher.finalize().to_hex().to_string();
    if actual != expected_blake3 {
        // 保留 part(不 rename 成成品),供排查;续传下次会重算
        return Err(XferError::Checksum {
            expected: expected_blake3.to_string(),
            actual,
        });
    }
    let final_path = download_dir.join(&name);
    fs::rename(&part, &final_path)?;
    Ok(final_path)
}

/// 算文件 blake3 与大小(发送前)。
pub fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, hasher.finalize().to_hex().to_string()))
}

/// 从 offset 起把文件字节推给 writer。
pub fn send_from(
    path: &Path,
    offset: u64,
    size: u64,
    writer: &mut impl Write,
    on_progress: &mut dyn FnMut(u64),
) -> io::Result<()> {
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut done = offset;
    let mut buf = vec![0u8; CHUNK];
    while done < size {
        let want = CHUNK.min((size - done) as usize);
        f.read_exact(&mut buf[..want])?;
        writer.write_all(&buf[..want])?;
        done += want as u64;
        on_progress(done);
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn safe_basename_rejects_traversal() {
        assert_eq!(safe_basename("report.pdf"), Some("report.pdf".to_string()));
        assert_eq!(safe_basename("图片.png"), Some("图片.png".to_string()));
        assert_eq!(safe_basename("../etc/passwd"), None);
        assert_eq!(safe_basename("a/b.txt"), None);
        assert_eq!(safe_basename("a\\b.txt"), None);
        assert_eq!(safe_basename("/abs"), None);
        assert_eq!(safe_basename(".."), None);
        assert_eq!(safe_basename(""), None);
    }

    #[test]
    fn receive_full_file_verifies_and_renames() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"hello bigpaw file transfer payload".to_vec();
        let hash = blake3::hash(&data).to_hex().to_string();
        let mut progress_calls = Vec::new();
        let mut on_p = |done: u64| progress_calls.push(done);
        let path = receive_into(
            dir.path(),
            "greeting.txt",
            data.len() as u64,
            0,
            &hash,
            &mut Cursor::new(data.clone()),
            &mut on_p,
        )
        .unwrap();
        assert_eq!(path, dir.path().join("greeting.txt"));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(!dir.path().join("greeting.txt.bigpaw-part").exists());
        assert_eq!(*progress_calls.last().unwrap(), data.len() as u64);
    }

    #[test]
    fn resume_from_offset_completes_file() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![7u8; 3_000_000]; // 跨多个块
        let hash = blake3::hash(&data).to_hex().to_string();
        // 预置部分文件:前 1MiB
        let offset = 1_048_576u64;
        std::fs::write(part_path(dir.path(), "big.bin"), &data[..offset as usize]).unwrap();
        assert_eq!(existing_offset(dir.path(), "big.bin"), offset);
        let mut noop = |_done: u64| {};
        let path = receive_into(
            dir.path(),
            "big.bin",
            data.len() as u64,
            offset,
            &hash,
            &mut Cursor::new(data[offset as usize..].to_vec()),
            &mut noop,
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn safe_basename_rejects_windows_hazards() {
        assert_eq!(safe_basename("CON"), None);
        assert_eq!(safe_basename("con.txt"), None);
        assert_eq!(safe_basename("COM1"), None);
        assert_eq!(safe_basename("LPT9.pdf"), None);
        assert_eq!(safe_basename("a."), None); // 尾部点
        assert_eq!(safe_basename("a "), None); // 尾部空格
        assert_eq!(safe_basename("x:hidden"), None); // NTFS ADS
        assert_eq!(safe_basename("a\u{202E}txt.exe"), None); // RTLO
                                                             // 正常名仍通过
        assert_eq!(safe_basename("report.pdf"), Some("report.pdf".to_string()));
        assert_eq!(safe_basename("图片.png"), Some("图片.png".to_string()));
        assert_eq!(
            safe_basename("console.log.txt"),
            Some("console.log.txt".to_string())
        ); // 不是保留名
    }

    #[test]
    fn oversized_part_is_truncated_to_offset_then_completed() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![5u8; 2_000_000];
        let hash = blake3::hash(&data).to_hex().to_string();
        let offset = 1_048_576u64;
        // 预置一个比 offset 大的、且尾部是垃圾字节的 part
        let mut corrupt = data[..offset as usize].to_vec();
        corrupt.extend_from_slice(&[0xFFu8; 500_000]); // 垃圾尾巴
        std::fs::write(part_path(dir.path(), "big.bin"), &corrupt).unwrap();
        let mut noop = |_d: u64| {};
        let path = receive_into(
            dir.path(),
            "big.bin",
            data.len() as u64,
            offset,
            &hash,
            &mut std::io::Cursor::new(data[offset as usize..].to_vec()),
            &mut noop,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            data,
            "垃圾尾巴必须被截断,成品与原文件一致"
        );
    }

    #[test]
    fn wrong_hash_is_error_and_keeps_part() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"payload".to_vec();
        let err = receive_into(
            dir.path(),
            "x.bin",
            data.len() as u64,
            0,
            &"0".repeat(64),
            &mut Cursor::new(data),
            &mut |_| {},
        );
        assert!(err.is_err());
        // 校验失败保留 part 供续传/排查,不留半个"成品"
        assert!(!dir.path().join("x.bin").exists());
    }

    #[test]
    fn hash_file_matches_blake3_of_contents() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![9u8; 2_000_000];
        let path = dir.path().join("src.bin");
        std::fs::write(&path, &data).unwrap();
        let (size, hash) = hash_file(&path).unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(hash, blake3::hash(&data).to_hex().to_string());
    }

    #[test]
    fn send_from_then_receive_into_roundtrips() {
        let dir = dir_pair();
        let (src_dir, dst_dir) = (&dir.0, &dir.1);
        let data = vec![3u8; 2_500_000];
        let src = src_dir.path().join("payload.bin");
        std::fs::write(&src, &data).unwrap();
        let (size, hash) = hash_file(&src).unwrap();

        let mut wire = Vec::new();
        let mut send_progress = Vec::new();
        send_from(&src, 0, size, &mut wire, &mut |d| send_progress.push(d)).unwrap();
        assert_eq!(wire, data);
        assert_eq!(*send_progress.last().unwrap(), size);

        let mut recv_progress = Vec::new();
        let path = receive_into(
            dst_dir.path(),
            "payload.bin",
            size,
            0,
            &hash,
            &mut Cursor::new(wire),
            &mut |d| recv_progress.push(d),
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    /// 小工具:两个独立临时目录(发送侧源文件目录、接收侧下载目录)。
    fn dir_pair() -> (tempfile::TempDir, tempfile::TempDir) {
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
    }

    #[test]
    fn send_from_resumes_from_offset() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![6u8; 3_000_000];
        let src = dir.path().join("resume.bin");
        std::fs::write(&src, &data).unwrap();
        let offset = 1_048_576u64;
        let size = data.len() as u64;
        let mut wire = Vec::new();
        send_from(&src, offset, size, &mut wire, &mut |_| {}).unwrap();
        assert_eq!(wire, data[offset as usize..]);
    }
}

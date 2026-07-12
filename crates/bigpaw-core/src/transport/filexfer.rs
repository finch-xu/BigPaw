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

/// 只取文件名部分,拒绝任何含路径分隔符/父目录/绝对路径的名字。
pub fn safe_basename(name: &str) -> Option<String> {
    if name.is_empty() || name == ".." || name == "." {
        return None;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
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
}

//! SQLite 持久化(M6):消息/文件传输历史、已知 peer。
//! 不变式:调用方(Core)保证"先写库、再发事件"。

use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// 会话时间线里的一条记录:文本消息或文件传输。
/// serde tag="kind" → 前端按 `item.kind === "text" | "file"` 判别。
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HistoryItem {
    #[serde(rename_all = "camelCase")]
    Text {
        id: String,
        peer_fp: String,
        direction: String,
        body: String,
        ts_ms: i64,
    },
    #[serde(rename_all = "camelCase")]
    File {
        xfer_id: String,
        peer_fp: String,
        direction: String,
        name: String,
        size: i64,
        is_dir: bool,
        status: String,
        path: Option<String>,
        ts_ms: i64,
    },
}

impl HistoryItem {
    pub fn ts_ms(&self) -> i64 {
        match self {
            HistoryItem::Text { ts_ms, .. } | HistoryItem::File { ts_ms, .. } => *ts_ms,
        }
    }
}

pub struct Storage {
    conn: Mutex<Connection>,
}

const SCHEMA_VERSION: i32 = 1;

impl Storage {
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open(data_dir.join("bigpaw.db"))?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_message(
        &self,
        id: &str,
        peer_fp: &str,
        direction: &str,
        body: &str,
        ts_ms: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT OR IGNORE INTO messages (id, peer_fp, direction, body, ts_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, peer_fp, direction, body, ts_ms],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_transfer(
        &self,
        xfer_id: &str,
        peer_fp: &str,
        direction: &str,
        name: &str,
        size: i64,
        is_dir: bool,
        status: &str,
        ts_ms: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT OR IGNORE INTO transfers
               (xfer_id, peer_fp, direction, name, size, is_dir, status, path, ts_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
            params![xfer_id, peer_fp, direction, name, size, is_dir as i32, status, ts_ms],
        )?;
        Ok(())
    }

    /// 状态推进(offered→active→done/failed/rejected)。`path` 仅完成时有值。
    /// 未知 xfer_id 无操作(与 TransportManager::respond_file 的幂等语义一致)。
    pub fn update_transfer(
        &self,
        xfer_id: &str,
        status: &str,
        path: Option<&str>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "UPDATE transfers SET status = ?2, path = COALESCE(?3, path)
             WHERE xfer_id = ?1",
            params![xfer_id, status, path],
        )?;
        Ok(())
    }

    /// 会话时间线一页:messages 与 transfers 合并,`before_ts` 之前(不含)
    /// 最近 `limit` 条,升序返回。kind 列区分两表来源。
    pub fn history(
        &self,
        peer_fp: &str,
        before_ts: Option<i64>,
        limit: u32,
    ) -> Result<Vec<HistoryItem>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let before = before_ts.unwrap_or(i64::MAX);
        let mut stmt = conn.prepare(
            "SELECT * FROM (
               SELECT 'text' AS kind, id AS k1, peer_fp, direction, body AS k2,
                      NULL AS k3, 0 AS k4, 0 AS k5, NULL AS k6, ts_ms
               FROM messages WHERE peer_fp = ?1 AND ts_ms < ?2
               UNION ALL
               SELECT 'file' AS kind, xfer_id AS k1, peer_fp, direction, name AS k2,
                      status AS k3, size AS k4, is_dir AS k5, path AS k6, ts_ms
               FROM transfers WHERE peer_fp = ?1 AND ts_ms < ?2
             ) ORDER BY ts_ms DESC LIMIT ?3",
        )?;
        let mut items: Vec<HistoryItem> = stmt
            .query_map(params![peer_fp, before, limit], row_to_item)?
            .collect::<Result<_, _>>()?;
        items.reverse();
        Ok(items)
    }
}

/// UNION 行 → HistoryItem。列序固定:kind, k1(id/xfer_id), peer_fp,
/// direction, k2(body/name), k3(status), k4(size), k5(is_dir), k6(path), ts_ms。
fn row_to_item(row: &rusqlite::Row<'_>) -> Result<HistoryItem, rusqlite::Error> {
    let kind: String = row.get(0)?;
    if kind == "text" {
        Ok(HistoryItem::Text {
            id: row.get(1)?,
            peer_fp: row.get(2)?,
            direction: row.get(3)?,
            body: row.get(4)?,
            ts_ms: row.get(9)?,
        })
    } else {
        Ok(HistoryItem::File {
            xfer_id: row.get(1)?,
            peer_fp: row.get(2)?,
            direction: row.get(3)?,
            name: row.get(4)?,
            status: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
            size: row.get(6)?,
            is_dir: row.get::<_, i32>(7)? != 0,
            path: row.get(8)?,
            ts_ms: row.get(9)?,
        })
    }
}

fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
               id        TEXT PRIMARY KEY,
               peer_fp   TEXT NOT NULL,
               direction TEXT NOT NULL,
               body      TEXT NOT NULL,
               ts_ms     INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_messages_peer_ts
               ON messages(peer_fp, ts_ms);
             CREATE TABLE IF NOT EXISTS transfers (
               xfer_id   TEXT PRIMARY KEY,
               peer_fp   TEXT NOT NULL,
               direction TEXT NOT NULL,
               name      TEXT NOT NULL,
               size      INTEGER NOT NULL,
               is_dir    INTEGER NOT NULL DEFAULT 0,
               status    TEXT NOT NULL,
               path      TEXT,
               ts_ms     INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_transfers_peer_ts
               ON transfers(peer_fp, ts_ms);
             CREATE TABLE IF NOT EXISTS peers (
               fingerprint  TEXT PRIMARY KEY,
               nickname     TEXT NOT NULL,
               protocol     TEXT NOT NULL,
               last_addr    TEXT,
               last_seen_ms INTEGER NOT NULL
             );",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Storage {
        let dir = tempfile::tempdir().unwrap();
        // tempdir 在函数返回时删除,测试内自己保住它
        let s = Storage::open(dir.path()).unwrap();
        std::mem::forget(dir);
        s
    }

    #[test]
    fn open_creates_db_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let _s = Storage::open(dir.path()).unwrap();
        assert!(dir.path().join("bigpaw.db").exists());
        // 二次打开(迁移幂等)
        let _s2 = Storage::open(dir.path()).unwrap();
    }

    #[test]
    fn insert_and_read_message() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "你好", 1000).unwrap();
        s.insert_message("m2", "peerA", "out", "hi", 2000).unwrap();
        let items = s.history("peerA", None, 50).unwrap();
        assert_eq!(items.len(), 2);
        // 返回升序(旧→新),供 UI 直接渲染
        match &items[0] {
            HistoryItem::Text { body, ts_ms, .. } => {
                assert_eq!(body, "你好");
                assert_eq!(*ts_ms, 1000);
            }
            other => panic!("期望 Text,得到 {other:?}"),
        }
    }

    #[test]
    fn insert_message_id_conflict_is_idempotent() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "a", 1).unwrap();
        // 同 id 再插不报错(INSERT OR IGNORE)
        s.insert_message("m1", "peerA", "in", "a", 1).unwrap();
        assert_eq!(s.history("peerA", None, 50).unwrap().len(), 1);
    }

    #[test]
    fn transfer_insert_update_and_merged_history() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "先发一句", 1000).unwrap();
        s.insert_transfer("x1", "peerA", "in", "a.zip", 2048, false, "offered", 1500)
            .unwrap();
        s.update_transfer("x1", "done", Some("/tmp/a.zip")).unwrap();
        s.insert_message("m2", "peerA", "out", "收到了吗", 2000).unwrap();

        let items = s.history("peerA", None, 50).unwrap();
        assert_eq!(items.len(), 3, "文本与文件合并进同一条时间线");
        assert_eq!(
            items.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![1000, 1500, 2000],
            "升序"
        );
        match &items[1] {
            HistoryItem::File { status, path, .. } => {
                assert_eq!(status, "done");
                assert_eq!(path.as_deref(), Some("/tmp/a.zip"));
            }
            other => panic!("期望 File,得到 {other:?}"),
        }
    }

    #[test]
    fn history_cursor_pagination() {
        let s = mem();
        for i in 0..10 {
            s.insert_message(&format!("m{i}"), "peerA", "in", "x", i * 100).unwrap();
        }
        let page1 = s.history("peerA", None, 4).unwrap();
        assert_eq!(
            page1.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![600, 700, 800, 900],
            "第一页是最新 4 条"
        );
        let page2 = s.history("peerA", Some(600), 4).unwrap();
        assert_eq!(
            page2.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![200, 300, 400, 500],
            "游标之前的一页,不含游标本身"
        );
    }

    #[test]
    fn history_isolates_peers() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "a", 1).unwrap();
        s.insert_message("m2", "peerB", "in", "b", 2).unwrap();
        assert_eq!(s.history("peerA", None, 50).unwrap().len(), 1);
    }
}

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

/// 全局搜索命中:只带定位与摘要,点击后用 history_around 拉上下文。
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub peer_fp: String,
    pub ts_ms: i64,
    /// 命中的消息正文或文件名(原文,截断交给前端 CSS)
    pub snippet: String,
    /// "text" | "file"
    pub kind: String,
}

/// peers 表一行:启动时预热 roster(Offline 态)用。
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownPeer {
    pub fingerprint: String,
    pub nickname: String,
    /// "native" | "ipmsg"
    pub protocol: String,
    pub last_addr: Option<String>,
    pub last_seen_ms: i64,
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
    /// 终态(done/failed/rejected)不可被后到的状态覆盖——防 respond_file 调用方线程与传输完成线程的写入竞态。
    pub fn update_transfer(
        &self,
        xfer_id: &str,
        status: &str,
        path: Option<&str>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "UPDATE transfers SET status = ?2, path = COALESCE(?3, path)
             WHERE xfer_id = ?1 AND status NOT IN ('done', 'failed', 'rejected')",
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

    /// 搜索定位的上下文窗:目标时间戳前 `half` 条 + 目标及之后 `half` 条,
    /// 升序返回。两个方向各查一次再拼接,不依赖 OFFSET。
    pub fn history_around(
        &self,
        peer_fp: &str,
        ts_ms: i64,
        half: u32,
    ) -> Result<Vec<HistoryItem>, StorageError> {
        let mut before = self.history(peer_fp, Some(ts_ms), half)?;
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT * FROM (
               SELECT 'text' AS kind, id AS k1, peer_fp, direction, body AS k2,
                      NULL AS k3, 0 AS k4, 0 AS k5, NULL AS k6, ts_ms
               FROM messages WHERE peer_fp = ?1 AND ts_ms >= ?2
               UNION ALL
               SELECT 'file' AS kind, xfer_id AS k1, peer_fp, direction, name AS k2,
                      status AS k3, size AS k4, is_dir AS k5, path AS k6, ts_ms
               FROM transfers WHERE peer_fp = ?1 AND ts_ms >= ?2
             ) ORDER BY ts_ms ASC LIMIT ?3",
        )?;
        let after: Vec<HistoryItem> = stmt
            .query_map(params![peer_fp, ts_ms, half + 1], row_to_item)?
            .collect::<Result<_, _>>()?;
        before.extend(after);
        Ok(before)
    }

    /// 全局 LIKE 搜索(消息正文 + 文件名),新→旧。`\` 为转义符,
    /// 用户输入里的 % _ \ 都按字面匹配。
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<SearchHit>, StorageError> {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT peer_fp, ts_ms, snippet, kind FROM (
               SELECT peer_fp, ts_ms, body AS snippet, 'text' AS kind
               FROM messages WHERE body LIKE ?1 ESCAPE '\\'
               UNION ALL
               SELECT peer_fp, ts_ms, name AS snippet, 'file' AS kind
               FROM transfers WHERE name LIKE ?1 ESCAPE '\\'
             ) ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let hits = stmt
            .query_map(params![pattern, limit], |row| {
                Ok(SearchHit {
                    peer_fp: row.get(0)?,
                    ts_ms: row.get(1)?,
                    snippet: row.get(2)?,
                    kind: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(hits)
    }

    /// 清空历史:`Some(fp)` 单会话,`None` 全部。messages 与 transfers 同删。
    pub fn clear_history(&self, peer_fp: Option<&str>) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        match peer_fp {
            Some(fp) => {
                conn.execute("DELETE FROM messages WHERE peer_fp = ?1", params![fp])?;
                conn.execute("DELETE FROM transfers WHERE peer_fp = ?1", params![fp])?;
            }
            None => {
                conn.execute("DELETE FROM messages", [])?;
                conn.execute("DELETE FROM transfers", [])?;
            }
        }
        Ok(())
    }

    pub fn upsert_peer(
        &self,
        fingerprint: &str,
        nickname: &str,
        protocol: &str,
        last_addr: Option<&str>,
        last_seen_ms: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT INTO peers (fingerprint, nickname, protocol, last_addr, last_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(fingerprint) DO UPDATE SET
               nickname = excluded.nickname,
               protocol = excluded.protocol,
               last_addr = COALESCE(excluded.last_addr, peers.last_addr),
               last_seen_ms = excluded.last_seen_ms",
            params![fingerprint, nickname, protocol, last_addr, last_seen_ms],
        )?;
        Ok(())
    }

    pub fn known_peers(&self) -> Result<Vec<KnownPeer>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT fingerprint, nickname, protocol, last_addr, last_seen_ms
             FROM peers ORDER BY last_seen_ms DESC",
        )?;
        let peers = stmt
            .query_map([], |row| {
                Ok(KnownPeer {
                    fingerprint: row.get(0)?,
                    nickname: row.get(1)?,
                    protocol: row.get(2)?,
                    last_addr: row.get(3)?,
                    last_seen_ms: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(peers)
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

    #[test]
    fn history_around_returns_context_window() {
        let s = mem();
        for i in 0..20 {
            s.insert_message(&format!("m{i}"), "peerA", "in", "x", i * 100).unwrap();
        }
        // 目标 ts=1000,前后各 3 条 → [700..=1300],含目标本身
        let items = s.history_around("peerA", 1000, 3).unwrap();
        assert_eq!(
            items.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![700, 800, 900, 1000, 1100, 1200, 1300]
        );
    }

    #[test]
    fn search_covers_message_body_and_file_name() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "明天开会记得带电脑", 1000).unwrap();
        s.insert_message("m2", "peerB", "out", "好的", 2000).unwrap();
        s.insert_transfer("x1", "peerB", "in", "会议纪要.docx", 10, false, "done", 3000)
            .unwrap();
        let hits = s.search("会", 50).unwrap();
        assert_eq!(hits.len(), 2, "命中消息正文与文件名各一");
        assert_eq!(hits[0].ts_ms, 3000, "新的在前");
        assert_eq!(hits[0].kind, "file");
        assert_eq!(hits[1].peer_fp, "peerA");
    }

    #[test]
    fn search_escapes_like_wildcards() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "百分号%字面量", 1000).unwrap();
        s.insert_message("m2", "peerA", "in", "别的", 2000).unwrap();
        let hits = s.search("%", 50).unwrap();
        assert_eq!(hits.len(), 1, "% 应按字面匹配,不是通配一切");
    }

    #[test]
    fn clear_history_single_peer_and_all() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "a", 1).unwrap();
        s.insert_transfer("x1", "peerA", "in", "f", 1, false, "done", 2).unwrap();
        s.insert_message("m2", "peerB", "in", "b", 3).unwrap();

        s.clear_history(Some("peerA")).unwrap();
        assert!(s.history("peerA", None, 50).unwrap().is_empty());
        assert_eq!(s.history("peerB", None, 50).unwrap().len(), 1, "别的会话不受影响");

        s.clear_history(None).unwrap();
        assert!(s.history("peerB", None, 50).unwrap().is_empty(), "None = 全部清空");
    }

    #[test]
    fn upsert_peer_and_known_peers() {
        let s = mem();
        s.upsert_peer("fpA", "alice", "native", Some("192.168.1.5"), 1000).unwrap();
        s.upsert_peer("fpA", "alice-renamed", "native", Some("192.168.1.6"), 2000)
            .unwrap();
        // COALESCE 回归:last_addr 传 None 不得抹掉旧地址,其余字段照常更新
        s.upsert_peer("fpA", "alice-renamed", "native", None, 3000).unwrap();
        s.upsert_peer("ipmsg:k", "bob-feiq", "ipmsg", None, 1500).unwrap();
        let peers = s.known_peers().unwrap();
        assert_eq!(peers.len(), 2, "同 fingerprint 覆盖不重复");
        let a = peers.iter().find(|p| p.fingerprint == "fpA").unwrap();
        assert_eq!(a.nickname, "alice-renamed");
        assert_eq!(a.last_addr.as_deref(), Some("192.168.1.6"));
        assert_eq!(a.last_seen_ms, 3000);
    }

    #[test]
    fn update_transfer_never_regresses_terminal_status() {
        let s = mem();
        s.insert_transfer("x1", "peerA", "in", "a.zip", 10, false, "offered", 100)
            .unwrap();
        s.update_transfer("x1", "done", Some("/tmp/a.zip")).unwrap();
        // 竞态场景:respond_file 的 "active" 晚于 FileDone 到达,不得覆盖终态
        s.update_transfer("x1", "active", None).unwrap();
        match &s.history("peerA", None, 10).unwrap()[0] {
            HistoryItem::File { status, path, .. } => {
                assert_eq!(status, "done", "终态不可回退");
                assert_eq!(path.as_deref(), Some("/tmp/a.zip"));
            }
            other => panic!("期望 File,得到 {other:?}"),
        }
    }
}

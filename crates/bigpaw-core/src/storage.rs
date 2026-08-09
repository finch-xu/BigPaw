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

/// 会话摘要一行(M7b 消息视图):该 peer 的最后一条消息/文件。
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvSummary {
    pub peer_fp: String,
    pub ts_ms: i64,
    /// 文本正文或文件名(原文,截断交给前端 CSS)
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
    /// 对端最后声明的工作组名(M7a,v2 迁移新增列)。
    pub group: Option<String>,
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
        /// 群消息的发送者指纹(M7c);单聊恒为 None。
        sender_fp: Option<String>,
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

const SCHEMA_VERSION: i32 = 3;

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
        sender_fp: Option<&str>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT OR IGNORE INTO messages (id, peer_fp, direction, body, ts_ms, sender_fp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, peer_fp, direction, body, ts_ms, sender_fp],
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

    /// 会话时间线一页:messages 与 transfers 合并,复合游标 `(ts_ms, id)` 之前
    /// (不含)最近 `limit` 条,升序返回。kind 列区分两表来源。
    ///
    /// 排序与游标比较都用双键 `(ts_ms DESC, id DESC)`:仅按 `ts_ms` 比较在
    /// 同一毫秒内插入多条记录时会把游标卡在时间戳相同的一簇中间,导致
    /// `ts_ms < 游标` 漏掉同毫秒的剩余条目——即"永久丢失"。加入 `id` 作为
    /// 次级键后,游标变成簇内的一个全序位置,不会再丢条目也不会重复。
    ///
    /// `before=None` 表示取最新一页,不设上界。为了只维护一条 SQL(不拆成
    /// 有/无游标两个 prepare),用一对不可能被真实数据超过的"哨兵"值代入
    /// 同一查询:`ts_ms=i64::MAX`(真实时间戳不可能达到)、
    /// `id="\u{10FFFF}"`(Unicode 最大码点;真实 id 是 UUID,纯 ASCII 十六进制
    /// 加连字符,在 SQLite 默认的 BINARY/memcmp 排序下恒小于该哨兵)。
    pub fn history(
        &self,
        peer_fp: &str,
        before: Option<(i64, &str)>,
        limit: u32,
    ) -> Result<Vec<HistoryItem>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let (before_ts, before_id) = before.unwrap_or((i64::MAX, "\u{10FFFF}"));
        let mut stmt = conn.prepare(
            "SELECT * FROM (
               SELECT 'text' AS kind, id AS k1, peer_fp, direction, body AS k2,
                      NULL AS k3, 0 AS k4, 0 AS k5, NULL AS k6, ts_ms, sender_fp AS k7
               FROM messages WHERE peer_fp = ?1
               UNION ALL
               SELECT 'file' AS kind, xfer_id AS k1, peer_fp, direction, name AS k2,
                      status AS k3, size AS k4, is_dir AS k5, path AS k6, ts_ms, NULL AS k7
               FROM transfers WHERE peer_fp = ?1
             ) WHERE ts_ms < ?2 OR (ts_ms = ?2 AND k1 < ?3)
             ORDER BY ts_ms DESC, k1 DESC LIMIT ?4",
        )?;
        let mut items: Vec<HistoryItem> = stmt
            .query_map(params![peer_fp, before_ts, before_id, limit], row_to_item)?
            .collect::<Result<_, _>>()?;
        items.reverse();
        Ok(items)
    }

    /// 搜索定位的上下文窗:目标时间戳前 `half` 条 + 目标及之后 `half` 条,
    /// 升序返回。两个方向各查一次再拼接,不依赖 OFFSET。
    ///
    /// 前半段游标用 `(ts_ms, "")`——空串比任何真实 UUID 都小,所以
    /// `ts_ms = 目标 AND id < ""` 恒假,等价于单纯 `ts_ms < 目标`:目标本身
    /// 及所有与目标同毫秒的其它条目都不会落入前半段,全部留给后半段
    /// (`ts_ms >= 目标`,原样未变)。两段因此互斥、拼接后不重复也不丢条目。
    pub fn history_around(
        &self,
        peer_fp: &str,
        ts_ms: i64,
        half: u32,
    ) -> Result<Vec<HistoryItem>, StorageError> {
        let mut before = self.history(peer_fp, Some((ts_ms, "")), half)?;
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT * FROM (
               SELECT 'text' AS kind, id AS k1, peer_fp, direction, body AS k2,
                      NULL AS k3, 0 AS k4, 0 AS k5, NULL AS k6, ts_ms, sender_fp AS k7
               FROM messages WHERE peer_fp = ?1 AND ts_ms >= ?2
               UNION ALL
               SELECT 'file' AS kind, xfer_id AS k1, peer_fp, direction, name AS k2,
                      status AS k3, size AS k4, is_dir AS k5, path AS k6, ts_ms, NULL AS k7
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
        group: Option<&str>,
        last_seen_ms: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT INTO peers (fingerprint, nickname, protocol, last_addr, group_name, last_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(fingerprint) DO UPDATE SET
               nickname = excluded.nickname,
               protocol = excluded.protocol,
               last_addr = COALESCE(excluded.last_addr, peers.last_addr),
               group_name = excluded.group_name,
               last_seen_ms = excluded.last_seen_ms",
            params![fingerprint, nickname, protocol, last_addr, group, last_seen_ms],
        )?;
        Ok(())
    }

    /// 每个会话(peer_fp)的最后一条记录,按时间倒序(M7b 消息视图数据源)。
    /// 双键 `(ts_ms, k1)` 取最大,口径与 `history` 的游标一致——同毫秒多条时
    /// 结果确定,不依赖插入顺序。
    pub fn conversation_summaries(&self) -> Result<Vec<ConvSummary>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT peer_fp, ts_ms, k2, kind FROM (
               SELECT peer_fp, ts_ms, k1, k2, kind,
                      ROW_NUMBER() OVER (
                        PARTITION BY peer_fp ORDER BY ts_ms DESC, k1 DESC
                      ) AS rn
               FROM (
                 SELECT peer_fp, ts_ms, id AS k1, body AS k2, 'text' AS kind FROM messages
                 UNION ALL
                 SELECT peer_fp, ts_ms, xfer_id AS k1, name AS k2, 'file' AS kind FROM transfers
               )
             ) WHERE rn = 1 ORDER BY ts_ms DESC",
        )?;
        let sums = stmt
            .query_map([], |row| {
                Ok(ConvSummary {
                    peer_fp: row.get(0)?,
                    ts_ms: row.get(1)?,
                    snippet: row.get(2)?,
                    kind: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(sums)
    }

    /// 写入/覆盖一个群(M7c):members 序列化为 JSON 存 members_json。
    pub fn upsert_group(&self, g: &crate::groups::Group, created_ts: i64) -> Result<(), StorageError> {
        let members_json = serde_json::to_string(
            &g.members
                .iter()
                .map(|m| (m.fp.clone(), m.nick.clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_string());
        let conn = self.conn.lock().expect("storage lock");
        conn.execute(
            "INSERT INTO groups (group_id, name, creator_fp, version, members_json, created_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id) DO UPDATE SET
               name = excluded.name,
               version = excluded.version,
               members_json = excluded.members_json",
            params![
                g.group_id,
                g.name,
                g.creator_fp,
                g.version as i64,
                members_json,
                created_ts
            ],
        )?;
        Ok(())
    }

    pub fn delete_group(&self, group_id: &str) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        conn.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id])?;
        Ok(())
    }

    pub fn load_groups(&self) -> Result<Vec<crate::groups::Group>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT group_id, name, creator_fp, version, members_json FROM groups",
        )?;
        let groups = stmt
            .query_map([], |row| {
                let members_json: String = row.get(4)?;
                let pairs: Vec<(String, String)> =
                    serde_json::from_str(&members_json).unwrap_or_default();
                Ok(crate::groups::Group {
                    group_id: row.get(0)?,
                    name: row.get(1)?,
                    creator_fp: row.get(2)?,
                    version: row.get::<_, i64>(3)? as u64,
                    members: pairs
                        .into_iter()
                        .map(|(fp, nick)| crate::groups::GroupMember { fp, nick })
                        .collect(),
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(groups)
    }

    pub fn known_peers(&self) -> Result<Vec<KnownPeer>, StorageError> {
        let conn = self.conn.lock().expect("storage lock");
        let mut stmt = conn.prepare(
            "SELECT fingerprint, nickname, protocol, last_addr, last_seen_ms, group_name
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
                    group: row.get(5)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(peers)
    }
}

/// UNION 行 → HistoryItem。列序固定:kind, k1(id/xfer_id), peer_fp,
/// direction, k2(body/name), k3(status), k4(size), k5(is_dir), k6(path), ts_ms,
/// k7(sender_fp,仅 text 有值)。
fn row_to_item(row: &rusqlite::Row<'_>) -> Result<HistoryItem, rusqlite::Error> {
    let kind: String = row.get(0)?;
    if kind == "text" {
        Ok(HistoryItem::Text {
            id: row.get(1)?,
            peer_fp: row.get(2)?,
            direction: row.get(3)?,
            body: row.get(4)?,
            ts_ms: row.get(9)?,
            sender_fp: row.get(10)?,
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
    }
    // v2(M7a):peers 表新增 group_name 列(对端声明的工作组名)。
    // v1→v2 老库与"上面刚建完 v1 表结构的全新库"都走这条 ALTER。
    if version < 2 {
        conn.execute_batch("ALTER TABLE peers ADD COLUMN group_name TEXT;")?;
    }
    // v3(M7c):群表 + 群消息发送者列。群历史复用 messages 表,
    // peer_fp 列泛化为会话 id(单聊=对端指纹,群聊=group_id);
    // sender_fp 仅群聊入站消息有值(单聊 NULL)。
    if version < 3 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS groups (
               group_id     TEXT PRIMARY KEY,
               name         TEXT NOT NULL,
               creator_fp   TEXT NOT NULL,
               version      INTEGER NOT NULL,
               members_json TEXT NOT NULL,
               created_ts   INTEGER NOT NULL
             );
             ALTER TABLE messages ADD COLUMN sender_fp TEXT;",
        )?;
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
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

    /// HistoryItem → 复合游标 (ts_ms, id),供分页测试拼下一页的 `before` 参数。
    fn cursor(it: &HistoryItem) -> (i64, String) {
        match it {
            HistoryItem::Text { id, ts_ms, .. } => (*ts_ms, id.clone()),
            HistoryItem::File { xfer_id, ts_ms, .. } => (*ts_ms, xfer_id.clone()),
        }
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
        s.insert_message("m1", "peerA", "in", "你好", 1000, None).unwrap();
        s.insert_message("m2", "peerA", "out", "hi", 2000, None).unwrap();
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
        s.insert_message("m1", "peerA", "in", "a", 1, None).unwrap();
        // 同 id 再插不报错(INSERT OR IGNORE)
        s.insert_message("m1", "peerA", "in", "a", 1, None).unwrap();
        assert_eq!(s.history("peerA", None, 50).unwrap().len(), 1);
    }

    #[test]
    fn transfer_insert_update_and_merged_history() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "先发一句", 1000, None).unwrap();
        s.insert_transfer("x1", "peerA", "in", "a.zip", 2048, false, "offered", 1500)
            .unwrap();
        s.update_transfer("x1", "done", Some("/tmp/a.zip")).unwrap();
        s.insert_message("m2", "peerA", "out", "收到了吗", 2000, None).unwrap();

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
            s.insert_message(&format!("m{i}"), "peerA", "in", "x", i * 100, None).unwrap();
        }
        let page1 = s.history("peerA", None, 4).unwrap();
        assert_eq!(
            page1.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![600, 700, 800, 900],
            "第一页是最新 4 条"
        );
        let (t, id) = cursor(&page1[0]);
        let page2 = s.history("peerA", Some((t, &id)), 4).unwrap();
        assert_eq!(
            page2.iter().map(HistoryItem::ts_ms).collect::<Vec<_>>(),
            vec![200, 300, 400, 500],
            "游标之前的一页,不含游标本身"
        );
    }

    #[test]
    fn history_cursor_survives_same_timestamp_boundary() {
        let s = mem();
        // 5 条同毫秒消息 + 1 条更早的,页大小 3:边界正好落在同毫秒簇中间
        for i in 0..5 {
            s.insert_message(&format!("m{i}"), "peerA", "in", "x", 1000, None).unwrap();
        }
        s.insert_message("m_old", "peerA", "in", "old", 500, None).unwrap();
        let page1 = s.history("peerA", None, 3).unwrap();
        assert_eq!(page1.len(), 3);
        let cursor = |items: &[HistoryItem]| match &items[0] {
            HistoryItem::Text { id, ts_ms, .. } => (*ts_ms, id.clone()),
            HistoryItem::File { xfer_id, ts_ms, .. } => (*ts_ms, xfer_id.clone()),
        };
        let (t1, i1) = cursor(&page1);
        let page2 = s.history("peerA", Some((t1, &i1)), 3).unwrap();
        let (t2, i2) = cursor(&page2);
        let page3 = s.history("peerA", Some((t2, &i2)), 3).unwrap();
        let mut all: Vec<String> = [page1, page2, page3]
            .concat()
            .iter()
            .map(|it| match it {
                HistoryItem::Text { id, .. } => id.clone(),
                HistoryItem::File { xfer_id, .. } => xfer_id.clone(),
            })
            .collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 6, "同毫秒簇跨页边界不得丢条目也不得重复");
    }

    #[test]
    fn history_isolates_peers() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "a", 1, None).unwrap();
        s.insert_message("m2", "peerB", "in", "b", 2, None).unwrap();
        assert_eq!(s.history("peerA", None, 50).unwrap().len(), 1);
    }

    #[test]
    fn history_around_returns_context_window() {
        let s = mem();
        for i in 0..20 {
            s.insert_message(&format!("m{i}"), "peerA", "in", "x", i * 100, None).unwrap();
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
        s.insert_message("m1", "peerA", "in", "明天开会记得带电脑", 1000, None).unwrap();
        s.insert_message("m2", "peerB", "out", "好的", 2000, None).unwrap();
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
        s.insert_message("m1", "peerA", "in", "百分号%字面量", 1000, None).unwrap();
        s.insert_message("m2", "peerA", "in", "别的", 2000, None).unwrap();
        let hits = s.search("%", 50).unwrap();
        assert_eq!(hits.len(), 1, "% 应按字面匹配,不是通配一切");
    }

    #[test]
    fn clear_history_single_peer_and_all() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "a", 1, None).unwrap();
        s.insert_transfer("x1", "peerA", "in", "f", 1, false, "done", 2).unwrap();
        s.insert_message("m2", "peerB", "in", "b", 3, None).unwrap();

        s.clear_history(Some("peerA")).unwrap();
        assert!(s.history("peerA", None, 50).unwrap().is_empty());
        assert_eq!(s.history("peerB", None, 50).unwrap().len(), 1, "别的会话不受影响");

        s.clear_history(None).unwrap();
        assert!(s.history("peerB", None, 50).unwrap().is_empty(), "None = 全部清空");
    }

    #[test]
    fn upsert_peer_and_known_peers() {
        let s = mem();
        s.upsert_peer("fpA", "alice", "native", Some("192.168.1.5"), None, 1000).unwrap();
        s.upsert_peer("fpA", "alice-renamed", "native", Some("192.168.1.6"), None, 2000)
            .unwrap();
        // COALESCE 回归:last_addr 传 None 不得抹掉旧地址,其余字段照常更新
        s.upsert_peer("fpA", "alice-renamed", "native", None, None, 3000).unwrap();
        s.upsert_peer("ipmsg:k", "bob-feiq", "ipmsg", None, None, 1500).unwrap();
        let peers = s.known_peers().unwrap();
        assert_eq!(peers.len(), 2, "同 fingerprint 覆盖不重复");
        let a = peers.iter().find(|p| p.fingerprint == "fpA").unwrap();
        assert_eq!(a.nickname, "alice-renamed");
        assert_eq!(a.last_addr.as_deref(), Some("192.168.1.6"));
        assert_eq!(a.last_seen_ms, 3000);
    }

    /// M7b:会话摘要 = 每个 peer_fp 的最后一条(文本或文件),按 ts 倒序。
    #[test]
    fn conversation_summaries_returns_last_item_per_peer() {
        let s = mem();
        s.insert_message("m1", "peerA", "in", "第一条", 100, None).unwrap();
        s.insert_message("m2", "peerA", "out", "A 的最后一条", 300, None).unwrap();
        s.insert_transfer("x1", "peerB", "in", "报告.pdf", 10, false, "done", 500)
            .unwrap();
        s.insert_message("m3", "peerB", "in", "早于文件", 400, None).unwrap();
        let sums = s.conversation_summaries().unwrap();
        assert_eq!(sums.len(), 2);
        assert_eq!(sums[0].peer_fp, "peerB", "最近活跃的会话排前");
        assert_eq!(sums[0].snippet, "报告.pdf");
        assert_eq!(sums[0].kind, "file");
        assert_eq!(sums[0].ts_ms, 500);
        assert_eq!(sums[1].peer_fp, "peerA");
        assert_eq!(sums[1].snippet, "A 的最后一条");
        assert_eq!(sums[1].kind, "text");
    }

    #[test]
    fn conversation_summaries_empty_db_is_empty() {
        assert!(mem().conversation_summaries().unwrap().is_empty());
    }

    /// M7a:peers 表 v2 迁移新增 group_name 列,组名随 upsert 持久化,
    /// 重开库(v2 已就位再次 migrate)不报错。
    #[test]
    fn peers_table_persists_group() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.upsert_peer("fpA", "alice", "native", Some("192.168.1.5"), Some("研发部"), 1000)
            .unwrap();
        s.upsert_peer("fpB", "bob", "ipmsg", None, None, 2000).unwrap();
        let peers = s.known_peers().unwrap();
        let a = peers.iter().find(|p| p.fingerprint == "fpA").unwrap();
        assert_eq!(a.group, Some("研发部".to_string()));
        let b = peers.iter().find(|p| p.fingerprint == "fpB").unwrap();
        assert_eq!(b.group, None);
        drop(s);
        let s2 = Storage::open(dir.path()).unwrap();
        assert_eq!(s2.known_peers().unwrap().len(), 2, "v2 库重开不报错");
    }

    /// v1 老库(无 group_name 列)打开时必须原地迁移成功且旧数据可读。
    #[test]
    fn migrates_v1_db_in_place() {
        let dir = tempfile::tempdir().unwrap();
        // 手工造一个 v1 库:建 v1 完整表结构 + user_version=1 + 一行旧数据
        {
            let conn = Connection::open(dir.path().join("bigpaw.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                   id TEXT PRIMARY KEY, peer_fp TEXT NOT NULL, direction TEXT NOT NULL,
                   body TEXT NOT NULL, ts_ms INTEGER NOT NULL
                 );
                 CREATE TABLE transfers (
                   xfer_id TEXT PRIMARY KEY, peer_fp TEXT NOT NULL, direction TEXT NOT NULL,
                   name TEXT NOT NULL, size INTEGER NOT NULL, is_dir INTEGER NOT NULL DEFAULT 0,
                   status TEXT NOT NULL, path TEXT, ts_ms INTEGER NOT NULL
                 );
                 CREATE TABLE peers (
                   fingerprint  TEXT PRIMARY KEY,
                   nickname     TEXT NOT NULL,
                   protocol     TEXT NOT NULL,
                   last_addr    TEXT,
                   last_seen_ms INTEGER NOT NULL
                 );
                 INSERT INTO peers VALUES ('fpOld', 'old-nick', 'native', NULL, 42);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        let s = Storage::open(dir.path()).unwrap();
        let peers = s.known_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].group, None, "老数据组名为 NULL → None");
        // 迁移后可正常写入组名
        s.upsert_peer("fpOld", "old-nick", "native", None, Some("市场部"), 100)
            .unwrap();
        assert_eq!(
            s.known_peers().unwrap()[0].group,
            Some("市场部".to_string())
        );
    }

    /// M7c:群表往返/覆盖/删除;群历史(peer_fp=group_id)与单聊不串。
    #[test]
    fn groups_table_roundtrip_and_history_isolation() {
        let s = mem();
        let g = crate::groups::Group {
            group_id: "gid-1".to_string(),
            name: "猫猫群".to_string(),
            creator_fp: "me".to_string(),
            version: 1,
            members: vec![
                crate::groups::GroupMember { fp: "me".to_string(), nick: "我".to_string() },
                crate::groups::GroupMember { fp: "b".to_string(), nick: "乙".to_string() },
            ],
        };
        s.upsert_group(&g, 100).unwrap();
        let loaded = s.load_groups().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], g);

        // 覆盖(版本推进)
        let mut g2 = g.clone();
        g2.version = 2;
        g2.members.pop();
        s.upsert_group(&g2, 100).unwrap();
        assert_eq!(s.load_groups().unwrap()[0].version, 2);
        assert_eq!(s.load_groups().unwrap()[0].members.len(), 1);

        // 群历史与单聊隔离:conv 主键分别是 group_id 与对端指纹
        s.insert_message("m1", "gid-1", "in", "群里的话", 200, Some("b")).unwrap();
        s.insert_message("m2", "b", "in", "私聊的话", 300, None).unwrap();
        let group_hist = s.history("gid-1", None, 10).unwrap();
        assert_eq!(group_hist.len(), 1);
        match &group_hist[0] {
            HistoryItem::Text { sender_fp, body, .. } => {
                assert_eq!(sender_fp.as_deref(), Some("b"));
                assert_eq!(body, "群里的话");
            }
            other => panic!("期望 Text,得到 {other:?}"),
        }
        assert_eq!(s.history("b", None, 10).unwrap().len(), 1, "单聊不串群");

        s.delete_group("gid-1").unwrap();
        assert!(s.load_groups().unwrap().is_empty());
    }

    /// v2 老库(有 group_name、无 groups 表/sender_fp)打开时原地迁移。
    #[test]
    fn migrates_v2_db_in_place() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = Connection::open(dir.path().join("bigpaw.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                   id TEXT PRIMARY KEY, peer_fp TEXT NOT NULL, direction TEXT NOT NULL,
                   body TEXT NOT NULL, ts_ms INTEGER NOT NULL
                 );
                 INSERT INTO messages VALUES ('old-m', 'peerX', 'in', '旧消息', 42);
                 CREATE TABLE transfers (
                   xfer_id TEXT PRIMARY KEY, peer_fp TEXT NOT NULL, direction TEXT NOT NULL,
                   name TEXT NOT NULL, size INTEGER NOT NULL, is_dir INTEGER NOT NULL DEFAULT 0,
                   status TEXT NOT NULL, path TEXT, ts_ms INTEGER NOT NULL
                 );
                 CREATE TABLE peers (
                   fingerprint TEXT PRIMARY KEY, nickname TEXT NOT NULL, protocol TEXT NOT NULL,
                   last_addr TEXT, last_seen_ms INTEGER NOT NULL, group_name TEXT
                 );
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }
        let s = Storage::open(dir.path()).unwrap();
        // 旧消息可读,sender_fp 为 None
        match &s.history("peerX", None, 10).unwrap()[0] {
            HistoryItem::Text { sender_fp, .. } => assert_eq!(*sender_fp, None),
            other => panic!("期望 Text,得到 {other:?}"),
        }
        assert!(s.load_groups().unwrap().is_empty(), "groups 表已建且为空");
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

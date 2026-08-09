//! 群聊状态机(M7c):成员表单写者=建群者,版本号 LWW 合并。
//! 纯内存状态 + 纯函数,零 IO——持久化/网络扇出由 core 编排。

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub fp: String,
    pub nick: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub group_id: String,
    pub name: String,
    pub creator_fp: String,
    /// 成员表版本:仅建群者递增;接收方按"更高版本胜"合并。
    pub version: u64,
    pub members: Vec<GroupMember>,
}

impl Group {
    /// fp 是否在成员表内。
    pub fn has_member(&self, fp: &str) -> bool {
        self.members.iter().any(|m| m.fp == fp)
    }
}

/// `GroupsState::apply_info` 的合并结论,core 据此决定持久化/上报动作。
#[derive(Debug, PartialEq, Eq)]
pub enum InfoOutcome {
    /// 新群(自己在成员表内)已加入。
    Joined,
    /// 已知群按更高版本覆盖。
    Updated,
    /// 新版本成员表里没有自己:本地删除该群(被移出)。
    Removed,
    /// 版本不高于本地(重复/乱序到达),或新群成员表里没有自己:忽略。
    Ignored,
}

/// 本机已知群集合。
#[derive(Default)]
pub struct GroupsState {
    groups: std::collections::HashMap<String, Group>,
}

impl GroupsState {
    pub fn new(initial: Vec<Group>) -> Self {
        Self {
            groups: initial.into_iter().map(|g| (g.group_id.clone(), g)).collect(),
        }
    }

    pub fn get(&self, group_id: &str) -> Option<&Group> {
        self.groups.get(group_id)
    }

    pub fn list(&self) -> Vec<Group> {
        let mut v: Vec<Group> = self.groups.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.group_id.cmp(&b.group_id)));
        v
    }

    /// 本地直接写入(建群者自己 create/update 时用,不走 LWW 判定)。
    pub fn upsert_local(&mut self, g: Group) {
        self.groups.insert(g.group_id.clone(), g);
    }

    pub fn remove(&mut self, group_id: &str) -> Option<Group> {
        self.groups.remove(group_id)
    }

    /// 收到对端 GroupInfo 的合并逻辑(LWW):
    /// - 未知群:自己在成员表 → 加入(Joined);不在 → 忽略(误发)。
    /// - 已知群:version 更高 → 自己仍在成员表则覆盖(Updated),
    ///   不在则删除本地群(Removed);version ≤ 本地 → Ignored。
    pub fn apply_info(&mut self, incoming: Group, self_fp: &str) -> InfoOutcome {
        match self.groups.get(&incoming.group_id) {
            None => {
                if incoming.has_member(self_fp) {
                    self.groups.insert(incoming.group_id.clone(), incoming);
                    InfoOutcome::Joined
                } else {
                    InfoOutcome::Ignored
                }
            }
            Some(existing) => {
                if incoming.version <= existing.version {
                    return InfoOutcome::Ignored;
                }
                if incoming.has_member(self_fp) {
                    self.groups.insert(incoming.group_id.clone(), incoming);
                    InfoOutcome::Updated
                } else {
                    self.groups.remove(&incoming.group_id);
                    InfoOutcome::Removed
                }
            }
        }
    }
}

/// 扇出目标:成员表减去自己(在线与否由调用方按 roster 决定,离线静默跳过)。
pub fn fan_out_targets(group: &Group, self_fp: &str) -> Vec<String> {
    group
        .members
        .iter()
        .filter(|m| m.fp != self_fp)
        .map(|m| m.fp.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "me-fp";

    fn member(fp: &str) -> GroupMember {
        GroupMember {
            fp: fp.to_string(),
            nick: format!("nick-{fp}"),
        }
    }

    fn group(id: &str, version: u64, member_fps: &[&str]) -> Group {
        Group {
            group_id: id.to_string(),
            name: "测试群".to_string(),
            creator_fp: "creator-fp".to_string(),
            version,
            members: member_fps.iter().map(|f| member(f)).collect(),
        }
    }

    #[test]
    fn unknown_group_with_self_joins() {
        let mut s = GroupsState::default();
        let out = s.apply_info(group("g1", 1, &[ME, "b"]), ME);
        assert_eq!(out, InfoOutcome::Joined);
        assert!(s.get("g1").is_some());
    }

    #[test]
    fn unknown_group_without_self_is_ignored() {
        let mut s = GroupsState::default();
        let out = s.apply_info(group("g1", 1, &["a", "b"]), ME);
        assert_eq!(out, InfoOutcome::Ignored);
        assert!(s.get("g1").is_none(), "误发的群不入库");
    }

    #[test]
    fn higher_version_overwrites_lower_is_ignored() {
        let mut s = GroupsState::new(vec![group("g1", 2, &[ME, "b"])]);
        assert_eq!(
            s.apply_info(group("g1", 3, &[ME, "b", "c"]), ME),
            InfoOutcome::Updated
        );
        assert_eq!(s.get("g1").unwrap().members.len(), 3);
        // 乱序到达的旧版本(以及等版本重复)不回退
        assert_eq!(s.apply_info(group("g1", 2, &[ME]), ME), InfoOutcome::Ignored);
        assert_eq!(s.apply_info(group("g1", 3, &[ME]), ME), InfoOutcome::Ignored);
        assert_eq!(s.get("g1").unwrap().members.len(), 3);
    }

    #[test]
    fn removed_from_higher_version_deletes_group() {
        let mut s = GroupsState::new(vec![group("g1", 1, &[ME, "b"])]);
        assert_eq!(
            s.apply_info(group("g1", 2, &["b", "c"]), ME),
            InfoOutcome::Removed
        );
        assert!(s.get("g1").is_none());
    }

    #[test]
    fn fan_out_excludes_self() {
        let g = group("g1", 1, &[ME, "b", "c"]);
        assert_eq!(fan_out_targets(&g, ME), vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn list_sorted_by_name_then_id() {
        let mut a = group("g2", 1, &[ME]);
        a.name = "苹果群".to_string();
        let mut b = group("g1", 1, &[ME]);
        b.name = "香蕉群".to_string();
        let s = GroupsState::new(vec![b, a]);
        let names: Vec<String> = s.list().into_iter().map(|g| g.name).collect();
        assert_eq!(names, vec!["苹果群".to_string(), "香蕉群".to_string()]);
    }
}

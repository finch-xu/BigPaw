import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAppStore, type Group } from "./store";
import Avatar from "./Avatar";
import { IS_TAURI } from "./mock";

/** 建群面板(M7c):群名 + 成员多选。仅 native 协议对端可选(飞秋无法入群)。 */
export default function CreateGroupModal() {
  const peers = useAppStore((s) => s.peers);
  const setShowCreateGroup = useAppStore((s) => s.setShowCreateGroup);
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");

  const candidates = peers.filter((p) => p.protocol === "native");

  function toggle(fp: string) {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(fp)) next.delete(fp);
      else next.add(fp);
      return next;
    });
  }

  async function handleCreate() {
    const n = name.trim();
    if (!n || selected.size === 0) {
      setError("群名和至少一位成员都不能为空");
      return;
    }
    if (!IS_TAURI) {
      setShowCreateGroup(false);
      return;
    }
    try {
      const group = await invoke<Group>("create_group", {
        name: n,
        memberFps: [...selected],
      });
      const st = useAppStore.getState();
      st.setGroups([...st.groups, group]);
      st.setShowCreateGroup(false);
      void st.openConversation(group.groupId);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div
      className="fixed inset-0 z-10 flex items-center justify-center bg-black/30 backdrop-blur-[2px]"
      onClick={() => setShowCreateGroup(false)}
    >
      <div
        className="flex max-h-[80vh] w-[24rem] flex-col rounded-2xl border border-border2 bg-background p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-3 text-base font-bold">创建群聊</h2>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={32}
          placeholder="群名称"
          className="mb-3 w-full rounded-lg border border-border bg-panel px-3 py-1.5 text-sm outline-none focus:border-primary"
        />
        <p className="mb-1 text-xs text-muted-foreground">
          选择成员(仅 BigPaw 用户,飞秋用户无法加入群聊)
        </p>
        <ul className="min-h-0 flex-1 space-y-0.5 overflow-y-auto">
          {candidates.length === 0 && (
            <li className="py-4 text-sm text-muted-foreground">暂无可选的 BigPaw 联系人</li>
          )}
          {candidates.map((p) => (
            <li key={p.fingerprint}>
              <label className="flex cursor-pointer items-center gap-2.5 rounded-xl px-2 py-1.5 hover:bg-hover">
                <input
                  type="checkbox"
                  checked={selected.has(p.fingerprint)}
                  onChange={() => toggle(p.fingerprint)}
                  className="accent-(--primary)"
                />
                <Avatar fp={p.fingerprint} name={p.nickname} size={28} />
                <span className="min-w-0 flex-1 truncate text-sm">{p.nickname}</span>
                {p.state === "offline" && (
                  <span className="text-[10px] text-muted-foreground">离线</span>
                )}
              </label>
            </li>
          ))}
        </ul>
        {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
        <div className="mt-4 flex gap-2">
          <button
            onClick={() => setShowCreateGroup(false)}
            className="flex-1 rounded-full border border-border py-2 text-sm text-fg2 hover:bg-hover"
          >
            取消
          </button>
          <button
            onClick={handleCreate}
            className="flex-1 rounded-full bg-primary py-2 text-sm text-primary-foreground hover:bg-primary-strong"
          >
            创建({selected.size})
          </button>
        </div>
      </div>
    </div>
  );
}

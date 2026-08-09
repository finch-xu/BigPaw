import { useState } from "react";
import { useAppStore, type Peer } from "./store";
import Avatar from "./Avatar";

const statusDotClass = (state: Peer["state"]) => {
  switch (state) {
    case "reachable":
      return "bg-success";
    case "unreachable":
      return "bg-destructive";
    case "offline":
      return "bg-muted-foreground/40";
    case "discovered":
    default:
      return "bg-warning";
  }
};

function PeerRow({ p, selected, onClick }: { p: Peer; selected: boolean; onClick: () => void }) {
  return (
    <li
      onClick={onClick}
      className={
        "mx-2 flex cursor-pointer items-center gap-2.5 rounded-xl px-2.5 py-2 " +
        (selected ? "bg-active" : "hover:bg-hover") +
        (p.state === "offline" ? " opacity-55" : "")
      }
    >
      <div className="relative shrink-0">
        <Avatar fp={p.fingerprint} name={p.nickname} size={36} />
        <span
          className={`absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full ring-2 ring-sidebar ${statusDotClass(p.state)}`}
          title={p.state === "unreachable" ? "可见但无法连接,可能是防火墙拦截" : undefined}
        />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-sm font-medium">{p.nickname}</span>
          {p.protocol === "ipmsg" && (
            <span
              className="shrink-0 rounded-md bg-border2 px-1.5 py-0.5 text-[10px] font-medium text-fg2"
              title="旧协议(IPMsg/飞秋兼容),消息为明文传输"
            >
              旧协议
            </span>
          )}
        </div>
        <div className="truncate text-xs text-muted-foreground">{p.addrs[0] ?? ""}</div>
      </div>
    </li>
  );
}

/** 按组名聚合:有组名的按拼音/本地化排序在前,未分组("")最后。 */
function groupsOf(list: Peer[]): Array<[string, Peer[]]> {
  const m = new Map<string, Peer[]>();
  for (const p of list) {
    const key = p.group ?? "";
    const bucket = m.get(key);
    if (bucket) bucket.push(p);
    else m.set(key, [p]);
  }
  return [...m.entries()].sort((a, b) =>
    a[0] === "" ? 1 : b[0] === "" ? -1 : a[0].localeCompare(b[0], "zh-CN"),
  );
}

/** 通讯录视图(M7b):全部联系人(含离线)按组折叠展示,组头带在线/总数。 */
export default function ContactTree() {
  const peers = useAppStore((s) => s.peers);
  const selectedFp = useAppStore((s) => s.selectedFp);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  if (peers.length === 0) {
    return <p className="px-4 py-6 text-sm text-muted-foreground">正在搜索局域网设备…</p>;
  }

  const groups = groupsOf(peers);

  return (
    <div>
      {groups.map(([group, members]) => {
        const online = members.filter((p) => p.state !== "offline").length;
        const isCollapsed = collapsed[group] ?? false;
        // 组内排序:在线在前,组内按昵称
        const sorted = [...members].sort(
          (a, b) =>
            Number(a.state === "offline") - Number(b.state === "offline") ||
            a.nickname.localeCompare(b.nickname, "zh-CN"),
        );
        return (
          <div key={group || "__ungrouped__"}>
            <button
              onClick={() => setCollapsed((c) => ({ ...c, [group]: !isCollapsed }))}
              className="flex w-full items-center gap-1 px-4 pb-1 pt-3 text-left text-[10px] font-semibold uppercase tracking-wide text-muted-foreground hover:text-fg2"
            >
              <span
                className={
                  "inline-block transition-transform " + (isCollapsed ? "" : "rotate-90")
                }
              >
                ▶
              </span>
              <span className="truncate">{group || "未分组"}</span>
              <span className="ml-auto shrink-0 font-normal normal-case">
                {online}/{members.length}
              </span>
            </button>
            {!isCollapsed && (
              <ul className="space-y-0.5">
                {sorted.map((p) => (
                  <PeerRow
                    key={p.fingerprint}
                    p={p}
                    selected={selectedFp === p.fingerprint}
                    onClick={() => void useAppStore.getState().openConversation(p.fingerprint)}
                  />
                ))}
              </ul>
            )}
          </div>
        );
      })}
    </div>
  );
}

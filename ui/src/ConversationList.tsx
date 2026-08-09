import { useAppStore } from "./store";
import Avatar from "./Avatar";

/** 相对时间:今天显示 HH:mm,昨天显示"昨天",更早显示 M/D。 */
function relTime(ts: number): string {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString())
    return d.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return "昨天";
  return d.toLocaleDateString("zh-CN", { month: "numeric", day: "numeric" });
}

/** 消息视图(M7b/M7c):有会话往来的对象 + 已加入的群,按最后消息时间倒序。
 * 尚无消息的群也显示(tsMs=0 沉底),否则新建的群没有入口。 */
export default function ConversationList() {
  const peers = useAppStore((s) => s.peers);
  const groups = useAppStore((s) => s.groups);
  const convSummaries = useAppStore((s) => s.convSummaries);
  const unread = useAppStore((s) => s.unread);
  const selectedFp = useAppStore((s) => s.selectedFp);

  const rows: Array<[string, { tsMs: number; snippet: string; kind: "text" | "file" }]> =
    Object.entries(convSummaries);
  for (const g of groups) {
    if (!convSummaries[g.groupId]) {
      rows.push([g.groupId, { tsMs: 0, snippet: "群已创建,来说点什么吧", kind: "text" }]);
    }
  }
  rows.sort((a, b) => b[1].tsMs - a[1].tsMs);

  if (rows.length === 0) {
    return (
      <p className="px-4 py-6 text-sm text-muted-foreground">
        暂无会话,去「通讯录」找人聊聊
      </p>
    );
  }

  return (
    <ul className="space-y-0.5">
      {rows.map(([fp, sum]) => {
        const group = groups.find((g) => g.groupId === fp);
        const peer = peers.find((p) => p.fingerprint === fp);
        const name = group ? group.name : (peer?.nickname ?? fp.slice(0, 8));
        const n = unread[fp] ?? 0;
        return (
          <li
            key={fp}
            onClick={() => void useAppStore.getState().openConversation(fp)}
            className={
              "mx-2 flex cursor-pointer items-center gap-2.5 rounded-xl px-2.5 py-2 " +
              (selectedFp === fp ? "bg-active" : "hover:bg-hover")
            }
          >
            <div className="relative shrink-0">
              <Avatar fp={fp} name={name} size={36} />
              {n > 0 && (
                <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-white">
                  {n > 99 ? "99+" : n}
                </span>
              )}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate text-sm font-medium">{name}</span>
                  {group && (
                    <span className="shrink-0 rounded-md bg-border2 px-1.5 py-0.5 text-[10px] font-medium text-fg2">
                      群
                    </span>
                  )}
                </span>
                <span className="shrink-0 text-[10px] text-muted-foreground">
                  {sum.tsMs > 0 ? relTime(sum.tsMs) : ""}
                </span>
              </div>
              <div className="truncate text-xs text-muted-foreground">
                {sum.kind === "file" ? "📎 " : ""}
                {sum.snippet}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

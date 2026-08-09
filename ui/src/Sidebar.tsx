import { useState } from "react";
import { useAppStore } from "./store";
import ConversationList from "./ConversationList";
import ContactTree from "./ContactTree";

type Tab = "chats" | "contacts";

/** 左栏容器(M7b 飞书式):消息/通讯录双视图 + 搜索 + 状态条 + 设置入口。 */
export default function Sidebar() {
  const self = useAppStore((s) => s.self);
  const peers = useAppStore((s) => s.peers);
  const ipmsg = useAppStore((s) => s.ipmsg);
  const searchQuery = useAppStore((s) => s.searchQuery);
  const searchHits = useAppStore((s) => s.searchHits);
  const unread = useAppStore((s) => s.unread);
  const [tab, setTab] = useState<Tab>("chats");

  const searching = searchQuery.trim().length > 0;
  const nickOf = (fp: string) =>
    peers.find((p) => p.fingerprint === fp)?.nickname ?? fp.slice(0, 8);
  const totalUnread = Object.values(unread).reduce((a, b) => a + b, 0);

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-sidebar">
      <header className="px-4 pb-3 pt-4">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-sm font-bold">{self?.nickname ?? "…"}</span>
          {self && (
            <span className="shrink-0 rounded-full border border-border2 bg-panel px-2 py-0.5 text-[10px] text-muted-foreground">
              #{self.fingerprint.slice(0, 8)}
            </span>
          )}
        </div>
        <input
          value={searchQuery}
          onChange={(e) => {
            const q = e.target.value;
            useAppStore.getState().setSearchQuery(q);
            void useAppStore.getState().runSearch(q);
          }}
          placeholder="搜索聊天记录…"
          className="mt-3 w-full rounded-full border border-transparent bg-panel px-3 py-1.5 text-xs outline-none placeholder:text-muted-foreground focus:border-primary"
        />
        {!searching && (
          <div className="mt-3 flex gap-1 rounded-full bg-panel p-1">
            {(
              [
                ["chats", "消息"],
                ["contacts", "通讯录"],
              ] as Array<[Tab, string]>
            ).map(([key, label]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={
                  "relative flex-1 rounded-full py-1 text-xs " +
                  (tab === key
                    ? "bg-primary text-primary-foreground"
                    : "text-fg2 hover:bg-hover")
                }
              >
                {label}
                {key === "chats" && totalUnread > 0 && tab !== "chats" && (
                  <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-destructive" />
                )}
              </button>
            ))}
          </div>
        )}
      </header>
      <div className="flex-1 overflow-y-auto pb-2">
        {searching ? (
          <ul className="space-y-0.5">
            {searchHits.length === 0 && (
              <li className="px-4 py-6 text-sm text-muted-foreground">没有匹配的记录</li>
            )}
            {searchHits.map((h, i) => (
              <li
                key={`${h.peerFp}-${h.tsMs}-${i}`}
                onClick={() => void useAppStore.getState().jumpToMessage(h.peerFp, h.tsMs)}
                className="mx-2 cursor-pointer rounded-xl px-2.5 py-2 hover:bg-hover"
              >
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span className="font-medium text-fg2">{nickOf(h.peerFp)}</span>
                  <span>{new Date(h.tsMs).toLocaleDateString("zh-CN")}</span>
                </div>
                <div className="truncate text-sm">
                  {h.kind === "file" ? "📎 " : ""}
                  {h.snippet}
                </div>
              </li>
            ))}
          </ul>
        ) : tab === "chats" ? (
          <ConversationList />
        ) : (
          <ContactTree />
        )}
      </div>
      {ipmsg && ipmsg.enabled && !ipmsg.available && (
        <p className="border-t border-border2 px-4 py-2 text-xs text-muted-foreground">
          IPMsg 兼容层未启用(2425 端口被占用,可能本机在跑飞秋)
        </p>
      )}
      {ipmsg && !ipmsg.enabled && (
        <p className="border-t border-border2 px-4 py-2 text-xs text-muted-foreground">
          IPMsg 兼容层已在设置中关闭
        </p>
      )}
      <button
        onClick={() => useAppStore.getState().setShowSettings(true)}
        className="flex items-center gap-2 border-t border-border px-4 py-2.5 text-left text-sm text-fg2 hover:bg-hover"
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
        设置
      </button>
    </aside>
  );
}

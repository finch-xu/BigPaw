import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Peer, type SelfInfo } from "./store";
import ChatPane from "./ChatPane";
import SettingsModal from "./SettingsModal";
import Avatar from "./Avatar";
import EmptyState from "./EmptyState";
import { IS_TAURI, installMocks } from "./mock";

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

export default function App() {
  const self = useAppStore((s) => s.self);
  const peers = useAppStore((s) => s.peers);
  const selectedFp = useAppStore((s) => s.selectedFp);
  const ipmsg = useAppStore((s) => s.ipmsg);
  const searchQuery = useAppStore((s) => s.searchQuery);
  const searchHits = useAppStore((s) => s.searchHits);
  const showSettings = useAppStore((s) => s.showSettings);

  useEffect(() => {
    if (!IS_TAURI) {
      installMocks();
      return;
    }
    // 事件处理里统一走 getState():回调生命周期长于渲染周期,不闭包旧状态
    const st = () => useAppStore.getState();
    let cancelled = false;
    const unlisteners: Array<() => void> = [];
    (async () => {
      try {
        // 先订阅再拉快照:快照是全量状态,晚到的快照覆盖早到的事件也不会丢数据
        const subs = await Promise.all([
          listen<Peer[]>("roster://updated", (e) => st().setPeers(e.payload)),
          listen<{ peerFp: string; id: string; body: string; tsMs: number }>(
            "message://received",
            (e) => st().appendText({ kind: "text", direction: "in", ...e.payload }),
          ),
          listen<{ xferId: string; peerFp: string; name: string; size: number; isDir: boolean }>(
            "file://offered",
            (e) =>
              st().upsertFile({
                ...e.payload,
                direction: "in",
                status: "offered",
                tsMs: Date.now(),
              }),
          ),
          listen<{ xferId: string; done: number; total: number }>("file://progress", (e) =>
            st().upsertFile({ xferId: e.payload.xferId, done: e.payload.done, size: e.payload.total }),
          ),
          listen<{ xferId: string; path: string }>("file://done", (e) =>
            st().upsertFile({ xferId: e.payload.xferId, status: "done", path: e.payload.path }),
          ),
          listen<{ xferId: string; reason: string }>("file://failed", (e) =>
            st().upsertFile({ xferId: e.payload.xferId, status: "failed" }),
          ),
        ]);
        if (cancelled) {
          subs.forEach((u) => u());
          return;
        }
        unlisteners.push(...subs);
        st().setSelf(await invoke<SelfInfo>("get_self_info"));
        st().setPeers(await invoke<Peer[]>("get_roster"));
        st().setIpmsg(await invoke<{ available: boolean; enabled: boolean }>("ipmsg_status"));
      } catch (e) {
        console.error("初始化失败:", e);
      }
    })();
    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
    };
  }, []);

  const online = peers.filter((p) => p.state !== "offline");
  const offline = peers.filter((p) => p.state === "offline");
  const searching = searchQuery.trim().length > 0;
  const nickOf = (fp: string) =>
    peers.find((p) => p.fingerprint === fp)?.nickname ?? fp.slice(0, 8);

  return (
    <main className="flex h-screen bg-background text-foreground">
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
          ) : (
            <>
              <ul className="space-y-0.5">
                {online.map((p) => (
                  <PeerRow
                    key={p.fingerprint}
                    p={p}
                    selected={selectedFp === p.fingerprint}
                    onClick={() => void useAppStore.getState().openConversation(p.fingerprint)}
                  />
                ))}
                {online.length === 0 && (
                  <li className="px-4 py-6 text-sm text-muted-foreground">正在搜索局域网设备…</li>
                )}
              </ul>
              {offline.length > 0 && (
                <>
                  <div className="px-4 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    离线
                  </div>
                  <ul className="space-y-0.5">
                    {offline.map((p) => (
                      <PeerRow
                        key={p.fingerprint}
                        p={p}
                        selected={selectedFp === p.fingerprint}
                        onClick={() => void useAppStore.getState().openConversation(p.fingerprint)}
                      />
                    ))}
                  </ul>
                </>
              )}
            </>
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
      {selectedFp ? <ChatPane key={selectedFp} fp={selectedFp} /> : <EmptyState />}
      {showSettings && <SettingsModal />}
    </main>
  );
}

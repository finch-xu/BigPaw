import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Peer, type SelfInfo } from "./store";
import ChatPane from "./ChatPane";

const statusDotClass = (state: Peer["state"]) => {
  switch (state) {
    case "reachable":
      return "bg-green-500";
    case "unreachable":
      return "bg-red-500";
    case "offline":
      return "bg-gray-300";
    case "discovered":
    default:
      return "bg-amber-400";
  }
};

function PeerRow({ p, selected, onClick }: { p: Peer; selected: boolean; onClick: () => void }) {
  return (
    <li
      onClick={onClick}
      className={
        "flex cursor-pointer items-center gap-2 px-4 py-3 hover:bg-amber-100 " +
        (selected ? "bg-amber-100" : "") +
        (p.state === "offline" ? " opacity-60" : "")
      }
    >
      <span
        className={`h-2 w-2 shrink-0 rounded-full ${statusDotClass(p.state)}`}
        title={p.state === "unreachable" ? "可见但无法连接,可能是防火墙拦截" : undefined}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate font-medium">{p.nickname}</span>
          {p.protocol === "ipmsg" && (
            <span
              className="shrink-0 rounded bg-amber-200 px-1.5 py-0.5 text-[10px] font-medium text-amber-800"
              title="旧协议(IPMsg/飞秋兼容),消息为明文传输"
            >
              旧协议
            </span>
          )}
        </div>
        <div className="truncate text-xs text-amber-700">{p.addrs[0] ?? ""}</div>
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
    <main className="flex h-screen bg-[#fefbf5] text-amber-950">
      <aside className="flex w-64 shrink-0 flex-col border-r border-amber-200">
        <header className="border-b border-amber-200 p-4">
          <div className="font-bold">{self?.nickname ?? "…"}</div>
          <div className="text-xs text-amber-700">
            {self ? `#${self.fingerprint.slice(0, 8)}` : ""}
          </div>
          <input
            value={searchQuery}
            onChange={(e) => {
              const q = e.target.value;
              useAppStore.getState().setSearchQuery(q);
              void useAppStore.getState().runSearch(q);
            }}
            placeholder="搜索聊天记录…"
            className="mt-2 w-full rounded border border-amber-300 bg-white px-2 py-1 text-xs outline-none focus:border-amber-500"
          />
        </header>
        <div className="flex-1 overflow-y-auto">
          {searching ? (
            <ul>
              {searchHits.length === 0 && (
                <li className="px-4 py-6 text-sm text-amber-600">没有匹配的记录</li>
              )}
              {searchHits.map((h, i) => (
                <li
                  key={`${h.peerFp}-${h.tsMs}-${i}`}
                  onClick={() => void useAppStore.getState().jumpToMessage(h.peerFp, h.tsMs)}
                  className="cursor-pointer border-b border-amber-100 px-4 py-2 hover:bg-amber-100"
                >
                  <div className="flex items-center justify-between text-xs text-amber-700">
                    <span className="font-medium">{nickOf(h.peerFp)}</span>
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
              <ul>
                {online.map((p) => (
                  <PeerRow
                    key={p.fingerprint}
                    p={p}
                    selected={selectedFp === p.fingerprint}
                    onClick={() => void useAppStore.getState().openConversation(p.fingerprint)}
                  />
                ))}
                {online.length === 0 && (
                  <li className="px-4 py-6 text-sm text-amber-600">正在搜索局域网设备…</li>
                )}
              </ul>
              {offline.length > 0 && (
                <>
                  <div className="px-4 pb-1 pt-3 text-[10px] font-semibold uppercase text-amber-400">
                    离线
                  </div>
                  <ul>
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
          <p className="border-t border-amber-200 px-4 py-2 text-xs text-amber-600">
            IPMsg 兼容层未启用(2425 端口被占用,可能本机在跑飞秋)
          </p>
        )}
        {ipmsg && !ipmsg.enabled && (
          <p className="border-t border-amber-200 px-4 py-2 text-xs text-amber-400">
            IPMsg 兼容层已在设置中关闭
          </p>
        )}
        <button
          onClick={() => useAppStore.getState().setShowSettings(true)}
          className="border-t border-amber-200 px-4 py-2 text-left text-sm text-amber-700 hover:bg-amber-100"
        >
          ⚙ 设置
        </button>
      </aside>
      {selectedFp ? (
        <ChatPane key={selectedFp} fp={selectedFp} />
      ) : (
        <section className="flex flex-1 items-center justify-center text-amber-400">
          大脚猫在等对面上线
        </section>
      )}
      {showSettings && null /* Task 11 挂载 <SettingsModal /> */}
    </main>
  );
}

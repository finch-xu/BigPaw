import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Peer, type SelfInfo } from "./store";
import ChatPane from "./ChatPane";

export default function App() {
  const self = useAppStore((s) => s.self);
  const peers = useAppStore((s) => s.peers);
  const selectedFp = useAppStore((s) => s.selectedFp);
  const setSelf = useAppStore((s) => s.setSelf);
  const setPeers = useAppStore((s) => s.setPeers);
  const select = useAppStore((s) => s.select);
  const appendMessage = useAppStore((s) => s.appendMessage);
  const upsertTransfer = useAppStore((s) => s.upsertTransfer);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let unMsgListen: (() => void) | undefined;
    let unFileOffered: (() => void) | undefined;
    let unFileProgress: (() => void) | undefined;
    let unFileDone: (() => void) | undefined;
    let unFileFailed: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      try {
        // 先订阅再拉快照:快照是全量状态,晚到的快照覆盖早到的事件也不会丢数据
        const un = await listen<Peer[]>("roster://updated", (e) => setPeers(e.payload));
        const unMsg = await listen<{ peerFp: string; id: string; body: string; tsMs: number }>(
          "message://received",
          (e) => appendMessage({ ...e.payload, direction: "in" }),
        );
        const unOffered = await listen<{
          xferId: string;
          peerFp: string;
          name: string;
          size: number;
        }>("file://offered", (e) =>
          upsertTransfer({
            ...e.payload,
            done: 0,
            direction: "in",
            status: "offered",
          }),
        );
        const unProgress = await listen<{ xferId: string; done: number; total: number }>(
          "file://progress",
          (e) =>
            upsertTransfer({
              xferId: e.payload.xferId,
              done: e.payload.done,
              size: e.payload.total,
            }),
        );
        const unDone = await listen<{ xferId: string; path: string }>("file://done", (e) =>
          upsertTransfer({ xferId: e.payload.xferId, status: "done", path: e.payload.path }),
        );
        const unFailed = await listen<{ xferId: string; reason: string }>(
          "file://failed",
          (e) => upsertTransfer({ xferId: e.payload.xferId, status: "failed" }),
        );
        if (cancelled) {
          un();
          unMsg();
          unOffered();
          unProgress();
          unDone();
          unFailed();
          return;
        }
        unlisten = un;
        unMsgListen = unMsg;
        unFileOffered = unOffered;
        unFileProgress = unProgress;
        unFileDone = unDone;
        unFileFailed = unFailed;
        setSelf(await invoke<SelfInfo>("get_self_info"));
        setPeers(await invoke<Peer[]>("get_roster"));
      } catch (e) {
        console.error("初始化失败:", e);
      }
    })();
    return () => {
      cancelled = true;
      unlisten?.();
      unMsgListen?.();
      unFileOffered?.();
      unFileProgress?.();
      unFileDone?.();
      unFileFailed?.();
    };
  }, [setSelf, setPeers, appendMessage, upsertTransfer]);

  const online = peers.filter((p) => p.state !== "offline");

  const statusDotClass = (state: Peer["state"]) => {
    switch (state) {
      case "reachable":
        return "bg-green-500";
      case "unreachable":
        return "bg-red-500";
      case "discovered":
      default:
        return "bg-amber-400";
    }
  };

  return (
    <main className="flex h-screen bg-[#fefbf5] text-amber-950">
      <aside className="flex w-64 shrink-0 flex-col border-r border-amber-200">
        <header className="border-b border-amber-200 p-4">
          <div className="font-bold">{self?.nickname ?? "…"}</div>
          <div className="text-xs text-amber-700">
            {self ? `#${self.fingerprint.slice(0, 8)}` : ""}
          </div>
        </header>
        <ul className="flex-1 overflow-y-auto">
          {online.map((p) => (
            <li
              key={p.fingerprint}
              onClick={() => select(p.fingerprint)}
              className={
                "flex items-center gap-2 px-4 py-3 hover:bg-amber-100 cursor-pointer " +
                (selectedFp === p.fingerprint ? "bg-amber-100" : "")
              }
            >
              <span
                className={`h-2 w-2 shrink-0 rounded-full ${statusDotClass(p.state)}`}
                title={
                  p.state === "unreachable"
                    ? "可见但无法连接,可能是防火墙拦截"
                    : undefined
                }
              />
              <div className="min-w-0">
                <div className="truncate font-medium">{p.nickname}</div>
                <div className="truncate text-xs text-amber-700">{p.addrs[0] ?? ""}</div>
              </div>
            </li>
          ))}
          {online.length === 0 && (
            <li className="px-4 py-6 text-sm text-amber-600">正在搜索局域网设备…</li>
          )}
        </ul>
      </aside>
      {selectedFp ? (
        <ChatPane fp={selectedFp} />
      ) : (
        <section className="flex flex-1 items-center justify-center text-amber-400">
          大脚猫在等对面上线
        </section>
      )}
    </main>
  );
}

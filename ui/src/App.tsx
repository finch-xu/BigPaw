import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Peer, type SelfInfo } from "./store";
import ChatPane from "./ChatPane";
import SettingsModal from "./SettingsModal";
import Sidebar from "./Sidebar";
import EmptyState from "./EmptyState";
import { IS_TAURI, installMocks } from "./mock";

export default function App() {
  const selectedFp = useAppStore((s) => s.selectedFp);
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
        await st().loadConversations(); // 消息视图数据源(M7b)
      } catch (e) {
        console.error("初始化失败:", e);
      }
    })();
    return () => {
      cancelled = true;
      unlisteners.forEach((u) => u());
    };
  }, []);

  return (
    <main className="flex h-screen bg-background text-foreground">
      <Sidebar />
      {selectedFp ? <ChatPane key={selectedFp} fp={selectedFp} /> : <EmptyState />}
      {showSettings && <SettingsModal />}
    </main>
  );
}

import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import { useAppStore, type TimelineItem } from "./store";
import FileBubble from "./FileBubble";

function timeOf(ts: number): string {
  return new Date(ts).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
}

function dayOf(ts: number): string {
  return new Date(ts).toLocaleDateString("zh-CN", { month: "long", day: "numeric" });
}

function sameDay(a: number, b: number): boolean {
  return new Date(a).toDateString() === new Date(b).toDateString();
}

function keyOf(it: TimelineItem): string {
  return it.kind === "text" ? `t-${it.id}` : `f-${it.xferId}`;
}

export default function ChatPane({ fp }: { fp: string }) {
  const peer = useAppStore((s) => s.peers.find((p) => p.fingerprint === fp));
  const conv = useAppStore((s) => s.conversations[fp]);
  const highlightTs = useAppStore((s) => s.highlightTs);
  const setHighlightTs = useAppStore((s) => s.setHighlightTs);
  const loadOlder = useAppStore((s) => s.loadOlder);
  const appendText = useAppStore((s) => s.appendText);
  const clearConversation = useAppStore((s) => s.clearConversation);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const listRef = useRef<HTMLUListElement>(null);
  const stickBottom = useRef(true); // 用户是否停在底部附近(决定新消息是否自动滚)
  const items = conv?.items ?? [];

  const offline = !peer || peer.state === "offline";
  const isIpmsg = peer?.protocol === "ipmsg";

  // 新消息自动滚动:仅当用户本就在底部附近;搜索跳转时滚到高亮条目
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    if (highlightTs !== null) {
      el.querySelector("[data-highlight='1']")?.scrollIntoView({ block: "center" });
      const t = setTimeout(() => setHighlightTs(null), 2000);
      return () => clearTimeout(t);
    }
    if (stickBottom.current) el.scrollTop = el.scrollHeight;
  }, [items.length, highlightTs, setHighlightTs, fp]);

  async function onScroll() {
    const el = listRef.current;
    if (!el) return;
    stickBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (el.scrollTop === 0 && conv?.hasMore) {
      const prevHeight = el.scrollHeight;
      await loadOlder(fp);
      // 保持视口停在原来那条消息,而不是跳回顶部
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight - prevHeight;
      });
    }
  }

  async function handleSend() {
    const body = draft.trim();
    if (!body || offline) return;
    try {
      const sent = await invoke<{ id: string; tsMs: number }>("send_text", {
        fingerprint: fp,
        body,
      });
      stickBottom.current = true; // 自己发的永远滚到底
      appendText({ kind: "text", id: sent.id, peerFp: fp, direction: "out", body, tsMs: sent.tsMs });
      setDraft("");
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleSendFile() {
    try {
      const path = await open({ multiple: false, directory: false });
      if (!path || Array.isArray(path)) return;
      const xferId = await invoke<string>("offer_file", { fingerprint: fp, path });
      // 后端已落库;这里补一条 live 条目让 UI 立即可见(时间线里的文件气泡)
      const name = path.split(/[\\/]/).pop() ?? path;
      stickBottom.current = true;
      useAppStore.getState().upsertFile({
        xferId,
        peerFp: fp,
        direction: "out",
        name,
        status: "active",
        tsMs: Date.now(),
      });
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleClear() {
    // Tauri WebView 里 window.confirm 不可靠,统一走 plugin-dialog
    const ok = await confirm("清除与该联系人的全部聊天记录?此操作不可恢复。", {
      title: "清除记录",
      kind: "warning",
    });
    if (!ok) return;
    try {
      await clearConversation(fp);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="flex flex-1 flex-col">
      <header className="flex items-center justify-between border-b border-amber-200 p-3">
        <span className="font-medium">{peer?.nickname ?? fp.slice(0, 8)}</span>
        <button
          onClick={handleClear}
          className="rounded border border-amber-300 px-2 py-1 text-xs text-amber-700 hover:bg-amber-100"
        >
          清除本会话记录
        </button>
      </header>
      {isIpmsg && (
        <p className="border-b border-amber-200 bg-amber-50 px-4 py-2 text-xs text-amber-700">
          ⚠ 明文传输,对方为飞秋/旧客户端(仅支持文本与单文件,不加密)
        </p>
      )}
      <ul ref={listRef} onScroll={onScroll} className="flex-1 space-y-2 overflow-y-auto p-4">
        {conv?.hasMore && (
          <li className="text-center text-xs text-amber-400">上滑加载更早的记录</li>
        )}
        {items.map((it, i) => (
          <li key={keyOf(it)}>
            {(i === 0 || !sameDay(items[i - 1].tsMs, it.tsMs)) && (
              <div className="my-2 text-center text-xs text-amber-400">{dayOf(it.tsMs)}</div>
            )}
            <div
              data-highlight={highlightTs === it.tsMs ? "1" : undefined}
              className={
                (it.direction === "out" ? "text-right" : "text-left") +
                (highlightTs === it.tsMs ? " rounded-lg bg-amber-200/60 transition-colors" : "")
              }
            >
              {it.kind === "text" ? (
                <span
                  className={
                    "inline-block max-w-[70%] rounded-lg px-3 py-2 text-sm " +
                    (it.direction === "out" ? "bg-amber-800 text-white" : "bg-amber-100")
                  }
                >
                  {it.body}
                </span>
              ) : (
                <FileBubble item={it} />
              )}
              <div className="mt-0.5 text-[10px] text-amber-400">{timeOf(it.tsMs)}</div>
            </div>
          </li>
        ))}
      </ul>
      {error && <p className="px-4 py-1 text-xs text-red-600">操作失败: {error}</p>}
      <footer className="flex gap-2 border-t border-amber-200 p-3">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.nativeEvent.isComposing) handleSend();
          }}
          disabled={offline}
          placeholder={offline ? "对方不在线,无法发送" : "输入消息,回车发送"}
          className="flex-1 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm outline-none focus:border-amber-500 disabled:bg-amber-50 disabled:text-amber-400"
        />
        <button
          onClick={handleSend}
          disabled={offline}
          className="rounded-lg bg-amber-800 px-4 py-2 text-sm text-white hover:bg-amber-700 disabled:opacity-40"
        >
          发送
        </button>
        <button
          onClick={handleSendFile}
          disabled={offline}
          className="rounded-lg border border-amber-300 px-4 py-2 text-sm text-amber-800 hover:bg-amber-100 disabled:opacity-40"
        >
          发送文件
        </button>
      </footer>
    </section>
  );
}

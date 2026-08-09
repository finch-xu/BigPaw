import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import { useAppStore, type TimelineItem } from "./store";
import FileBubble from "./FileBubble";
import Avatar from "./Avatar";

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
  const group = useAppStore((s) => s.groups.find((g) => g.groupId === fp));
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

  const isGroup = !!group;
  // 群会话不依赖单个对端在线状态:发言逐成员尽力送达(spec 冻结)。
  const offline = isGroup ? false : !peer || peer.state === "offline";
  const isIpmsg = peer?.protocol === "ipmsg";
  const title = isGroup ? group.name : (peer?.nickname ?? fp.slice(0, 8));
  const stateLabel = isGroup
    ? `${group.members.length} 位成员`
    : offline
      ? "离线"
      : peer!.state === "unreachable"
        ? "可见但无法连接"
        : peer!.state === "discovered"
          ? "已发现"
          : "在线";
  /** 群消息气泡上的发送者昵称:优先群成员表(nick 随成员表同步),兜底 roster。 */
  const senderNick = (senderFp: string): string =>
    group?.members.find((m) => m.fp === senderFp)?.nick ??
    useAppStore.getState().peers.find((p) => p.fingerprint === senderFp)?.nickname ??
    senderFp.slice(0, 8);

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
      const sent = isGroup
        ? await invoke<{ id: string; tsMs: number }>("send_group_text", { groupId: fp, body })
        : await invoke<{ id: string; tsMs: number }>("send_text", { fingerprint: fp, body });
      stickBottom.current = true; // 自己发的永远滚到底
      appendText({ kind: "text", id: sent.id, peerFp: fp, direction: "out", body, tsMs: sent.tsMs });
      setDraft("");
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleLeaveGroup() {
    const ok = await confirm("退出该群?退出后将不再收到群消息(历史记录保留)。", {
      title: "退出群聊",
      kind: "warning",
    });
    if (!ok) return;
    try {
      await invoke("leave_group", { groupId: fp });
      const st = useAppStore.getState();
      st.setGroups(st.groups.filter((g) => g.groupId !== fp));
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
    <section className="flex min-w-0 flex-1 flex-col">
      <header className="flex items-center gap-2.5 border-b border-border bg-panel px-4 py-2.5">
        <Avatar fp={fp} name={title} size={32} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">{title}</div>
          <div className="text-xs text-muted-foreground">{stateLabel}</div>
        </div>
        {isGroup && (
          <button
            onClick={handleLeaveGroup}
            className="shrink-0 text-xs text-muted-foreground hover:text-destructive"
          >
            退出群聊
          </button>
        )}
        <button
          onClick={handleClear}
          className="shrink-0 text-xs text-muted-foreground hover:text-destructive"
        >
          清除本会话记录
        </button>
      </header>
      {isIpmsg && (
        <p className="border-b border-border2 bg-warning-bg px-4 py-2 text-xs text-warning-fg">
          明文传输,对方为飞秋/旧客户端(仅支持文本与单文件,不加密)
        </p>
      )}
      <ul ref={listRef} onScroll={onScroll} className="flex-1 space-y-1.5 overflow-y-auto px-4 py-3">
        {conv?.hasMore && (
          <li className="py-1 text-center text-xs text-muted-foreground">上滑加载更早的记录</li>
        )}
        {items.map((it, i) => {
          const out = it.direction === "out";
          const showAvatar = !out && (i === 0 || items[i - 1].direction === "out");
          // 群消息(M7c):气泡头像/名字用发送者身份,而不是会话本身
          const itemSenderFp = it.kind === "text" ? (it.senderFp ?? null) : null;
          const bubbleFp = isGroup && itemSenderFp ? itemSenderFp : fp;
          const bubbleName = isGroup && itemSenderFp ? senderNick(itemSenderFp) : (peer?.nickname ?? "?");
          return (
            <li key={keyOf(it)}>
              {(i === 0 || !sameDay(items[i - 1].tsMs, it.tsMs)) && (
                <div className="mx-auto my-3 w-fit rounded-full border border-border2 bg-panel px-3 py-0.5 text-[11px] text-muted-foreground">
                  {dayOf(it.tsMs)}
                </div>
              )}
              <div
                data-highlight={highlightTs === it.tsMs ? "1" : undefined}
                className={
                  "flex items-end gap-2 " +
                  (out ? "justify-end" : "") +
                  (highlightTs === it.tsMs ? " rounded-xl bg-active transition-colors" : "")
                }
              >
                {!out &&
                  (showAvatar || (isGroup && itemSenderFp) ? (
                    <Avatar fp={bubbleFp} name={bubbleName} size={28} />
                  ) : (
                    <div className="w-7 shrink-0" />
                  ))}
                <div className={"max-w-[70%] " + (out ? "text-right" : "text-left")}>
                  {isGroup && !out && itemSenderFp && (
                    <div className="mb-0.5 text-[10px] text-muted-foreground">
                      {senderNick(itemSenderFp)}
                    </div>
                  )}
                  {it.kind === "text" ? (
                    <span
                      className={
                        "inline-block rounded-[18px] px-3.5 py-2 text-left text-sm " +
                        (out
                          ? "rounded-br-md bg-bubble-out text-bubble-out-fg"
                          : "rounded-bl-md border border-bubble-in-border bg-bubble-in")
                      }
                    >
                      {it.body}
                    </span>
                  ) : (
                    <FileBubble item={it} />
                  )}
                  <div className="mt-0.5 text-[10px] text-muted-foreground">{timeOf(it.tsMs)}</div>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {error && <p className="px-4 py-1 text-xs text-destructive">操作失败: {error}</p>}
      <footer className="flex items-center gap-2 border-t border-border px-4 py-3">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.nativeEvent.isComposing) handleSend();
          }}
          disabled={offline}
          placeholder={offline ? "对方不在线,无法发送" : "输入消息,回车发送"}
          className="min-w-0 flex-1 rounded-full border border-transparent bg-panel px-4 py-2 text-sm outline-none placeholder:text-muted-foreground focus:border-primary disabled:opacity-50"
        />
        <button
          onClick={handleSendFile}
          disabled={offline || isGroup}
          title={isGroup ? "群内暂不支持发文件(仍可私聊发送)" : "发送文件"}
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-border text-fg2 hover:bg-hover disabled:opacity-40"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
          </svg>
        </button>
        <button
          onClick={handleSend}
          disabled={offline}
          className="shrink-0 rounded-full bg-primary px-5 py-2 text-sm text-primary-foreground hover:bg-primary-strong disabled:opacity-40"
        >
          发送
        </button>
      </footer>
    </section>
  );
}

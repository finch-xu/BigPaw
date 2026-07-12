import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useAppStore } from "./store";
import TransferPanel from "./TransferPanel";

export default function ChatPane({ fp }: { fp: string }) {
  const peer = useAppStore((s) => s.peers.find((p) => p.fingerprint === fp));
  const messages = useAppStore((s) => s.messages[fp] ?? []);
  const appendMessage = useAppStore((s) => s.appendMessage);
  const upsertTransfer = useAppStore((s) => s.upsertTransfer);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");

  async function handleSend() {
    const body = draft.trim();
    if (!body) return;
    try {
      const sent = await invoke<{ id: string; tsMs: number }>("send_text", {
        fingerprint: fp,
        body,
      });
      appendMessage({ id: sent.id, peerFp: fp, body, tsMs: sent.tsMs, direction: "out" });
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
      const name = path.split(/[\\/]/).pop() ?? path;
      upsertTransfer({
        xferId,
        peerFp: fp,
        name,
        size: 0,
        done: 0,
        direction: "out",
        status: "active",
      });
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <section className="flex flex-1 flex-col">
      <header className="border-b border-amber-200 p-3 font-medium">
        {peer?.nickname ?? fp.slice(0, 8)}
      </header>
      <ul className="flex-1 space-y-2 overflow-y-auto p-4">
        {messages.map((m) => (
          <li key={m.id} className={m.direction === "out" ? "text-right" : "text-left"}>
            <span
              className={
                "inline-block max-w-[70%] rounded-lg px-3 py-2 text-sm " +
                (m.direction === "out" ? "bg-amber-800 text-white" : "bg-amber-100")
              }
            >
              {m.body}
            </span>
          </li>
        ))}
      </ul>
      {error && <p className="px-4 py-1 text-xs text-red-600">发送失败: {error}</p>}
      <TransferPanel fp={fp} />
      <footer className="flex gap-2 border-t border-amber-200 p-3">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.nativeEvent.isComposing) handleSend();
          }}
          placeholder="输入消息,回车发送"
          className="flex-1 rounded-lg border border-amber-300 bg-white px-3 py-2 text-sm outline-none focus:border-amber-500"
        />
        <button
          onClick={handleSend}
          className="rounded-lg bg-amber-800 px-4 py-2 text-sm text-white hover:bg-amber-700"
        >
          发送
        </button>
        <button
          onClick={handleSendFile}
          className="rounded-lg border border-amber-300 px-4 py-2 text-sm text-amber-800 hover:bg-amber-100"
        >
          发送文件
        </button>
      </footer>
    </section>
  );
}

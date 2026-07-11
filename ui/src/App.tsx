import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export default function App() {
  const [reply, setReply] = useState("");

  async function handlePing() {
    try {
      setReply(await invoke<string>("ping"));
    } catch (e) {
      setReply(`IPC 不可用: ${e}`);
    }
  }

  return (
    <main className="flex h-screen flex-col items-center justify-center gap-4 bg-[#fefbf5]">
      <h1 className="text-3xl font-bold text-amber-900">BigPaw · 大脚猫</h1>
      <button
        onClick={handlePing}
        className="rounded-lg bg-amber-800 px-4 py-2 text-white hover:bg-amber-700"
      >
        Ping Rust Core
      </button>
      {reply && <p className="text-amber-900">{reply}</p>}
    </main>
  );
}

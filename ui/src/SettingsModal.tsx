import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import { useAppStore, type Settings } from "./store";

export default function SettingsModal() {
  const setShowSettings = useAppStore((s) => s.setShowSettings);
  const clearAll = useAppStore((s) => s.clearAll);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [needRestart, setNeedRestart] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    invoke<Settings>("get_settings")
      .then(setSettings)
      .catch((e) => setError(String(e)));
  }, []);

  async function save(next: Settings, restartHint: boolean) {
    const prev = settings;
    setSettings(next);
    try {
      await invoke("set_settings", { value: next });
      if (restartHint) setNeedRestart(true);
      setError("");
    } catch (e) {
      // 回滚:失败的改动不得被后续保存夹带落盘(set_settings 是整对象覆盖)
      setSettings(prev);
      setError(String(e));
    }
  }

  async function pickDownloadDir() {
    if (!settings) return;
    try {
      const dir = await open({ directory: true, multiple: false });
      if (typeof dir === "string") void save({ ...settings, downloadDir: dir }, false);
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleClearAll() {
    const ok = await confirm("清空所有聊天记录?此操作不可恢复。", {
      title: "清空记录",
      kind: "warning",
    });
    if (!ok) return;
    try {
      await clearAll();
    } catch (e) {
      setError(String(e));
    }
  }

  if (!settings) {
    if (!error) return null;
    return (
      <div
        className="fixed inset-0 z-10 flex items-center justify-center bg-black/30"
        onClick={() => setShowSettings(false)}
      >
        <div className="w-96 rounded-xl bg-white p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
          <p className="text-sm text-red-600">读取设置失败: {error}</p>
          <button
            onClick={() => setShowSettings(false)}
            className="mt-4 w-full rounded-lg bg-amber-800 py-2 text-sm text-white hover:bg-amber-700"
          >
            关闭
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-10 flex items-center justify-center bg-black/30"
      onClick={() => setShowSettings(false)}
    >
      <div
        className="w-96 rounded-xl bg-white p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-4 text-base font-bold">设置</h2>

        <label className="mb-3 block text-sm">
          <span className="text-amber-700">昵称(重启后生效)</span>
          <input
            defaultValue={settings.nickname ?? ""}
            onBlur={(e) => {
              const v = e.target.value.trim();
              if (v !== (settings.nickname ?? ""))
                void save({ ...settings, nickname: v || null }, true);
            }}
            placeholder="留空使用主机名"
            className="mt-1 w-full rounded border border-amber-300 px-2 py-1.5 outline-none focus:border-amber-500"
          />
        </label>

        <div className="mb-3 text-sm">
          <span className="text-amber-700">默认下载目录</span>
          <div className="mt-1 flex items-center gap-2">
            <span className="min-w-0 flex-1 truncate text-xs text-amber-600">
              {settings.downloadDir ?? "系统下载文件夹"}
            </span>
            <button
              onClick={pickDownloadDir}
              className="shrink-0 rounded border border-amber-300 px-2 py-1 text-xs hover:bg-amber-100"
            >
              选择…
            </button>
          </div>
        </div>

        <label className="mb-4 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={settings.ipmsgEnabled}
            onChange={(e) => void save({ ...settings, ipmsgEnabled: e.target.checked }, true)}
          />
          <span>
            IPMsg/飞秋兼容<span className="text-amber-500">(重启后生效)</span>
          </span>
        </label>

        <button
          onClick={handleClearAll}
          className="w-full rounded-lg border border-red-300 py-2 text-sm text-red-600 hover:bg-red-50"
        >
          清空所有聊天记录
        </button>

        {needRestart && (
          <p className="mt-3 text-xs text-amber-600">部分设置将在重启应用后生效。</p>
        )}
        {error && <p className="mt-3 text-xs text-red-600">保存失败: {error}</p>}

        <button
          onClick={() => setShowSettings(false)}
          className="mt-4 w-full rounded-lg bg-amber-800 py-2 text-sm text-white hover:bg-amber-700"
        >
          关闭
        </button>
      </div>
    </div>
  );
}

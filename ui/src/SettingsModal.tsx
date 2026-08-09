import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import { useAppStore, type NetIface, type Settings } from "./store";
import { getThemePref, setThemePref, type ThemePref } from "./theme";
import { IS_TAURI } from "./mock";

const MOCK_SETTINGS: Settings = {
  nickname: null,
  downloadDir: null,
  ipmsgEnabled: true,
  excludedInterfaces: [],
};

const MOCK_IFACES: NetIface[] = [
  { name: "en0", ip: "192.168.1.23", netmask: "255.255.255.0", isVirtual: false, excluded: false },
  { name: "en5", ip: "192.168.56.10", netmask: "255.255.255.0", isVirtual: false, excluded: false },
  { name: "utun3", ip: "10.8.0.2", netmask: "255.255.255.0", isVirtual: true, excluded: false },
];

const THEME_OPTIONS: Array<[ThemePref, string]> = [
  ["light", "亮色"],
  ["dark", "暗色"],
  ["system", "跟随系统"],
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      {children}
    </div>
  );
}

export default function SettingsModal() {
  const setShowSettings = useAppStore((s) => s.setShowSettings);
  const clearAll = useAppStore((s) => s.clearAll);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [ifaces, setIfaces] = useState<NetIface[]>([]);
  const [needRestart, setNeedRestart] = useState(false);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState<ThemePref>(getThemePref());

  useEffect(() => {
    if (!IS_TAURI) {
      setSettings(MOCK_SETTINGS);
      setIfaces(MOCK_IFACES);
      return;
    }
    invoke<Settings>("get_settings")
      .then(setSettings)
      .catch((e) => setError(String(e)));
    invoke<NetIface[]>("list_network_interfaces")
      .then(setIfaces)
      .catch((e) => setError(String(e)));
  }, []);

  async function save(next: Settings, restartHint: boolean) {
    setSettings(next);
    if (!IS_TAURI) return;
    try {
      await invoke("set_settings", { value: next });
      if (restartHint) setNeedRestart(true);
      setError("");
    } catch (e) {
      // 回滚:不能恢复"本次调用开始时"的快照——多个 save 连续触发时(如网络接口区
      // 连点几个 checkbox),陈旧快照会把后一次已成功落盘的改动从 UI 上抹掉。
      // 后端(settings.json,由 set_settings 落盘)才是唯一真源,失败后应以它为准。
      try {
        setSettings(await invoke<Settings>("get_settings"));
      } catch {
        // 拉真值也失败:保底保留当前乐观值,不再引入二次状态跳变
      }
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

  function toggleIface(name: string, enabled: boolean) {
    if (!settings) return;
    const next = enabled
      ? settings.excludedInterfaces.filter((n) => n !== name)
      : [...settings.excludedInterfaces, name];
    // checkbox 展示只读 settings.excludedInterfaces,ifaces.excluded 目前无渲染路径读取,
    // 不再维护这份影子状态,避免它与 settings 不同步却无人察觉。
    void save({ ...settings, excludedInterfaces: next }, false);
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

  function switchTheme(pref: ThemePref) {
    setThemePref(pref);
    setTheme(pref);
  }

  if (!settings) {
    if (!error) return null;
    return (
      <div
        className="fixed inset-0 z-10 flex items-center justify-center bg-black/30 backdrop-blur-[2px]"
        onClick={() => setShowSettings(false)}
      >
        <div
          className="w-[26rem] rounded-2xl border border-border2 bg-background p-6 shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          <p className="text-sm text-destructive">读取设置失败: {error}</p>
          <button
            onClick={() => setShowSettings(false)}
            className="mt-4 w-full rounded-full bg-primary py-2 text-sm text-primary-foreground hover:bg-primary-strong"
          >
            关闭
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="fixed inset-0 z-10 flex items-center justify-center bg-black/30 backdrop-blur-[2px]"
      onClick={() => setShowSettings(false)}
    >
      <div
        className="max-h-[85vh] w-[26rem] overflow-y-auto rounded-2xl border border-border2 bg-background p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="mb-4 text-base font-bold">设置</h2>

        <Section title="个人">
          <label className="block text-sm">
            <span className="text-fg2">昵称(重启后生效)</span>
            <input
              defaultValue={settings.nickname ?? ""}
              onBlur={(e) => {
                const v = e.target.value.trim();
                if (v !== (settings.nickname ?? ""))
                  void save({ ...settings, nickname: v || null }, true);
              }}
              placeholder="留空使用主机名"
              className="mt-1 w-full rounded-lg border border-border bg-panel px-3 py-1.5 outline-none focus:border-primary"
            />
          </label>
        </Section>

        <Section title="外观">
          <div className="flex w-fit gap-1 rounded-full bg-panel p-1">
            {THEME_OPTIONS.map(([v, label]) => (
              <button
                key={v}
                onClick={() => switchTheme(v)}
                className={
                  "rounded-full px-3 py-1 text-xs " +
                  (theme === v
                    ? "bg-primary text-primary-foreground"
                    : "text-fg2 hover:bg-hover")
                }
              >
                {label}
              </button>
            ))}
          </div>
        </Section>

        <Section title="传输">
          <div className="text-sm">
            <span className="text-fg2">默认下载目录</span>
            <div className="mt-1 flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
                {settings.downloadDir ?? "系统下载文件夹"}
              </span>
              <button
                onClick={pickDownloadDir}
                className="shrink-0 rounded-full border border-border px-3 py-1 text-xs text-fg2 hover:bg-hover"
              >
                选择…
              </button>
            </div>
          </div>
        </Section>

        <Section title="网络接口">
          <div className="flex flex-col gap-1.5">
            {ifaces.map((f) => (
              <label key={f.name} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!settings.excludedInterfaces.includes(f.name)}
                  onChange={(e) => toggleIface(f.name, e.target.checked)}
                  className="accent-(--primary)"
                />
                <span>{f.name}</span>
                <span className="text-xs text-muted-foreground">{f.ip}</span>
                {f.isVirtual && (
                  <span className="rounded-full bg-panel px-1.5 py-0.5 text-[10px] text-fg2">
                    虚拟
                  </span>
                )}
              </label>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-muted-foreground">
            取消勾选后,BigPaw 不在该网络上宣告自己(即时生效);新插入的网卡默认启用。
          </p>
        </Section>

        <Section title="兼容">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={settings.ipmsgEnabled}
              onChange={(e) => void save({ ...settings, ipmsgEnabled: e.target.checked }, true)}
              className="accent-(--primary)"
            />
            <span>
              IPMsg/飞秋兼容<span className="text-muted-foreground">(重启后生效)</span>
            </span>
          </label>
        </Section>

        <Section title="数据">
          <button
            onClick={handleClearAll}
            className="w-full rounded-full border border-destructive/40 py-2 text-sm text-destructive hover:bg-destructive/10"
          >
            清空所有聊天记录
          </button>
        </Section>

        {needRestart && (
          <p className="mt-3 text-xs text-warning-fg">部分设置将在重启应用后生效。</p>
        )}
        {error && <p className="mt-3 text-xs text-destructive">保存失败: {error}</p>}

        <button
          onClick={() => setShowSettings(false)}
          className="mt-4 w-full rounded-full bg-primary py-2 text-sm text-primary-foreground hover:bg-primary-strong"
        >
          关闭
        </button>
      </div>
    </div>
  );
}

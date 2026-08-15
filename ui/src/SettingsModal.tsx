import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import { useAppStore, type NetIface, type SelfInfo, type Settings } from "./store";
import { getThemePref, setThemePref, type ThemePref } from "./theme";
import { IS_TAURI } from "./mock";

const MOCK_SETTINGS: Settings = {
  nickname: null,
  group: null,
  downloadDir: null,
  ipmsgEnabled: true,
  excludedInterfaces: [],
  allowedNetworks: [],
};

/** 前端轻校验(只拦明显错误,权威校验在后端 validate_allowed_networks):
 *  单 IP `a.b.c.d`、CIDR `a.b.c.d/n`、区间 `a.b.c.d-a.b.c.d`。 */
const SCOPE_LINE_RE = /^\d{1,3}(\.\d{1,3}){3}(\s*\/\s*\d{1,2}|\s*-\s*\d{1,3}(\.\d{1,3}){3})?$/;

function splitScopeLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

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

type TabKey = "personal" | "appearance" | "transfer" | "network" | "data";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "personal", label: "个人" },
  { key: "appearance", label: "外观" },
  { key: "transfer", label: "传输" },
  { key: "network", label: "网络" },
  { key: "data", label: "数据" },
];

export default function SettingsModal() {
  const setShowSettings = useAppStore((s) => s.setShowSettings);
  const clearAll = useAppStore((s) => s.clearAll);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [ifaces, setIfaces] = useState<NetIface[]>([]);
  const [needRestart, setNeedRestart] = useState(false);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState<ThemePref>(getThemePref());
  const [activeTab, setActiveTab] = useState<TabKey>("personal");
  // 允许网段清单用本地草稿(多行文本),点"应用"才校验 + 保存——不能像 checkbox
  // 那样每击键即存:半行输入必然校验失败,会刷屏报错。
  const [scopeDraft, setScopeDraft] = useState("");
  const [scopeError, setScopeError] = useState("");
  const [scopeBusy, setScopeBusy] = useState(false);

  useEffect(() => {
    if (settings) setScopeDraft(settings.allowedNetworks.join("\n"));
  }, [settings?.allowedNetworks]);

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
    const prevNickname = settings?.nickname ?? null;
    setSettings(next);
    if (!IS_TAURI) return;
    try {
      await invoke("set_settings", { value: next });
      if (restartHint) setNeedRestart(true);
      setError("");
      // 昵称热生效后对端立即看到新名字、这里设置页也已显示新值,但本机侧栏
      // 头部(App.tsx 的 self.nickname)只在挂载时拉过一次,不会跟着变——
      // 设置页又刚去掉"重启后生效"提示,不补拉会让用户以为改名没生效。
      if (next.nickname !== prevNickname) {
        try {
          useAppStore.getState().setSelf(await invoke<SelfInfo>("get_self_info"));
        } catch {
          // 拉 self 失败不影响本次保存已经成功;不额外报错,避免掩盖已成功的保存结果
        }
      }
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

  async function applyScope() {
    if (!settings) return;
    const lines = splitScopeLines(scopeDraft);
    const bad = lines.findIndex((l) => !SCOPE_LINE_RE.test(l));
    if (bad >= 0) {
      setScopeError(`第 ${bad + 1} 行格式无法识别:${lines[bad]}`);
      return;
    }
    setScopeBusy(true);
    try {
      // 后端权威校验并返回归一化文本(CIDR 主机位归零),再落盘 + 热生效
      const canonical = IS_TAURI
        ? await invoke<string[]>("validate_allowed_networks", { lines })
        : lines;
      setScopeError("");
      await save({ ...settings, allowedNetworks: canonical }, false);
    } catch (e) {
      setScopeError(String(e));
    } finally {
      setScopeBusy(false);
    }
  }

  const scopeDirty =
    settings !== null && splitScopeLines(scopeDraft).join("\n") !== settings.allowedNetworks.join("\n");

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
        className="flex h-[30rem] max-h-[85vh] w-[44rem] max-w-[95vw] overflow-hidden rounded-2xl border border-border2 bg-background shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <nav className="w-44 shrink-0 border-r border-border bg-panel p-3">
          <h2 className="mb-3 px-2 text-base font-bold">设置</h2>
          <div className="flex flex-col gap-0.5">
            {TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={
                  "w-full rounded-lg px-3 py-1.5 text-left text-sm " +
                  (activeTab === t.key
                    ? "bg-primary text-primary-foreground"
                    : "text-fg2 hover:bg-hover")
                }
              >
                {t.label}
              </button>
            ))}
          </div>
        </nav>
        <div className="relative flex-1 overflow-y-auto p-6">
          <button
            aria-label="关闭"
            onClick={() => setShowSettings(false)}
            className="absolute right-4 top-4 rounded-full px-2 py-0.5 text-lg leading-none text-fg2 hover:bg-hover"
          >
            ×
          </button>
          <h3 className="mb-4 text-sm font-semibold">
            {TABS.find((t) => t.key === activeTab)!.label}
          </h3>

          {activeTab === "personal" && (
            <>
              <label className="block text-sm">
                <span className="text-fg2">昵称</span>
                <input
                  defaultValue={settings.nickname ?? ""}
                  onBlur={(e) => {
                    const v = e.target.value.trim();
                    if (v !== (settings.nickname ?? ""))
                      void save({ ...settings, nickname: v || null }, false);
                  }}
                  placeholder="留空使用主机名"
                  className="mt-1 w-full rounded-lg border border-border bg-panel px-3 py-1.5 outline-none focus:border-primary"
                />
              </label>
              <label className="mt-4 block text-sm">
                <span className="text-fg2">分组</span>
                <input
                  defaultValue={settings.group ?? ""}
                  maxLength={32}
                  onBlur={(e) => {
                    // \0 是 IPMsg 报文的字段分隔符,混入会破坏线上格式
                    const v = e.target.value.replace(/\0/g, "").trim();
                    if (v !== (settings.group ?? ""))
                      void save({ ...settings, group: v || null }, false);
                  }}
                  placeholder="留空则不设分组"
                  className="mt-1 w-full rounded-lg border border-border bg-panel px-3 py-1.5 outline-none focus:border-primary"
                />
                <span className="mt-1 block text-xs text-muted-foreground">
                  广播给局域网内所有人(含飞秋),对方会把你归到该组显示。
                </span>
              </label>
            </>
          )}

          {activeTab === "appearance" && (
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
          )}

          {activeTab === "transfer" && (
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
          )}

          {activeTab === "network" && (
            <>
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

              <label className="mt-4 flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={settings.ipmsgEnabled}
                  onChange={(e) =>
                    void save({ ...settings, ipmsgEnabled: e.target.checked }, true)
                  }
                  className="accent-(--primary)"
                />
                <span>
                  IPMsg/飞秋兼容<span className="text-muted-foreground">(重启后生效)</span>
                </span>
              </label>

              <div className="mt-4 flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-sm">
                    限定网络范围
                    <span className="text-muted-foreground">
                      (留空 = 不限制{settings.allowedNetworks.length > 0 ? ",当前已限定" : ""})
                    </span>
                  </span>
                  <button
                    onClick={() => void applyScope()}
                    disabled={!scopeDirty || scopeBusy}
                    className="shrink-0 rounded-full border border-border px-3 py-1 text-xs text-fg2 hover:bg-hover disabled:cursor-default disabled:opacity-40"
                  >
                    {scopeBusy ? "应用中…" : "应用"}
                  </button>
                </div>
                <textarea
                  value={scopeDraft}
                  onChange={(e) => {
                    setScopeDraft(e.target.value);
                    if (scopeError) setScopeError("");
                  }}
                  rows={4}
                  spellCheck={false}
                  placeholder={"192.168.1.0/24\n10.0.0.5\n10.0.0.10-10.0.0.20"}
                  className="w-full resize-y rounded-lg border border-border bg-panel px-2 py-1.5 font-mono text-xs text-fg outline-none focus:border-primary"
                />
                {scopeError && <p className="text-xs text-destructive">{scopeError}</p>}
                <p className="text-xs text-muted-foreground">
                  每行一条:单 IP / CIDR / 起-止区间。只与范围内的主机互相发现、连接;范围外主机
                  完全看不到本机(即时生效)。未被整段覆盖的网卡改为逐台单播宣告(每网卡最多 1024 台)。
                </p>
              </div>
            </>
          )}

          {activeTab === "data" && (
            <button
              onClick={handleClearAll}
              className="w-full rounded-full border border-destructive/40 py-2 text-sm text-destructive hover:bg-destructive/10"
            >
              清空所有聊天记录
            </button>
          )}

          {needRestart && (
            <p className="mt-3 text-xs text-warning-fg">部分设置将在重启应用后生效。</p>
          )}
          {error && <p className="mt-3 text-xs text-destructive">保存失败: {error}</p>}
        </div>
      </div>
    </div>
  );
}

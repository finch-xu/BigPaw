import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useAppStore, type UpdateState } from "./store";
import { IS_TAURI } from "./mock";
import { RELEASES_URL, checkForUpdate } from "./updater";

const REPO_URL = "https://github.com/finch-xu/BigPaw";

function fmtBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${n} B`;
}

/** 把 store.update 翻译成一行状态文案;idle 返回空串(不占位) */
function describe(u: UpdateState): string {
  switch (u.status) {
    case "idle":
      return "";
    case "checking":
      return "正在检查更新…";
    case "latest":
      return "当前已是最新版本。";
    case "available":
      return `发现新版本 v${u.version},可点击「检查更新」重新获取安装提示。`;
    case "downloading": {
      const p = u.progress;
      if (!p) return "正在下载…";
      if (p.total) return `正在下载… ${Math.floor((p.done / p.total) * 100)}% (${fmtBytes(p.done)} / ${fmtBytes(p.total)})`;
      return `正在下载… ${fmtBytes(p.done)}`;
    }
    case "ready":
      return `v${u.version} 已安装,重启 BigPaw 后生效。`;
    case "error":
      return `检查更新失败:${u.error ?? "未知错误"}`;
  }
}

/** 设置页「关于」:版本号 + 手动检查更新 + 仓库/下载链接 */
export default function AboutPanel() {
  const update = useAppStore((s) => s.update);
  const [version, setVersion] = useState<string>(IS_TAURI ? "…" : "dev");

  useEffect(() => {
    if (!IS_TAURI) return;
    getVersion()
      .then(setVersion)
      .catch(() => setVersion("?"));
  }, []);

  const busy = update.status === "checking" || update.status === "downloading";
  const statusText = describe(update);
  const statusClass =
    update.status === "error" ? "text-destructive" : update.status === "ready" ? "text-warning-fg" : "text-muted-foreground";

  function openLink(url: string) {
    if (IS_TAURI) void openUrl(url);
    else window.open(url, "_blank", "noopener");
  }

  return (
    <div className="flex flex-col gap-4 text-sm">
      <div>
        <p className="text-base font-semibold">BigPaw · 大脚猫</p>
        <p className="text-xs text-muted-foreground">版本 {version}</p>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={() => void checkForUpdate({ silent: false })}
          disabled={busy || !IS_TAURI}
          className="rounded-full border border-border px-4 py-1.5 text-xs text-fg2 hover:bg-hover disabled:cursor-default disabled:opacity-40"
        >
          {update.status === "checking" ? "检查中…" : update.status === "downloading" ? "下载中…" : "检查更新"}
        </button>
        {statusText && <p className={`text-xs ${statusClass}`}>{statusText}</p>}
      </div>
      <p className="text-xs text-muted-foreground">
        更新包来自 GitHub Releases,下载后会校验签名再安装。deb/rpm 安装的 Linux 用户需手动下载新版。
      </p>

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <button onClick={() => openLink(REPO_URL)} className="text-primary hover:underline">
          GitHub 仓库
        </button>
        <button onClick={() => openLink(RELEASES_URL)} className="text-primary hover:underline">
          下载页面(Releases)
        </button>
      </div>
    </div>
  );
}

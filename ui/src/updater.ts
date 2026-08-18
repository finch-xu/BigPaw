// 自动更新(Tauri 2 官方 updater 方案)。
//
// 端点/公钥在 src-tauri/tauri.conf.json plugins.updater;清单 latest.json 由
// .github/workflows/release.yml 的 generate-manifest job 用 scripts/generate-latest-json.mjs
// 生成并挂在 GitHub Release 上。这里只做交互编排:
//   check() → 有新版 → 系统对话框询问 → downloadAndInstall() → 询问重启 → relaunch()
// 状态写进 store.update,「关于」页据此显示文案与进度。
//
// deb/rpm 安装的 Linux 用户不能原地升级(updater 只会安装 AppImage,对 deb 抛
// "invalid updater binary format"),改为提示并打开 Release 页面手动下载。
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ask, message } from "@tauri-apps/plugin-dialog";
import { getBundleType } from "@tauri-apps/api/app";
import { useAppStore } from "./store";
import { IS_TAURI } from "./mock";

export const RELEASES_URL = "https://github.com/finch-xu/BigPaw/releases/latest";

/** 这些打包格式 updater 不能原地安装,只能引导去下载页 */
const MANUAL_INSTALL_BUNDLES = new Set(["deb", "rpm"]);

/** 对话框里 release notes 最多展示的行数/字符数,太长会把系统对话框撑爆 */
const NOTES_MAX_LINES = 8;
const NOTES_MAX_CHARS = 400;

let inFlight = false;

/**
 * 启动静默检查发现新版时是否弹窗。目前策略是"每次启动都弹";如果嫌烦,可以在这里
 * 记住用户上次点"稍后"的版本号(localStorage),同一版本不再打扰、只在「关于」页显示。
 */
function shouldPromptOnStartup(_version: string): boolean {
  return true;
}

function trimNotes(body: string | undefined): string {
  if (!body) return "";
  const lines = body.trim().split(/\r?\n/).slice(0, NOTES_MAX_LINES);
  let text = lines.join("\n");
  if (text.length > NOTES_MAX_CHARS) text = text.slice(0, NOTES_MAX_CHARS) + "…";
  return text ? `\n\n${text}` : "";
}

async function isManualInstallBundle(): Promise<boolean> {
  try {
    const kind = await getBundleType();
    return kind != null && MANUAL_INSTALL_BUNDLES.has(kind);
  } catch {
    return false;
  }
}

/**
 * 检查更新并按需引导安装。
 * - silent=true:启动时静默检查,已是最新/失败都不打扰用户(只写 store / console)。
 * - silent=false:「关于」页手动触发,每一步都有对话框反馈。
 * 同一时刻只允许一个流程在跑;重复调用直接忽略。
 */
export async function checkForUpdate(opts: { silent: boolean }): Promise<void> {
  if (!IS_TAURI || inFlight) return;
  inFlight = true;
  const setUpdate = useAppStore.getState().setUpdate;
  setUpdate({ status: "checking" });
  try {
    const update = await check();
    if (!update) {
      setUpdate({ status: "latest" });
      if (!opts.silent) await message("当前已是最新版本。", { title: "检查更新", kind: "info" });
      return;
    }
    setUpdate({ status: "available", version: update.version });
    if (opts.silent && !shouldPromptOnStartup(update.version)) return;

    if (await isManualInstallBundle()) {
      await promptManualDownload(update);
    } else {
      await promptDownloadAndInstall(update);
    }
  } catch (e) {
    const err = e instanceof Error ? e.message : String(e);
    setUpdate({ status: "error", error: err });
    if (opts.silent) {
      console.warn("检查更新失败:", err);
    } else {
      await message(`检查更新失败:${err}`, { title: "检查更新", kind: "error" });
    }
  } finally {
    inFlight = false;
  }
}

async function promptManualDownload(update: Update): Promise<void> {
  const go = await ask(
    `发现新版本 v${update.version}。${trimNotes(update.body)}\n\n` +
      "当前是 deb/rpm 方式安装,无法自动升级。是否打开下载页面?",
    { title: "发现新版本", kind: "info", okLabel: "前往下载", cancelLabel: "稍后" },
  );
  await update.close();
  if (go) await openUrl(RELEASES_URL);
}

async function promptDownloadAndInstall(update: Update): Promise<void> {
  const setUpdate = useAppStore.getState().setUpdate;
  const go = await ask(
    `发现新版本 v${update.version}。${trimNotes(update.body)}\n\n现在下载并安装吗?`,
    { title: "发现新版本", kind: "info", okLabel: "立即更新", cancelLabel: "稍后" },
  );
  if (!go) {
    await update.close();
    return;
  }

  let done = 0;
  let total: number | null = null;
  setUpdate({ status: "downloading", version: update.version, progress: { done, total } });
  await update.downloadAndInstall((ev) => {
    if (ev.event === "Started") {
      total = ev.data.contentLength ?? null;
    } else if (ev.event === "Progress") {
      done += ev.data.chunkLength;
    }
    setUpdate({ status: "downloading", version: update.version, progress: { done, total } });
  });
  // Windows 上 downloadAndInstall 会启动安装器并退出当前进程,走不到这里;
  // macOS/Linux 原地替换后需要重启才生效。
  setUpdate({ status: "ready", version: update.version });
  const restart = await ask("更新已安装,重启 BigPaw 后生效。现在重启吗?", {
    title: "更新完成",
    kind: "info",
    okLabel: "立即重启",
    cancelLabel: "稍后",
  });
  if (restart) await relaunch();
}

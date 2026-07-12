import { invoke } from "@tauri-apps/api/core";
import { useAppStore, type FileItem } from "./store";

function formatSize(n: number): string {
  if (!n || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

const STATUS_LABEL: Record<FileItem["status"], string> = {
  offered: "待处理",
  active: "传输中",
  done: "已完成",
  failed: "失败",
  rejected: "已拒绝",
};

/** 时间线里的文件传输气泡:live 传输带进度条与接受/拒绝,历史记录只读。 */
export default function FileBubble({ item }: { item: FileItem }) {
  const upsertFile = useAppStore((s) => s.upsertFile);
  const pct =
    item.size > 0 ? Math.min(100, Math.round(((item.done ?? 0) / item.size) * 100)) : 0;

  async function accept() {
    try {
      const downloadDir = await invoke<string>("default_download_dir");
      await invoke("respond_file", { xferId: item.xferId, accept: true, downloadDir });
      upsertFile({ xferId: item.xferId, status: "active" });
    } catch (e) {
      console.error("接受文件失败:", e);
      upsertFile({ xferId: item.xferId, status: "failed" });
    }
  }

  async function reject() {
    try {
      await invoke("respond_file", { xferId: item.xferId, accept: false, downloadDir: "" });
    } catch (e) {
      console.error("拒绝文件失败:", e);
    } finally {
      upsertFile({ xferId: item.xferId, status: "rejected" });
    }
  }

  return (
    <div className="inline-block max-w-[70%] rounded-lg border border-amber-200 bg-white px-3 py-2 text-left text-sm">
      <div className="flex items-center gap-2">
        <span className="truncate font-medium" title={item.name}>
          {item.isDir ? "📁" : "📎"} {item.name}
        </span>
        {!(item.isDir && item.size === 0) && (
          <span className="shrink-0 text-xs text-amber-600">{formatSize(item.size)}</span>
        )}
      </div>
      {item.status === "active" && (
        <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-amber-100">
          <div className="h-full bg-amber-700 transition-[width]" style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="mt-1 flex items-center gap-2 text-xs text-amber-700">
        <span>
          {item.direction === "in" ? "接收" : "发送"} · {STATUS_LABEL[item.status]}
        </span>
        {item.direction === "in" && item.status === "offered" && (
          <>
            <button
              onClick={accept}
              className="rounded bg-amber-800 px-2 py-0.5 text-white hover:bg-amber-700"
            >
              接受
            </button>
            <button onClick={reject} className="rounded border border-amber-300 px-2 py-0.5 hover:bg-amber-100">
              拒绝
            </button>
          </>
        )}
        {item.status === "done" && item.path && (
          <span className="truncate text-amber-600" title={item.path}>
            已保存: {item.path}
          </span>
        )}
      </div>
    </div>
  );
}

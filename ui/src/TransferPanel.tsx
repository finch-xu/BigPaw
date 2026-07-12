import { invoke } from "@tauri-apps/api/core";
import { useAppStore, type Transfer } from "./store";

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

function statusLabel(status: Transfer["status"]): string {
  switch (status) {
    case "offered":
      return "待处理";
    case "active":
      return "传输中";
    case "done":
      return "已完成";
    case "failed":
      return "失败";
    case "rejected":
      return "已拒绝";
  }
}

/** 会话内的文件传输列表:进度条 + 接受/拒绝(M3 范围内不做"打开所在文件夹",
 * 完成后只展示保存路径文本,openPath 留给后续里程碑)。 */
export default function TransferPanel({ fp }: { fp: string }) {
  const transfers = useAppStore((s) =>
    Object.values(s.transfers).filter((t) => t.peerFp === fp),
  );
  const upsertTransfer = useAppStore((s) => s.upsertTransfer);

  if (transfers.length === 0) return null;

  async function accept(xferId: string) {
    try {
      const downloadDir = await invoke<string>("default_download_dir");
      await invoke("respond_file", { xferId, accept: true, downloadDir });
      upsertTransfer({ xferId, status: "active" });
    } catch (e) {
      upsertTransfer({ xferId, status: "failed" });
      console.error("接受文件失败:", e);
    }
  }

  async function reject(xferId: string) {
    try {
      await invoke("respond_file", { xferId, accept: false, downloadDir: "" });
    } catch (e) {
      console.error("拒绝文件失败:", e);
    } finally {
      upsertTransfer({ xferId, status: "rejected" });
    }
  }

  return (
    <div className="max-h-56 space-y-2 overflow-y-auto border-t border-amber-200 p-3">
      <h3 className="text-xs font-semibold text-amber-700">文件传输</h3>
      <ul className="space-y-2">
        {transfers.map((t) => {
          const pct = t.size > 0 ? Math.min(100, Math.round((t.done / t.size) * 100)) : 0;
          return (
            <li key={t.xferId} className="text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate" title={t.name}>
                  {t.isDir ? `📁 文件夹: ${t.name}` : t.name}
                </span>
                {/* 文件夹大小/进度是尽力而为(整棵树可能未知总大小),
                    size===0 时不展示误导性的 "0 B"。 */}
                {!(t.isDir && t.size === 0) && (
                  <span className="shrink-0 text-xs text-amber-600">{formatSize(t.size)}</span>
                )}
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded bg-amber-100">
                <div
                  className="h-full bg-amber-700 transition-[width]"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <div className="mt-1 flex items-center gap-2 text-xs text-amber-700">
                <span>
                  {t.direction === "in" ? "接收" : "发送"} · {statusLabel(t.status)}
                </span>
                {t.direction === "in" && t.status === "offered" && (
                  <>
                    <button
                      onClick={() => accept(t.xferId)}
                      className="rounded bg-amber-800 px-2 py-0.5 text-white hover:bg-amber-700"
                    >
                      接受
                    </button>
                    <button
                      onClick={() => reject(t.xferId)}
                      className="rounded border border-amber-300 px-2 py-0.5 hover:bg-amber-100"
                    >
                      拒绝
                    </button>
                  </>
                )}
                {t.status === "done" && t.path && (
                  <span className="truncate text-amber-600">已保存: {t.path}</span>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

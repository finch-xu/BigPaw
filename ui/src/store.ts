import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface Peer {
  fingerprint: string;
  nickname: string;
  addrs: string[];
  port: number;
  protocol: "native" | "ipmsg";
  state: "discovered" | "reachable" | "unreachable" | "offline";
}

export interface SelfInfo {
  nickname: string;
  fingerprint: string;
}

/** 与后端 storage::HistoryItem 的 serde 输出一一对应(tag="kind")。 */
export interface TextItem {
  kind: "text";
  id: string;
  peerFp: string;
  direction: "in" | "out";
  body: string;
  tsMs: number;
}

export interface FileItem {
  kind: "file";
  xferId: string;
  peerFp: string;
  direction: "in" | "out";
  name: string;
  size: number;
  isDir: boolean;
  status: "offered" | "active" | "done" | "failed" | "rejected";
  path?: string | null;
  tsMs: number;
  /** 仅 live 传输有:已完成字节数(不持久化,重启即失) */
  done?: number;
}

export type TimelineItem = TextItem | FileItem;

export interface Conversation {
  items: TimelineItem[]; // 恒按 tsMs 升序
  hasMore: boolean;
  loaded: boolean;
}

export interface SearchHit {
  peerFp: string;
  tsMs: number;
  snippet: string;
  kind: "text" | "file";
}

export interface Settings {
  nickname: string | null;
  downloadDir: string | null;
  ipmsgEnabled: boolean;
}

const PAGE = 50;

const emptyConv = (): Conversation => ({ items: [], hasMore: true, loaded: false });

/** 分页游标用的条目 id:文本用消息 id,文件用 xferId。与后端复合游标 (ts_ms, id) 对齐。 */
const idOf = (it: TimelineItem): string => (it.kind === "text" ? it.id : it.xferId);

interface AppState {
  self: SelfInfo | null;
  peers: Peer[];
  selectedFp: string | null;
  conversations: Record<string, Conversation>;
  ipmsg: { available: boolean; enabled: boolean } | null;
  searchQuery: string;
  searchHits: SearchHit[];
  /** 搜索跳转的目标时间戳:ChatPane 据此高亮并滚动到该条 */
  highlightTs: number | null;
  showSettings: boolean;

  setSelf: (self: SelfInfo) => void;
  setPeers: (peers: Peer[]) => void;
  setIpmsg: (s: { available: boolean; enabled: boolean }) => void;
  setShowSettings: (v: boolean) => void;
  setHighlightTs: (ts: number | null) => void;

  openConversation: (fp: string) => Promise<void>;
  loadOlder: (fp: string) => Promise<void>;
  appendText: (item: TextItem) => void;
  upsertFile: (patch: Partial<FileItem> & { xferId: string }) => void;
  jumpToMessage: (fp: string, tsMs: number) => Promise<void>;
  setSearchQuery: (q: string) => void;
  runSearch: (q: string) => Promise<void>;
  clearConversation: (fp: string) => Promise<void>;
  clearAll: () => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => ({
  self: null,
  peers: [],
  selectedFp: null,
  conversations: {},
  ipmsg: null,
  searchQuery: "",
  searchHits: [],
  highlightTs: null,
  showSettings: false,

  setSelf: (self) => set({ self }),
  setPeers: (peers) => set({ peers }),
  setIpmsg: (ipmsg) => set({ ipmsg }),
  setShowSettings: (showSettings) => set({ showSettings }),
  setHighlightTs: (highlightTs) => set({ highlightTs }),

  openConversation: async (fp) => {
    set({ selectedFp: fp, highlightTs: null });
    if (get().conversations[fp]?.loaded) return;
    const items = await invoke<TimelineItem[]>("get_history", {
      fingerprint: fp,
      limit: PAGE,
    });
    set((s) => ({
      conversations: {
        ...s.conversations,
        [fp]: { items, hasMore: items.length === PAGE, loaded: true },
      },
    }));
  },

  loadOlder: async (fp) => {
    const conv = get().conversations[fp];
    if (!conv || !conv.hasMore || conv.items.length === 0) return;
    const older = await invoke<TimelineItem[]>("get_history", {
      fingerprint: fp,
      beforeTsMs: conv.items[0].tsMs,
      beforeId: idOf(conv.items[0]),
      limit: PAGE,
    });
    set((s) => ({
      conversations: {
        ...s.conversations,
        [fp]: {
          items: [...older, ...(s.conversations[fp]?.items ?? [])],
          hasMore: older.length === PAGE,
          loaded: true,
        },
      },
    }));
  },

  appendText: (item) =>
    set((s) => {
      const conv = s.conversations[item.peerFp] ?? emptyConv();
      return {
        conversations: {
          ...s.conversations,
          [item.peerFp]: { ...conv, items: [...conv.items, item] },
        },
      };
    }),

  // 按 xferId 找到既有文件条目原位更新;找不到(全新 offer)则按 peerFp 追加。
  // FileProgress 事件不带 peerFp,所以先全会话扫描。
  upsertFile: (patch) =>
    set((s) => {
      for (const [fp, conv] of Object.entries(s.conversations)) {
        const idx = conv.items.findIndex(
          (it) => it.kind === "file" && it.xferId === patch.xferId,
        );
        if (idx >= 0) {
          const items = [...conv.items];
          items[idx] = { ...(items[idx] as FileItem), ...patch };
          return { conversations: { ...s.conversations, [fp]: { ...conv, items } } };
        }
      }
      if (!patch.peerFp) return s; // progress 先于 offered 到达:丢弃,offered 会补
      const conv = s.conversations[patch.peerFp] ?? emptyConv();
      const item: FileItem = {
        kind: "file",
        xferId: patch.xferId,
        peerFp: patch.peerFp,
        direction: patch.direction ?? "in",
        name: patch.name ?? "",
        size: patch.size ?? 0,
        isDir: patch.isDir ?? false,
        status: patch.status ?? "offered",
        tsMs: patch.tsMs ?? Date.now(),
        done: patch.done,
        path: patch.path,
      };
      return {
        conversations: {
          ...s.conversations,
          [patch.peerFp]: { ...conv, items: [...conv.items, item] },
        },
      };
    }),

  jumpToMessage: async (fp, tsMs) => {
    const items = await invoke<TimelineItem[]>("get_history_around", {
      fingerprint: fp,
      tsMs,
    });
    set((s) => ({
      selectedFp: fp,
      highlightTs: tsMs,
      searchQuery: "",
      searchHits: [],
      conversations: {
        ...s.conversations,
        // around 窗口替换缓存:hasMore 重置为 true,向上翻页从窗口顶继续
        [fp]: { items, hasMore: true, loaded: true },
      },
    }));
  },

  setSearchQuery: (searchQuery) => set({ searchQuery }),

  runSearch: async (q) => {
    if (!q.trim()) {
      set({ searchHits: [] });
      return;
    }
    const hits = await invoke<SearchHit[]>("search_history", { query: q });
    set({ searchHits: hits });
  },

  clearConversation: async (fp) => {
    await invoke("clear_history", { fingerprint: fp }); // 后端删成功才清 UI
    set((s) => ({
      conversations: {
        ...s.conversations,
        [fp]: { items: [], hasMore: false, loaded: true },
      },
    }));
  },

  clearAll: async () => {
    await invoke("clear_history", {});
    set({ conversations: {}, searchHits: [] });
  },
}));

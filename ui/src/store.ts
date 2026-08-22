import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface Peer {
  fingerprint: string;
  nickname: string;
  addrs: string[];
  port: number;
  protocol: "native" | "ipmsg";
  state: "discovered" | "reachable" | "unreachable" | "offline";
  /** 对端声明的工作组名(M7a),null = 未分组 */
  group: string | null;
}

export interface SelfInfo {
  nickname: string;
  fingerprint: string;
}

/** 与后端 storage::HistoryItem 的 serde 输出一一对应(tag="kind")。 */
export interface TextItem {
  kind: "text";
  id: string;
  /** 会话 id:单聊=对端指纹,群聊(M7c)=groupId */
  peerFp: string;
  direction: "in" | "out";
  body: string;
  tsMs: number;
  /** 群消息发送者指纹(M7c);单聊无 */
  senderFp?: string | null;
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

/** 与后端 storage::ConvSummary 对应;前端以 peerFp 为键存 Record。 */
export interface ConvSummary {
  tsMs: number;
  snippet: string;
  kind: "text" | "file";
}

/** 与后端 groups::Group 对应(M7c)。 */
export interface GroupMember {
  fp: string;
  nick: string;
}
export interface Group {
  groupId: string;
  name: string;
  creatorFp: string;
  version: number;
  members: GroupMember[];
}

export interface Settings {
  nickname: string | null;
  /** 我的分组(M7a),null = 未设置 */
  group: string | null;
  downloadDir: string | null;
  ipmsgEnabled: boolean;
  excludedInterfaces: string[];
  /** 允许的对端网段清单(网络范围限定):每项单 IP / CIDR / 起-止区间;空 = 不限制 */
  allowedNetworks: string[];
  /** 全局通知开关(M8) */
  notifyEnabled: boolean;
  /** 提示音开关(M8) */
  notifySound: boolean;
  /** 通知是否显示消息内容(M8) */
  notifyShowPreview: boolean;
  /** 已静音的会话 id(M8) */
  mutedConversations: string[];
}

/** 与后端 `list_network_interfaces` 返回的 IfaceDto 一一对应。 */
export interface NetIface {
  name: string;
  ip: string;
  netmask: string;
  isVirtual: boolean;
  excluded: boolean;
}

/** Tauri 环境检测。刻意不从 ./mock 导入:mock.ts 反过来 import 本文件,
 *  引入循环依赖不值当——这是个一行常量。 */
const IS_TAURI = "__TAURI_INTERNALS__" in window;

/** 通知壳层「这个会话的未读清了」。托盘红点由壳层独立维护,三个清零入口
 *  (打开会话 / 清空单会话 / 清空全部)都必须经过这里,否则红点会和
 *  列表数字分叉。null = 全部清空。 */
async function tellShellUnreadCleared(convId: string | null): Promise<void> {
  if (!IS_TAURI) return;
  try {
    await invoke("notify_clear_unread", { convId });
  } catch {
    // 清红点失败不该阻断 UI:最坏是红点多亮一会儿,下次打开会话会再清一次
  }
}

/** 选中会话的唯一入口(M8)。三件事绑成一体:设置 selectedFp、把该会话的未读
 *  归零、把「当前会话」上报给壳层。
 *
 *  写 selectedFp 的地方有两处(openConversation 与 jumpToMessage),都必须走这里。
 *  漏掉任何一处,壳层的 active 就会停在上一个打开过的会话上:窗口聚焦时决策
 *  规则 2 会反过来压制用户**真正在看**的那个会话的通知,而给那个陈旧会话放行
 *  ——漏消息正是本子系统要防的事。这与清零信号收敛到 tellShellUnreadCleared
 *  是同一条纪律。
 *
 *  `extra` 放各入口特有的状态(高亮时间戳、搜索态、会话缓存),与上面三件事
 *  合并进同一次 set,避免多余的一次渲染。 */
function selectConversation(
  set: (updater: (s: AppState) => Partial<AppState>) => void,
  fp: string,
  extra?: (s: AppState) => Partial<AppState>,
): void {
  set((s) => ({
    ...(extra ? extra(s) : {}),
    selectedFp: fp,
    unread: { ...s.unread, [fp]: 0 },
  }));
  if (!IS_TAURI) return;
  // set_active 本身就含「该会话已读」语义,不必再调 notify_clear_unread
  void invoke("notify_set_active", { convId: fp }).catch(() => {});
}

const PAGE = 50;

const emptyConv = (): Conversation => ({ items: [], hasMore: true, loaded: false });

/** 分页游标用的条目 id:文本用消息 id,文件用 xferId。与后端复合游标 (ts_ms, id) 对齐。 */
const idOf = (it: TimelineItem): string => (it.kind === "text" ? it.id : it.xferId);

/** 更新流程状态机:idle → checking → latest | available → downloading → ready | error */
export interface UpdateState {
  status: "idle" | "checking" | "latest" | "available" | "downloading" | "ready" | "error";
  /** 检测到的新版本号(available 及之后有效) */
  version?: string;
  /** 下载进度;total 为 null 表示服务端未给 Content-Length */
  progress?: { done: number; total: number | null };
  error?: string;
}

interface AppState {
  self: SelfInfo | null;
  peers: Peer[];
  selectedFp: string | null;
  conversations: Record<string, Conversation>;
  /** 消息视图数据源(M7b):每会话最后一条摘要,启动拉取 + 收发时增量更新 */
  convSummaries: Record<string, ConvSummary>;
  /** 未读计数(内存态,重启清零):仅非当前选中会话的入站消息/文件计数 */
  unread: Record<string, number>;
  /** 已静音的会话 id(M8):启动拉取一次,切换时先落盘再改 UI */
  mutedConvs: string[];
  /** 已加入的群(M7c):启动拉取 + group://updated 全量替换 */
  groups: Group[];
  /** 建群面板开关(M7c) */
  showCreateGroup: boolean;
  ipmsg: { available: boolean; enabled: boolean } | null;
  searchQuery: string;
  searchHits: SearchHit[];
  /** 搜索跳转的目标时间戳:ChatPane 据此高亮并滚动到该条 */
  highlightTs: number | null;
  showSettings: boolean;
  /** 自动更新状态(见 updater.ts):「关于」页据此显示文案/进度 */
  update: UpdateState;

  setSelf: (self: SelfInfo) => void;
  setPeers: (peers: Peer[]) => void;
  setIpmsg: (s: { available: boolean; enabled: boolean }) => void;
  setShowSettings: (v: boolean) => void;
  setUpdate: (update: UpdateState) => void;
  setHighlightTs: (ts: number | null) => void;

  loadConversations: () => Promise<void>;
  loadGroups: () => Promise<void>;
  setGroups: (groups: Group[]) => void;
  setShowCreateGroup: (v: boolean) => void;
  openConversation: (fp: string) => Promise<void>;
  loadOlder: (fp: string) => Promise<void>;
  appendText: (item: TextItem) => void;
  upsertFile: (patch: Partial<FileItem> & { xferId: string }) => void;
  jumpToMessage: (fp: string, tsMs: number) => Promise<void>;
  setSearchQuery: (q: string) => void;
  runSearch: (q: string) => Promise<void>;
  clearConversation: (fp: string) => Promise<void>;
  clearAll: () => Promise<void>;
  loadMuted: () => Promise<void>;
  toggleMute: (convId: string) => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => ({
  self: null,
  peers: [],
  selectedFp: null,
  conversations: {},
  convSummaries: {},
  unread: {},
  mutedConvs: [],
  groups: [],
  showCreateGroup: false,
  ipmsg: null,
  searchQuery: "",
  searchHits: [],
  highlightTs: null,
  showSettings: false,
  update: { status: "idle" },

  setSelf: (self) => set({ self }),
  setPeers: (peers) => set({ peers }),
  setIpmsg: (ipmsg) => set({ ipmsg }),
  setShowSettings: (showSettings) => set({ showSettings }),
  // 整体替换而非合并:避免上一轮的 progress/error 残留到下一轮
  setUpdate: (update) => set({ update }),
  setHighlightTs: (highlightTs) => set({ highlightTs }),

  loadConversations: async () => {
    const list = await invoke<Array<{ peerFp: string } & ConvSummary>>("list_conversations");
    const summaries: Record<string, ConvSummary> = {};
    for (const s of list) summaries[s.peerFp] = { tsMs: s.tsMs, snippet: s.snippet, kind: s.kind };
    set({ convSummaries: summaries });
  },

  loadGroups: async () => {
    set({ groups: await invoke<Group[]>("list_groups") });
  },
  setGroups: (groups) => set({ groups }),
  setShowCreateGroup: (showCreateGroup) => set({ showCreateGroup }),

  openConversation: async (fp) => {
    selectConversation(set, fp, () => ({ highlightTs: null }));
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
      // 摘要与未读随消息同步更新(M7b):入站且非当前选中会话 → 未读+1
      const unreadDelta =
        item.direction === "in" && s.selectedFp !== item.peerFp ? 1 : 0;
      return {
        conversations: {
          ...s.conversations,
          [item.peerFp]: { ...conv, items: [...conv.items, item] },
        },
        convSummaries: {
          ...s.convSummaries,
          [item.peerFp]: { tsMs: item.tsMs, snippet: item.body, kind: "text" },
        },
        unread: unreadDelta
          ? { ...s.unread, [item.peerFp]: (s.unread[item.peerFp] ?? 0) + 1 }
          : s.unread,
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
      // 全新文件条目:摘要与未读同步更新(M7b),规则同 appendText
      const unreadDelta =
        item.direction === "in" && s.selectedFp !== item.peerFp ? 1 : 0;
      return {
        conversations: {
          ...s.conversations,
          [patch.peerFp]: { ...conv, items: [...conv.items, item] },
        },
        convSummaries: {
          ...s.convSummaries,
          [item.peerFp]: { tsMs: item.tsMs, snippet: item.name, kind: "file" },
        },
        unread: unreadDelta
          ? { ...s.unread, [item.peerFp]: (s.unread[item.peerFp] ?? 0) + 1 }
          : s.unread,
      };
    }),

  jumpToMessage: async (fp, tsMs) => {
    const items = await invoke<TimelineItem[]>("get_history_around", {
      fingerprint: fp,
      tsMs,
    });
    selectConversation(set, fp, (s) => ({
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
    await tellShellUnreadCleared(fp);
    set((s) => {
      const { [fp]: _dropped, ...restSummaries } = s.convSummaries;
      const { [fp]: _droppedUnread, ...restUnread } = s.unread;
      return {
        conversations: {
          ...s.conversations,
          [fp]: { items: [], hasMore: false, loaded: true },
        },
        convSummaries: restSummaries,
        unread: restUnread,
      };
    });
  },

  clearAll: async () => {
    await invoke("clear_history", {});
    await tellShellUnreadCleared(null);
    set({ conversations: {}, searchHits: [], convSummaries: {}, unread: {} });
  },

  loadMuted: async () => {
    if (!IS_TAURI) return;
    const s = await invoke<Settings>("get_settings");
    set({ mutedConvs: s.mutedConversations });
  },

  toggleMute: async (convId) => {
    const muted = !get().mutedConvs.includes(convId);
    if (IS_TAURI) {
      // 先落盘再改 UI:失败时 UI 不会显示一个其实没保存上的状态
      await invoke("set_conversation_muted", { convId, muted });
    }
    set((s) => ({
      mutedConvs: muted
        ? [...s.mutedConvs, convId]
        : s.mutedConvs.filter((c) => c !== convId),
    }));
  },
}));

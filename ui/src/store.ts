import { create } from "zustand";

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

export interface ChatMessage {
  id: string;
  peerFp: string;
  body: string;
  tsMs: number;
  direction: "in" | "out";
}

export interface Transfer {
  xferId: string;
  peerFp: string;
  name: string;
  size: number;
  done: number;
  direction: "in" | "out";
  status: "offered" | "active" | "done" | "failed" | "rejected";
  path?: string;
}

interface AppState {
  self: SelfInfo | null;
  peers: Peer[];
  selectedFp: string | null;
  messages: Record<string, ChatMessage[]>;
  transfers: Record<string, Transfer>;
  /** IPMsg 兼容层是否启用(2425 端口):null = 尚未查询到。 */
  ipmsgAvailable: boolean | null;
  setSelf: (self: SelfInfo) => void;
  setPeers: (peers: Peer[]) => void;
  select: (fp: string | null) => void;
  appendMessage: (m: ChatMessage) => void;
  upsertTransfer: (t: Partial<Transfer> & { xferId: string }) => void;
  setIpmsgAvailable: (available: boolean) => void;
}

export const useAppStore = create<AppState>((set) => ({
  self: null,
  peers: [],
  selectedFp: null,
  messages: {},
  transfers: {},
  ipmsgAvailable: null,
  setSelf: (self) => set({ self }),
  setPeers: (peers) => set({ peers }),
  select: (selectedFp) => set({ selectedFp }),
  appendMessage: (m) =>
    set((s) => ({
      messages: { ...s.messages, [m.peerFp]: [...(s.messages[m.peerFp] ?? []), m] },
    })),
  upsertTransfer: (t) =>
    set((s) => ({
      transfers: {
        ...s.transfers,
        [t.xferId]: { ...s.transfers[t.xferId], ...t } as Transfer,
      },
    })),
  setIpmsgAvailable: (ipmsgAvailable) => set({ ipmsgAvailable }),
}));

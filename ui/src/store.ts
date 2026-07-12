import { create } from "zustand";

export interface Peer {
  fingerprint: string;
  nickname: string;
  addrs: string[];
  port: number;
  protocol: "native" | "ipmsg";
  state: "discovered" | "offline";
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

interface AppState {
  self: SelfInfo | null;
  peers: Peer[];
  selectedFp: string | null;
  messages: Record<string, ChatMessage[]>;
  setSelf: (self: SelfInfo) => void;
  setPeers: (peers: Peer[]) => void;
  select: (fp: string | null) => void;
  appendMessage: (m: ChatMessage) => void;
}

export const useAppStore = create<AppState>((set) => ({
  self: null,
  peers: [],
  selectedFp: null,
  messages: {},
  setSelf: (self) => set({ self }),
  setPeers: (peers) => set({ peers }),
  select: (selectedFp) => set({ selectedFp }),
  appendMessage: (m) =>
    set((s) => ({
      messages: { ...s.messages, [m.peerFp]: [...(s.messages[m.peerFp] ?? []), m] },
    })),
}));

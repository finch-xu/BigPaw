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

interface AppState {
  self: SelfInfo | null;
  peers: Peer[];
  setSelf: (self: SelfInfo) => void;
  setPeers: (peers: Peer[]) => void;
}

export const useAppStore = create<AppState>((set) => ({
  self: null,
  peers: [],
  setSelf: (self) => set({ self }),
  setPeers: (peers) => set({ peers }),
}));

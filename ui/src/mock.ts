import { useAppStore, type Conversation, type Group, type Peer, type TimelineItem } from "./store";

/** Tauri 环境检测:桌面 app 里为 true;纯浏览器(vite dev 预览)为 false。 */
export const IS_TAURI = "__TAURI_INTERNALS__" in window;

const now = Date.now();
const MIN = 60_000;
const H = 3_600_000;
const DAY = 24 * H;

const fp1 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const fp2 = "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1";
const fp3 = "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
const fp4 = "ipmsg-192.168.1.77";
const fp5 = "d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3";
const fp6 = "e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4";

const peers: Peer[] = [
  { fingerprint: fp1, nickname: "工位小王", addrs: ["192.168.1.23"], port: 24917, protocol: "native", state: "reachable", group: "研发部" },
  { fingerprint: fp2, nickname: "测试机-Win11", addrs: ["192.168.1.45"], port: 24917, protocol: "native", state: "unreachable", group: "研发部" },
  { fingerprint: fp3, nickname: "Aria", addrs: ["192.168.1.60"], port: 24917, protocol: "native", state: "discovered", group: null },
  { fingerprint: fp4, nickname: "飞秋-前台", addrs: ["192.168.1.77"], port: 2425, protocol: "ipmsg", state: "reachable", group: "行政部" },
  { fingerprint: fp5, nickname: "老李的Mac", addrs: ["192.168.1.88"], port: 24917, protocol: "native", state: "offline", group: null },
  { fingerprint: fp6, nickname: "会议室NUC", addrs: ["192.168.1.99"], port: 24917, protocol: "native", state: "offline", group: null },
];

const conv = (items: TimelineItem[]): Conversation => ({ items, hasMore: false, loaded: true });

/** 与工位小王的会话:覆盖 昨天/今天 日期线、双向文本、文件各状态。 */
const conv1: TimelineItem[] = [
  { kind: "text", id: "m1", peerFp: fp1, direction: "in", body: "设计稿传你一份,回头看看", tsMs: now - DAY - 2 * H },
  { kind: "file", xferId: "x1", peerFp: fp1, direction: "in", name: "首页设计稿-v3.sketch", size: 48_234_567, isDir: false, status: "done", path: "/Users/me/Downloads/首页设计稿-v3.sketch", tsMs: now - DAY - 2 * H + MIN },
  { kind: "text", id: "m2", peerFp: fp1, direction: "out", body: "收到,明天给你反馈", tsMs: now - DAY - H },
  { kind: "text", id: "m3", peerFp: fp1, direction: "in", body: "在吗?昨天那个稿子看了没", tsMs: now - 50 * MIN },
  { kind: "text", id: "m4", peerFp: fp1, direction: "in", body: "另外把测试数据也发我一下", tsMs: now - 49 * MIN },
  { kind: "text", id: "m5", peerFp: fp1, direction: "out", body: "看了,整体不错,细节我批注在文件里了,你看下第 3 页的间距问题", tsMs: now - 45 * MIN },
  { kind: "file", xferId: "x2", peerFp: fp1, direction: "out", name: "测试数据.zip", size: 120_000_000, isDir: false, status: "active", done: 45_000_000, tsMs: now - 3 * MIN },
  { kind: "file", xferId: "x3", peerFp: fp1, direction: "in", name: "素材包", size: 0, isDir: true, status: "offered", tsMs: now - MIN },
];

/** 与飞秋的会话:用于预览旧协议明文横幅。 */
const conv4: TimelineItem[] = [
  { kind: "text", id: "m10", peerFp: fp4, direction: "in", body: "前台有你的快递", tsMs: now - 20 * MIN },
  { kind: "text", id: "m11", peerFp: fp4, direction: "out", body: "好的,马上来拿", tsMs: now - 18 * MIN },
];

/** 群样例(M7c):群会话预览,入站气泡带发送者昵称。 */
const gid1 = "mock-group-0001";
const mockSelfFp = "0718f00d5566deadbeef00112233445566778899aabbccddeeff001122334455";
const groups: Group[] = [
  {
    groupId: gid1,
    name: "猫猫研发群",
    creatorFp: mockSelfFp,
    version: 2,
    members: [
      { fp: mockSelfFp, nick: "我的MacBook" },
      { fp: fp1, nick: "工位小王" },
      { fp: fp3, nick: "Aria" },
    ],
  },
];
const convG1: TimelineItem[] = [
  { kind: "text", id: "gm1", peerFp: gid1, direction: "in", body: "这个群拉了 Aria 进来", tsMs: now - 30 * MIN, senderFp: fp1 },
  { kind: "text", id: "gm2", peerFp: gid1, direction: "in", body: "大家好~", tsMs: now - 29 * MIN, senderFp: fp3 },
  { kind: "text", id: "gm3", peerFp: gid1, direction: "out", body: "欢迎欢迎,今晚对齐一下进度", tsMs: now - 25 * MIN },
];

/** 纯浏览器预览:注入假数据,使 UI 无需 Tauri 后端即可完整渲染。 */
export function installMocks(): void {
  useAppStore.setState({
    self: { nickname: "我的MacBook", fingerprint: "0718f00d5566deadbeef00112233445566778899aabbccddeeff001122334455" },
    peers,
    ipmsg: { available: true, enabled: true },
    conversations: {
      [fp1]: conv(conv1),
      [fp2]: conv([]),
      [fp3]: conv([]),
      [fp4]: conv(conv4),
      [fp5]: conv([]),
      [fp6]: conv([]),
      [gid1]: conv(convG1),
    },
    // 消息视图(M7b):有会话往来的对象 + 未读样例
    convSummaries: {
      [fp1]: { tsMs: now - MIN, snippet: "素材包", kind: "file" },
      [fp4]: { tsMs: now - 18 * MIN, snippet: "好的,马上来拿", kind: "text" },
      [gid1]: { tsMs: now - 25 * MIN, snippet: "欢迎欢迎,今晚对齐一下进度", kind: "text" },
    },
    unread: { [fp1]: 3, [gid1]: 1 },
    groups,
  });
  // 截图调试用:允许在浏览器控制台操纵 store(仅 mock 模式暴露)
  (window as unknown as { __store?: typeof useAppStore }).__store = useAppStore;
}

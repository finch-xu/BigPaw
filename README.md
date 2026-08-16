# BigPaw · 大脚猫

> 无服务器的局域网即时通讯 + 高速文件传输工具,飞秋(IPMsg)替代品。
> 桌面端:**Windows / macOS / Linux**。

BigPaw 不需要任何服务器、账号或云。同一局域网内启动即互相发现,直接点对点收发消息与文件;既能和其它 BigPaw 节点走**加密原生协议**,也能和现有的**飞秋 / IPMsg** 客户端互通。

---

## 特性

- **零配置发现**:同网段启动即互相可见,无需登录、无需中心服务器。
- **双协议栈,自动择优**
  - **原生栈**:加密 TCP 直连,支持文本、文件、群组、历史记录等全部功能。
  - **IPMsg 兼容栈**:与飞秋 / IPMsg 明文互通(UDP/TCP `2425`),仅文本 + 文件,UI 标注「旧协议」角标。
  - 双方均为 BigPaw 时**自动升级**到加密原生协议。
- **高速文件传输**:目标跑满千兆(~110 MB/s,瓶颈落在磁盘而非网络),blake3 完整性校验,支持断点续传。
- **端到端加密**:自签证书 TLS,证书哈希即身份指纹(fingerprint = 公钥 SHA-256)。
- **统一联系人列表**:上线 / 心跳 / 离线 / 协议能力自动管理,并按指纹去重。
- **群组与历史**:群聊、本地历史记录、会话列表、全文搜索、可清空。
- **网络范围限定(0.5)**:`allowedNetworks` 允许网段清单(单 IP / CIDR / 起-止区间),语义借鉴 Syncthing——范围指**对端地址**;超范围的发现忽略、入站拒绝、出站不拨。开启**严格隐身**:网卡子网未被整段覆盖时不广播、关闭该网卡 mDNS,改为对范围内主机逐台单播。
- **中文友好**:飞秋使用 GBK,BigPaw 双向转码;不可表示字符(emoji 等)降级为 `?` 并在 UI 提示对方为旧客户端。

---

## 技术栈与架构

- **框架**:Tauri 2 + React 19(前端仅负责 UI)
- **核心语言**:Rust(tokio、socket2、mdns-sd、if-addrs、encoding_rs、blake3、serde)

**铁律**:文件字节流与全部网络 / 磁盘 IO 都在 Rust 核心内闭环,**绝不经过 Tauri IPC**。前端只发起指令、接收状态事件;进度事件节流到每 100~200ms 一次。这是能跑满千兆的关键。

```
┌─ 前端 UI (React) ── Tauri commands / events ─┐
│                 Rust Core                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ 发现层    │ │ 原生传输  │ │ IPMsg 兼容层  │  │
│  │ 三通道    │ │ 加密 TCP  │ │ UDP/TCP 2425 │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
│        统一用户列表状态机(能力标记)           │
└───────────────────────────────────────────────┘
```

### 三层发现(按优先级叠加)

1. **主通道 mDNS/DNS-SD**:应用自带协议栈(`mdns-sd`),不依赖 Bonjour / Avahi,跨平台行为一致;企业网络设备(Bonjour Gateway、AirGroup、UniFi reflector)可现成跨 VLAN 转发。
2. **辅通道 自定义 UDP 宣告**:子网定向广播 + 组播双发,对付禁 5353 / 禁标准组播的网络,按指纹与 mDNS 结果去重。
3. **兜底 单播探测**:持久化历史设备 IP,启动优先探测,常用联系人秒级恢复。

> **双向注册**:收到宣告后 TCP 回连对方端口注册,同时验证连通性;回连失败标记「可见但不可达」并给出防火墙提示——解决「发现正常但传输失败」的半通问题。

---

## 项目结构

```
BigPaw/
├─ crates/
│  ├─ bigpaw-core/    # 核心:identity / discovery / transport / roster / groups / storage / net_scope(零 Tauri 依赖)
│  └─ bigpaw-ipmsg/   # 飞秋 / IPMsg 兼容层(边界冻结的独立模块)
├─ src-tauri/         # Tauri 壳层:commands + 节流 events
├─ ui/                # React 19 + Vite + Tailwind 前端
└─ scripts/           # 构建 / 版本脚本
```

---

## 开发与构建

前置:**Rust**(stable) + **Node.js** + **pnpm** + Tauri 2 的[系统依赖](https://tauri.app/start/prerequisites/)。

```bash
# 安装前端依赖
pnpm -C ui install

# 开发模式(热重载,自动拉起前端 dev server)
pnpm -C src-tauri tauri dev
# 或使用 cargo:
cargo tauri dev

# 打包发布(各平台安装包)
cargo tauri build

# 运行 Rust 侧测试(含发现 / 传输 / IPMsg 集成用例)
cargo test
```

---

## 平台注意事项

- **Windows**:首次监听会触发 Defender 防火墙弹窗,误点「取消」会收不到广播——请允许放行(或安装时用 `netsh` 加规则)。
- **macOS**:macOS 15+ 首次会弹本地网络权限,请允许。
- **通用**:多网卡 / VPN / 虚拟机网卡环境下,BigPaw 会枚举物理接口并过滤 loopback / tun / 桥接虚拟网卡;支持手动绑定接口。

---

## 明确不做(V1)

无服务器、无账号体系(已定)· 飞秋私有方言扩展 · 语音 / 远程协助 · QUIC · 跨公网传输。

---

## 许可证

[GNU General Public License v3.0](LICENSE)

<div align="center">

<img src="assets/logo.png" alt="BigPaw" width="128" />

# BigPaw · 大脚猫

**Serverless LAN instant messaging + high-speed file transfer**, a modern LAN Messenger / IP Messenger / Feiqiu replacement

![Windows](https://img.shields.io/badge/Windows-0078D4?logo=windows&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-4B4B4B?logo=apple&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)
![Tauri](https://img.shields.io/badge/Tauri_2-24C8DB?logo=tauri&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-CE422B?logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React_19-61DAFB?logo=react&logoColor=black)

[简体中文](README.md) · **English** · [日本語](README.ja.md)

</div>

BigPaw needs no server, no account, and no cloud. Launch it on the same LAN and peers discover each other instantly, then exchange messages and files peer-to-peer. It speaks an **encrypted native protocol** with other BigPaw nodes, and stays interoperable with existing **IP Messenger (IPMsg) / Feiqiu** clients.

---

## Features

- **Zero-config discovery**: peers on the same subnet see each other on launch — no login, no central server.
- **Dual protocol stacks, best one chosen automatically**
  - **Native stack**: encrypted direct TCP, with the full feature set — text, files, groups, history.
  - **IPMsg compatibility stack**: plaintext interop with Feiqiu / IPMsg (UDP/TCP `2425`), text + files only, marked with a "legacy protocol" badge in the UI.
  - When both ends are BigPaw, the session is **automatically upgraded** to the encrypted native protocol.
- **High-speed file transfer**: targets a saturated gigabit link (~110 MB/s, bounded by disk rather than network), blake3 integrity verification, resumable transfers.
- **End-to-end encryption**: TLS with self-signed certificates; the certificate hash *is* the identity fingerprint (fingerprint = public key SHA-256).
- **Unified contact list**: online / heartbeat / offline / protocol-capability transitions are managed automatically, deduplicated by fingerprint.
- **Groups and history**: group chat, local message history, conversation list, full-text search, clearable.
- **Network scope restriction (0.5)**: `allowedNetworks` is an allow-list of networks (single IP / CIDR / start-end range) whose semantics follow Syncthing — the scope applies to the **peer address**; out-of-scope discoveries are ignored, inbound connections rejected, and outbound connections never dialed. With **strict stealth** enabled, BigPaw stops broadcasting and disables mDNS on any interface whose subnet is not fully covered, unicasting to in-scope hosts one by one instead.
- **CJK-friendly**: Feiqiu uses GBK, and BigPaw transcodes in both directions; characters that cannot be represented (emoji, etc.) degrade to `?` and the UI flags the peer as a legacy client.

---

## Stack and architecture

- **Framework**: Tauri 2 + React 19 (the frontend does UI only)
- **Core language**: Rust (tokio, socket2, mdns-sd, if-addrs, encoding_rs, blake3, serde)

**Hard rule**: file byte streams and all network / disk IO stay inside the Rust core and **never cross the Tauri IPC boundary**. The frontend only issues commands and receives state events; progress events are throttled to one every 100–200 ms. This is what makes saturating a gigabit link possible.

```
┌─ Frontend UI (React) ── Tauri commands / events ──────┐
│                       Rust Core                       │
│   ┌────────────┐ ┌───────────────┐ ┌──────────────┐   │
│   │ Discovery  │ │  Native xfer  │ │ IPMsg compat │   │
│   │ 3 channels │ │ encrypted TCP │ │ UDP/TCP 2425 │   │
│   └────────────┘ └───────────────┘ └──────────────┘   │
│      Unified roster state machine (capabilities)      │
└───────────────────────────────────────────────────────┘ └───────────────┘ └──────────────┘    │
│      Unified roster state machine (capabilities)      │
└───────────────────────────────────────────────────────┘ └────────────┘ └────────────────┘  │
│      Unified roster state machine (capabilities)  │
└───────────────────────────────────────────────────┘
```

### Three-layer discovery (stacked by priority)

1. **Primary channel — mDNS/DNS-SD**: the app ships its own stack (`mdns-sd`), so it does not depend on Bonjour / Avahi and behaves identically across platforms; enterprise gear (Bonjour Gateway, AirGroup, UniFi reflector) can forward it across VLANs out of the box.
2. **Secondary channel — custom UDP announcements**: subnet-directed broadcast plus multicast, sent in parallel, for networks that block 5353 or standard multicast; results are deduplicated against mDNS by fingerprint.
3. **Fallback — unicast probing**: known peer IPs are persisted and probed first at startup, so frequent contacts come back within seconds.

> **Bidirectional registration**: on receiving an announcement, BigPaw connects back to the peer's TCP port to register and, in doing so, verifies connectivity. A failed connect-back marks the peer "visible but unreachable" and surfaces a firewall hint — this is what resolves the half-open "discovery works but transfers fail" case.

---

## Project layout

```
BigPaw/
├─ crates/
│  ├─ bigpaw-core/    # core: identity / discovery / transport / roster / groups / storage / net_scope (zero Tauri deps)
│  └─ bigpaw-ipmsg/   # Feiqiu / IPMsg compatibility layer (standalone module with a frozen boundary)
├─ src-tauri/         # Tauri shell: commands + throttled events
├─ ui/                # React 19 + Vite + Tailwind frontend
└─ scripts/           # build / versioning scripts
```

---

## Development and build

Prerequisites: **Rust** (stable) + **Node.js** + **pnpm** + the Tauri 2 [system dependencies](https://tauri.app/start/prerequisites/).

```bash
# Install frontend dependencies
pnpm -C ui install

# Dev mode (hot reload, starts the frontend dev server automatically)
pnpm -C src-tauri tauri dev
# or with cargo:
cargo tauri dev

# Build release bundles (installers for each platform)
cargo tauri build

# Run the Rust-side tests (including discovery / transport / IPMsg integration cases)
cargo test
```

---

## Platform notes

- **Windows**: the first listen triggers a Defender firewall prompt; clicking "Cancel" by mistake means announcements never arrive — allow it (or add a rule with `netsh` at install time).
- **macOS**: macOS 15+ asks for local network permission on first launch; allow it.
- **General**: with multiple NICs / VPNs / virtual-machine adapters, BigPaw enumerates physical interfaces and filters out loopback / tun / bridged virtual adapters; manual interface binding is supported.

---

## Explicit non-goals (V1)

Serverless with no account system (settled) · Feiqiu private dialect extensions · voice / remote assistance · QUIC · transfers across the public internet.

---

## License

[GNU General Public License v3.0](LICENSE)

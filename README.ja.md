<div align="center">

<img src="assets/logo.png" alt="BigPaw" width="128" />

# BigPaw · 大脚猫

**サーバー不要の LAN インスタントメッセンジャー + 高速ファイル転送**、IP Messenger / LAN Messenger / 飞秋(Feiqiu)の代替アプリ

![Windows](https://img.shields.io/badge/Windows-0078D4?logo=windows&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-4B4B4B?logo=apple&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)
![Tauri](https://img.shields.io/badge/Tauri_2-24C8DB?logo=tauri&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-CE422B?logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React_19-61DAFB?logo=react&logoColor=black)

[简体中文](README.md) · [English](README.en.md) · **日本語**

</div>

BigPaw はサーバーもアカウントもクラウドも必要としません。同じ LAN 上で起動するだけで互いを検出し、メッセージとファイルを直接ピアツーピアでやり取りします。BigPaw 同士では**暗号化されたネイティブプロトコル**を使い、既存の **IP Messenger (IPMsg) / 飞秋** クライアントとも相互接続できます。

---

## 特徴

- **ゼロコンフィグ検出**:同一サブネット上で起動するだけで互いに見える。ログイン不要、中央サーバー不要。
- **デュアルプロトコルスタック、自動で最適を選択**
  - **ネイティブスタック**:暗号化された TCP 直結。テキスト・ファイル・グループ・履歴などの全機能に対応。
  - **IPMsg 互換スタック**:IP Messenger / 飞秋 と平文で相互接続(UDP/TCP `2425`)。テキストとファイルのみ対応で、UI に「レガシープロトコル」のバッジを表示。
  - 双方が BigPaw の場合は暗号化ネイティブプロトコルへ**自動アップグレード**。
- **高速ファイル転送**:ギガビット回線を使い切ることを目標(~110 MB/s。ボトルネックはネットワークではなくディスク側)。blake3 による完全性検証とレジューム転送に対応。
- **エンドツーエンド暗号化**:自己署名証明書による TLS。証明書のハッシュがそのまま ID フィンガープリントになります(fingerprint = 公開鍵の SHA-256)。
- **統一された連絡先リスト**:オンライン / ハートビート / オフライン / プロトコル能力の遷移を自動管理し、フィンガープリントで重複排除。
- **グループと履歴**:グループチャット、ローカル履歴、会話リスト、全文検索、履歴の消去。
- **ネットワーク範囲の限定(0.5)**:`allowedNetworks` は許可ネットワークのリスト(単一 IP / CIDR / 開始-終了レンジ)で、セマンティクスは Syncthing に倣っています。範囲が指すのは**相手側のアドレス**で、範囲外の検出は無視、着信は拒否、発信はダイヤルしません。**ストリクトステルス**を有効にすると、インターフェースのサブネットが範囲に完全には含まれない場合はブロードキャストを停止し、そのインターフェースの mDNS も無効化して、範囲内のホストへ 1 台ずつユニキャストします。
- **マルチバイト文字への配慮**:飞秋 は GBK を使うため、BigPaw が双方向でコード変換します。表現できない文字(絵文字など)は `?` に劣化させたうえで、相手がレガシークライアントであることを UI で通知します。

---

## 技術スタックとアーキテクチャ

- **フレームワーク**:Tauri 2 + React 19(フロントエンドは UI のみを担当)
- **コア言語**:Rust(tokio、socket2、mdns-sd、if-addrs、encoding_rs、blake3、serde)

**鉄則**:ファイルのバイトストリームとネットワーク / ディスク IO はすべて Rust コア内で完結させ、**Tauri の IPC を絶対に経由させない**。フロントエンドはコマンドを発行して状態イベントを受け取るだけで、進捗イベントは 100〜200ms に 1 回へスロットリングします。これがギガビットを使い切れる理由です。

```
┌─ フロントエンド UI (React) ── Tauri commands / events ────┐
│                         Rust Core                         │
│    ┌────────────┐ ┌────────────────┐ ┌──────────────┐     │
│    │   発見層   │ │ ネイティブ転送 │ │ IPMsg 互換層 │     │
│    │ 3 チャネル │ │   暗号化 TCP   │ │ UDP/TCP 2425 │     │
│    └────────────┘ └────────────────┘ └──────────────┘     │
│          統一ユーザーリスト状態機械(能力フラグ)           │
└───────────────────────────────────────────────────────────┘
```

### 3 層構成の検出(優先度順に重ねる)

1. **メインチャネル mDNS/DNS-SD**:アプリが自前のスタック(`mdns-sd`)を同梱しているため、Bonjour / Avahi に依存せず、プラットフォーム間で挙動が一致します。企業向けネットワーク機器(Bonjour Gateway、AirGroup、UniFi reflector)があれば、そのまま VLAN 越しに転送できます。
2. **サブチャネル 独自 UDP アナウンス**:サブネット指定ブロードキャストとマルチキャストを併用し、5353 番や標準マルチキャストがブロックされたネットワークに対応。結果はフィンガープリントで mDNS と重複排除します。
3. **フォールバック ユニキャスト探索**:既知のピア IP を永続化し、起動時に優先して探索するため、よく使う相手は数秒で復帰します。

> **双方向登録**:アナウンスを受信したら相手の TCP ポートへ接続し返して登録すると同時に、疎通も検証します。接続し返せなかった場合は「見えているが到達できない」とマークしてファイアウォールのヒントを提示します。これが「検出はできるのに転送に失敗する」という片通り状態の解決策です。

---

## プロジェクト構成

```
BigPaw/
├─ crates/
│  ├─ bigpaw-core/    # コア: identity / discovery / transport / roster / groups / storage / net_scope(Tauri 非依存)
│  └─ bigpaw-ipmsg/   # IP Messenger / 飞秋 互換レイヤ(境界を凍結した独立モジュール)
├─ src-tauri/         # Tauri シェル層: commands + スロットリングされた events
├─ ui/                # React 19 + Vite + Tailwind のフロントエンド
└─ scripts/           # ビルド / バージョニングスクリプト
```

---

## 開発とビルド

前提:**Rust**(stable)+ **Node.js** + **pnpm** と Tauri 2 の[システム要件](https://tauri.app/start/prerequisites/)。

```bash
# フロントエンドの依存関係をインストール
pnpm -C ui install

# 開発モード(ホットリロード。フロントエンドの dev server も自動起動)
pnpm -C src-tauri tauri dev
# または cargo から:
cargo tauri dev

# リリースビルド(各プラットフォーム向けインストーラー)。自動更新用の署名
# (createUpdaterArtifacts)が有効なため、updater 秘密鍵がない場合は --no-sign を付ける
# (その成果物は自動更新には使えない)
cargo tauri build --no-sign

# Rust 側のテストを実行(検出 / 転送 / IPMsg の結合テストを含む)
cargo test
```

---

## プラットフォーム別の注意事項

- **Windows**:初回のリッスン時に Defender のファイアウォール警告が出ます。誤って「キャンセル」を押すとアナウンスを受信できなくなるため、許可してください(インストール時に `netsh` でルールを追加しても構いません)。
- **macOS**:macOS 15 以降は初回起動時にローカルネットワークの許可を求められます。許可してください。
- **共通**:複数 NIC / VPN / 仮想マシンのアダプタがある環境では、物理インターフェースを列挙したうえで loopback / tun / ブリッジ仮想アダプタを除外します。インターフェースの手動バインドにも対応しています。

---

## V1 でやらないこと

サーバーレスかつアカウント体系なし(確定)· 飞秋 の独自方言拡張 · 音声 / リモートアシスト · QUIC · インターネット越しの転送。

---

## ライセンス

[GNU General Public License v3.0](LICENSE)

#!/usr/bin/env node
// 用各构建 job 上传的 .sig 文件 + tag 拼出 Tauri updater 要求的 latest.json。
//
// 用法: node scripts/generate-latest-json.mjs <tag> <sig-dir> <out-file>
// 环境变量:
//   GH_TOKEN  - gh CLI 鉴权 (workflow 里是 secrets.GITHUB_TOKEN)
//   GH_REPO   - owner/repo (用来拼下载 URL 与读 release notes)
//
// 输入约定: <sig-dir> 下每个 `<资产文件名>.sig` 对应一个已上传到 release 的资产,
// 资产文件名沿用 release.yml 的固定命名 BigPaw-<os>-<arch>.<ext>(不带版本号),
// 这里靠 "<os>-<arch>" 子串把它路由到 updater 的平台键。改命名时两边同步。
//
// 输出: { version, notes, pub_date, platforms: { "<os>-<arch>": { signature, url } } }
// Tauri 会先整体校验文件再比对版本,所以 6 个平台缺一都直接报错,不发半份清单。

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

const [, , tag, sigDir, outFile] = process.argv;
if (!tag || !sigDir || !outFile) {
  console.error("用法: generate-latest-json.mjs <tag> <sig-dir> <out-file>");
  process.exit(1);
}

const repo = process.env.GH_REPO;
if (!repo) {
  console.error("GH_REPO 环境变量未设置");
  process.exit(1);
}

const version = tag.startsWith("v") ? tag.slice(1) : tag;

// release notes 来自草稿 release 的 body(create-draft job 用 --generate-notes 生成)。
// 拿不到就留空:notes 是可选字段,不能因此让整次发布失败。
let notes = "";
try {
  notes = execFileSync(
    "gh",
    ["release", "view", tag, "--repo", repo, "--json", "body", "--jq", ".body"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
} catch (e) {
  console.warn("无法获取 release body, 使用空 notes:", e.message);
}

// 文件名子串 → updater 平台键。顺序无关,但子串之间不能互为前缀。
const PLATFORM_BY_SUFFIX = {
  "macos-arm64": "darwin-aarch64",
  "macos-x64": "darwin-x86_64",
  "windows-arm64": "windows-aarch64",
  "windows-x64": "windows-x86_64",
  "linux-arm64": "linux-aarch64",
  "linux-x64": "linux-x86_64",
};

// 每个平台只认它的 updater 产物后缀,防止同名 .deb.sig / .dmg 之类混进来撞键。
const UPDATER_EXT = {
  darwin: ".app.tar.gz",
  windows: ".exe",
  linux: ".AppImage",
};

const files = readdirSync(sigDir).filter((f) => f.endsWith(".sig")).sort();
console.log("发现 sig 文件:", files);

const platforms = {};
for (const sigName of files) {
  const assetName = sigName.slice(0, -".sig".length);
  const hit = Object.entries(PLATFORM_BY_SUFFIX).find(([sub]) => assetName.includes(sub));
  if (!hit) {
    console.warn("跳过未识别平台的 sig:", assetName);
    continue;
  }
  const key = hit[1];
  const os = key.split("-")[0];
  if (!assetName.endsWith(UPDATER_EXT[os])) {
    console.warn(`跳过非 updater 产物的 sig: ${assetName} (期望后缀 ${UPDATER_EXT[os]})`);
    continue;
  }
  if (platforms[key]) {
    throw new Error(`平台 ${key} 出现多个 sig: 已有 ${platforms[key].url}, 又遇到 ${assetName}`);
  }
  platforms[key] = {
    signature: readFileSync(resolve(sigDir, sigName), "utf8").trim(),
    url: `https://github.com/${repo}/releases/download/${tag}/${assetName}`,
  };
}

const missing = Object.values(PLATFORM_BY_SUFFIX).filter((k) => !platforms[k]);
if (missing.length > 0) {
  throw new Error(
    `缺少平台 ${missing.join(", ")} 的 .sig - 检查对应 build job 是否注入了 TAURI_SIGNING_PRIVATE_KEY,` +
      ` 以及 upload-artifact 的 sig-* 是否齐全`,
  );
}

const manifest = {
  version,
  notes,
  pub_date: new Date().toISOString(),
  platforms,
};

writeFileSync(outFile, JSON.stringify(manifest, null, 2) + "\n");
console.log(`写入 ${outFile}:`);
console.log(JSON.stringify(manifest, null, 2));

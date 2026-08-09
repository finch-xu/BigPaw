#!/usr/bin/env node
// 把版本号同步写进所有存放它的文件，发版第一步。
//
// 用法: node scripts/set-version.mjs 0.2.0
//   或: pnpm -C ui version:set 0.2.0
//
// 为什么需要这个脚本: 版本号在 Cargo.toml（workspace.package，三个成员 crate 都继
// 承它）/ tauri.conf.json / ui/package.json 里各存一份，没有任何构建期注入把它们
// 对齐。二进制与安装包文件名里的真实版本来自 tauri.conf.json，而 release 的版本
// 来自 git tag —— 两者不一致就会发出"文件名声称 0.2.0、装上还是 0.1.0"的安装包。
// .github/workflows/release.yml 的 verify-version job 是第二道防线，会在构建前
// 把 tag 和这几处逐一比对；这个脚本让它不容易被触发。

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const version = process.argv[2];
if (!version) {
  console.error("用法: node scripts/set-version.mjs <X.Y.Z>   例如 0.2.0");
  process.exit(1);
}
// 只收 MAJOR.MINOR.PATCH。release.yml 的 tag 触发是 v*，放进 -beta.1 这类后缀
// 也能跑，但目前没有预发布通道，先不放开。
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`版本号格式非法: ${version} (期望 MAJOR.MINOR.PATCH，如 0.2.0)`);
  process.exit(1);
}

/** 读文件 → 跑一次替换 → 写回。替换没命中就报错退出，绝不静默跳过某个文件。 */
function patch(relPath, pattern, replacement) {
  const path = join(root, relPath);
  const before = readFileSync(path, "utf8");
  const after = before.replace(pattern, replacement);
  if (after === before) {
    console.error(`✗ ${relPath}: 没有匹配到版本号字段或已是 ${version}，请手动检查`);
    process.exit(1);
  }
  writeFileSync(path, after);
  console.log(`✓ ${relPath}`);
}

// 只认行首的 `version = "..."`。根 Cargo.toml 里它只出现在 [workspace.package]，
// 依赖行都以 crate 名开头 (`tokio = { version = ... }`)，行首锚点足够区分。
patch("Cargo.toml", /^version\s*=\s*"[^"]+"/m, `version = "${version}"`);

patch("src-tauri/tauri.conf.json", /("version"\s*:\s*")[^"]+(")/, `$1${version}$2`);

patch("ui/package.json", /("version"\s*:\s*")[^"]+(")/, `$1${version}$2`);

// Cargo.lock 里三个 workspace 成员各有一条。cargo 下次构建时本会自动修，但先改掉
// 能让 CI 的工作区保持干净，也让 `cargo build --locked` 可用。
// `\r?\n` 而不是 `\n`: 仓库没有 .gitattributes 强制换行风格，克隆到 Windows 上的
// 工作区会是 CRLF，届时纯 `\n` 会匹配不上而误报。
for (const crate of ["bigpaw", "bigpaw-core", "bigpaw-ipmsg"]) {
  patch(
    "Cargo.lock",
    new RegExp(`(name = "${crate}"\\r?\\nversion = ")[^"]+(")`),
    `$1${version}$2`,
  );
}

console.log(`\n版本号已同步为 ${version}。接下来:`);
console.log(`  git add -u`);
console.log(`  git commit -m "chore: bump version to ${version}"`);
console.log(`  git tag v${version}`);
console.log(`  git push && git push --tags`);

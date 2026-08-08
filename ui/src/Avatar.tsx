/** 确定性生成头像:fp 哈希取 6 色淡彩底之一,显示昵称首字符。同一联系人永远同色。 */
function hashFp(fp: string): number {
  let h = 0;
  for (let i = 0; i < fp.length; i++) h = (h * 31 + fp.charCodeAt(i)) >>> 0;
  return h;
}

export default function Avatar({ fp, name, size = 36 }: { fp: string; name: string; size?: number }) {
  const idx = (hashFp(fp) % 6) + 1;
  const ch = (name.trim()[0] ?? "?").toUpperCase();
  return (
    <div
      className="flex shrink-0 select-none items-center justify-center rounded-full font-medium"
      style={{
        width: size,
        height: size,
        fontSize: Math.round(size * 0.42),
        background: `var(--avatar-${idx}-bg)`,
        color: `var(--avatar-${idx}-fg)`,
      }}
      aria-hidden
    >
      {ch}
    </div>
  );
}

/** 未选会话的空状态。全应用唯一的猫元素:低对比单色剪影,图形感而非卡通感。 */
export default function EmptyState() {
  return (
    <section className="flex flex-1 flex-col items-center justify-center gap-4">
      <svg width="200" height="120" viewBox="0 0 200 120" fill="none" aria-hidden className="text-border">
        {/* 蜷卧的猫剪影:身体 */}
        <path
          d="M28 96c-8-12-2-34 22-40 18-5 46-5 68 0 24 5 38 18 40 30 1 8-4 12-12 12H40c-6 0-9-1-12-2z"
          fill="currentColor"
        />
        {/* 头 */}
        <circle cx="150" cy="54" r="26" fill="currentColor" />
        {/* 耳朵 */}
        <path d="M132 36l3-17 15 8zM168 36l-3-17-15 8z" fill="currentColor" />
        {/* 尾巴 */}
        <path d="M30 90c-13-2-19-15-9-24" stroke="currentColor" strokeWidth="7" strokeLinecap="round" />
        {/* 闭眼:用背景色描在头上 */}
        <path d="M140 56q4 4 8 0M158 56q4 4 8 0" stroke="var(--background)" strokeWidth="2.5" strokeLinecap="round" />
      </svg>
      <p className="text-sm text-muted-foreground">大脚猫在等对面上线</p>
    </section>
  );
}

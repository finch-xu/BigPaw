/** 主题偏好:纯前端实现,存 localStorage,不进 settings.json。 */
export type ThemePref = "light" | "dark" | "system";

const KEY = "bigpaw-theme";
const media = window.matchMedia("(prefers-color-scheme: dark)");

export function getThemePref(): ThemePref {
  const v = localStorage.getItem(KEY);
  return v === "light" || v === "dark" ? v : "system";
}

function apply(pref: ThemePref): void {
  const dark = pref === "dark" || (pref === "system" && media.matches);
  document.documentElement.classList.toggle("dark", dark);
}

export function setThemePref(pref: ThemePref): void {
  if (pref === "system") localStorage.removeItem(KEY);
  else localStorage.setItem(KEY, pref);
  apply(pref);
}

export function initTheme(): void {
  apply(getThemePref());
  // system 模式下跟随系统切换;显式亮/暗时此回调读到的偏好不变,apply 幂等无害
  media.addEventListener("change", () => apply(getThemePref()));
}

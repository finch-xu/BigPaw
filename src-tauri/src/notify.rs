//! 消息提醒(M8):决策 + 未读状态机 + 托盘红点合成。
//!
//! 本模块刻意把「判断」与「副作用」分开:decide / paint_unread_dot / NotifyState
//! 全是纯逻辑,不碰 AppHandle,因此可以完整单元测试;Notifier 才做真正的
//! 发通知与换图标。GUI 特性通常最难测,这条分界线是本模块可测性的来源。

use bigpaw_core::settings::Settings;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

/// 同一会话两次系统通知之间的最小间隔:对端连发时不刷屏。
pub const NOTIFY_THROTTLE: Duration = Duration::from_secs(5);

/// 一条入站消息的处理结论。响铃与否不单独成态——它完全由
/// `Settings::notify_sound` 决定,且只在 `notify == true` 时才有意义。
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    /// 弹系统通知
    pub notify: bool,
    /// 计入托盘红点
    pub mark_unread: bool,
}

/// decide 的全部输入。窗口焦点、当前时刻等一律由调用方查好传进来,
/// 不在函数内部去查——这是它能被单测的前提。
pub struct DecideInput<'a> {
    pub conv_id: &'a str,
    pub settings: &'a Settings,
    pub window_focused: bool,
    pub active_conv: Option<&'a str>,
    /// 该会话上次弹通知的时刻;None = 从未弹过
    pub last_notify: Option<Instant>,
    pub now: Instant,
}

/// 提醒决策。**顺序不可调整**,每条规则短路返回:
///
/// | # | 条件 | notify | mark_unread |
/// |---|------|--------|-------------|
/// | 1 | 会话已静音 | ✗ | ✗ |
/// | 2 | 窗口聚焦且正是该会话 | ✗ | ✗ |
/// | 3 | 全局通知关闭 | ✗ | ✓ |
/// | 4 | 距上次通知不足 NOTIFY_THROTTLE | ✗ | ✓ |
/// | 5 | 其余 | ✓ | ✓ |
///
/// 规则 2 必须先于规则 3:否则「关了通知 + 用户正看着这个会话」会命中规则 3,
/// 给正在阅读的会话点亮托盘红点。
pub fn decide(i: DecideInput<'_>) -> Decision {
    // 1. 静音会话完全不参与提醒,也不点亮托盘红点(与微信/飞书一致)
    if i.settings.muted_conversations.iter().any(|c| c == i.conv_id) {
        return Decision { notify: false, mark_unread: false };
    }
    // 2. 用户正盯着这个会话看,任何提醒都是噪音
    if i.window_focused && i.active_conv == Some(i.conv_id) {
        return Decision { notify: false, mark_unread: false };
    }
    // 3. 关通知 ≠ 关未读指示
    if !i.settings.notify_enabled {
        return Decision { notify: false, mark_unread: true };
    }
    // 4. 节流窗口内不重复弹,红点照常
    if let Some(last) = i.last_notify {
        if i.now.duration_since(last) < NOTIFY_THROTTLE {
            return Decision { notify: false, mark_unread: true };
        }
    }
    Decision { notify: true, mark_unread: true }
}

/// 在图标右上角画一个带白边的实心红点,返回新的 RGBA 缓冲(长度与入参一致)。
///
/// 白边的作用:菜单栏/任务栏的底色深浅不定,纯红圆点在深色背景上会糊成一团,
/// 一圈 1.5px 的白边能让它在任何底色上都保持可辨认。
pub fn paint_unread_dot(rgba: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut out = rgba.to_vec();
    if width == 0 || height == 0 {
        return out;
    }
    // 缓冲长度来自入参,下标由 width/height 形参推出。两者不一致时原样返回,
    // 绝不能 panic——该函数可能在消息接收路径上被调用。
    if out.len() < width as usize * height as usize * 4 {
        return out;
    }
    let radius = (width.min(height) as f32 * 0.28).max(3.0);
    let cx = width as f32 - radius - 1.0;
    let cy = radius + 1.0;
    for y in 0..height {
        for x in 0..width {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist > radius {
                continue;
            }
            let idx = ((y * width + x) * 4) as usize;
            let (r, g, b) = if dist > radius - 1.5 {
                (255, 255, 255) // 外圈白边
            } else {
                (229, 57, 53) // Material Red 600,与前端 destructive 色接近
            };
            out[idx] = r;
            out[idx + 1] = g;
            out[idx + 2] = b;
            out[idx + 3] = 255;
        }
    }
    out
}

/// 状态机对一次输入的处理结论。
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// 是否要弹系统通知
    pub notify: bool,
    /// 托盘图标是否需要变更:Some(true)=红点版,Some(false)=素面版,None=不动。
    /// 只在未读集合空↔非空的跃迁时刻才是 Some。
    pub tray: Option<bool>,
}

/// 提醒子系统的纯状态机:不持有 AppHandle,不做任何 IO。
pub struct NotifyState {
    active: Option<String>,
    unread: HashSet<String>,
    last_notify: HashMap<String, Instant>,
}

impl NotifyState {
    pub fn new() -> Self {
        Self {
            active: None,
            unread: HashSet::new(),
            last_notify: HashMap::new(),
        }
    }

    /// 未读集合发生变化后,算出托盘要不要换图标。
    fn tray_transition(was_empty: bool, is_empty: bool) -> Option<bool> {
        if was_empty == is_empty {
            None
        } else {
            Some(!is_empty)
        }
    }

    pub fn on_incoming(
        &mut self,
        conv_id: &str,
        settings: &Settings,
        window_focused: bool,
        now: Instant,
    ) -> Outcome {
        let d = decide(DecideInput {
            conv_id,
            settings,
            window_focused,
            active_conv: self.active.as_deref(),
            last_notify: self.last_notify.get(conv_id).copied(),
            now,
        });
        let was_empty = self.unread.is_empty();
        if d.mark_unread {
            self.unread.insert(conv_id.to_string());
        }
        if d.notify {
            self.last_notify.insert(conv_id.to_string(), now);
        }
        Outcome {
            notify: d.notify,
            tray: Self::tray_transition(was_empty, self.unread.is_empty()),
        }
    }

    /// 前端切换会话时上报。Some(id) 顺带把该会话移出未读集合。
    pub fn set_active(&mut self, conv_id: Option<String>) -> Outcome {
        let was_empty = self.unread.is_empty();
        if let Some(id) = &conv_id {
            self.unread.remove(id);
        }
        self.active = conv_id;
        Outcome {
            notify: false,
            tray: Self::tray_transition(was_empty, self.unread.is_empty()),
        }
    }

    /// 窗口获得焦点:此刻用户眼前的就是 active 会话,把它的未读清掉。
    ///
    /// 这是「窗口隐藏期间 active 会话来消息 → 红点亮起」之后唯一的清除边:
    /// 用户回到窗口时该会话本来就是选中的,前端不会再发一次 set_active,
    /// 缺了这条边红点会永久卡红,而会话列表却一个角标都没有(前端因
    /// 会话 == selectedFp 跳过了自增),用户没有任何地方可以消掉它。
    ///
    /// active 为 None(还没打开过任何会话)时什么都不做——**绝不能**退化成
    /// `clear_unread(None)`,那会把其他会话的未读一并抹掉。
    pub fn on_window_focused(&mut self) -> Outcome {
        let Some(active) = self.active.clone() else {
            return Outcome { notify: false, tray: None };
        };
        self.clear_unread(Some(&active))
    }

    /// 清未读:Some(id) = 单个会话,None = 全部。
    pub fn clear_unread(&mut self, conv_id: Option<&str>) -> Outcome {
        let was_empty = self.unread.is_empty();
        match conv_id {
            Some(id) => {
                self.unread.remove(id);
            }
            None => self.unread.clear(),
        }
        Outcome {
            notify: false,
            tray: Self::tray_transition(was_empty, self.unread.is_empty()),
        }
    }
}

impl Default for NotifyState {
    fn default() -> Self {
        Self::new()
    }
}

/// 通知正文的最大字符数。按字符而非字节截断,避免切断多字节 UTF-8 序列。
const PREVIEW_MAX_CHARS: usize = 100;

/// 提示音音名。插件的 `sound` 是「显式指定音源」而非开关:
/// macOS / Linux 不设置即静音;Windows 的默认 toast 自带声音,故不设置。
fn sound_name() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some("Ping")
    }
    #[cfg(target_os = "linux")]
    {
        Some("message-new-instant")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// 提醒子系统的副作用层:把 NotifyState 的结论落到系统通知与托盘图标上。
/// Clone 出来的实例共享同一份状态(Arc),供事件泵线程与命令各持一份。
#[derive(Clone)]
pub struct Notifier(Arc<Inner>);

struct Inner {
    app: AppHandle,
    tray_normal: Image<'static>,
    tray_unread: Image<'static>,
    /// 设置缓存:避免每条消息都去读一次 settings.json。
    /// 唯一的一致性纪律点——set_settings / set_conversation_muted 落盘后必须
    /// 调 reload_settings 刷新它。
    settings: RwLock<Settings>,
    state: Mutex<NotifyState>,
}

impl Notifier {
    pub fn new(app: &AppHandle, settings: Settings) -> Self {
        let icon = app
            .default_window_icon()
            .expect("tauri.conf.json 的 bundle.icon 保证窗口图标必然存在");
        let (w, h) = (icon.width(), icon.height());
        // 先在借用态取 rgba 作画,再把素面版转成 'static 存起来:
        // Image::rgba(&'a self) 要求 &'a Image<'a>,对 Image<'static> 反而调不动。
        let unread_rgba = paint_unread_dot(icon.rgba(), w, h);
        Self(Arc::new(Inner {
            app: app.clone(),
            tray_normal: icon.clone().to_owned(),
            tray_unread: Image::new_owned(unread_rgba, w, h),
            settings: RwLock::new(settings),
            state: Mutex::new(NotifyState::new()),
        }))
    }

    pub fn reload_settings(&self, s: &Settings) {
        if let Ok(mut g) = self.0.settings.write() {
            *g = s.clone();
        }
    }

    /// 窗口是否真的在用户眼前:可见且聚焦才算。
    fn window_focused(&self) -> bool {
        self.0
            .app
            .get_webview_window("main")
            .map(|w| w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false))
            .unwrap_or(false)
    }

    fn apply_tray(&self, unread: Option<bool>) {
        let Some(unread) = unread else { return };
        let Some(tray) = self.0.app.tray_by_id("main") else { return };
        let icon = if unread {
            self.0.tray_unread.clone()
        } else {
            self.0.tray_normal.clone()
        };
        let _ = tray.set_icon(Some(icon));
    }

    /// 一条入站消息/文件到达。`preview` 是带内容的正文,`fallback` 是
    /// 关闭「显示消息内容」后使用的替代文案。
    pub fn on_incoming(&self, conv_id: &str, title: String, preview: String, fallback: &str) {
        // 内层块:克隆完立刻释放读锁,不让它横跨下面的窗口查询/托盘/通知 IO——
        // 否则 Task 6 的 set_settings → reload_settings(需要 .write())会被
        // 一次正在发送的通知卡住。
        let settings = {
            let Ok(g) = self.0.settings.read() else { return };
            g.clone()
        };
        let focused = self.window_focused();
        let outcome = {
            let Ok(mut st) = self.0.state.lock() else { return };
            st.on_incoming(conv_id, &settings, focused, Instant::now())
        };
        self.apply_tray(outcome.tray);
        if !outcome.notify {
            return;
        }
        let body = if settings.notify_show_preview {
            preview.chars().take(PREVIEW_MAX_CHARS).collect::<String>()
        } else {
            fallback.to_string()
        };
        let mut builder = self.0.app.notification().builder().title(title).body(body);
        if settings.notify_sound {
            if let Some(s) = sound_name() {
                builder = builder.sound(s);
            }
        }
        // 通知失败(Linux 无 notify daemon、macOS 未授权等)一律吞掉:
        // 提醒不能拖累消息接收链路。
        let _ = builder.show();
    }

    pub fn set_active(&self, conv_id: Option<String>) {
        let outcome = {
            let Ok(mut st) = self.0.state.lock() else { return };
            st.set_active(conv_id)
        };
        self.apply_tray(outcome.tray);
    }

    pub fn clear_unread(&self, conv_id: Option<&str>) {
        let outcome = {
            let Ok(mut st) = self.0.state.lock() else { return };
            st.clear_unread(conv_id)
        };
        self.apply_tray(outcome.tray);
    }

    /// 窗口获得焦点:由 lib.rs 的 `WindowEvent::Focused(true)` 驱动。
    /// 焦点只在 Rust 侧消费,前端不再上报一遍(设计 §11 的约束是「前端不额外
    /// 上报焦点」,不是「Rust 侧不响应焦点事件」)。
    pub fn on_window_focused(&self) {
        // 与其他入口同一纪律:锁在内层块里用完即放,不跨 apply_tray 的主线程往返。
        let outcome = {
            let Ok(mut st) = self.0.state.lock() else { return };
            st.on_window_focused()
        };
        self.apply_tray(outcome.tray);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings::default()
    }

    /// 构造一个「窗口隐藏、从未弹过通知」的基线输入。
    fn input<'a>(conv_id: &'a str, s: &'a Settings, now: Instant) -> DecideInput<'a> {
        DecideInput {
            conv_id,
            settings: s,
            window_focused: false,
            active_conv: None,
            last_notify: None,
            now,
        }
    }

    #[test]
    fn muted_conversation_is_fully_silent() {
        let mut s = settings();
        s.muted_conversations = vec!["abc".to_string()];
        let d = decide(input("abc", &s, Instant::now()));
        assert_eq!(d, Decision { notify: false, mark_unread: false });
    }

    #[test]
    fn mute_wins_over_global_switch_off() {
        // 顺序回归测试:规则 1(静音)必须先于规则 3(全局关闭)判定。
        // 把静音判断挪到规则 3 之后,这里会先命中规则 3 返回 mark_unread = true,
        // 给一个已静音的会话点亮托盘红点——违反规则 1「静音会话不参与全局红点」。
        // 断言的关键是 mark_unread == false,而不是 notify == false(后者两种
        // 顺序下都成立,验不出优先级)。
        let mut s = settings();
        s.muted_conversations = vec!["abc".to_string()];
        s.notify_enabled = false;
        assert_eq!(
            decide(input("abc", &s, Instant::now())),
            Decision { notify: false, mark_unread: false }
        );
    }

    #[test]
    fn mute_wins_over_throttle() {
        // 顺序回归测试:规则 1(静音)必须先于规则 4(节流)判定。
        // 若静音排在节流之后,节流分支会先返回 mark_unread = true,同样点亮红点。
        let mut s = settings();
        s.muted_conversations = vec!["abc".to_string()];
        let last = Instant::now();
        let mut i = input("abc", &s, last + Duration::from_secs(1));
        i.last_notify = Some(last);
        assert_eq!(decide(i), Decision { notify: false, mark_unread: false });
    }

    #[test]
    fn watching_this_conversation_suppresses_everything() {
        let s = settings();
        let now = Instant::now();
        let mut i = input("abc", &s, now);
        i.window_focused = true;
        i.active_conv = Some("abc");
        assert_eq!(decide(i), Decision { notify: false, mark_unread: false });
    }

    #[test]
    fn watching_wins_over_global_switch_off() {
        // 顺序回归测试:若「全局关闭」先于「正在看」判定,这里会错误地返回
        // mark_unread = true,给用户正在阅读的会话点亮托盘红点。
        let mut s = settings();
        s.notify_enabled = false;
        let now = Instant::now();
        let mut i = input("abc", &s, now);
        i.window_focused = true;
        i.active_conv = Some("abc");
        assert_eq!(decide(i), Decision { notify: false, mark_unread: false });
    }

    #[test]
    fn global_switch_off_still_marks_unread() {
        let mut s = settings();
        s.notify_enabled = false;
        assert_eq!(
            decide(input("abc", &s, Instant::now())),
            Decision { notify: false, mark_unread: true }
        );
    }

    #[test]
    fn focused_but_other_conversation_still_notifies() {
        // 本项目的选择:前台看着别的会话时仍然弹通知(与飞书/Slack 不同)
        let s = settings();
        let now = Instant::now();
        let mut i = input("abc", &s, now);
        i.window_focused = true;
        i.active_conv = Some("xyz");
        assert_eq!(decide(i), Decision { notify: true, mark_unread: true });
    }

    #[test]
    fn hidden_window_notifies_even_for_active_conversation() {
        // 窗口隐藏时 active_conv 是上次打开的会话,但用户看不见 → 必须提醒
        let s = settings();
        let now = Instant::now();
        let mut i = input("abc", &s, now);
        i.window_focused = false;
        i.active_conv = Some("abc");
        assert_eq!(decide(i), Decision { notify: true, mark_unread: true });
    }

    #[test]
    fn throttled_within_window_marks_unread_only() {
        let s = settings();
        let last = Instant::now();
        let now = last + Duration::from_secs(1);
        let mut i = input("abc", &s, now);
        i.last_notify = Some(last);
        assert_eq!(decide(i), Decision { notify: false, mark_unread: true });
    }

    #[test]
    fn notifies_again_after_throttle_window() {
        let s = settings();
        let last = Instant::now();
        let now = last + NOTIFY_THROTTLE + Duration::from_millis(1);
        let mut i = input("abc", &s, now);
        i.last_notify = Some(last);
        assert_eq!(decide(i), Decision { notify: true, mark_unread: true });
    }

    /// 构造一张全透明的测试图,便于断言「只有红点区域被改动」。
    fn blank(w: u32, h: u32) -> Vec<u8> {
        vec![0u8; (w * h * 4) as usize]
    }

    fn px(buf: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * w + x) * 4) as usize;
        [buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]
    }

    #[test]
    fn dot_preserves_buffer_size() {
        let out = paint_unread_dot(&blank(32, 32), 32, 32);
        assert_eq!(out.len(), 32 * 32 * 4);
    }

    #[test]
    fn dot_paints_top_right_corner_red() {
        let out = paint_unread_dot(&blank(32, 32), 32, 32);
        // 红点圆心在右上角:半径 ≈ 32*0.28 ≈ 9,圆心 ≈ (32-9-1, 9+1) = (22, 10)
        let [r, g, b, a] = px(&out, 32, 22, 10);
        assert_eq!(a, 255, "红点必须不透明");
        assert!(r > 180 && g < 100 && b < 100, "圆心应为红色,实际 {r},{g},{b}");
    }

    #[test]
    fn dot_leaves_bottom_left_untouched() {
        let out = paint_unread_dot(&blank(32, 32), 32, 32);
        assert_eq!(px(&out, 32, 2, 29), [0, 0, 0, 0], "左下角不该被改动");
    }

    #[test]
    fn dot_returns_original_when_buffer_too_short() {
        let tiny = vec![1u8, 2, 3, 4];
        let out = paint_unread_dot(&tiny, 32, 32);
        assert_eq!(out, tiny, "缓冲长度不足时应原样返回");
    }

    #[test]
    fn first_unread_turns_tray_on() {
        let s = settings();
        let mut st = NotifyState::new();
        let o = st.on_incoming("a", &s, false, Instant::now());
        assert!(o.notify);
        assert_eq!(o.tray, Some(true), "首条未读应点亮托盘");
    }

    #[test]
    fn second_unread_does_not_touch_tray_again() {
        let s = settings();
        let mut st = NotifyState::new();
        let t = Instant::now();
        st.on_incoming("a", &s, false, t);
        let o = st.on_incoming("b", &s, false, t);
        assert_eq!(o.tray, None, "已是红点态,不该重复调系统 API");
    }

    #[test]
    fn opening_the_conversation_clears_its_unread() {
        let s = settings();
        let mut st = NotifyState::new();
        st.on_incoming("a", &s, false, Instant::now());
        let o = st.set_active(Some("a".to_string()));
        assert_eq!(o.tray, Some(false), "唯一的未读被清掉,托盘应熄灭");
    }

    #[test]
    fn throttle_is_per_conversation() {
        // 会话 a 刚弹过,会话 b 立刻来消息仍应弹——节流不能跨会话串味
        let s = settings();
        let mut st = NotifyState::new();
        let t = Instant::now();
        st.on_incoming("a", &s, false, t);
        let o = st.on_incoming("b", &s, false, t);
        assert!(o.notify, "不同会话不共享节流窗口");
        let again = st.on_incoming("a", &s, false, t + Duration::from_secs(1));
        assert!(!again.notify, "同会话 1 秒内不重复弹");
    }

    #[test]
    fn clear_unread_all_turns_tray_off() {
        let s = settings();
        let mut st = NotifyState::new();
        let t = Instant::now();
        st.on_incoming("a", &s, false, t);
        st.on_incoming("b", &s, false, t);
        let o = st.clear_unread(None);
        assert_eq!(o.tray, Some(false));
    }

    #[test]
    fn state_feeds_active_conversation_into_decide() {
        // 连线回归测试:on_incoming 必须把 self.active 喂给 decide。
        // 若那里退化成 active_conv: None,规则 2 永远不触发,本例会弹通知并点红点。
        let s = settings();
        let mut st = NotifyState::new();
        st.set_active(Some("a".to_string()));
        let o = st.on_incoming("a", &s, true, Instant::now());
        assert!(!o.notify, "窗口聚焦且正是 active 会话 → 不该弹通知");
        assert_eq!(o.tray, None, "同上,也不该点亮托盘红点");
    }

    #[test]
    fn window_focus_clears_active_conversation_unread() {
        // 主场景回归:窗口隐藏期间 active 会话来消息 → 红点亮;用户切回窗口
        // (该会话本来就是选中的,前端不会再发 set_active)→ 红点必须熄灭。
        let s = settings();
        let mut st = NotifyState::new();
        st.set_active(Some("a".to_string()));
        let o = st.on_incoming("a", &s, false, Instant::now());
        assert_eq!(o.tray, Some(true), "窗口不可见 → 该点亮红点");
        let o = st.on_window_focused();
        assert!(st.unread.is_empty(), "active 会话的未读应被清空");
        assert_eq!(o.tray, Some(false), "唯一的未读被清掉 → 托盘熄灭");
    }

    #[test]
    fn window_focus_keeps_other_conversations_unread() {
        // 只清 active 自己那一个:别的会话仍未读,托盘继续亮红。
        let s = settings();
        let mut st = NotifyState::new();
        st.set_active(Some("a".to_string()));
        let t = Instant::now();
        st.on_incoming("a", &s, false, t);
        st.on_incoming("b", &s, false, t);
        let o = st.on_window_focused();
        assert_eq!(o.tray, None, "b 仍未读,托盘保持红点");
        assert!(!st.unread.contains("a"));
        assert!(st.unread.contains("b"));
    }

    #[test]
    fn window_focus_without_active_keeps_all_unread() {
        // active 为 None 时必须什么都不做:一旦退化成 clear_unread(None),
        // 用户只是切回窗口就会把所有会话的未读一起抹掉。
        let s = settings();
        let mut st = NotifyState::new();
        st.on_incoming("a", &s, false, Instant::now());
        let o = st.on_window_focused();
        assert_eq!(o.tray, None);
        assert!(st.unread.contains("a"), "尚未打开任何会话时不该清未读");
    }

    #[test]
    fn muted_conversation_never_lights_the_tray() {
        let mut s = settings();
        s.muted_conversations = vec!["a".to_string()];
        let mut st = NotifyState::new();
        let o = st.on_incoming("a", &s, false, Instant::now());
        assert!(!o.notify);
        assert_eq!(o.tray, None, "静音会话不点亮托盘");
    }
}

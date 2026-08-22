//! 消息提醒(M8):决策 + 未读状态机 + 托盘红点合成。
//!
//! 本模块刻意把「判断」与「副作用」分开:decide / paint_unread_dot / NotifyState
//! 全是纯逻辑,不碰 AppHandle,因此可以完整单元测试;Notifier 才做真正的
//! 发通知与换图标。GUI 特性通常最难测,这条分界线是本模块可测性的来源。

use bigpaw_core::settings::Settings;
use std::time::{Duration, Instant};

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
    fn mute_wins_over_everything_else() {
        // 静音 + 窗口隐藏 + 通知全局开启 → 仍然什么都不做,连红点都不点
        let mut s = settings();
        s.muted_conversations = vec!["abc".to_string()];
        let mut i = input("abc", &s, Instant::now());
        i.window_focused = false;
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
}

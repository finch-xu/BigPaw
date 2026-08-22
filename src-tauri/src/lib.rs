mod notify;

use bigpaw_core::core::{Core, CoreConfig};
use bigpaw_core::roster::Peer;
use bigpaw_core::net_scope::NetScope;
use bigpaw_core::settings::{self, Settings};
use bigpaw_core::transport::manager::TransportEvent;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};

fn data_dir(app: &AppHandle) -> PathBuf {
    app.path().app_data_dir().expect("app_data_dir 必然可解析")
}

/// 从托盘/Dock 恢复主窗口:显示、聚焦,并在 macOS 上切回 Regular 让 Dock 图标回来。
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        #[cfg(target_os = "macos")]
        {
            let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
            reapply_dock_icon();
        }
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// 会话标题:群聊取群名,单聊取对端昵称;都查不到时回退 id 前 8 位
/// ——与前端 ConversationList 的 `fp.slice(0, 8)` 行为保持一致。
fn conv_title(app: &AppHandle, conv_id: &str) -> String {
    let Some(core) = app.try_state::<AppCore>() else {
        return conv_id.chars().take(8).collect();
    };
    if let Some(g) = core.0.list_groups().into_iter().find(|g| g.group_id == conv_id) {
        return g.name;
    }
    core.0
        .roster_snapshot()
        .into_iter()
        .find(|p| p.fingerprint == conv_id)
        .map(|p| p.nickname)
        .unwrap_or_else(|| conv_id.chars().take(8).collect())
}

/// 群成员昵称反查:优先用群成员表里记录的昵称,退回 roster,再退回指纹前 8 位。
fn member_nick(app: &AppHandle, group_id: &str, sender_fp: &str) -> String {
    let Some(core) = app.try_state::<AppCore>() else {
        return sender_fp.chars().take(8).collect();
    };
    if let Some(g) = core.0.list_groups().into_iter().find(|g| g.group_id == group_id) {
        if let Some(m) = g.members.into_iter().find(|m| m.fp == sender_fp) {
            return m.nick;
        }
    }
    core.0
        .roster_snapshot()
        .into_iter()
        .find(|p| p.fingerprint == sender_fp)
        .map(|p| p.nickname)
        .unwrap_or_else(|| sender_fp.chars().take(8).collect())
}

/// dev 裸二进制(`cargo tauri dev`)没有 .app bundle 图标:Tauri 只在启动
/// Ready 时运行时设置一次 Dock 图标,而 Accessory→Regular 重新入 Dock 后
/// 该图标丢失,macOS 回退为通用可执行文件("控制台")图标。切回 Regular 后
/// 重设一次即可;打包后的 .app 图标来自 bundle,重设的是同一张图,无害。
#[cfg(target_os = "macos")]
fn reapply_dock_icon() {
    use objc2::{AllocAnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    // 256px(128@2x)恰好是 Dock 的最大显示规格,再大只是浪费内存。
    const ICON_PNG: &[u8] = include_bytes!("../icons/128x128@2x.png");
    let Some(mtm) = MainThreadMarker::new() else {
        return; // AppKit 只能主线程碰;调用点都在主线程事件回调里,这是保险
    };
    let ns_app = NSApplication::sharedApplication(mtm);
    let data = NSData::with_bytes(ICON_PNG);
    if let Some(icon) = NSImage::initWithData(NSImage::alloc(), &data) {
        unsafe { ns_app.setApplicationIconImage(Some(&icon)) };
    }
}

struct AppCore(Core);

#[derive(Serialize)]
struct SelfInfo {
    nickname: String,
    fingerprint: String,
}

/// IPC 连通性验证:前端 → Tauri 壳 → bigpaw-core 链路贯通的证明。
#[tauri::command]
fn ping() -> String {
    format!("pong v{}", bigpaw_core::PROTOCOL_VERSION)
}

#[tauri::command]
fn get_self_info(core: State<'_, AppCore>) -> SelfInfo {
    SelfInfo {
        nickname: core.0.nickname(),
        fingerprint: core.0.fingerprint().to_string(),
    }
}

#[tauri::command]
fn get_roster(core: State<'_, AppCore>) -> Vec<Peer> {
    core.0.roster_snapshot()
}

#[derive(Serialize)]
struct IpmsgStatusDto {
    available: bool,
    /// 设置里的开关值:false 时前端不显示"端口被占用"(是用户自己关的)。
    enabled: bool,
}

/// IPMsg 兼容层状态(M5):2425 端口被占用(常见于本机在跑飞秋)时
/// `available=false`,原生栈不受影响,前端据此提示"旧协议兼容层未启用"。
#[tauri::command]
fn ipmsg_status(app: AppHandle, core: State<'_, AppCore>) -> IpmsgStatusDto {
    IpmsgStatusDto {
        available: core.0.ipmsg_available(),
        enabled: settings::load(&data_dir(&app)).ipmsg_enabled,
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MessageDto {
    /// 会话 id:单聊=对端指纹,群聊(M7c)=group_id。
    peer_fp: String,
    id: String,
    body: String,
    ts_ms: u64,
    /// 群消息发送者指纹(M7c);单聊为 None。
    sender_fp: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SentDto {
    id: String,
    ts_ms: u64,
}

#[tauri::command]
fn send_text(
    core: State<'_, AppCore>,
    fingerprint: String,
    body: String,
) -> Result<SentDto, String> {
    core.0
        .send_text(&fingerprint, &body)
        .map(|s| SentDto {
            id: s.id,
            ts_ms: s.ts_ms,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn offer_file(
    core: State<'_, AppCore>,
    fingerprint: String,
    path: String,
) -> Result<String, String> {
    core.0
        .offer_file(&fingerprint, Path::new(&path))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn respond_file(
    core: State<'_, AppCore>,
    xfer_id: String,
    accept: bool,
    download_dir: String,
) -> Result<(), String> {
    core.0
        .respond_file(&xfer_id, accept, Path::new(&download_dir))
        .map_err(|e| e.to_string())
}

/// 默认下载目录:设置里配过就用设置值;否则系统下载目录,再退主目录。
#[tauri::command]
fn default_download_dir(app: AppHandle) -> String {
    if let Some(dir) = settings::load(&data_dir(&app)).download_dir {
        return dir;
    }
    app.path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[tauri::command]
fn get_history(
    core: State<'_, AppCore>,
    fingerprint: String,
    before_ts_ms: Option<i64>,
    before_id: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<bigpaw_core::storage::HistoryItem>, String> {
    // before_id 单独 Some 而 before_ts_ms 为 None 时忽略(游标要么整体缺席取
    // 最新页,要么两段都给);组装成 storage::history 要的复合游标。
    let before = before_ts_ms.map(|t| (t, before_id.unwrap_or_default()));
    core.0
        .storage()
        .history(
            &fingerprint,
            before.as_ref().map(|(t, id)| (*t, id.as_str())),
            limit.unwrap_or(50),
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_history_around(
    core: State<'_, AppCore>,
    fingerprint: String,
    ts_ms: i64,
) -> Result<Vec<bigpaw_core::storage::HistoryItem>, String> {
    core.0
        .storage()
        .history_around(&fingerprint, ts_ms, 25)
        .map_err(|e| e.to_string())
}

// ---- 群聊命令(M7c) ----

#[tauri::command]
fn list_groups(core: State<'_, AppCore>) -> Vec<bigpaw_core::groups::Group> {
    core.0.list_groups()
}

#[tauri::command]
fn create_group(
    core: State<'_, AppCore>,
    name: String,
    member_fps: Vec<String>,
) -> Result<bigpaw_core::groups::Group, String> {
    core.0
        .create_group(&name, &member_fps)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_group_members(
    core: State<'_, AppCore>,
    group_id: String,
    member_fps: Vec<String>,
) -> Result<bigpaw_core::groups::Group, String> {
    core.0
        .update_group_members(&group_id, &member_fps)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn leave_group(core: State<'_, AppCore>, group_id: String) -> Result<(), String> {
    core.0.leave_group(&group_id).map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupSentDto {
    id: String,
    ts_ms: u64,
}

#[tauri::command]
fn send_group_text(
    core: State<'_, AppCore>,
    group_id: String,
    body: String,
) -> Result<GroupSentDto, String> {
    core.0
        .send_group_text(&group_id, &body)
        .map(|s| GroupSentDto {
            id: s.id,
            ts_ms: s.ts_ms,
        })
        .map_err(|e| e.to_string())
}

/// 消息视图数据源(M7b):每会话最后一条记录,按时间倒序。
#[tauri::command]
fn list_conversations(
    core: State<'_, AppCore>,
) -> Result<Vec<bigpaw_core::storage::ConvSummary>, String> {
    core.0
        .storage()
        .conversation_summaries()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn search_history(
    core: State<'_, AppCore>,
    query: String,
) -> Result<Vec<bigpaw_core::storage::SearchHit>, String> {
    core.0.storage().search(&query, 100).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_history(
    core: State<'_, AppCore>,
    fingerprint: Option<String>,
) -> Result<(), String> {
    core.0
        .storage()
        .clear_history(fingerprint.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_settings(app: AppHandle) -> Settings {
    settings::load(&data_dir(&app))
}

#[tauri::command]
fn set_settings(app: AppHandle, core: State<'_, AppCore>, value: Settings) -> Result<(), String> {
    // 顺序不可反:必须先落盘成功,再让 Core 热生效——落盘失败时不能让运行中的
    // announce/transport/ipmsg/mdns 用上一份还未持久化的设置,否则重启后状态
    // 又会回退,造成"热生效了但重启就丢"的不一致。
    // 网络范围限定:落盘前做权威校验(与 Core::apply_settings 用同一个解析器),
    // 错误文本(含行号)直接回前端展示;坏配置绝不落盘。
    NetScope::parse(&value.allowed_networks).map_err(|e| e.to_string())?;
    settings::save(&data_dir(&app), &value).map_err(|e| e.to_string())?;
    core.0.apply_settings(&value);
    // 设置缓存必须跟着落盘一起更新,否则通知开关改了要等重启才生效
    if let Some(n) = app.try_state::<notify::Notifier>() {
        n.reload_settings(&value);
    }
    Ok(())
}

/// 前端切换会话时上报当前会话(M8)。顺带把该会话移出未读集合。
#[tauri::command]
fn notify_set_active(notifier: State<'_, notify::Notifier>, conv_id: Option<String>) {
    notifier.set_active(conv_id);
}

/// 清未读(M8):None = 全部。供前端 clearConversation / clearAll 调用,
/// 保证托盘红点与会话列表数字不分叉。
#[tauri::command]
fn notify_clear_unread(notifier: State<'_, notify::Notifier>, conv_id: Option<String>) {
    notifier.clear_unread(conv_id.as_deref());
}

/// 会话静音开关(M8):落盘后立刻刷新 Notifier 的设置缓存。
#[tauri::command]
fn set_conversation_muted(
    app: AppHandle,
    notifier: State<'_, notify::Notifier>,
    conv_id: String,
    muted: bool,
) -> Result<(), String> {
    let mut s = settings::load(&data_dir(&app));
    s.muted_conversations.retain(|c| c != &conv_id);
    if muted {
        s.muted_conversations.push(conv_id.clone());
    }
    settings::save(&data_dir(&app), &s).map_err(|e| e.to_string())?;
    notifier.reload_settings(&s);
    // 规则 1「静音会话不参与全局红点」是个状态断言,不只是对后续消息的过滤:
    // 刚被静音的会话可能还挂在未读集合里,不摘掉的话托盘会继续为一个
    // 已经不该提醒的会话亮红。
    if muted {
        notifier.clear_unread(Some(&conv_id));
    }
    Ok(())
}

/// 校验允许网段清单(每项单 IP / CIDR / 起-止区间),成功返回归一化文本
/// (CIDR 主机位归零后的形式),失败返回带行号的中文错误。前端实时校验用它,
/// 保证 TS 侧不用复制一份解析规则。
#[tauri::command]
fn validate_allowed_networks(lines: Vec<String>) -> Result<Vec<String>, String> {
    NetScope::parse(&lines)
        .map(|scope| scope.entries().iter().map(|e| e.canonical()).collect())
        .map_err(|e| e.to_string())
}

/// 网卡视图 DTO:字段与 `bigpaw_core::net_ifaces::IfaceView` 一一对应,camelCase
/// 序列化供前端设置页展示网卡列表(名称/IP/子网掩码/是否疑似虚拟网卡/是否已排除)。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IfaceDto {
    name: String,
    ip: String,
    netmask: String,
    is_virtual: bool,
    excluded: bool,
}

/// 列出全部网卡(不滤排除项),供设置页渲染网卡选择列表。
#[tauri::command]
fn list_network_interfaces(core: State<'_, AppCore>) -> Vec<IfaceDto> {
    core.0
        .list_interfaces()
        .into_iter()
        .map(|v| IfaceDto {
            name: v.name,
            ip: v.ip.to_string(),
            netmask: v.netmask.to_string(),
            is_virtual: v.is_virtual_hint,
            excluded: v.excluded,
        })
        .collect()
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FileOfferedDto {
    xfer_id: String,
    peer_fp: String,
    name: String,
    size: u64,
    /// 是否为文件夹报价(M5):原生传输恒为 `false`;ipmsg 对端发来的
    /// `IpmsgFileEntry::is_dir` 如实透传,前端据此展示"文件夹" offer,
    /// 接受时仍走同一个 `respond_file` 命令(Core 内部按 is_dir 路由)。
    is_dir: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FileProgressDto {
    xfer_id: String,
    done: u64,
    total: u64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FileDoneDto {
    xfer_id: String,
    path: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct FileFailedDto {
    xfer_id: String,
    reason: String,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        // 自动更新:前端用 @tauri-apps/plugin-updater 的 check()/downloadAndInstall(),
        // 端点与公钥在 tauri.conf.json plugins.updater;process 供安装后 relaunch;
        // opener 给不能原地升级的 deb 用户打开 Release 页面。
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let _ = window.hide();
                // macOS:关窗即切成 Accessory(菜单栏应用),Dock 图标消失
                #[cfg(target_os = "macos")]
                let _ = window
                    .app_handle()
                    .set_activation_policy(tauri::ActivationPolicy::Accessory);
                api.prevent_close(); // 阻止真正关闭 → 应用继续后台运行
            }
            // 窗口获得焦点(M8):用户此刻看到的就是 active 会话,清掉它的未读。
            // 少了这条边,「隐藏窗口 → active 会话来消息 → 点回窗口读完」之后
            // 托盘红点会永久卡住:该会话本来就是选中的,前端不会再发 set_active。
            // 必须走窗口事件而不是只在 show_main_window 里做——否则 alt-tab、
            // 直接点击窗口这些不经过托盘/Dock 的获得焦点方式全都漏掉。
            tauri::WindowEvent::Focused(true) if window.label() == "main" => {
                if let Some(n) = window.app_handle().try_state::<notify::Notifier>() {
                    n.on_window_focused();
                }
            }
            _ => {}
        })
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let core = Core::start(CoreConfig {
                data_dir,
                nickname: None,
            })?;

            // 提醒子系统(M8):必须在事件泵线程之前建好,线程要 clone 一份进去。
            // 注意:上面的局部变量 data_dir 已经把文件顶部同名的 data_dir() 辅助
            // 函数遮蔽掉了(且其值已 move 进 CoreConfig),这里直接重新问一次
            // app.path().app_data_dir() 取路径,不能指望调用那个函数。
            let notifier = notify::Notifier::new(
                app.handle(),
                settings::load(&app.path().app_data_dir()?),
            );

            // 系统托盘 / macOS 菜单栏:关窗后应用常驻此处,并提供唯一的"退出"入口。
            //
            // **必须建在任何会往 Notifier 里灌事件的线程之前**:apply_tray 在
            // tray_by_id("main") 取不到托盘时直接 return,若有消息落在「事件泵
            // 已在跑、托盘还没 build」的窗口里,未读会被记上但「空→非空」这条
            // 跃迁被丢弃;此后集合恒为非空,tray_transition 永远返回 None,
            // 图标余生都不会再变红。
            // 提前建没有代价:托盘只依赖 app 与 default_window_icon,不依赖
            // core / notifier 的 manage,菜单事件也都是运行时才回调。
            let show_i = MenuItem::with_id(app, "show", "显示 BigPaw", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_i = MenuItem::with_id(app, "quit", "退出 BigPaw", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &sep, &quit_i])?;

            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false) // 左键=显示窗口,右键=弹菜单(桌面 IM 常见范式)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0), // 真正退出:触发 ExitRequested → core.shutdown()
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            let mut rx = core.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while rx.changed().await.is_ok() {
                    let snapshot = rx.borrow_and_update().clone();
                    let _ = handle.emit("roster://updated", &snapshot);
                    // 节流:两次推送至少间隔 200ms(设计文档 §2 铁律)
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            });

            if let Some(events_rx) = core.take_events() {
                let handle = app.handle().clone();
                let notifier_ev = notifier.clone();
                std::thread::spawn(move || {
                    while let Ok(ev) = events_rx.recv() {
                        match ev {
                            TransportEvent::Message(ev) => {
                                let conv_id = ev.peer_fp.clone();
                                let title = conv_title(&handle, &conv_id);
                                let preview = match &ev.sender_fp {
                                    // 群消息:正文前缀发送者昵称
                                    Some(sfp) => format!("{}: {}", member_nick(&handle, &conv_id, sfp), ev.body),
                                    None => ev.body.clone(),
                                };
                                let fallback = if ev.sender_fp.is_some() {
                                    "群里有新消息"
                                } else {
                                    "发来一条新消息"
                                };
                                let _ = handle.emit(
                                    "message://received",
                                    MessageDto {
                                        peer_fp: ev.peer_fp,
                                        id: ev.id,
                                        body: ev.body,
                                        ts_ms: ev.ts_ms,
                                        sender_fp: ev.sender_fp,
                                    },
                                );
                                // 提醒一律排在 emit 之后:设计文档的头号铁律是
                                // 「提醒失败绝不影响消息接收链路」,所以提醒路径上
                                // 任何耗时或故障都不该挡在前端拿到消息之前。这条顺序
                                // 与通知插件当下是同步还是异步实现无关——它守的是
                                // 铁律本身,插件换实现、或提醒路径 panic 时同样成立。
                                notifier_ev.on_incoming(&conv_id, title, preview, fallback);
                            }
                            TransportEvent::FileOffered {
                                xfer_id,
                                peer_fp,
                                name,
                                size,
                                is_dir,
                            } => {
                                // peer_fp 马上要被 emit 的 FileOfferedDto 移走,提醒要用的
                                // 会话 id 得先克隆一份(与 Message 分支的 conv_id 同一思路)。
                                let conv_id = peer_fp.clone();
                                let title = conv_title(&handle, &conv_id);
                                let preview = if is_dir {
                                    format!("发来文件夹:{name}")
                                } else {
                                    format!("发来文件:{name}")
                                };
                                let _ = handle.emit(
                                    "file://offered",
                                    FileOfferedDto {
                                        xfer_id,
                                        peer_fp,
                                        name,
                                        size,
                                        is_dir,
                                    },
                                );
                                // 提醒一律排在 emit 之后:设计文档的头号铁律是
                                // 「提醒失败绝不影响消息接收链路」,所以提醒路径上
                                // 任何耗时或故障都不该挡在前端拿到消息之前。这条顺序
                                // 与通知插件当下是同步还是异步实现无关——它守的是
                                // 铁律本身,插件换实现、或提醒路径 panic 时同样成立。
                                notifier_ev.on_incoming(&conv_id, title, preview, "发来一个文件");
                            }
                            TransportEvent::FileProgress {
                                xfer_id,
                                done,
                                total,
                            } => {
                                // 不在壳层节流:bigpaw-core 已按 150ms 做过节流(见
                                // manager.rs PROGRESS_THROTTLE),这里必须立即转发。
                                let _ = handle.emit(
                                    "file://progress",
                                    FileProgressDto {
                                        xfer_id,
                                        done,
                                        total,
                                    },
                                );
                            }
                            TransportEvent::FileDone { xfer_id, path } => {
                                let _ = handle.emit(
                                    "file://done",
                                    FileDoneDto {
                                        xfer_id,
                                        path: path.to_string_lossy().into_owned(),
                                    },
                                );
                            }
                            TransportEvent::FileFailed { xfer_id, reason } => {
                                let _ =
                                    handle.emit("file://failed", FileFailedDto { xfer_id, reason });
                            }
                            // 群列表变化(M7c):全量列表直接转发,前端整体替换。
                            TransportEvent::GroupsChanged(list) => {
                                let _ = handle.emit("group://updated", &list);
                            }
                            // 群帧在 core 泵线程已被拦截解释,不会到达这里(防御)。
                            TransportEvent::Group { .. } => {}
                        }
                    }
                });
            }

            app.manage(notifier);
            app.manage(AppCore(core));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ping,
            get_self_info,
            get_roster,
            send_text,
            offer_file,
            respond_file,
            default_download_dir,
            ipmsg_status,
            get_history,
            get_history_around,
            list_conversations,
            list_groups,
            create_group,
            update_group_members,
            leave_group,
            send_group_text,
            search_history,
            clear_history,
            get_settings,
            set_settings,
            list_network_interfaces,
            validate_allowed_networks,
            notify_set_active,
            notify_clear_unread,
            set_conversation_muted
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::ExitRequested { .. } => {
                // 退出前注销 mDNS,让对端立刻看到我们下线
                if let Some(core) = app_handle.try_state::<AppCore>() {
                    core.0.shutdown();
                }
            }
            // macOS:Dock 图标点击 / Cmd+Tab 激活时恢复窗口(并切回 Regular)
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show_main_window(app_handle),
            _ => {}
        });
}

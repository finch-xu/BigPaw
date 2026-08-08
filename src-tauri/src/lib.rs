use bigpaw_core::core::{Core, CoreConfig};
use bigpaw_core::roster::Peer;
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
        nickname: core.0.nickname().to_string(),
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
    peer_fp: String,
    id: String,
    body: String,
    ts_ms: u64,
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
fn set_settings(app: AppHandle, value: Settings) -> Result<(), String> {
    settings::save(&data_dir(&app), &value).map_err(|e| e.to_string())
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
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                // macOS:关窗即切成 Accessory(菜单栏应用),Dock 图标消失
                #[cfg(target_os = "macos")]
                let _ = window
                    .app_handle()
                    .set_activation_policy(tauri::ActivationPolicy::Accessory);
                api.prevent_close(); // 阻止真正关闭 → 应用继续后台运行
            }
        })
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let core = Core::start(CoreConfig {
                data_dir,
                nickname: None,
            })?;

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
                std::thread::spawn(move || {
                    while let Ok(ev) = events_rx.recv() {
                        match ev {
                            TransportEvent::Message(ev) => {
                                let _ = handle.emit(
                                    "message://received",
                                    MessageDto {
                                        peer_fp: ev.peer_fp,
                                        id: ev.id,
                                        body: ev.body,
                                        ts_ms: ev.ts_ms,
                                    },
                                );
                            }
                            TransportEvent::FileOffered {
                                xfer_id,
                                peer_fp,
                                name,
                                size,
                                is_dir,
                            } => {
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
                        }
                    }
                });
            }

            // 系统托盘 / macOS 菜单栏:关窗后应用常驻此处,并提供唯一的"退出"入口
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
            search_history,
            clear_history,
            get_settings,
            set_settings
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

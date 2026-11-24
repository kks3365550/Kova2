//! 단일 인스턴스 뮤텍스·표시 이벤트 및 시스템 트레이 아이콘 관리.
use crate::ipc::send;
use crate::MainWindow;
use slint::ComponentHandle;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

fn make_icon() -> Icon {
    // 32x32 RGBA(assets/kova_32.rgba)
    Icon::from_rgba(include_bytes!("../assets/kova_32.rgba").to_vec(), 32, 32).unwrap()
}

#[cfg(windows)]
static SINGLE_MUTEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
static SHOW_EVENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 업데이트 재시작 직전 등 새 인스턴스를 허용해야 할 때 단일 인스턴스 뮤텍스·표시 이벤트 핸들을 닫는다.
#[cfg(windows)]
pub(crate) fn release_single_instance() {
    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(h: isize) -> i32;
    }
    let m = SINGLE_MUTEX.swap(0, std::sync::atomic::Ordering::SeqCst);
    if m != 0 {
        unsafe {
            CloseHandle(m as isize);
        }
    }
    let ev = SHOW_EVENT.swap(0, std::sync::atomic::Ordering::SeqCst);
    if ev != 0 {
        unsafe {
            CloseHandle(ev as isize);
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn release_single_instance() {}

/// 두 번째 인스턴스가 보낸 창 표시 신호(`Local\Kova2AppShowEvent`)가 왔는지 비차단으로 확인한다.
#[cfg(windows)]
pub(crate) fn poll_show_event() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(h: isize, millis: u32) -> u32;
    }
    const WAIT_OBJECT_0: u32 = 0;
    let ev = SHOW_EVENT.load(std::sync::atomic::Ordering::SeqCst);
    ev != 0 && unsafe { WaitForSingleObject(ev as isize, 0) } == WAIT_OBJECT_0
}

#[cfg(not(windows))]
pub(crate) fn poll_show_event() -> bool {
    false
}

/// 이름 있는 뮤텍스로 앱을 하나만 띄운다. 이미 있으면 표시 이벤트 신호 + 기존 창 활성화 후 false.
#[cfg(windows)]
pub(crate) fn single_instance() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateMutexW(attrs: *const u8, initial: i32, name: *const u16) -> isize;
        fn CreateEventW(
            attrs: *const u8,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> isize;
        fn OpenEventW(desired_access: u32, inherit: i32, name: *const u16) -> isize;
        fn SetEvent(h: isize) -> i32;
        fn CloseHandle(h: isize) -> i32;
        fn GetLastError() -> u32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(class: *const u16, title: *const u16) -> isize;
        fn ShowWindow(h: isize, cmd: i32) -> i32;
        fn SetForegroundWindow(h: isize) -> i32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    let name: Vec<u16> = "Local\\Kova2AppSingleInstance\0".encode_utf16().collect();
    let ev_name: Vec<u16> = "Local\\Kova2AppShowEvent\0".encode_utf16().collect();
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if h != 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        SINGLE_MUTEX.store(h as usize, std::sync::atomic::Ordering::SeqCst);
        let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, ev_name.as_ptr()) };
        if ev != 0 {
            SHOW_EVENT.store(ev as usize, std::sync::atomic::Ordering::SeqCst);
        }
        return true; // 프로세스가 끝날 때까지(또는 release_single_instance 호출 시까지) 핸들을 쥐고 있는다
    }
    if h == 0 {
        return true; // 뮤텍스를 못 만들어도 앱은 띄운다
    }
    unsafe {
        CloseHandle(h);
        let ev = OpenEventW(EVENT_MODIFY_STATE, 0, ev_name.as_ptr());
        if ev != 0 {
            SetEvent(ev);
            CloseHandle(ev);
        }
    }
    let title: Vec<u16> = "Kova\0".encode_utf16().collect();
    unsafe {
        let w = FindWindowW(std::ptr::null(), title.as_ptr());
        if w != 0 {
            ShowWindow(w, 9); // SW_RESTORE
            SetForegroundWindow(w);
        }
    }
    false
}

/// 트레이 아이콘과 이벤트 폴링 타이머의 수명을 유지한다.
pub(crate) struct TrayHandle {
    _tray: Option<TrayIcon>,
    _timer: slint::Timer,
}

pub(crate) fn setup_tray(w: &MainWindow) -> TrayHandle {
    let menu = Menu::new();
    let open = MenuItem::new("열기", true, None);
    let backup_all = MenuItem::new("지금 백업 (모든 프로파일)", true, None);
    let quit = MenuItem::new("종료", true, None);
    menu.append_items(&[&open, &backup_all, &quit]).unwrap();
    let tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Kova")
        .with_icon(make_icon())
        .build()
    {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("트레이 아이콘 생성 건너뜀: {e}");
            None
        }
    };

    // 트레이 메뉴 이벤트 및 두 번째 인스턴스 창 표시 신호를 Slint 이벤트 루프에서 주기적으로 처리
    let weak = w.as_weak();
    let (open_id, quit_id, backup_id) = (
        open.id().clone(),
        quit.id().clone(),
        backup_all.id().clone(),
    );
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(100),
        move || {
            if poll_show_event() {
                if let Some(w) = weak.upgrade() {
                    let _ = w.show();
                    w.window().set_minimized(false);
                }
            }
            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                if ev.id == open_id {
                    if let Some(w) = weak.upgrade() {
                        let _ = w.show();
                        w.window().set_minimized(false);
                    }
                } else if ev.id == backup_id {
                    let store =
                        kova_core::config::ConfigStore::new(kova_service::default_config_dir());
                    for p in store.profiles() {
                        send(weak.clone(), "backup", p.id);
                    }
                } else if ev.id == quit_id {
                    let _ = slint::quit_event_loop();
                }
            }
        },
    );

    TrayHandle {
        _tray: tray,
        _timer: timer,
    }
}

//! 자동 업데이트 조회·검증·관리자 권한 설치.
use crate::tray::release_single_instance;
use crate::util::{app_locked, BusyGate, LOCKED_MSG};
use crate::MainWindow;
use slint::ComponentHandle;

const UPDATE_BASE: &str = "https://github.com";
const UPDATE_REPO: &str = "kks3365550/Kova";

/// 최신 버전 조회만 한다.
pub(crate) fn check_update(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let current = env!("CARGO_PKG_VERSION");
        let text = match kova_core::fetch::latest_tag(UPDATE_BASE, UPDATE_REPO) {
            Ok(tag) if kova_core::update::is_newer(&tag, current) => {
                format!("새 버전 {tag} 이(가) 있습니다 (현재 {current})")
            }
            Ok(tag) => format!("최신입니다 (최신 {tag}, 현재 {current})"),
            Err(e) => format!("확인 실패: {e}"),
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_update_text(text.into());
            }
        });
    });
}

/// 앱 시작 시 1회 백그라운드 업데이트 확인: 새 버전이 있을 때만 조용히 알리고, 최신이거나 오프라인이면 무시한다.
pub(crate) fn check_update_silent(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let current = env!("CARGO_PKG_VERSION");
        if let Ok(tag) = kova_core::fetch::latest_tag(UPDATE_BASE, UPDATE_REPO) {
            if kova_core::update::is_newer(&tag, current) {
                let msg = format!(
                    "새 버전 {tag} 이(가) 출시되었습니다 (현재 {current}) — 환경설정 > '클라우드 & 알림' 탭에서 설치 가능"
                );
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_update_text(msg.into());
                    }
                });
            }
        }
    });
}

/// 최신 조회 → 서명 검증된 패키지 → 설치 폴더에 적용(실패 시 롤백).
pub(crate) fn do_install() -> Result<(String, bool), String> {
    let current = env!("CARGO_PKG_VERSION");
    let tag = kova_core::fetch::latest_tag(UPDATE_BASE, UPDATE_REPO).map_err(|e| e.to_string())?;
    if !kova_core::update::is_newer(&tag, current) {
        return Ok((format!("이미 최신입니다 ({current})"), false));
    }
    let pkg = kova_core::fetch::fetch_verified(
        UPDATE_BASE,
        UPDATE_REPO,
        &tag,
        kova_core::fetch::TRUSTED_KEYS,
        500 << 20,
    )
    .map_err(|e| e.to_string())?;
    kova_core::fetch::ensure_package_newer(&pkg, "kova-app.exe", current)
        .map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or("설치 폴더를 알 수 없음")?.to_path_buf();
    let backup = dir.join("update_backup");
    let r = kova_core::install::apply(&pkg, &dir, &backup, &["kova-app.exe"])
        .map_err(|e| e.to_string())?;
    // 서비스는 옛 파일로 계속 돌고 있으므로 완전히 정지될 때까지 확인한 뒤 새 파일로 다시 시작한다
    let svc = |a: &str| {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("sc.exe")
            .args([a, "KovaSvc"])
            .creation_flags(0x0800_0000)
            .output()
    };
    let _ = svc("stop");
    let stopped = stop_service_wait("KovaSvc", std::time::Duration::from_secs(30));
    let _ = svc("start");
    let svc_note = if stopped {
        "서비스 재시작"
    } else {
        "서비스 정지 대기 초과 후 재시작 시도"
    };
    Ok((
        format!(
            "{tag} 설치 완료({}개 파일, {svc_note}). 앱을 다시 시작합니다",
            r.files
        ),
        true,
    ))
}

pub(crate) fn parse_service_stopped(sc_query_out: &str) -> bool {
    sc_query_out.contains("STOPPED") || sc_query_out.contains("1060")
}

fn stop_service_wait(service_name: &str, timeout: std::time::Duration) -> bool {
    use std::os::windows::process::CommandExt;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let out = std::process::Command::new("sc.exe")
            .args(["query", service_name])
            .creation_flags(0x0800_0000)
            .output();
        if let Ok(o) = out {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if parse_service_stopped(&text) || o.status.code() == Some(1060) {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// 관리자 권한 도우미가 결과 파일에 적는 형식: 첫 줄 `installed`/`noop`, 이어서 안내 문구.
pub(crate) fn encode_install_result(installed: bool, text: &str) -> String {
    format!("{}\n{text}", if installed { "installed" } else { "noop" })
}

/// `encode_install_result` 의 반대. 첫 줄 표식이 없으면(옛 버전이 쓴 파일) 설치 안 한 것으로 보고 전체를 문구로 쓴다.
pub(crate) fn decode_install_result(raw: &str) -> (bool, String) {
    match raw.split_once('\n') {
        Some(("installed", t)) => (true, t.to_string()),
        Some(("noop", t)) => (false, t.to_string()),
        _ => (false, raw.to_string()),
    }
}

/// 사용자가 "업데이트 설치"를 눌렀을 때만 실행.
pub(crate) fn install_update(weak: slint::Weak<MainWindow>, gate: BusyGate) {
    let Some(guard) = gate.lock() else {
        if let Some(w) = weak.upgrade() {
            w.set_update_text("이미 업데이트 설치가 진행 중입니다.".into());
        }
        return;
    };
    if let Some(w) = weak.upgrade() {
        w.set_update_text("업데이트 확인 및 설치 준비 중…".into());
    }
    let exe_path = std::env::current_exe().unwrap_or_default();
    std::thread::spawn(move || {
        let _guard = guard;
        let run = || -> Result<(bool, String), String> {
            use std::os::windows::process::CommandExt;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let res = std::env::temp_dir().join(format!("kova_update_{}.txt", std::process::id()));
            let _ = std::fs::remove_file(&res);
            let q = |p: &std::path::Path| p.to_string_lossy().replace('\'', "''");
            let cmd = format!(
                "Start-Process -FilePath '{}' -ArgumentList '--install-update','\"{}\"' -Verb RunAs -Wait",
                q(&exe),
                q(&res)
            );
            let st = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
                .creation_flags(0x0800_0000)
                .output()
                .map_err(|e| e.to_string())?;
            let text = std::fs::read_to_string(&res).ok();
            let _ = std::fs::remove_file(&res);
            match text {
                Some(t) => Ok(decode_install_result(&t)),
                None if !st.status.success() => Err("관리자 권한 승인이 취소되었습니다".into()),
                None => Err("설치 결과를 받지 못했습니다".into()),
            }
        };
        let (installed, mut text) =
            run().unwrap_or_else(|e| (false, format!("설치하지 않음: {e}")));
        let mut restarted = false;
        if installed {
            release_single_instance();
            use std::os::windows::process::CommandExt;
            match std::process::Command::new(&exe_path)
                .creation_flags(0x0800_0000)
                .spawn()
            {
                Ok(mut child) => {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    if matches!(child.try_wait(), Ok(None)) {
                        restarted = true;
                    } else {
                        text.push_str(" — 새 앱이 시작되지 않았습니다. Kova 를 직접 실행하세요");
                    }
                }
                Err(e) => text.push_str(&format!(
                    " — 자동 재시작 실패({e}). Kova 를 직접 실행하세요"
                )),
            }
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_update_text(text.into());
            }
            if restarted {
                let _ = slint::quit_event_loop();
            }
        });
    });
}

pub(crate) fn wire(w: &MainWindow) {
    let weak = w.as_weak();
    w.on_check_update(move || check_update(weak.clone()));

    let weak = w.as_weak();
    let update_gate = BusyGate::default();
    w.on_install_update(move || {
        if app_locked() {
            if let Some(w) = weak.upgrade() {
                w.set_update_text(LOCKED_MSG.into());
            }
            return;
        }
        install_update(weak.clone(), update_gate.clone());
    });

    // 앱 시작 시 1회 백그라운드로 새 버전 확인
    check_update_silent(w.as_weak());
}

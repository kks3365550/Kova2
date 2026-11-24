#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
slint::include_modules!();

mod disk_image;
mod ipc;
mod picker;
mod profiles;
mod restore;
mod settings;
mod tray;
mod updater;
mod util;

#[cfg(test)]
mod tests;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn main() -> Result<(), slint::PlatformError> {
    kova_core::applog::install_panic_hook(kova_service::default_config_dir(), "Kova 앱");
    // 앱은 키를 읽지 않는다(키 폴더는 SYSTEM·관리자 전용): 암호화 저장소의 목록·찾아보기는 평문 매니페스트로,
    // 내용(블롭)이 필요한 복원·복구 훈련은 서비스에 맡긴다
    kova_core::repocrypto::install_service_only_provider();

    // 관리자 권한으로 다시 실행된 업데이트 설치 도우미: 설치하고 결과를 파일에 적은 뒤 끝낸다
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--install-update") {
        let (text, installed) =
            updater::do_install().unwrap_or_else(|e| (format!("설치하지 않음: {e}"), false));
        if let Some(f) = args.get(i + 1) {
            let _ = std::fs::write(f, updater::encode_install_result(installed, &text));
        }
        return Ok(());
    }

    // 앱이 둘 뜨면 클릭이 엉키고 서비스 연결도 겹치므로, 이미 떠 있으면 그 창을 앞으로 가져오고 끝낸다
    #[cfg(windows)]
    if !tray::single_instance() {
        return Ok(());
    }

    let w = MainWindow::new()?;
    w.set_app_version(env!("CARGO_PKG_VERSION").into());
    w.on_cancel_job(ipc::cancel_job);

    let banner_gen: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    profiles::wire(&w, &banner_gen);
    restore::wire(&w, &banner_gen);
    disk_image::wire(&w);
    settings::wire(&w);
    updater::wire(&w);
    picker::wire(&w);

    ipc::spawn_ipc(w.as_weak(), banner_gen);
    let _tray_handle = tray::setup_tray(&w);

    // --tray: 로그인 자동 실행용. 창을 띄우지 않고 트레이로만 시작하며, 창을 닫아도 종료하지 않는다(트레이 "종료"로 끝낸다)
    if std::env::args().any(|a| a == "--tray") {
        slint::run_event_loop_until_quit()
    } else {
        let _ = w.show();
        w.run()
    }
}

//! KovaSvc IPC 클라이언트·이벤트 구독·상태 폴링.
use crate::disk_image::image_rows;
use crate::profiles::rows as profile_rows;
use crate::restore::snaps;
use crate::settings::{offsite_rows, setting_lines};
use crate::util::{
    alert_rows, changed_only, drive_rows, kind_label, profile_name, repo_drive_usage, toast,
};
use crate::{AlertRow, DriveRow, ImageRow, MainWindow, ProfileRow, RunRow, SnapRow};
use slint::Model;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// 홈 화면의 "진행 중" 목록 한 줄(서비스 이벤트로 갱신).
#[derive(Debug, Clone)]
pub(crate) struct RunInfo {
    pub id: u64,
    pub name: String,
    pub pct: u64,
    pub current: String,
    pub cancellable: bool,
    pub kind: String,
}

/// 이벤트 하나를 진행 중 목록에 반영한다. 완료 이벤트인 경우 완료된 작업의 RunInfo를 반환한다.
pub(crate) fn update_running(
    rows: &mut Vec<RunInfo>,
    e: &kova_ipc::Event,
    name_of: &dyn Fn(&str) -> String,
) -> Option<RunInfo> {
    match e {
        kova_ipc::Event::JobStarted {
            job_id,
            profile_id,
            kind,
        } => {
            rows.retain(|r| r.id != *job_id);
            rows.push(RunInfo {
                id: *job_id,
                name: name_of(profile_id),
                pct: 0,
                current: String::new(),
                cancellable: kind == "backup" || kind.starts_with("image"),
                kind: kind.clone(),
            });
            None
        }
        kova_ipc::Event::Progress {
            job_id,
            percent,
            current,
        } => {
            if let Some(r) = rows.iter_mut().find(|r| r.id == *job_id) {
                r.pct = (*percent).min(100);
                r.current = current.clone();
            }
            None
        }
        kova_ipc::Event::JobFinished { job_id, .. } => {
            let pos = rows.iter().position(|r| r.id == *job_id)?;
            Some(rows.remove(pos))
        }
        _ => None,
    }
}

/// 서비스가 유휴(running == 0)로 응답했고 그사이 새 작업 이벤트가 오지 않았을 때만 공유 running 목록을 비운다.
pub(crate) fn try_clear_idle_running(
    running: &Mutex<Vec<RunInfo>>,
    event_seq: &AtomicU64,
    seq_before: u64,
) -> bool {
    let mut r = running.lock().unwrap();
    if event_seq.load(Ordering::SeqCst) == seq_before {
        r.clear();
        true
    } else {
        false
    }
}

/// 서비스 요청 결과에서 실패 사유를 찾는다(연결 실패 또는 서비스가 돌려준 Error). 성공이면 None.
pub(crate) fn send_failure(res: &std::io::Result<Vec<kova_ipc::Event>>) -> Option<String> {
    match res {
        Err(e) => Some(format!(
            "Kova 서비스에 연결할 수 없습니다. 서비스가 켜져 있는지 확인하세요 ({e})"
        )),
        Ok(evs) => evs.iter().find_map(|e| match e {
            kova_ipc::Event::Error { message } => Some(message.clone()),
            _ => None,
        }),
    }
}

/// 서비스에 요청 하나를 보내고 응답을 모은다(화면 스레드가 아닌 곳에서 부른다).
pub(crate) fn ipc_once(req: &kova_ipc::Request) -> std::io::Result<Vec<kova_ipc::Event>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(kova_ipc::request(kova_ipc::PIPE_NAME, req))
}

/// 결과 문구(`Done`)를 돌려주는 서비스 요청. 서비스에 닿지 못하거나 거절되면 Err(사유).
pub(crate) fn ipc_done(req: &kova_ipc::Request) -> Result<String, String> {
    let res = ipc_once(req);
    if let Some(why) = send_failure(&res) {
        return Err(why);
    }
    res.ok()
        .into_iter()
        .flatten()
        .find_map(|e| match e {
            kova_ipc::Event::Done { message } => Some(message),
            _ => None,
        })
        .ok_or_else(|| "서비스가 응답하지 않았습니다(서비스를 최신 버전으로 업데이트하세요)".into())
}

/// 서비스에 작업을 요청한다(호출자 스레드에서 동기 실행). 요청이 거절되거나 서비스에 닿지 못하면 화면의 완료 카드에 실패를 띄운다.
pub(crate) fn send_sync(weak: slint::Weak<MainWindow>, kind: String, id: String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let res = rt.block_on(kova_ipc::request(
        kova_ipc::PIPE_NAME,
        &kova_ipc::Request::RunNow {
            profile_id: id,
            kind: kind.clone(),
        },
    ));
    if let Some(why) = send_failure(&res) {
        let title = format!("{} 요청 실패", kind_label(&kind));
        let _ = weak.upgrade_in_event_loop(move |w| {
            w.set_job_completed_ok(false);
            w.set_job_completed_title(title.into());
            w.set_job_completed_msg(why.into());
            w.set_job_completed_show(true);
        });
    }
}

/// 서비스에 작업을 요청한다. 요청이 거절되거나 서비스에 닿지 못하면 화면의 완료 카드에 실패를 띄운다.
pub(crate) fn send(weak: slint::Weak<MainWindow>, kind: impl Into<String>, id: String) {
    let kind: String = kind.into();
    std::thread::spawn(move || send_sync(weak, kind, id));
}

pub(crate) fn cancel_job(id: i32) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = rt.block_on(kova_ipc::request(
            kova_ipc::PIPE_NAME,
            &kova_ipc::Request::Cancel { job_id: id as u64 },
        ));
    });
}

/// 서비스와 통신하는 백그라운드 스레드: 상태 폴링 + 이벤트 구독. 화면 갱신은 이벤트 루프로 넘긴다.
pub(crate) fn spawn_ipc(weak: slint::Weak<MainWindow>, banner_gen: Arc<AtomicU64>) {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    );
    let running: Arc<Mutex<Vec<RunInfo>>> = Arc::new(Mutex::new(vec![]));
    let event_seq: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let (w1, rt1, running_poll, seq_poll) =
        (weak.clone(), rt.clone(), running.clone(), event_seq.clone());
    std::thread::spawn(move || {
        rt1.block_on(async move {
            let mut last_off: Option<Vec<(String, String, String)>> = None;
            let mut last_profiles: Option<Vec<ProfileRow>> = None;
            let mut last_snaps: Option<Vec<SnapRow>> = None;
            let mut last_drives: Option<Vec<DriveRow>> = None;
            let mut last_images: Option<Vec<ImageRow>> = None;
            let mut last_alerts: Option<Vec<AlertRow>> = None;
            let mut last_lines: Option<Vec<slint::SharedString>> = None;
            loop {
                let seq_before = seq_poll.load(Ordering::SeqCst);
                let status_res =
                    kova_ipc::request(kova_ipc::PIPE_NAME, &kova_ipc::Request::Status).await;
                let is_svc_idle = match &status_res {
                    Ok(evs) => matches!(
                        evs.first(),
                        Some(kova_ipc::Event::Status { running: 0, .. })
                    ),
                    _ => false,
                };
                let text = match status_res {
                    Ok(evs) => match evs.first() {
                        Some(kova_ipc::Event::Status { waiting, running }) => {
                            format!("서비스 연결됨 · 실행 중 {running} · 대기 {waiting}")
                        }
                        _ => "서비스 응답 이상".into(),
                    },
                    Err(_) => "서비스에 연결할 수 없음 (Kova 서비스가 꺼져 있습니다)".into(),
                };
                let w = w1.clone();
                let mut profiles = profile_rows();
                let snapshots = snaps();
                // 대상별 크기: 가장 최근 스냅샷 요약("파일 N개 · 크기")의 크기 부분
                for p in profiles.iter_mut() {
                    if let Some(s) = snapshots.iter().find(|s| s.name == p.name) {
                        if let Some((_, sz)) = s.summary.split_once(" · ") {
                            p.size = sz.into();
                        }
                    }
                }
                let (alerts, lines, off) = (alert_rows(), setting_lines(), offsite_rows());
                // 사이드바·'저장소 열기'가 쓰는 실제 저장소 경로(첫 프로파일). 없으면 빈 값
                let main_repo: slint::SharedString =
                    kova_core::config::ConfigStore::new(kova_service::default_config_dir())
                        .profiles()
                        .first()
                        .map(|p| p.repo_dir.clone())
                        .unwrap_or_default()
                        .into();
                let (repo_drive_free, repo_drive_pct) = repo_drive_usage(main_repo.as_str());
                // 입력 중인 칸이 2초마다 초기화되지 않도록, 내용이 바뀐 때만 모델을 교체한다
                let key: Vec<(String, String, String)> = off
                    .iter()
                    .map(|o| (o.id.to_string(), o.name.to_string(), o.dir.to_string()))
                    .collect();
                let off = if last_off.as_ref() == Some(&key) {
                    None
                } else {
                    last_off = Some(key);
                    Some(off)
                };
                let profiles = changed_only(&mut last_profiles, profiles);
                let snapshots = changed_only(&mut last_snaps, snapshots);
                let drives = changed_only(&mut last_drives, drive_rows());
                let images = changed_only(&mut last_images, image_rows());
                let alerts = changed_only(&mut last_alerts, alerts);
                let lines = changed_only(&mut last_lines, lines);
                let n = kova_core::alerts::AlertLog::new(&kova_service::default_config_dir())
                    .unacknowledged();
                let alert = if n > 0 {
                    format!("확인하지 않은 알림 {n}건 (백업 실패 등)")
                } else {
                    String::new()
                };
                let should_clear_running =
                    is_svc_idle && try_clear_idle_running(&running_poll, &seq_poll, seq_before);
                let seq_ui = seq_poll.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = w.upgrade() {
                        if w.get_main_repo() != main_repo {
                            w.set_main_repo(main_repo);
                        }
                        if w.get_repo_drive_free() != repo_drive_free.as_str() {
                            w.set_repo_drive_free(repo_drive_free.into());
                        }
                        if w.get_repo_drive_pct() != repo_drive_pct {
                            w.set_repo_drive_pct(repo_drive_pct);
                        }
                        w.set_service_ok(text.starts_with("서비스 연결됨"));
                        w.set_service_status(text.into());
                        w.set_alert_text(alert.into());
                        if should_clear_running
                            && seq_ui.load(Ordering::SeqCst) == seq_before
                            && w.get_running().row_count() > 0
                        {
                            w.set_running(
                                std::rc::Rc::new(slint::VecModel::<RunRow>::default()).into(),
                            );
                        }
                        if let Some(images) = images {
                            if let Some(f) = images.first() {
                                if w.get_img_path().is_empty() {
                                    w.set_img_path(f.path.clone());
                                }
                                if w.get_vol_img().is_empty() {
                                    w.set_vol_img(f.path.clone());
                                }
                            }
                            w.set_images(std::rc::Rc::new(slint::VecModel::from(images)).into());
                        }
                        if let Some(drives) = drives {
                            w.set_drives(std::rc::Rc::new(slint::VecModel::from(drives)).into());
                        }
                        if let Some(off) = off {
                            w.set_offsite_rows(std::rc::Rc::new(slint::VecModel::from(off)).into());
                        }
                        if let Some(alerts) = alerts {
                            w.set_alerts(std::rc::Rc::new(slint::VecModel::from(alerts)).into());
                        }
                        if let Some(lines) = lines {
                            w.set_setting_lines(
                                std::rc::Rc::new(slint::VecModel::from(lines)).into(),
                            );
                        }
                        if let Some(profiles) = profiles {
                            w.set_profiles(
                                std::rc::Rc::new(slint::VecModel::from(profiles)).into(),
                            );
                        }
                        if let Some(snapshots) = snapshots {
                            w.set_snapshots(
                                std::rc::Rc::new(slint::VecModel::from(snapshots)).into(),
                            );
                        }
                    }
                });
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    });
    std::thread::spawn(move || {
        rt.block_on(async move {
            loop {
                let w = weak.clone();
                let _ = kova_ipc::stream(kova_ipc::PIPE_NAME, &kova_ipc::Request::Subscribe, |e| {
                    let (run_rows, finished_info) = {
                        let mut r = running.lock().unwrap();
                        if matches!(
                            e,
                            kova_ipc::Event::JobStarted { .. }
                                | kova_ipc::Event::Progress { .. }
                                | kova_ipc::Event::JobFinished { .. }
                        ) {
                            event_seq.fetch_add(1, Ordering::SeqCst);
                        }
                        let fin = update_running(&mut r, &e, &profile_name);
                        let rows: Vec<RunRow> = r
                            .iter()
                            .map(|x| RunRow {
                                id: x.id as i32,
                                name: x.name.clone().into(),
                                pct: x.pct as i32,
                                current: x.current.clone().into(),
                                cancellable: x.cancellable,
                                kind: x.kind.clone().into(),
                                label: format!("{} 진행 중", kind_label(&x.kind)).into(),
                            })
                            .collect();
                        (rows, fin)
                    };
                    let finished_kind = finished_info
                        .map(|f| f.kind)
                        .unwrap_or_else(|| "backup".into());
                    {
                        let w = w.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = w.upgrade() {
                                w.set_running(
                                    std::rc::Rc::new(slint::VecModel::from(run_rows)).into(),
                                );
                            }
                        });
                    }
                    if let kova_ipc::Event::JobStarted { .. } = e {
                        banner_gen.fetch_add(1, Ordering::SeqCst);
                        let w_start = w.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = w_start.upgrade() {
                                w.set_job_completed_show(false);
                            }
                        });
                    }
                    if let kova_ipc::Event::JobFinished {
                        ref profile_id,
                        ok,
                        ref message,
                        ..
                    } = e
                    {
                        let my_gen = banner_gen.fetch_add(1, Ordering::SeqCst) + 1;
                        let p_name = profile_name(profile_id);
                        let action = kind_label(&finished_kind);
                        let title = if ok {
                            format!("{action} 완료: {p_name}")
                        } else if message == "취소됨" {
                            format!("{action} 취소됨: {p_name}")
                        } else {
                            format!("{action} 실패: {p_name}")
                        };
                        let is_ok = ok;
                        let msg_text = message.clone();
                        let w_done = w.clone();
                        let profiles = profile_rows();
                        let snapshots = snaps();
                        let alerts = alert_rows();
                        let n =
                            kova_core::alerts::AlertLog::new(&kova_service::default_config_dir())
                                .unacknowledged();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = w_done.upgrade() {
                                w.set_job_completed_ok(is_ok);
                                w.set_job_completed_title(title.into());
                                w.set_job_completed_msg(msg_text.into());
                                w.set_job_completed_show(true);
                                w.set_profiles(
                                    std::rc::Rc::new(slint::VecModel::from(profiles)).into(),
                                );
                                w.set_snapshots(
                                    std::rc::Rc::new(slint::VecModel::from(snapshots)).into(),
                                );
                                w.set_alerts(
                                    std::rc::Rc::new(slint::VecModel::from(alerts)).into(),
                                );
                                if n > 0 {
                                    w.set_alert_text(
                                        format!("확인하지 않은 알림 {n}건 (백업 실패 등)").into(),
                                    );
                                } else {
                                    w.set_alert_text("".into());
                                }
                            }
                        });
                        if is_ok {
                            let w_auto = w.clone();
                            let gen_ref = banner_gen.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                                if gen_ref.load(Ordering::SeqCst) == my_gen {
                                    let _ = slint::invoke_from_event_loop(move || {
                                        if gen_ref.load(Ordering::SeqCst) == my_gen {
                                            if let Some(w) = w_auto.upgrade() {
                                                w.set_job_completed_show(false);
                                            }
                                        }
                                    });
                                }
                            });
                        }
                    }
                    let line = match e {
                        kova_ipc::Event::JobStarted {
                            profile_id, kind, ..
                        } => format!("시작: {profile_id} ({})", kind_label(&kind)),
                        kova_ipc::Event::Progress {
                            percent, current, ..
                        } => format!("진행 {percent}% {current}"),
                        kova_ipc::Event::JobFinished {
                            profile_id,
                            ok,
                            message,
                            ..
                        } => {
                            if !ok && message != "취소됨" {
                                toast(
                                    &format!("Kova {} 실패", kind_label(&finished_kind)),
                                    &format!("{}: {message}", profile_name(&profile_id)),
                                );
                            }
                            format!(
                                "{} {profile_id}: {message}",
                                if ok { "완료" } else { "실패" }
                            )
                        }
                        _ => return true,
                    };
                    let w = w.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = w.upgrade() {
                            let old = w.get_log_text().to_string();
                            let keep: Vec<&str> = old.lines().take(11).collect();
                            w.set_log_text((line + "\n" + &keep.join("\n")).trim_end().into());
                        }
                    });
                    true
                })
                .await;
                // 연결이 끊기면 진행 중 표시를 비운다(서비스가 죽었는데 취소 버튼이 남지 않도록)
                {
                    let mut r = running.lock().unwrap();
                    event_seq.fetch_add(1, Ordering::SeqCst);
                    r.clear();
                }
                let w = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = w.upgrade() {
                        w.set_running(
                            std::rc::Rc::new(slint::VecModel::<RunRow>::default()).into(),
                        );
                    }
                });
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    });
}

//! 스냅샷 목록, 탐색, 통합 검색, 복원(암호화 복구 코드 포함), 스냅샷 Diff, 클라우드 Pull/Prune.
use crate::ipc::{ipc_done, ipc_once, send_failure, send_sync};
use crate::util::{
    app_locked, chrono_fmt, fmt_size, gc_target, human_mb, resolve_profile_id, BusyGate, LOCKED_MSG,
};
use crate::{BrowseRow, DiffRow, GlobalFileRow, MainWindow, SnapRow};
use kova_core::config::ConfigStore;
use slint::ComponentHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const BROWSE_LIMIT: usize = 500;
const DIFF_LIMIT: usize = 500;

/// 모든 프로파일의 저장소를 가로질러 파일명/초성으로 통합 검색하고 시점별 버전 수를 집계한다.
pub(crate) fn search_all_repos(
    store: &ConfigStore,
    query: &str,
) -> Vec<(String, String, String, String, usize, String)> {
    let q = query.trim();
    if q.is_empty() {
        return Vec::new();
    }
    let mut seen_repos = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in store.profiles() {
        if p.repo_dir.is_empty() || !seen_repos.insert(p.repo_dir.clone()) {
            continue;
        }
        let repo = Path::new(&p.repo_dir);
        let Ok(items) = kova_engine::search::search_snapshots(repo, q, 50, 40, true) else {
            continue;
        };
        for item in items {
            let info = format!(
                "{} · {} · {}",
                item.latest_size_formatted, item.latest_mtime_formatted, item.latest_snapshot_id
            );
            out.push((
                item.filename,
                item.rel_path,
                p.repo_dir.clone(),
                item.latest_snapshot_id,
                item.version_count.max(1),
                info,
            ));
        }
    }
    out.truncate(60);
    out
}

pub(crate) fn snaps() -> Vec<SnapRow> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let mut all: Vec<(f64, SnapRow)> = vec![];
    // 프로파일 둘이 같은 저장소를 쓰면 같은 스냅샷이 두 번 보이므로 (저장소, 번호)당 한 줄만 둔다
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();
    let ids: std::collections::HashSet<String> =
        store.profiles().into_iter().map(|p| p.id).collect();
    for p in store.profiles() {
        let repo = PathBuf::from(&p.repo_dir);
        if !repo.join("metadata.db").exists() {
            continue; // 읽기만 한다: 없는 저장소에 DB 를 새로 만들지 않는다
        }
        let Ok(h) = kova_core::history::History::open(&repo) else {
            continue;
        };
        for r in h.list_snapshots().unwrap_or_default() {
            if !r.profile_id.is_empty() && r.profile_id != p.id && ids.contains(&r.profile_id) {
                continue;
            }
            if !seen.insert((p.repo_dir.to_lowercase(), r.id.clone())) {
                continue;
            }
            let v = if r.verify_error_count > 0 {
                "오류 있음"
            } else if r.is_verified {
                "검증됨"
            } else {
                "미검증"
            };
            all.push((
                r.created_at,
                SnapRow {
                    id: r.id.clone().into(),
                    profile_id: p.id.clone().into(),
                    repo: p.repo_dir.clone().into(),
                    when: chrono_fmt(r.created_at).into(),
                    name: p.name.clone().into(),
                    summary: format!(
                        "파일 {}개 · {}",
                        r.total_files,
                        human_mb(r.total_bytes as u64)
                    )
                    .into(),
                    verified: v.into(),
                },
            ));
        }
    }
    all.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    all.into_iter().take(50).map(|x| x.1).collect()
}

/// 같은 저장소에서 `target_id` 직전(바로 이전 시점) 스냅샷 ID 를 찾는다.
fn find_previous_snapshot(repo: &Path, target_id: &str) -> Option<String> {
    if !repo.join("metadata.db").is_file() {
        return None;
    }
    let h = kova_core::history::History::open(repo).ok()?;
    let mut list = h.list_snapshots().ok()?;
    list.sort_by(|a, b| {
        b.created_at
            .partial_cmp(&a.created_at)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.id.cmp(&a.id))
    });
    let pos = list.iter().position(|r| r.id == target_id)?;
    list.get(pos + 1).map(|r| r.id.clone())
}

/// 스냅샷 변경 내역(Diff)을 서비스(`Request::DiffSnapshots`)에 요청해 화면에 띄운다.
fn diff_snapshot_job(
    weak: slint::Weak<MainWindow>,
    repo: String,
    target_id: String,
    title: String,
) {
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_diff_title(title.into());
        w.set_diff_summary("".into());
        w.set_diff_items(std::rc::Rc::new(slint::VecModel::<DiffRow>::default()).into());
        w.set_diff_status("이전 스냅샷과 변경 내역을 비교하는 중…".into());
        w.set_browse_open(false);
        w.set_diff_open(true);
    });
    std::thread::spawn(move || {
        let Some(base_id) = find_previous_snapshot(Path::new(&repo), &target_id) else {
            let _ = weak.upgrade_in_event_loop(move |w| {
                w.set_diff_status(
                    "비교할 이전 스냅샷이 없습니다 (이 저장소의 첫 번째 스냅샷입니다)".into(),
                );
            });
            return;
        };
        let req = kova_ipc::Request::DiffSnapshots {
            repo,
            base_id: base_id.clone(),
            target_id: target_id.clone(),
            limit: DIFF_LIMIT,
        };
        let res = ipc_once(&req);
        if let Some(why) = send_failure(&res) {
            let _ = weak.upgrade_in_event_loop(move |w| {
                w.set_diff_status(format!("변경 내역 비교 실패: {why}").into());
            });
            return;
        }
        let diff = res.ok().into_iter().flatten().find_map(|e| match e {
            kova_ipc::Event::DiffResult {
                added,
                modified,
                deleted,
                unchanged_count,
            } => Some((added, modified, deleted, unchanged_count)),
            _ => None,
        });
        match diff {
            Some((added, modified, deleted, unchanged_count)) => {
                let summary = format!(
                    "추가 {} · 수정 {} · 삭제 {} · 변경 없음 {}",
                    added.len(),
                    modified.len(),
                    deleted.len(),
                    unchanged_count
                );
                let mut rows = Vec::with_capacity(added.len() + modified.len() + deleted.len());
                for it in added {
                    rows.push(DiffRow {
                        kind: "+".into(),
                        path: it.path.into(),
                        detail: if it.is_dir {
                            "폴더".into()
                        } else {
                            fmt_size(it.size).into()
                        },
                    });
                }
                for it in modified {
                    rows.push(DiffRow {
                        kind: "~".into(),
                        path: it.path.into(),
                        detail: if it.is_dir {
                            "폴더".into()
                        } else {
                            format!("{} → {}", fmt_size(it.old_size), fmt_size(it.size)).into()
                        },
                    });
                }
                for it in deleted {
                    rows.push(DiffRow {
                        kind: "-".into(),
                        path: it.path.into(),
                        detail: if it.is_dir {
                            "폴더".into()
                        } else {
                            fmt_size(it.old_size.max(it.size)).into()
                        },
                    });
                }
                let status = format!("비교 기준: {base_id} → {target_id}");
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_diff_summary(summary.into());
                        w.set_diff_items(std::rc::Rc::new(slint::VecModel::from(rows)).into());
                        w.set_diff_status(status.into());
                    }
                });
            }
            None => {
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_diff_status(
                        "서비스가 응답하지 않았습니다(서비스를 최신 버전으로 업데이트하세요)"
                            .into(),
                    );
                });
            }
        }
    });
}

/// 암호화 저장소 복원은 키를 가진 서비스가 한다(파일 쓰기는 이 사용자 권한으로). 진행률을 화면에 흘리고 결과 문구를 돌려준다.
fn restore_via_service(
    weak: &slint::Weak<MainWindow>,
    repo: &str,
    sid: &str,
    target: Option<&Path>,
    only: Option<Vec<String>>,
    recovery_code: Option<String>,
) -> String {
    let rec = recovery_code
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(kova_ipc::Secret);
    let req = kova_ipc::Request::Restore {
        repo: repo.to_string(),
        session_id: sid.to_string(),
        target: target.map(|t| t.to_string_lossy().into_owned()),
        only,
        recovery_code: rec,
    };
    let mut last = std::time::Instant::now() - std::time::Duration::from_secs(5);
    let mut result: Option<Result<String, String>> = None;
    let r = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|rt| {
            rt.block_on(kova_ipc::stream_as_caller(
                kova_ipc::PIPE_NAME,
                &req,
                |e| match e {
                    kova_ipc::Event::RestoreProgress { done, total } => {
                        if last.elapsed() >= std::time::Duration::from_secs(1) {
                            last = std::time::Instant::now();
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_restore_text(format!("복원 중… {done}/{total}").into())
                            });
                        }
                        true
                    }
                    kova_ipc::Event::Done { message } => {
                        result = Some(Ok(message));
                        false
                    }
                    kova_ipc::Event::Error { message } => {
                        result = Some(Err(message));
                        false
                    }
                    _ => true,
                },
            ))
            .map_err(|e| e.to_string())
        });
    match (result, r) {
        (Some(Ok(m)), _) => m,
        (Some(Err(e)), _) if e.starts_with("복원") => e,
        (Some(Err(e)), _) => format!("복원 실패: {e}"),
        (None, Err(e)) => format!("복원 실패: Kova 서비스에 연결할 수 없습니다 ({e})"),
        (None, Ok(())) => "복원 실패: 서비스 응답이 끊겼습니다".into(),
    }
}

/// 스냅샷 파일 탐색 패널의 상태.
#[derive(Default)]
struct BrowseState {
    repo: String,
    sid: String,
    dir: String,
    query: String,
    items: Vec<kova_engine::ops::BrowseItem>,
    sel: std::collections::BTreeSet<String>,
    seq: u64,
}
type Browse = Arc<Mutex<BrowseState>>;

fn browse_info(it: &kova_engine::ops::BrowseItem) -> String {
    if it.is_dir {
        format!("파일 {}개 · {}", it.files, human_mb(it.size))
    } else {
        human_mb(it.size)
    }
}

fn browse_render(weak: &slint::Weak<MainWindow>, st: &Browse, status: String) {
    let (rows, dir, n) = {
        let s = st.lock().unwrap();
        let rows: Vec<BrowseRow> = s
            .items
            .iter()
            .map(|it| BrowseRow {
                name: it.name.clone().into(),
                path: it.path.clone().into(),
                is_dir: it.is_dir,
                info: browse_info(it).into(),
                selected: s.sel.contains(&it.path),
            })
            .collect();
        let dir = if s.query.is_empty() {
            format!("/{}", s.dir)
        } else {
            format!("검색: {}", s.query)
        };
        (rows, dir, s.sel.len() as i32)
    };
    let w = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(w) = w.upgrade() {
            w.set_browse_items(std::rc::Rc::new(slint::VecModel::from(rows)).into());
            w.set_browse_dir(dir.into());
            w.set_browse_selected(n);
            w.set_browse_status(status.into());
        }
    });
}

fn browse_load(weak: slint::Weak<MainWindow>, st: Browse, dir: String, query: String) {
    let (repo, sid, seq) = {
        let mut s = st.lock().unwrap();
        s.seq += 1;
        (s.repo.clone(), s.sid.clone(), s.seq)
    };
    browse_render(&weak, &st, "읽는 중…".into());
    std::thread::spawn(move || {
        let res =
            kova_engine::ops::browse_snapshot(Path::new(&repo), &sid, &dir, &query, BROWSE_LIMIT);
        let status = {
            let mut s = st.lock().unwrap();
            if s.seq != seq {
                return;
            }
            match res {
                Ok(items) => {
                    let status = if items.is_empty() {
                        "항목이 없습니다".to_string()
                    } else if items.len() >= BROWSE_LIMIT {
                        format!("처음 {BROWSE_LIMIT}개만 표시합니다. 검색으로 좁혀 보세요")
                    } else {
                        String::new()
                    };
                    s.dir = dir;
                    s.query = query;
                    s.items = items;
                    status
                }
                Err(e) => format!("목록을 읽지 못했습니다: {e}"),
            }
        };
        browse_render(&weak, &st, status);
    });
}

fn parent_dir(dir: &str) -> String {
    dir.rsplit_once('/')
        .map(|(a, _)| a.to_string())
        .unwrap_or_default()
}

/// 스냅샷을 원래 위치로 되돌린다(같은 이름의 파일은 덮어쓴다).
fn restore_inplace_job(
    weak: slint::Weak<MainWindow>,
    repo: String,
    sid: String,
    only: Option<Vec<String>>,
    recovery_code: Option<String>,
) {
    let show = |w: &slint::Weak<MainWindow>, t: String| {
        let w = w.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = w.upgrade() {
                w.set_restore_text(t.into());
            }
        });
    };
    show(&weak, "원래 위치로 복원 중…".into());
    std::thread::spawn(move || {
        let repo_path = PathBuf::from(&repo);
        if kova_core::repocrypto::is_enabled(&repo_path) {
            let text = restore_via_service(&weak, &repo, &sid, None, only, recovery_code);
            show(&weak, text);
            return;
        }
        let _lock = match kova_core::lock::RepoLock::acquire_wait(
            &repo_path,
            std::time::Duration::from_secs(5),
        ) {
            Ok(l) => l,
            Err(kova_core::lock::LockError::Busy) => {
                show(
                    &weak,
                    "복원 실패: 다른 작업이 저장소를 사용 중입니다. 잠시 후 다시 시도하세요".into(),
                );
                return;
            }
            Err(e) => {
                show(&weak, format!("복원 실패: 저장소 잠금 오류({e})"));
                return;
            }
        };
        let opts = kova_engine::ops::RestoreOptions {
            repo: repo_path,
            session_id: sid,
            only,
            target: None,
        };
        let cancel = AtomicBool::new(false);
        let text = match kova_engine::ops::run_restore(&opts, &|_| {}, &cancel) {
            Ok(s) => format!(
                "원래 위치로 복원 완료 (항목 {}개, {:.0}초)",
                s.total_files, s.elapsed_seconds
            ),
            Err(e) => format!("복원 실패: {e}"),
        };
        show(&weak, text);
    });
}

fn restore_snapshot_job(
    weak: slint::Weak<MainWindow>,
    repo: String,
    sid: String,
    target: String,
    only: Option<Vec<String>>,
    recovery_code: Option<String>,
) {
    let show = |w: &slint::Weak<MainWindow>, t: String| {
        let w = w.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = w.upgrade() {
                w.set_restore_text(t.into());
            }
        });
    };
    let repo_path = PathBuf::from(&repo);
    let target = match kova_core::restore_target::check(&target, &repo_path) {
        Ok(t) => t,
        Err(e) => {
            show(&weak, format!("복원하지 않음: {e}"));
            return;
        }
    };
    show(&weak, "복원 시작…".into());
    std::thread::spawn(move || {
        if kova_core::repocrypto::is_enabled(&repo_path) {
            let text = restore_via_service(&weak, &repo, &sid, Some(&target), only, recovery_code);
            show(&weak, text);
            return;
        }
        let _lock = match kova_core::lock::RepoLock::acquire_wait(
            &repo_path,
            std::time::Duration::from_secs(5),
        ) {
            Ok(l) => l,
            Err(kova_core::lock::LockError::Busy) => {
                show(
                    &weak,
                    "복원 실패: 다른 작업이 저장소를 사용 중입니다. 잠시 후 다시 시도하세요".into(),
                );
                return;
            }
            Err(e) => {
                show(&weak, format!("복원 실패: 저장소 잠금 오류({e})"));
                return;
            }
        };
        let last = Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(5));
        let w2 = weak.clone();
        let on_event = move |ev: kova_engine::ops::Event| {
            if let kova_engine::ops::Event::RestoreProgress { done, total } = ev {
                let mut l = last.lock().unwrap();
                if l.elapsed() >= std::time::Duration::from_secs(1) {
                    *l = std::time::Instant::now();
                    let w = w2.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = w.upgrade() {
                            w.set_restore_text(format!("복원 중… {done}/{total}").into());
                        }
                    });
                }
            }
        };
        let opts = kova_engine::ops::RestoreOptions {
            repo: repo_path,
            session_id: sid,
            only,
            target: Some(target.clone()),
        };
        let cancel = AtomicBool::new(false);
        let text = match kova_engine::ops::run_restore(&opts, &on_event, &cancel) {
            Ok(s) => format!(
                "복원 완료: {} (항목 {}개, {:.0}초)",
                target.display(),
                s.total_files,
                s.elapsed_seconds
            ),
            Err(e) => format!("복원 실패: {e}"),
        };
        show(&weak, text);
    });
}

/// 클라우드(Google Drive / S3)에서 로컬 저장소로 스트리밍 복원(Pull)을 수행한다.
pub(crate) fn cloud_pull_job(
    weak: slint::Weak<MainWindow>,
    provider: String,
    dest_repo: String,
    gate: BusyGate,
) {
    if app_locked() {
        let _ = weak.upgrade_in_event_loop(|w| w.set_cloud_ops_text(LOCKED_MSG.into()));
        return;
    }
    let dest = dest_repo.trim().to_string();
    if dest.is_empty() {
        let _ = weak.upgrade_in_event_loop(|w| {
            w.set_cloud_ops_text("클라우드에서 내려받을 대상 로컬 저장소 폴더를 입력하세요".into())
        });
        return;
    }
    let Some(guard) = gate.lock() else {
        let _ = weak.upgrade_in_event_loop(|w| {
            w.set_cloud_ops_text("이미 클라우드 복원 또는 정리 작업이 진행 중입니다.".into())
        });
        return;
    };
    let _ = weak.upgrade_in_event_loop(|w| {
        w.set_cloud_ops_text("클라우드에서 백업 데이터를 내려받는 중…".into())
    });
    std::thread::spawn(move || {
        let _guard = guard;
        let req = kova_ipc::Request::CloudPull {
            provider,
            dest_repo: dest,
        };
        let mut last = std::time::Instant::now() - std::time::Duration::from_secs(5);
        let mut result: Option<Result<String, String>> = None;
        let r = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| {
                rt.block_on(kova_ipc::stream(kova_ipc::PIPE_NAME, &req, |e| match e {
                    kova_ipc::Event::RestoreProgress { done, total } => {
                        if last.elapsed() >= std::time::Duration::from_millis(500) {
                            last = std::time::Instant::now();
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_cloud_ops_text(
                                    format!("클라우드 복원 중… {done}/{total}").into(),
                                )
                            });
                        }
                        true
                    }
                    kova_ipc::Event::Done { message } => {
                        result = Some(Ok(message));
                        false
                    }
                    kova_ipc::Event::Error { message } => {
                        result = Some(Err(message));
                        false
                    }
                    _ => true,
                }))
                .map_err(|e| e.to_string())
            });
        let msg = match (result, r) {
            (Some(Ok(m)), _) => m,
            (Some(Err(e)), _) => format!("클라우드 복원 실패: {e}"),
            (None, Err(e)) => format!("클라우드 복원 실패: 서비스 연결 오류 ({e})"),
            (None, Ok(())) => "클라우드 복원 실패: 서비스 응답이 끊겼습니다".into(),
        };
        let _ = weak.upgrade_in_event_loop(move |w| w.set_cloud_ops_text(msg.into()));
    });
}

/// 원격 클라우드 저장소 고아 파일 정리(GC)를 서비스(`Request::CloudPrune`)에 요청한다.
pub(crate) fn cloud_prune_job(weak: slint::Weak<MainWindow>, profile_hint: String, gate: BusyGate) {
    if app_locked() {
        let _ = weak.upgrade_in_event_loop(|w| w.set_cloud_ops_text(LOCKED_MSG.into()));
        return;
    }
    let Some(guard) = gate.lock() else {
        let _ = weak.upgrade_in_event_loop(|w| {
            w.set_cloud_ops_text("이미 클라우드 복원 또는 정리 작업이 진행 중입니다.".into())
        });
        return;
    };
    let _ = weak.upgrade_in_event_loop(|w| {
        w.set_cloud_ops_text("원격 클라우드 고아 파일 정리(GC) 중…".into())
    });
    std::thread::spawn(move || {
        let _guard = guard;
        let store = ConfigStore::new(kova_service::default_config_dir());
        let msg = match resolve_profile_id(&store, &profile_hint) {
            Some(pid) => match ipc_done(&kova_ipc::Request::CloudPrune { profile_id: pid }) {
                Ok(m) => m,
                Err(e) => format!("원격 정리 실패: {e}"),
            },
            None => "정리할 프로파일을 찾을 수 없습니다. 먼저 백업 프로파일을 생성하세요".into(),
        };
        let _ = weak.upgrade_in_event_loop(move |w| w.set_cloud_ops_text(msg.into()));
    });
}

fn current_recovery_code(weak: &slint::Weak<MainWindow>) -> Option<String> {
    weak.upgrade()
        .map(|w| w.get_restore_recovery_code().to_string())
        .filter(|s| !s.trim().is_empty())
}

pub(crate) fn wire(w: &MainWindow, banner_gen: &Arc<AtomicU64>) {
    // Global cross-snapshot search & single-file restore
    {
        let weak = w.as_weak();
        w.on_global_search(move |q| {
            let query = q.trim().to_string();
            if query.is_empty() {
                if let Some(w) = weak.upgrade() {
                    w.set_global_results(slint::ModelRc::new(slint::VecModel::from(Vec::new())));
                    w.set_global_status("검색어를 입력하세요 (파일명 또는 초성)".into());
                }
                return;
            }
            if let Some(w) = weak.upgrade() {
                w.set_global_status("전체 스냅샷 검색 중…".into());
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                let found = search_all_repos(&store, &query);
                let count = found.len();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        let rows: Vec<GlobalFileRow> = found
                            .into_iter()
                            .map(|(filename, rel_path, repo, sid, vc, info)| GlobalFileRow {
                                filename: filename.into(),
                                rel_path: rel_path.into(),
                                repo: repo.into(),
                                snapshot_id: sid.into(),
                                versions: format!("{vc}개 버전").into(),
                                info: info.into(),
                            })
                            .collect();
                        w.set_global_results(slint::ModelRc::new(slint::VecModel::from(rows)));
                        w.set_global_status(
                            if count == 0 {
                                format!("'{query}' 에 일치하는 백업 파일이 없습니다")
                            } else {
                                format!("'{query}' 검색 결과 {count}건 (최신 시점 기준)")
                            }
                            .into(),
                        );
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_global_restore(move |repo, sid, rel_path, target| {
            let only = Some(vec![rel_path.to_string()]);
            let rec = current_recovery_code(&weak);
            if target.as_str() == "@원래자리" {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        w.set_restore_text(LOCKED_MSG.into());
                    }
                    return;
                }
                restore_inplace_job(weak.clone(), repo.to_string(), sid.to_string(), only, rec);
            } else {
                restore_snapshot_job(
                    weak.clone(),
                    repo.to_string(),
                    sid.to_string(),
                    target.to_string(),
                    only,
                    rec,
                );
            }
        });
    }

    // Snapshot Diff viewer
    {
        let weak = w.as_weak();
        w.on_diff_snapshot(move |repo, sid, title| {
            diff_snapshot_job(
                weak.clone(),
                repo.to_string(),
                sid.to_string(),
                title.to_string(),
            );
        });
    }

    // Full snapshot restore / delete / GC
    {
        let weak = w.as_weak();
        w.on_restore_snapshot(move |repo, sid, t| {
            let rec = current_recovery_code(&weak);
            restore_snapshot_job(
                weak.clone(),
                repo.to_string(),
                sid.to_string(),
                t.to_string(),
                None,
                rec,
            )
        });

        let weak = w.as_weak();
        w.on_restore_inplace(move |repo, sid| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_restore_text(LOCKED_MSG.into());
                }
                return;
            }
            let rec = current_recovery_code(&weak);
            restore_inplace_job(weak.clone(), repo.to_string(), sid.to_string(), None, rec)
        });

        let weak = w.as_weak();
        let bg = banner_gen.clone();
        w.on_run_gc(move |id| {
            bg.fetch_add(1, Ordering::SeqCst);
            if let Some(w) = weak.upgrade() {
                w.set_job_completed_show(false);
            }
            let locked = app_locked();
            let (weak, id) = (weak.clone(), id.to_string());
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                match gc_target(locked, &store, &id) {
                    Ok(pid) => send_sync(weak, "gc".into(), pid),
                    Err(e) => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                w.set_restore_text(e.into());
                            }
                        });
                    }
                }
            });
        });

        let weak = w.as_weak();
        w.on_delete_snapshot(move |repo, sid| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_restore_text(LOCKED_MSG.into());
                }
                return;
            }
            let (repo, sid) = (repo.to_string(), sid.to_string());
            let weak = weak.clone();
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                let pid = resolve_profile_id(&store, &repo);
                let via_service = pid.and_then(|pid| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    rt.block_on(kova_ipc::request(
                        kova_ipc::PIPE_NAME,
                        &kova_ipc::Request::RunNow {
                            profile_id: pid,
                            kind: format!("delsnap:{sid}"),
                        },
                    ))
                    .ok()
                });
                let text = if via_service.is_some() {
                    "삭제를 요청했습니다. 잠시 뒤 목록에서 사라집니다(실패하면 알림에 표시됩니다)"
                        .to_string()
                } else {
                    match kova_core::retention::delete_snapshot(Path::new(&repo), &sid) {
                        Ok(m) | Err(m) => m,
                    }
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_restore_text(text.into());
                    }
                });
            });
        });
    }

    // Snapshot File Browser
    {
        let st: Browse = Default::default();
        let weak = w.as_weak();
        let s2 = st.clone();
        w.on_open_browse(move |repo, sid, title| {
            {
                let mut s = s2.lock().unwrap();
                let seq = s.seq;
                *s = BrowseState {
                    repo: repo.to_string(),
                    sid: sid.to_string(),
                    seq,
                    ..Default::default()
                };
            }
            if let Some(w) = weak.upgrade() {
                w.set_browse_title(title);
            }
            browse_load(weak.clone(), s2.clone(), String::new(), String::new());
        });

        let (weak, s2) = (w.as_weak(), st.clone());
        w.on_browse_go(move |d| {
            browse_load(weak.clone(), s2.clone(), d.to_string(), String::new())
        });

        let (weak, s2) = (w.as_weak(), st.clone());
        w.on_browse_up(move || {
            let d = parent_dir(&s2.lock().unwrap().dir);
            browse_load(weak.clone(), s2.clone(), d, String::new());
        });

        let (weak, s2) = (w.as_weak(), st.clone());
        w.on_browse_search(move |q| {
            let dir = s2.lock().unwrap().dir.clone();
            browse_load(weak.clone(), s2.clone(), dir, q.trim().to_string());
        });

        let (weak, s2) = (w.as_weak(), st.clone());
        w.on_browse_toggle(move |p| {
            {
                let mut s = s2.lock().unwrap();
                if !s.sel.remove(p.as_str()) {
                    s.sel.insert(p.to_string());
                }
            }
            browse_render(&weak, &s2, String::new());
        });

        let (weak, s2) = (w.as_weak(), st);
        w.on_browse_restore(move |t| {
            let (repo, sid, sel) = {
                let s = s2.lock().unwrap();
                (
                    s.repo.clone(),
                    s.sid.clone(),
                    s.sel.iter().cloned().collect::<Vec<_>>(),
                )
            };
            if sel.is_empty() {
                if let Some(w) = weak.upgrade() {
                    w.set_restore_text("복원할 파일이나 폴더를 먼저 선택하세요".into());
                }
                return;
            }
            let rec = current_recovery_code(&weak);
            if t.as_str() == "@원래자리" {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        w.set_restore_text(LOCKED_MSG.into());
                    }
                    return;
                }
                restore_inplace_job(weak.clone(), repo, sid, Some(sel), rec);
            } else {
                restore_snapshot_job(weak.clone(), repo, sid, t.to_string(), Some(sel), rec);
            }
        });
    }

    // Cloud Pull & Remote GC (Settings Tab 2)
    {
        let cloud_gate = BusyGate::default();
        let weak = w.as_weak();
        let g1 = cloud_gate.clone();
        w.on_cloud_pull(move |prov, dest| {
            cloud_pull_job(weak.clone(), prov.to_string(), dest.to_string(), g1.clone());
        });

        let weak = w.as_weak();
        w.on_cloud_prune(move |pid| {
            cloud_prune_job(weak.clone(), pid.to_string(), cloud_gate.clone());
        });
    }
}

use super::*;
use crate::jobs_image::{remove_stale_partials, speed_note};
use crate::jobs_maint::extract_vss_guids;
use kova_core::history::History;
use std::fs;

fn wait_idle(s: &Supervisor) {
    let t = Instant::now();
    while s.counts() != (0, 0) {
        assert!(t.elapsed() < Duration::from_secs(60), "작업이 끝나지 않음");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn setup(src_exists: bool) -> (tempfile::TempDir, Supervisor) {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("원본");
    if src_exists {
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), "안녕 kova").unwrap();
    }
    let mut p = Profile::new("p1", "시험");
    p.sources = vec![src.to_string_lossy().into()];
    p.repo_dir = d.path().join("repo").to_string_lossy().into();
    p.auto_backup_enabled = true;
    let cfg = d.path().join("cfg");
    let store = ConfigStore::new(&cfg);
    store.upsert(p).unwrap();
    // 시험은 섀도 복사본을 만들지 않는다(실제 VSS 시험은 따로 --ignored 로 돌린다)
    let mut st = store.settings();
    st.use_vss = false;
    store.save_settings(&st).unwrap();
    (d, Supervisor::new(cfg, 2))
}

/// KOVA2_KEY_DIR 를 바꾸는 시험끼리 겹치지 않게 한다.
static KEY_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct KeyDirGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl KeyDirGuard {
    fn new() -> Self {
        let lock = KEY_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("KOVA2_KEY_DIR", dir.path());
        Self { _lock: lock, dir }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

impl Drop for KeyDirGuard {
    fn drop(&mut self) {
        std::env::remove_var("KOVA2_KEY_DIR");
    }
}

#[test]
fn tick_warns_when_backup_is_stale_and_runs_periodic_drill() {
    let (d, s) = setup(true);
    assert_eq!(s.tick(Local::now()), 1);
    wait_idle(&s);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut p = store.get("p1").unwrap();
    assert!(p.extra.contains_key("last_success_at") && p.extra.contains_key("last_drill_at"));
    p.auto_backup_enabled = false;
    // 검증·GC 는 이 시험의 대상이 아니므로 이미 한 것으로 해 둔다(작업이 실제 시각을 기록해 가짜 미래 시각과 어긋나기 때문)
    let later = Local::now() + chrono::Duration::days(10);
    p.extra
        .insert("last_verify_at".into(), (later.timestamp() as f64).into());
    p.extra
        .insert("last_gc_at".into(), (later.timestamp() as f64).into());
    store.upsert(p).unwrap();
    // 10일 뒤: 백업 성공 기록이 오래돼 경고가 남고, 주기 복구 훈련이 돈다
    let t = Instant::now();
    let later_ts = later.timestamp() as f64;
    loop {
        let p = store.get("p1").unwrap();
        if let Some(txt) = p.extra.get("last_drill_text").and_then(|v| v.as_str()) {
            assert!(txt.contains("통과"), "{txt}");
            break;
        }
        // 같은 시점에 도래한 검증·GC 가 먼저 끝나야 훈련이 시작된다. 훈련이 시작된 뒤에는 다른 작업이 겹치지 않게 틱을 멈춘다
        let started = p
            .extra
            .get("last_drill_at")
            .and_then(|v| v.as_f64())
            .is_some_and(|t| t >= later_ts - 1.0);
        if !started {
            s.tick(later);
            wait_idle(&s);
        }
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "drill timeout {:?} later={later_ts}",
            p.extra
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let alerts = kova_core::alerts::AlertLog::new(&d.path().join("cfg")).list();
    assert!(alerts
        .iter()
        .any(|a| a.message.contains("일째 백업 성공 기록이 없습니다")));
    // 같은 날 다시 틱해도 경고가 중복되지 않는다
    let n = alerts.len();
    s.tick(later);
    assert_eq!(
        kova_core::alerts::AlertLog::new(&d.path().join("cfg"))
            .list()
            .len(),
        n
    );
}

#[test]
fn tick_runs_backup_updates_profile_and_pushes_events() {
    let (d, s) = setup(true);
    let rx = s.subscribe();
    assert_eq!(s.tick(Local::now()), 1);
    wait_idle(&s);
    let p = ConfigStore::new(d.path().join("cfg")).get("p1").unwrap();
    assert_eq!(p.last_status, "success");
    assert!(p.last_snapshot_id.is_some() && p.last_run.is_some());
    let evs: Vec<SvcEvent> = rx.try_iter().collect();
    assert!(matches!(evs.first(), Some(SvcEvent::JobStarted { .. })));
    assert!(matches!(
        evs.last(),
        Some(SvcEvent::JobFinished { ok: true, .. })
    ));
    // 이력 DB 가 스냅샷을 반영했다
    let h = History::open(&d.path().join("repo")).unwrap();
    assert_eq!(h.list_snapshots().unwrap().len(), 1);
    // 방금 돌았으니 바로 다시 큐잉되지 않는다
    assert_eq!(s.tick(Local::now()), 0);
}

#[test]
fn failure_is_recorded_with_retry_count() {
    let (d, s) = setup(false);
    let rx = s.subscribe();
    s.tick(Local::now());
    wait_idle(&s);
    let p = ConfigStore::new(d.path().join("cfg")).get("p1").unwrap();
    assert_eq!(p.last_status, "failed");
    assert_eq!(kova_core::schedule::retry_count(&p), 1);
    assert!(rx
        .try_iter()
        .any(|e| matches!(e, SvcEvent::JobFinished { ok: false, .. })));
}

#[test]
#[cfg(windows)]
fn backup_is_refused_when_free_space_is_below_the_minimum() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.min_free_disk_gb = 100_000_000; // 어떤 디스크에도 없는 크기
    store.save_settings(&st).unwrap();
    let rx = s.subscribe();
    s.tick(Local::now());
    wait_idle(&s);
    let evs: Vec<SvcEvent> = rx.try_iter().collect();
    let msg = evs.iter().find_map(|e| match e {
        SvcEvent::JobFinished {
            ok: false, message, ..
        } => Some(message.clone()),
        _ => None,
    });
    assert!(
        msg.is_some_and(|m| m.contains("여유 공간이 부족")),
        "{evs:?}"
    );
    // 백업이 시작되지 않았으니 스냅샷이 없다
    assert_eq!(store.get("p1").unwrap().last_status, "failed");
    assert!(store.get("p1").unwrap().last_snapshot_id.is_none());
    // 기준을 0(검사 끔)으로 낮추면 같은 프로파일이 정상 백업된다
    st.min_free_disk_gb = 0;
    store.save_settings(&st).unwrap();
    let mut p = store.get("p1").unwrap();
    p.last_run = None;
    p.extra.insert("retry_count".into(), 0.into());
    store.upsert(p).unwrap();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert_eq!(store.get("p1").unwrap().last_status, "success");
}

/// 실제 VSS 로 백업한다(관리자 권한 필요): `cargo test -p kova-service vss -- --ignored`
#[test]
#[ignore]
#[cfg(windows)]
fn vss_backup_reads_from_shadow_and_records_original_paths() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.use_vss = true;
    st.min_free_disk_gb = 0;
    st.enable_ransomware_protection = false;
    store.save_settings(&st).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let evs: Vec<SvcEvent> = rx.try_iter().collect();
    let msg = evs.iter().find_map(|e| match e {
        SvcEvent::JobFinished {
            ok: true, message, ..
        } => Some(message.clone()),
        _ => None,
    });
    assert!(
        msg.as_ref()
            .is_some_and(|m| m.contains("VSS 스냅샷 1개 사용")),
        "{evs:?}"
    );
    // 매니페스트에는 섀도 경로가 아니라 원래 원본 경로가 기록되고, 복원하면 내용이 같다
    let sid = store.get("p1").unwrap().last_snapshot_id.unwrap();
    let manifest = fs::read_to_string(
        d.path()
            .join("repo")
            .join("snapshots")
            .join(format!("{sid}.json")),
    )
    .unwrap();
    assert!(!manifest.contains("GLOBALROOT"), "{manifest}");
    let out = d.path().join("out");
    let ro = kova_engine::ops::RestoreOptions {
        repo: d.path().join("repo"),
        session_id: sid,
        target: Some(out.clone()),
        only: None,
    };
    kova_engine::ops::run_restore(&ro, &|_| {}, &AtomicBool::new(false)).unwrap();
    let found = fs::read_dir(&out)
        .unwrap()
        .flatten()
        .any(|e| e.path().join("a.txt").is_file() || e.file_name() == "a.txt");
    assert!(found);
}

#[test]
#[cfg(windows)]
fn encryption_refuses_plain_backup_then_writes_only_ciphertext() {
    let _keys = KeyDirGuard::new();
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.min_free_disk_gb = 0;
    st.enable_ransomware_protection = false;
    st.encrypt_backups = true;
    store.save_settings(&st).unwrap();
    let repo = d.path().join("repo");
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let p = store.get("p1").unwrap();
    assert_eq!(p.last_status, "failed");
    assert!(!repo.join("blobs").exists() || kova_core::repocrypto::is_enabled(&repo));
    kova_core::repocrypto::enable(&repo).unwrap();
    let mut p = store.get("p1").unwrap();
    p.last_run = None;
    p.extra.insert("retry_count".into(), 0.into());
    store.upsert(p).unwrap();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert_eq!(store.get("p1").unwrap().last_status, "success");
    // 백업은 새 블롭을 팩 파일로 쓴다
    let blob = fs::read_dir(repo.join("packs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "pack"))
        .unwrap();
    assert_eq!(&fs::read(&blob).unwrap()[..4], b"ENC\x01");
}

#[test]
fn ransomware_protection_locks_new_files_and_retention_still_deletes() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.enable_ransomware_protection = true;
    st.min_free_disk_gb = 0;
    store.save_settings(&st).unwrap();
    let repo = d.path().join("repo");
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert_eq!(store.get("p1").unwrap().last_status, "success");
    let first = store.get("p1").unwrap().last_snapshot_id.unwrap();
    let manifest = repo.join("snapshots").join(format!("{first}.json"));
    let ro = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().readonly();
    assert!(ro(&manifest), "매니페스트가 잠겨야 함");
    // 백업은 새 블롭을 팩 파일로 쓴다
    let blob = fs::read_dir(repo.join("packs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "pack"))
        .unwrap();
    assert!(ro(&blob) && fs::write(&blob, b"x").is_err());
    // 보존 개수를 1로 줄이고 새 백업을 만들면 잠긴 옛 스냅샷도 서비스가 승인 경로로 지운다
    let mut p = store.get("p1").unwrap();
    p.retention_count = 1;
    p.last_run = None;
    store.upsert(p).unwrap();
    fs::write(d.path().join("원본").join("b.txt"), "새 파일").unwrap();
    std::thread::sleep(Duration::from_millis(1200)); // 스냅샷 ID·시각이 초 단위라 겹치지 않게
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert!(!manifest.exists(), "옛 스냅샷이 정리되어야 함");
    // 임시 폴더를 지울 수 있도록 잠금 해제
    let _ = kova_core::worm::unprotect_directory(&repo, true);
}

#[test]
fn partially_missing_sources_are_skipped_with_a_note() {
    let (d, s) = setup(true);
    let mut p = ConfigStore::new(d.path().join("cfg")).get("p1").unwrap();
    let gone = d.path().join("없는폴더").to_string_lossy().to_string();
    p.sources.push(gone.clone());
    ConfigStore::new(d.path().join("cfg")).upsert(p).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let done = rx
        .try_iter()
        .find_map(|e| match e {
            SvcEvent::JobFinished { ok, message, .. } => Some((ok, message)),
            _ => None,
        })
        .unwrap();
    assert!(done.0, "{}", done.1);
    assert!(
        done.1.contains("원본 1개 없어 제외") && done.1.contains(&gone),
        "{}",
        done.1
    );
}

#[test]
fn gc_job_removes_only_old_orphans() {
    let (d, s) = setup(true);
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let blobs = d.path().join("repo").join("blobs").join("zz");
    fs::create_dir_all(&blobs).unwrap();
    let young = blobs.join("young.blob");
    fs::write(&young, b"x").unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Gc);
    wait_idle(&s);
    assert!(rx
        .try_iter()
        .any(|e| matches!(e, SvcEvent::JobFinished { ok: true, .. })));
    assert!(young.exists(), "1시간 미만 블롭은 지우지 않는다");
}

/// 실계정 시험(수동): 앱에서 구글 드라이브를 연결한 뒤 `cargo test -p kova-service real_drive -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_drive_backup_replicates_via_service() {
    let (d, s) = setup(true);
    let real = std::path::PathBuf::from(std::env::var("ProgramData").unwrap())
        .join("Kova2")
        .join("config");
    let cfg = d.path().join("cfg");
    for f in ["gdrive_client.json", "gdrive_token.bin"] {
        std::fs::copy(real.join(f), cfg.join(f)).unwrap();
    }
    let store = ConfigStore::new(cfg);
    let mut st = store.settings();
    st.offsite_provider = "gdrive".into();
    store.save_settings(&st).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let msg = rx
        .try_iter()
        .find_map(|e| {
            if let SvcEvent::JobFinished { message, .. } = e {
                Some(message)
            } else {
                None
            }
        })
        .expect("완료 이벤트");
    println!("MSG: {msg}");
    assert!(msg.contains("구글 드라이브 복제 1개 스냅샷"), "{msg}");
}

#[test]
fn backup_replicates_to_offsite_dir_when_configured() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut p = store.get("p1").unwrap();
    let off = d.path().join("offsite");
    p.extra.insert(
        "offsite_dir".into(),
        off.to_string_lossy().to_string().into(),
    );
    store.upsert(p).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let msg = rx
        .try_iter()
        .find_map(|e| {
            if let SvcEvent::JobFinished {
                ok: true, message, ..
            } = e
            {
                Some(message)
            } else {
                None
            }
        })
        .expect("성공 이벤트");
    assert!(msg.contains("오프사이트 복제 1개 스냅샷"), "{msg}");
    assert!(kova_core::verify::verify_repo(&off, true).unwrap().ok());
}

#[test]
fn failure_leaves_an_alert_but_success_does_not() {
    let (d, s) = setup(false);
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let log = kova_core::alerts::AlertLog::new(&d.path().join("cfg"));
    let v = log.list();
    assert_eq!(v.len(), 1);
    assert_eq!(
        (v[0].level.as_str(), v[0].profile_id.as_str()),
        ("error", "p1")
    );
    let (d2, s2) = setup(true);
    s2.enqueue("p1", Kind::Backup);
    wait_idle(&s2);
    assert!(kova_core::alerts::AlertLog::new(&d2.path().join("cfg"))
        .list()
        .is_empty());
}

#[test]
fn sleep_guard_can_be_created_and_dropped() {
    drop(SleepGuard::new());
}

#[test]
fn resolve_profile_handles_id_repo_and_default() {
    let (d, s) = setup(true);
    // 1. Direct ID
    assert_eq!(s.resolve_profile("p1").map(|p| p.id), Some("p1".into()));
    // 2. Repo path
    let repo_str = d.path().join("repo").to_string_lossy().to_string();
    assert_eq!(
        s.resolve_profile(&repo_str).map(|p| p.id),
        Some("p1".into())
    );
    // 3. "default" and empty string
    assert_eq!(
        s.resolve_profile("default").map(|p| p.id),
        Some("p1".into())
    );
    assert_eq!(s.resolve_profile("").map(|p| p.id), Some("p1".into()));
    assert_eq!(s.resolve_profile("   ").map(|p| p.id), Some("p1".into()));
    // 4. Snapshot ID file check
    let snap_dir = d.path().join("repo").join("snapshots");
    std::fs::create_dir_all(&snap_dir).unwrap();
    std::fs::write(snap_dir.join("20261121_103641.json"), "{}").unwrap();
    assert_eq!(
        s.resolve_profile("20261121_103641").map(|p| p.id),
        Some("p1".into())
    );
    // 5. Unknown string
    assert_eq!(s.resolve_profile("nonexistent"), None);
}

#[test]
fn manual_enqueue_and_unknown_profile() {
    let (_d, s) = setup(true);
    let rx = s.subscribe();
    assert!(matches!(
        s.enqueue("없음", Kind::Backup),
        Enqueue::Queued(_)
    ));
    wait_idle(&s);
    assert!(rx
        .try_iter()
        .any(|e| matches!(e, SvcEvent::JobFinished { ok: false, .. })));
}

#[test]
fn verify_job_passes_after_backup() {
    let (d, s) = setup(true);
    s.tick(Local::now());
    wait_idle(&s);
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Verify);
    wait_idle(&s);
    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobFinished { ok: true, ref message, .. } if message.contains("정밀 검증 통과")
    )));
    let log = fs::read_to_string(kova_core::applog::log_path(&d.path().join("cfg"))).unwrap();
    assert!(log.contains("작업 시작") && log.contains("작업 종료"));
    // 화면이 읽는 스냅샷 기록에도 검증 결과가 남아야 한다
    let h = History::open(&d.path().join("repo")).unwrap();
    let recs = h.list_snapshots().unwrap();
    assert!(
        !recs.is_empty()
            && recs
                .iter()
                .all(|r| r.is_verified && r.verify_error_count == 0)
    );
}

#[test]
fn repo_lock_blocks_concurrent_backup_and_verify() {
    let (d, s) = setup(true);
    let repo = d.path().join("repo");
    let _held = kova_core::lock::RepoLock::try_acquire(&repo).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobFinished { ok: false, ref message, .. } if message.contains("다른 작업이 저장소를 사용 중")
    )));
}

#[test]
fn maintenance_tick_queues_deep_verify_and_gc_after_interval() {
    let (d, s) = setup(true);
    let now = Local::now();
    s.tick(now);
    wait_idle(&s);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut p = store.get("p1").unwrap();
    p.auto_backup_enabled = false;
    let eight_days_ago = now.timestamp() as f64 - 8.0 * 86_400.0;
    p.extra
        .insert("last_verify_at".into(), eight_days_ago.into());
    p.extra.insert("last_gc_at".into(), eight_days_ago.into());
    store.upsert(p).unwrap();

    let rx = s.subscribe();
    assert_eq!(s.tick(now), 1);
    wait_idle(&s);
    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobStarted {
            kind: Kind::Verify,
            ..
        }
    )));
    // 검증이 끝난 직후 다음 틱에서는 밀린 GC가 예약된다
    let rx2 = s.subscribe();
    assert_eq!(s.tick(now), 1);
    wait_idle(&s);
    assert!(rx2
        .try_iter()
        .any(|e| matches!(e, SvcEvent::JobStarted { kind: Kind::Gc, .. })));
}

#[test]
fn ransomware_anomaly_pauses_retention_and_emits_alert() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.enable_ransomware_protection = false;
    store.save_settings(&st).unwrap();
    let mut p = store.get("p1").unwrap();
    p.retention_count = 1;
    store.upsert(p).unwrap();

    // 1차 정상 백업
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let first_sid = store.get("p1").unwrap().last_snapshot_id.unwrap();

    // 랜섬웨어 의심 확장자(.locked) 파일 6개 생성 후 2차 백업
    let src = d.path().join("원본");
    for i in 0..6 {
        fs::write(src.join(format!("doc{i}.locked")), "encrypted").unwrap();
    }
    std::thread::sleep(Duration::from_millis(1200));
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);

    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobFinished { ok: true, ref message, .. } if message.contains("이상 징후")
    )));
    // retention_count=1 이더라도 이상 징후 감지 시 1차 정상 스냅샷이 삭제되지 않고 보존된다
    let first_manifest = d
        .path()
        .join("repo")
        .join("snapshots")
        .join(format!("{first_sid}.json"));
    assert!(first_manifest.exists(), "정상 옛 스냅샷이 보존되어야 함");
    // 경고 알림도 기록되어야 함
    let alerts = kova_core::alerts::AlertLog::new(&d.path().join("cfg")).list();
    assert!(alerts
        .iter()
        .any(|a| a.level == "warning" && a.message.contains("이상 징후")));
}

#[test]
fn image_job_rejects_non_fixed_drive_and_leaves_no_output() {
    let (d, s) = setup(true);
    let rx = s.subscribe();
    // 존재하지 않는 드라이브(Q:)는 고정 드라이브가 아니라 섀도 복사본을 만들기 전에 거부된다
    s.enqueue("p1", Kind::Image('Q'));
    wait_idle(&s);
    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobFinished { ok: false, ref message, .. } if message.contains("고정")
    )));
    let imgs = d.path().join("repo").join("images");
    assert!(!imgs.exists() || std::fs::read_dir(imgs).unwrap().count() == 0);
}

#[tokio::test]
async fn run_now_over_pipe_streams_events_to_subscriber() {
    let (_d, s) = setup(true);
    let name = format!(r"\\.\pipe\kova-svc-test-{}", std::process::id());
    let h: Arc<dyn kova_ipc::Handler> = Arc::new(IpcHandler(s));
    let n2 = name.clone();
    tokio::spawn(async move {
        let _ = kova_ipc::serve(&n2, h).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let n3 = name.clone();
    let sub = tokio::spawn(async move {
        kova_ipc::request_until(&n3, &kova_ipc::Request::Subscribe, |e| {
            matches!(e, kova_ipc::Event::JobFinished { .. })
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let q = kova_ipc::request(
        &name,
        &kova_ipc::Request::RunNow {
            profile_id: "p1".into(),
            kind: "backup".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        q[0],
        kova_ipc::Event::Queued { merged: false, .. }
    ));
    let evs = sub.await.unwrap().unwrap();
    assert!(matches!(
        evs.first(),
        Some(kova_ipc::Event::JobStarted { .. })
    ));
    assert!(matches!(
        evs.last(),
        Some(kova_ipc::Event::JobFinished { ok: true, .. })
    ));
    let bad = kova_ipc::request(
        &name,
        &kova_ipc::Request::RunNow {
            profile_id: "p1".into(),
            kind: "format".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(bad[0], kova_ipc::Event::Error { .. }));
}

#[test]
fn retention_runs_after_backup_for_this_profile_only() {
    let (d, s) = setup(true);
    let cfg = ConfigStore::new(d.path().join("cfg"));
    let mut p = cfg.get("p1").unwrap();
    p.retention_count = 1;
    cfg.upsert(p).unwrap();
    // 다른 프로파일이 같은 저장소에 만든 스냅샷은 건드리면 안 된다
    let snaps = d.path().join("repo/snapshots");
    fs::create_dir_all(&snaps).unwrap();
    fs::write(
        snaps.join("other1.json"),
        r#"{"id":"other1","created_at":1,"profile_id":"zzz"}"#,
    )
    .unwrap();
    fs::write(
        snaps.join("other2.json"),
        r#"{"id":"other2","created_at":2,"profile_id":"zzz"}"#,
    )
    .unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    std::thread::sleep(Duration::from_millis(1100)); // 세션 ID 가 초 단위라 겹치지 않게
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let mine: Vec<_> = fs::read_dir(&snaps)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with("other"))
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "retention_count=1 이면 내 스냅샷은 1개만 남아야 함: {mine:?}"
    );
    assert!(snaps.join("other1.json").exists() && snaps.join("other2.json").exists());
    assert!(rx.try_iter().any(
        |e| matches!(e, SvcEvent::JobFinished { ref message, .. } if message.contains("정리"))
    ));
}

#[test]
fn resolve_profile_disambiguates_shared_repo_by_manifest_profile_id() {
    let (d, s) = setup(false);
    let cfg = ConfigStore::new(d.path().join("cfg"));
    let mut p2 = Profile::new("p2", "프로파일 2");
    p2.repo_dir = d.path().join("repo").to_string_lossy().to_string();
    cfg.upsert(p2).unwrap();
    // p1 and p2 share repo_dir.
    let snaps = d.path().join("repo/snapshots");
    fs::create_dir_all(&snaps).unwrap();
    fs::write(
        snaps.join("snap_for_p2.json"),
        r#"{"id":"snap_for_p2","profile_id":"p2","files":[{"path":"test","size":10}]}"#,
    )
    .unwrap();
    let resolved = s.resolve_profile("snap_for_p2");
    assert_eq!(resolved.as_ref().map(|p| p.id.as_str()), Some("p2"));
}

#[test]
fn resolve_profile_disambiguates_shared_repo_encrypted_snapshot_by_history() {
    let (d, s) = setup(false);
    let cfg = ConfigStore::new(d.path().join("cfg"));
    let mut p2 = Profile::new("p2", "프로파일 2");
    p2.repo_dir = d.path().join("repo").to_string_lossy().to_string();
    cfg.upsert(p2).unwrap();

    let repo = d.path().join("repo");
    let snaps = repo.join("snapshots");
    fs::create_dir_all(&snaps).unwrap();
    // Encrypted snapshot file (.enc cannot be loaded as plaintext json by CasStorage)
    fs::write(snaps.join("snap_enc_p2.json.enc"), b"cipher_data").unwrap();

    // Record in SQLite History
    let _ = History::open(&repo).unwrap();
    let conn = kova_core::rusqlite::Connection::open(repo.join("metadata.db")).unwrap();
    conn.execute(
        "INSERT INTO snapshots_meta (id, profile_id) VALUES (?1, ?2)",
        kova_core::rusqlite::params!["snap_enc_p2", "p2"],
    )
    .unwrap();

    let resolved = s.resolve_profile("snap_enc_p2");
    assert_eq!(resolved.as_ref().map(|p| p.id.as_str()), Some("p2"));
}

fn first_error(r: kova_ipc::Reply) -> Option<String> {
    match r {
        kova_ipc::Reply::Once(v) => v.into_iter().find_map(|e| match e {
            kova_ipc::Event::Error { message } => Some(message),
            _ => None,
        }),
        kova_ipc::Reply::Stream(_) => None,
    }
}

fn once_events(r: kova_ipc::Reply) -> Vec<kova_ipc::Event> {
    match r {
        kova_ipc::Reply::Once(v) => v,
        kova_ipc::Reply::Stream(_) => panic!("Once 여야 함"),
    }
}

fn run_now(kind: &str, pid: &str) -> kova_ipc::Request {
    kova_ipc::Request::RunNow {
        profile_id: pid.into(),
        kind: kind.into(),
    }
}

#[test]
fn ipc_refuses_destructive_requests_from_unprivileged_callers() {
    use kova_ipc::{Caller, Handler};
    let (_d, s) = setup(true);
    let h = IpcHandler(s.clone());
    let user = Caller { privileged: false };
    for kind in ["delsnap:20261121_000000", "gc", "image:C", "image_inc:C"] {
        let msg = first_error(h.handle(run_now(kind, "p1"), user));
        assert!(
            msg.as_deref().is_some_and(|m| m.contains("관리자 권한")),
            "{kind}: {msg:?}"
        );
    }
    assert!(
        first_error(h.handle(kova_ipc::Request::Cancel { job_id: 1 }, user))
            .is_some_and(|m| m.contains("관리자 권한"))
    );
    assert_eq!(s.counts(), (0, 0), "거부된 요청은 큐에 들어가면 안 됨");
    // 백업·검증·상태는 일반 사용자도 된다
    assert!(first_error(h.handle(run_now("backup", "p1"), user)).is_none());
    wait_idle(&s);
    assert!(first_error(h.handle(run_now("verify", "p1"), user)).is_none());
    wait_idle(&s);
    assert!(first_error(h.handle(kova_ipc::Request::Status, user)).is_none());
    // 관리자 호출자는 정리 요청을 낼 수 있다
    let admin = Caller { privileged: true };
    assert!(first_error(h.handle(run_now("gc", "p1"), admin)).is_none());
    wait_idle(&s);
    // 모르는 종류는 권한과 무관하게 "알 수 없는 작업"
    assert!(first_error(h.handle(run_now("format", "p1"), admin))
        .is_some_and(|m| m.contains("알 수 없는")));
}

/// 관리자 권한으로 구글 토큰을 저장하고, 일반 사용자는 연결 여부 조회만 가능(첫 연결 포함 저장·해제 거부).
#[test]
fn gdrive_token_is_stored_by_service_and_status_reveals_only_connected() {
    use kova_ipc::{Caller, Event, Handler, Request, Secret};
    let (d, s) = setup(true);
    let h = IpcHandler(s.clone());
    let user = Caller { privileged: false };
    let admin = Caller { privileged: true };
    let status = |h: &IpcHandler| once_events(h.handle(Request::GdriveStatus, user));
    assert_eq!(status(&h), vec![Event::GdriveStatus { connected: false }]);
    let tok = r#"{"refresh":"RT-secret","access":"AT-secret","expires_at":0}"#;
    // 미연결 상태라도 일반 사용자의 토큰 저장은 거부된다
    assert!(first_error(h.handle(
        Request::GdriveStoreToken {
            token: Secret(tok.into()),
        },
        user
    ))
    .is_some_and(|m| m.contains("관리자 권한")));
    assert_eq!(status(&h), vec![Event::GdriveStatus { connected: false }]);
    // 관리자가 잘못된 토큰을 넘기면 오류
    let bad = Request::GdriveStoreToken {
        token: Secret("garbage".into()),
    };
    assert!(first_error(h.handle(bad, admin)).is_some());
    assert_eq!(status(&h), vec![Event::GdriveStatus { connected: false }]);
    // 관리자가 유효 토큰을 넘기면 저장
    let ok = h.handle(
        Request::GdriveStoreToken {
            token: Secret(tok.into()),
        },
        admin,
    );
    assert!(matches!(ok, kova_ipc::Reply::Once(ref v) if matches!(v[..], [Event::Done { .. }])));
    assert_eq!(status(&h), vec![Event::GdriveStatus { connected: true }]);
    // 연결된 뒤에도 일반 사용자의 교체·해제는 거부된다
    assert!(first_error(h.handle(
        Request::GdriveStoreToken {
            token: Secret(tok.into()),
        },
        user
    ))
    .is_some_and(|m| m.contains("관리자 권한")));
    assert!(first_error(h.handle(Request::GdriveDisconnect, user))
        .is_some_and(|m| m.contains("관리자 권한")));
    assert_eq!(status(&h), vec![Event::GdriveStatus { connected: true }]);
    // 토큰은 로그에 남지 않는다
    let log =
        fs::read_to_string(kova_core::applog::log_path(&d.path().join("cfg"))).unwrap_or_default();
    assert!(log.contains("토큰 저장"), "{log}");
    assert!(!log.contains("RT-secret") && !log.contains("AT-secret"));
}

/// 암호화 켜기·키 복원·복구 코드 내보내기는 모두 관리자 전용이며, 복구 코드는 로그에 남지 않는다.
#[test]
#[cfg(windows)]
fn encryption_keys_are_managed_by_service_and_export_needs_admin() {
    use kova_ipc::{Caller, Event, Handler, Request, Secret};
    let keys = KeyDirGuard::new();
    let (d, s) = setup(true);
    let h = IpcHandler(s.clone());
    let user = Caller { privileged: false };
    let admin = Caller { privileged: true };
    // 켜기·키 복원·내보내기 모두 일반 사용자에게 거부
    assert!(first_error(h.handle(Request::EnableEncryption, user))
        .is_some_and(|m| m.contains("관리자 권한")));
    assert!(first_error(h.handle(
        Request::RestoreKey {
            code: Secret("00000000".into()),
        },
        user
    ))
    .is_some_and(|m| m.contains("관리자 권한")));
    assert!(first_error(h.handle(Request::ExportRecoveryCodes, user))
        .is_some_and(|m| m.contains("관리자 권한")));
    // 관리자 켜기: 새로 켠 저장소의 복구 코드를 이때 한 번 돌려준다
    let codes = match &once_events(h.handle(Request::EnableEncryption, admin))[..] {
        [Event::Encrypted { codes }] => codes.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(codes.len(), 1);
    let line = codes[0].0.clone();
    let code = line.rsplit(": ").next().unwrap().to_string();
    assert!(kova_core::repocrypto::is_enabled(&d.path().join("repo")));
    // 다시 켜면 이미 켠 저장소는 건너뛴다
    assert!(matches!(
        &once_events(h.handle(Request::EnableEncryption, admin))[..],
        [Event::Encrypted { codes }] if codes.is_empty()
    ));
    // 키 파일을 잃은 뒤 관리자가 복구 코드로 되살린다(틀린 코드는 실패)
    for f in fs::read_dir(keys.path()).unwrap() {
        fs::remove_file(f.unwrap().path()).unwrap();
    }
    let restore = |c: &str| {
        once_events(h.handle(
            Request::RestoreKey {
                code: Secret(c.into()),
            },
            admin,
        ))
    };
    assert!(matches!(restore("00000000")[..], [Event::Error { .. }]));
    assert!(matches!(restore(&code)[..], [Event::Done { .. }]));
    assert_eq!(fs::read_dir(keys.path()).unwrap().count(), 1);
    // 관리자는 내보낼 수 있다
    match &once_events(h.handle(Request::ExportRecoveryCodes, admin))[..] {
        [Event::RecoveryCodes { entries }] => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].code.0, code);
            assert_eq!(entries[0].name, "시험");
        }
        other => panic!("{other:?}"),
    }
    // 가장 토큰 없는 복원 요청은 거부(SYSTEM 권한으로 쓰지 않는다)
    let req = Request::Restore {
        repo: d.path().join("repo").to_string_lossy().into(),
        session_id: "x".into(),
        target: None,
        only: None,
        recovery_code: None,
    };
    assert!(first_error(h.handle(req.clone(), admin)).is_some());
    assert!(first_error(h.handle_with_token(req, admin, None)).is_some());
    // 복구 코드는 로그에 남지 않는다
    let log =
        fs::read_to_string(kova_core::applog::log_path(&d.path().join("cfg"))).unwrap_or_default();
    assert!(!log.contains(&code), "{log}");
}

#[test]
fn run_now_with_empty_profile_id_is_refused() {
    use kova_ipc::{Caller, Handler};
    let (_d, s) = setup(true);
    let h = IpcHandler(s.clone());
    for pid in ["", "   "] {
        assert!(first_error(h.handle(run_now("backup", pid), Caller::default())).is_some());
    }
    assert_eq!(s.counts(), (0, 0));
}

#[test]
fn wire_job_ids_start_from_time_and_fit_the_apps_i32() {
    for secs in [0i64, 1, 1_999_999, 2_000_000, 1_763_700_000, i64::MAX] {
        let b = wire_id_base(secs);
        assert!(b + 1_000_000 < i32::MAX as u64, "{secs} -> {b}");
    }
    assert_ne!(wire_id_base(1_763_700_000), wire_id_base(1_763_700_001));
}

#[test]
fn cancel_over_ipc_translates_the_wire_job_id() {
    use kova_ipc::{Caller, Handler};
    let (d, s) = setup(true);
    let _held = kova_core::lock::RepoLock::try_acquire(&d.path().join("repo")).unwrap();
    let h = IpcHandler(s.clone());
    let admin = Caller { privileged: true };
    let kova_ipc::Reply::Once(v) = h.handle(run_now("backup", "p1"), admin) else {
        panic!()
    };
    let Some(kova_ipc::Event::Queued { job_id, .. }) = v.first().cloned() else {
        panic!("{v:?}")
    };
    assert!(job_id > s.0.id_base);
    // 잠금 대기(3초) 중이라 아직 실행 중이다
    let kova_ipc::Reply::Once(c) = h.handle(kova_ipc::Request::Cancel { job_id }, admin) else {
        panic!()
    };
    assert_eq!(
        c,
        vec![kova_ipc::Event::Cancelled {
            job_id,
            found: true
        }]
    );
    // 내부 번호(1)를 그대로 보내면 다른 작업으로 취급되지 않는다
    let kova_ipc::Reply::Once(c) = h.handle(kova_ipc::Request::Cancel { job_id: 1 }, admin) else {
        panic!()
    };
    assert!(matches!(
        c[0],
        kova_ipc::Event::Cancelled { found: false, .. }
    ));
    wait_idle(&s);
}

#[test]
fn regular_schedule_slot_resets_exhausted_retry_count() {
    let (d, s) = setup(false); // 원본이 없어 백업은 실패한다
    let store = ConfigStore::new(d.path().join("cfg"));
    let now = Local::now();
    let mut p = store.get("p1").unwrap();
    p.schedule_type = "interval_hours".into();
    p.schedule_value = "1".into();
    p.last_status = "failed".into();
    p.last_run = Some(now.timestamp() as f64 - 2.0 * 3600.0);
    p.extra
        .insert("retry_count".into(), (MAX_AUTO_RETRIES as u64).into());
    store.upsert(p.clone()).unwrap();
    assert!(regular_slot_due(&p, now));
    assert_eq!(s.tick(now), 1);
    wait_idle(&s);
    // 0 으로 되돌린 뒤 이번 실패가 1회로 기록된다(한도 위로 계속 쌓이지 않음)
    assert_eq!(
        kova_core::schedule::retry_count(&store.get("p1").unwrap()),
        1
    );

    // 재시도 회차는 정기 회차가 아니다
    let mut r = store.get("p1").unwrap();
    r.schedule_value = "24".into();
    r.last_run = Some(now.timestamp() as f64 - 3600.0);
    assert!(should_run(&r, now) && !regular_slot_due(&r, now));
}

#[test]
fn lock_busy_is_not_alerted_cools_down_and_does_not_resurrect_profile() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.webhook_url = String::new();
    store.save_settings(&st).unwrap();
    let held = kova_core::lock::RepoLock::try_acquire(&d.path().join("repo")).unwrap();
    let rx = s.subscribe();
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    assert!(rx.try_iter().any(|e| matches!(
        e,
        SvcEvent::JobFinished { ok: false, ref message, .. } if message.starts_with(BUSY_PREFIX)
    )));
    assert!(
        kova_core::alerts::AlertLog::new(&d.path().join("cfg"))
            .list()
            .is_empty(),
        "잠금 충돌은 알림을 남기지 않는다"
    );
    let p = store.get("p1").unwrap();
    assert!(lock_busy_recently(&p, Local::now().timestamp() as f64));
    // 스케줄이 도래했어도(last_run 없음) 쿨다운 동안은 다시 큐에 넣지 않는다
    assert_eq!(s.tick(Local::now()), 0);

    // 잠금 대기 중에 프로파일이 지워지면 결과 기록으로 되살아나지 않는다
    s.enqueue("p1", Kind::Backup);
    std::thread::sleep(Duration::from_millis(300));
    store.delete("p1").unwrap();
    wait_idle(&s);
    assert!(store.get("p1").is_none());
    drop(held);
}

#[test]
fn shutdown_cancels_running_jobs_and_starts_no_new_ones() {
    let (d, s) = setup(true);
    let held = kova_core::lock::RepoLock::try_acquire(&d.path().join("repo")).unwrap();
    s.enqueue("p1", Kind::Backup);
    assert_eq!(s.counts().1, 1);
    let mut waits = 0;
    assert!(s.shutdown(Duration::from_secs(20), || waits += 1));
    assert_eq!(s.counts(), (0, 0));
    s.enqueue("p1", Kind::Backup);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(s.counts(), (1, 0), "중지 중에는 새 작업을 시작하지 않는다");
    assert_eq!(s.tick(Local::now()), 0);
    drop(held);
}

#[test]
fn leftover_vss_markers_are_reported_once() {
    let (d, s) = setup(true);
    let cfg = d.path().join("cfg");
    fs::write(
        cfg.join("vss_inflight_7.txt"),
        "2026-11-21 10:00:00 파일 백업",
    )
    .unwrap();
    assert_eq!(s.report_leftover_vss(), 1);
    assert!(!cfg.join("vss_inflight_7.txt").exists());
    assert_eq!(s.report_leftover_vss(), 0);
    let log = fs::read_to_string(kova_core::applog::log_path(&cfg)).unwrap();
    assert!(log.contains("VSS 섀도 복사본을 정리하지 못했을 수"));
}

#[test]
fn leftover_vss_extracts_valid_guids_and_ignores_junk() {
    let text = "2026-11-24 10:00:00 파일 백업\n{11111111-1111-1111-1111-111111111111}\nnot-a-guid\nshadow_id={22222222-2222-2222-2222-222222222222}\n{11111111-1111-1111-1111-111111111111}\n'; Remove-Item C:\\";
    let ids = extract_vss_guids(text);
    assert_eq!(
        ids,
        vec![
            "{11111111-1111-1111-1111-111111111111}".to_string(),
            "{22222222-2222-2222-2222-222222222222}".to_string(),
        ]
    );
}

#[test]
fn resolve_profile_does_not_create_repo_folders() {
    let (d, s) = setup(true);
    let repo = d.path().join("repo");
    assert!(!repo.exists());
    assert_eq!(s.resolve_profile("없는스냅샷"), None);
    assert!(!repo.exists(), "조회만으로 저장소 폴더·DB 를 만들면 안 됨");
}

#[test]
fn stale_partial_images_are_removed_but_fresh_ones_kept() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("C_20261121_000000.qblk");
    fs::write(&f, b"part").unwrap();
    assert_eq!(
        remove_stale_partials(d.path(), Duration::from_secs(3600)),
        0
    );
    assert!(f.exists());
    assert_eq!(remove_stale_partials(d.path(), Duration::ZERO), 1);
    assert!(!f.exists());
}

#[test]
fn subscriber_that_never_reads_is_dropped_when_full() {
    let (_d, s) = setup(true);
    let rx = s.subscribe();
    for i in 0..(SUB_CAPACITY as u64 + 5) {
        s.emit(SvcEvent::Progress {
            job_id: i,
            percent: 0,
            current: String::new(),
        });
    }
    assert!(s.0.subs.lock().unwrap().is_empty());
    assert_eq!(rx.try_iter().count(), SUB_CAPACITY);
}

#[test]
fn cancelled_backup_does_not_push_alert() {
    let (d, s) = setup(true);
    let held = kova_core::lock::RepoLock::try_acquire(&d.path().join("repo")).unwrap();
    let rx = s.subscribe();
    let Enqueue::Queued(job_id) = s.enqueue("p1", Kind::Backup) else {
        panic!("백업이 큐에 들어가야 함");
    };
    assert!(s.cancel(job_id));
    drop(held);
    wait_idle(&s);
    let evs: Vec<SvcEvent> = rx.try_iter().collect();
    assert!(
        evs.iter().any(|e| matches!(
            e,
            SvcEvent::JobFinished {
                ok: false,
                ref message,
                ..
            } if message == "취소됨"
        )),
        "{evs:?}"
    );
    assert!(
        kova_core::alerts::AlertLog::new(&d.path().join("cfg"))
            .list()
            .is_empty(),
        "취소된 백업은 알림을 남기지 않아야 함"
    );
}

#[test]
fn failed_verify_and_gc_enter_cooldown_and_preserve_last_verify_at() {
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let now = Local::now();
    let now_ts = now.timestamp() as f64;
    let eight_days_ago = now_ts - 8.0 * 86_400.0;
    let mut p = store.get("p1").unwrap();
    p.auto_backup_enabled = false;
    p.last_snapshot_id = Some("s1".into());
    p.last_run = Some(now_ts);
    p.extra
        .insert("last_verify_at".into(), eight_days_ago.into());
    p.extra.insert("last_gc_at".into(), eight_days_ago.into());
    p.extra.insert("last_drill_at".into(), now_ts.into());
    store.upsert(p).unwrap();

    // repo/snapshots 를 파일로 만들어 verify_repo 가 Err 를 반환하도록 유도
    let repo = d.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("snapshots"), b"not-a-dir").unwrap();

    assert_eq!(s.tick(now), 1);
    wait_idle(&s);
    let after_verify = store.get("p1").unwrap();
    assert_eq!(
        after_verify
            .extra
            .get("last_verify_at")
            .and_then(|v| v.as_f64()),
        Some(eight_days_ago),
        "verify_repo 오류 시 last_verify_at 를 갱신하면 안 됨"
    );
    assert_eq!(
        s.tick(now),
        0,
        "Verify 실패 후 쿨다운 동안은 다음 틱에서 재큐잉하지 않아야 함"
    );

    // 이번에는 손상된 매니페스트로 GC 실패를 유도하고 쿨다운 확인
    fs::remove_file(repo.join("snapshots")).unwrap();
    fs::create_dir_all(repo.join("snapshots")).unwrap();
    fs::write(repo.join("snapshots").join("bad.json"), b"{corrupt").unwrap();
    s.clear_maint_failed("p1");
    let mut p2 = store.get("p1").unwrap();
    p2.extra.insert("last_verify_at".into(), now_ts.into());
    store.upsert(p2).unwrap();

    assert_eq!(s.tick(now), 1);
    wait_idle(&s);
    assert_eq!(
        s.tick(now),
        0,
        "Gc 실패 후 쿨다운 동안은 다음 틱에서 재큐잉하지 않아야 함"
    );
}

#[test]
fn shutdown_waits_for_active_bg_and_refuses_new_drill_and_restore() {
    let (_d, s) = setup(true);
    let guard = s.try_begin_drill("p1").unwrap();
    assert!(
        s.try_begin_drill("p1").is_err(),
        "같은 프로파일의 중복 훈련은 거부되어야 함"
    );
    let (r_guard, r_cancel) = s.try_begin_restore().unwrap();
    assert!(!s.shutdown(Duration::from_millis(100), || {}));
    assert!(
        r_cancel.load(Ordering::SeqCst),
        "shutdown 은 진행 중 복원의 취소 플래그를 세워야 함"
    );
    drop(guard);
    drop(r_guard);
    assert!(s.shutdown(Duration::from_secs(2), || {}));
    assert!(s.try_begin_drill("p1").is_err());
    assert!(s.try_begin_restore().is_err());
}

#[test]
fn shows_speed_and_eta() {
    assert_eq!(speed_note(0, 100, 5.0), "");
    assert_eq!(speed_note(10, 100, 0.5), "");
    let s = speed_note(600_000_000, 1_200_000_000, 2.0);
    assert!(s.contains("300MB/s") && s.contains("약 1분 남음"), "{s}");
    assert!(speed_note(4_000_000_000, 8_000_000_000, 2.0).contains("2.0GB/s"));
}

// ───────────────────── 신규 Phase 1–3 IPC·보안·기능 단위 시험 ─────────────────────

#[test]
#[cfg(windows)]
fn unprivileged_caller_is_refused_for_all_admin_ipc_requests() {
    use kova_ipc::{Caller, Event, Handler, Request, Secret};
    let (d, s) = setup(true);
    let h = IpcHandler(s);
    let user = Caller { privileged: false };
    let admin = Caller { privileged: true };

    let admin_only = vec![
        Request::EnableEncryption,
        Request::RestoreKey {
            code: Secret("00000000".into()),
        },
        Request::GdriveStoreToken {
            token: Secret(r#"{"refresh":"r","access":"a","expires_at":0}"#.into()),
        },
        Request::GdriveDisconnect,
        Request::ExportRecoveryCodes,
        Request::S3SaveConfig {
            endpoint: "https://s3.example.com".into(),
            region: "ap-northeast-2".into(),
            bucket: "my-bucket".into(),
            prefix: "pc1".into(),
            access_key: "AKIA".into(),
            secret_key: Secret("s3-super-secret".into()),
        },
        Request::S3DeleteConfig,
        Request::S3TestConnection,
        Request::SmbSaveCred {
            share: r"\\nas01\backups".into(),
            username: "svc".into(),
            password: Secret("smb-super-secret".into()),
        },
        Request::SmbDeleteCred {
            share: r"\\nas01\backups".into(),
        },
        Request::SmtpSaveConfig {
            host: "smtp.example.com".into(),
            port: 587,
            username: "alerts@example.com".into(),
            password: Secret("smtp-super-secret".into()),
            from: "alerts@example.com".into(),
            to: "ops@example.com".into(),
            use_tls: true,
        },
        Request::SmtpDeleteConfig,
        Request::SmtpTest,
        Request::CloudPull {
            provider: "s3".into(),
            dest_repo: d.path().join("pulled").to_string_lossy().into(),
        },
        Request::CloudPrune {
            profile_id: "p1".into(),
        },
    ];

    for req in admin_only {
        let msg = first_error(h.handle(req.clone(), user));
        assert!(
            msg.as_deref().is_some_and(|m| m.contains("관리자 권한")),
            "{req:?} -> {msg:?}"
        );
    }

    // 관리자는 S3 / SMB / SMTP 저장·조회·삭제가 모두 가능하며 비밀은 로그에 남지 않는다
    assert!(matches!(
        &once_events(h.handle(
            Request::S3SaveConfig {
                endpoint: "https://s3.example.com".into(),
                region: "ap-northeast-2".into(),
                bucket: "kova-bkt".into(),
                prefix: "prod".into(),
                access_key: "AKIA123".into(),
                secret_key: Secret("s3-super-secret".into()),
            },
            admin
        ))[..],
        [Event::Done { .. }]
    ));
    assert!(matches!(
        &once_events(h.handle(Request::S3Status, user))[..],
        [Event::S3Status {
            configured: true,
            ref bucket,
            ..
        }] if bucket == "kova-bkt"
    ));
    assert!(matches!(
        &once_events(h.handle(Request::S3DeleteConfig, admin))[..],
        [Event::Done { .. }]
    ));

    assert!(matches!(
        &once_events(h.handle(
            Request::SmbSaveCred {
                share: r"\\nas01\backups".into(),
                username: "svc_user".into(),
                password: Secret("smb-super-secret".into()),
            },
            admin
        ))[..],
        [Event::Done { .. }]
    ));
    assert!(matches!(
        &once_events(h.handle(Request::SmbListCreds, user))[..],
        [Event::SmbCreds { ref creds }] if creds.len() == 1 && creds[0].username == "svc_user"
    ));
    assert!(matches!(
        &once_events(h.handle(
            Request::SmbDeleteCred {
                share: r"\\nas01\backups".into(),
            },
            admin
        ))[..],
        [Event::Done { .. }]
    ));

    assert!(matches!(
        &once_events(h.handle(
            Request::SmtpSaveConfig {
                host: "smtp.example.com".into(),
                port: 587,
                username: "alerts@example.com".into(),
                password: Secret("smtp-super-secret".into()),
                from: "alerts@example.com".into(),
                to: "ops@example.com".into(),
                use_tls: true,
            },
            admin
        ))[..],
        [Event::Done { .. }]
    ));
    assert!(matches!(
        &once_events(h.handle(Request::SmtpStatus, user))[..],
        [Event::SmtpStatus {
            configured: true,
            port: 587,
            ..
        }]
    ));
    assert!(matches!(
        &once_events(h.handle(Request::SmtpDeleteConfig, admin))[..],
        [Event::Done { .. }]
    ));

    let log =
        fs::read_to_string(kova_core::applog::log_path(&d.path().join("cfg"))).unwrap_or_default();
    assert!(
        !log.contains("s3-super-secret")
            && !log.contains("smb-super-secret")
            && !log.contains("smtp-super-secret"),
        "비밀값이 로그에 노출됨: {log}"
    );
}

#[test]
#[cfg(windows)]
fn encrypted_restore_requires_admin_or_valid_recovery_code() {
    use kova_ipc::{Caller, ClientToken, Event, Handler, Reply, Request, Secret};

    struct OverrideCaller {
        inner: IpcHandler,
        privileged: Arc<AtomicBool>,
    }

    impl Handler for OverrideCaller {
        fn handle(&self, req: Request, _caller: Caller) -> Reply {
            self.inner.handle(
                req,
                Caller {
                    privileged: self.privileged.load(Ordering::SeqCst),
                },
            )
        }

        fn handle_with_token(
            &self,
            req: Request,
            _caller: Caller,
            token: Option<ClientToken>,
        ) -> Reply {
            self.inner.handle_with_token(
                req,
                Caller {
                    privileged: self.privileged.load(Ordering::SeqCst),
                },
                token,
            )
        }
    }

    let _keys = KeyDirGuard::new();
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.min_free_disk_gb = 0;
    st.enable_ransomware_protection = false;
    st.encrypt_backups = true;
    store.save_settings(&st).unwrap();

    let repo = d.path().join("repo");
    let code = kova_core::repocrypto::enable(&repo)
        .unwrap()
        .expect("암호화 활성화");
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let sid = store
        .get("p1")
        .unwrap()
        .last_snapshot_id
        .expect("스냅샷 생성");
    let repo_str = repo.to_string_lossy().to_string();

    // 1) 직접 호출(토큰 없음): 일반 사용자는 권한/복구 코드 단계에서 먼저 거부되고,
    //    유효 복구 코드나 관리자 권한이 있으면 권한 검사를 통과해 토큰 검사로 넘어간다
    let h = IpcHandler(s.clone());
    let user = Caller { privileged: false };
    let admin = Caller { privileged: true };
    let no_code_req = Request::Restore {
        repo: repo_str.clone(),
        session_id: sid.clone(),
        target: Some(d.path().join("out_direct").to_string_lossy().into()),
        only: None,
        recovery_code: None,
    };
    assert_eq!(
        first_error(h.handle_with_token(no_code_req.clone(), user, None)).as_deref(),
        Some(crate::restore::ENCRYPTED_RESTORE_AUTH_REQUIRED)
    );
    let wrong_code_req = Request::Restore {
        repo: repo_str.clone(),
        session_id: sid.clone(),
        target: Some(d.path().join("out_direct").to_string_lossy().into()),
        only: None,
        recovery_code: Some(Secret("0".repeat(64))),
    };
    assert_eq!(
        first_error(h.handle_with_token(wrong_code_req, user, None)).as_deref(),
        Some(crate::restore::ENCRYPTED_RESTORE_AUTH_REQUIRED)
    );
    let valid_code_req = Request::Restore {
        repo: repo_str.clone(),
        session_id: sid.clone(),
        target: Some(d.path().join("out_direct").to_string_lossy().into()),
        only: None,
        recovery_code: Some(Secret(code.clone())),
    };
    assert_eq!(
        first_error(h.handle_with_token(valid_code_req, user, None)).as_deref(),
        Some(crate::restore::RESTORE_NEEDS_CALLER)
    );
    assert_eq!(
        first_error(h.handle_with_token(no_code_req, admin, None)).as_deref(),
        Some(crate::restore::RESTORE_NEEDS_CALLER)
    );

    // 2) 실제 가장 토큰(stream_as_caller)을 통한 엔드투엔드 암호화 복원 검증
    let rt = tokio::runtime::Runtime::new().unwrap();
    let priv_flag = Arc::new(AtomicBool::new(false));
    let pipe = format!(r"\\.\pipe\kova-svc-enc-restore-{}", std::process::id());
    let wrapped: Arc<dyn Handler> = Arc::new(OverrideCaller {
        inner: IpcHandler(s.clone()),
        privileged: priv_flag.clone(),
    });
    rt.block_on(async {
        let p2 = pipe.clone();
        tokio::spawn(async move {
            let _ = kova_ipc::serve(&p2, wrapped).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let run_restore_req = |req: Request| {
            let pipe = pipe.clone();
            async move {
                let mut evs = Vec::new();
                kova_ipc::stream_as_caller(&pipe, &req, |e| {
                    evs.push(e);
                    true
                })
                .await
                .unwrap();
                evs
            }
        };

        // 2-a) 일반 사용자 + 복구 코드 없음 -> 거부
        priv_flag.store(false, Ordering::SeqCst);
        let out_refused = d.path().join("out_refused");
        let evs = run_restore_req(Request::Restore {
            repo: repo_str.clone(),
            session_id: sid.clone(),
            target: Some(out_refused.to_string_lossy().into()),
            only: None,
            recovery_code: None,
        })
        .await;
        assert!(
            matches!(evs.last(), Some(Event::Error { message }) if message == crate::restore::ENCRYPTED_RESTORE_AUTH_REQUIRED),
            "{evs:?}"
        );
        assert!(!out_refused.exists());

        // 2-b) 일반 사용자 + 유효 복구 코드 -> 복원 성공
        let out_user = d.path().join("out_user_code");
        let evs = run_restore_req(Request::Restore {
            repo: repo_str.clone(),
            session_id: sid.clone(),
            target: Some(out_user.to_string_lossy().into()),
            only: None,
            recovery_code: Some(Secret(code.clone())),
        })
        .await;
        assert!(
            matches!(evs.last(), Some(Event::Done { message }) if message.contains("복원 완료")),
            "{evs:?}"
        );
        assert_eq!(fs::read_to_string(out_user.join("a.txt")).unwrap(), "안녕 kova");

        // 2-c) 관리자 + 복구 코드 없음 -> 복원 성공
        priv_flag.store(true, Ordering::SeqCst);
        let out_admin = d.path().join("out_admin");
        let evs = run_restore_req(Request::Restore {
            repo: repo_str.clone(),
            session_id: sid.clone(),
            target: Some(out_admin.to_string_lossy().into()),
            only: None,
            recovery_code: None,
        })
        .await;
        assert!(
            matches!(evs.last(), Some(Event::Done { message }) if message.contains("복원 완료")),
            "{evs:?}"
        );
        assert_eq!(
            fs::read_to_string(out_admin.join("a.txt")).unwrap(),
            "안녕 kova"
        );
    });
    rt.shutdown_timeout(Duration::from_secs(1));

    // 암호화 저장소 DiffSnapshots 도 일반 사용자는 거부, 관리자는 허용
    let diff_req = Request::DiffSnapshots {
        repo: repo_str,
        base_id: sid.clone(),
        target_id: sid,
        limit: 100,
    };
    assert!(
        first_error(h.handle(diff_req.clone(), user)).is_some_and(|m| m.contains("관리자 권한"))
    );
    assert!(matches!(
        &once_events(h.handle(diff_req, admin))[..],
        [Event::DiffResult { .. }]
    ));
}

#[test]
fn job_history_records_completed_backup_and_returns_via_ipc() {
    use kova_ipc::{Caller, Event, Handler, Request};
    let (_d, s) = setup(true);
    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    s.enqueue("p1", Kind::Verify);
    wait_idle(&s);

    let h = IpcHandler(s);
    let evs = once_events(h.handle(Request::JobHistory { limit: 10 }, Caller::default()));
    let [Event::JobHistory { rows }] = &evs[..] else {
        panic!("expected JobHistory, got {evs:?}");
    };
    assert_eq!(rows.len(), 2, "{rows:?}");
    // 최신순: Verify 다음 Backup
    assert_eq!(rows[0].kind, "verify");
    assert!(rows[0].ok);
    assert_eq!(rows[1].kind, "backup");
    assert_eq!(rows[1].profile_id, "p1");
    assert!(rows[1].ok);
    assert!(rows[1].bytes > 0);
    assert!(rows[1].files > 0);
    assert!(rows[1].finished_at >= rows[1].started_at);
}

#[test]
fn diff_snapshots_returns_added_modified_and_deleted_entries() {
    use kova_ipc::{Caller, Event, Handler, Request};
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.enable_ransomware_protection = false;
    store.save_settings(&st).unwrap();

    let src = d.path().join("원본");
    fs::write(src.join("keep.txt"), "same content").unwrap();
    fs::write(src.join("mod.txt"), "version 1").unwrap();
    fs::write(src.join("del.txt"), "to be deleted").unwrap();

    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let sid1 = store.get("p1").unwrap().last_snapshot_id.unwrap();

    std::thread::sleep(Duration::from_millis(50));
    fs::write(src.join("mod.txt"), "version 2 updated content").unwrap();
    fs::remove_file(src.join("del.txt")).unwrap();
    fs::write(src.join("add.txt"), "brand new file").unwrap();

    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);
    let sid2 = store.get("p1").unwrap().last_snapshot_id.unwrap();
    assert_ne!(sid1, sid2);

    let h = IpcHandler(s);
    let repo_str = d.path().join("repo").to_string_lossy().to_string();
    let evs = once_events(h.handle(
        Request::DiffSnapshots {
            repo: repo_str,
            base_id: sid1.clone(),
            target_id: sid2.clone(),
            limit: 100,
        },
        Caller::default(),
    ));
    let [Event::DiffResult {
        added,
        modified,
        deleted,
        unchanged_count,
    }] = &evs[..]
    else {
        panic!("expected DiffResult, got {evs:?}");
    };
    assert!(
        added.iter().any(|e| e.path.ends_with("add.txt")),
        "added={added:?}"
    );
    assert!(
        modified.iter().any(|e| e.path.ends_with("mod.txt")),
        "modified={modified:?}"
    );
    assert!(
        deleted.iter().any(|e| e.path.ends_with("del.txt")),
        "deleted={deleted:?}"
    );
    assert!(*unchanged_count >= 1, "unchanged_count={unchanged_count}");

    // 등록되지 않은 저장소 경로는 거부
    assert!(first_error(h.handle(
        Request::DiffSnapshots {
            repo: d.path().join("unregistered").to_string_lossy().into(),
            base_id: sid1,
            target_id: sid2,
            limit: 100,
        },
        Caller::default(),
    ))
    .is_some());
}

#[test]
fn ipc_info_and_fleet_status_return_valid_responses() {
    use kova_ipc::{Caller, Event, Handler, Request};
    let (d, s) = setup(true);
    let store = ConfigStore::new(d.path().join("cfg"));
    let mut st = store.settings();
    st.fleet_endpoint = "https://fleet.example.com/api/heartbeat".into();
    store.save_settings(&st).unwrap();

    s.enqueue("p1", Kind::Backup);
    wait_idle(&s);

    let h = IpcHandler(s);
    let info = once_events(h.handle(Request::Info, Caller::default()));
    assert_eq!(
        info,
        vec![Event::Info {
            protocol_version: kova_ipc::PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").into(),
        }]
    );

    let fleet = once_events(h.handle(Request::FleetStatus, Caller::default()));
    let [Event::FleetStatus {
        hostname,
        service_version,
        profiles_total,
        healthy,
        stale,
        last_backup_at,
        unacked_alerts,
        fleet_endpoint,
    }] = &fleet[..]
    else {
        panic!("expected FleetStatus, got {fleet:?}");
    };
    assert!(!hostname.is_empty());
    assert_eq!(service_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(*profiles_total, 1);
    assert_eq!(*healthy, 1);
    assert_eq!(*stale, 0);
    assert!(last_backup_at.is_some());
    assert_eq!(*unacked_alerts, 0);
    assert_eq!(fleet_endpoint, "https://fleet.example.com/api/heartbeat");
}

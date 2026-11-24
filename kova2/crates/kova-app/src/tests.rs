//! kova-app 단위 테스트(기존 29개 전부 보존 + Phase 1–3 신규 테스트).
use crate::disk_image::{
    build_pe_ps_args, is_kova_image_path, is_verified, mark_verified, run_export_drivers,
    scan_image_dir, verified_marker,
};
use crate::ipc::{send_failure, try_clear_idle_running, update_running, RunInfo};
use crate::picker::{build_pick_script, parse_picked, pick_plan, PickPlan};
use crate::profiles::{
    apply_schedule_mode, keep_existing_with, missing_count_with, prog_candidates,
    schedule_mode_from_type, source_rows_with,
};
use crate::restore::search_all_repos;
use crate::settings::{
    apply_fleet_endpoint, apply_ops_settings, apply_settings, apply_watch_settings,
    set_offsite_provider_in,
};
use crate::updater::{decode_install_result, encode_install_result, parse_service_stopped};
use crate::util::{
    fmt_size, gc_target, human_mb, kind_label, repo_drive_usage, resolve_profile_id, shorten_alert,
    system_drive_letter, try_begin, BusyGate, LOCKED_MSG,
};

#[test]
fn verified_marker_follows_image_changes() {
    let img = std::env::temp_dir().join(format!("kova_vm_{}.qblk", std::process::id()));
    std::fs::write(&img, b"abc").unwrap();
    assert!(!is_verified(&img));
    mark_verified(&img);
    assert!(is_verified(&img));
    std::fs::write(&img, b"abcd").unwrap();
    assert!(!is_verified(&img));
    let _ = std::fs::remove_file(&img);
    let _ = std::fs::remove_file(verified_marker(&img));
}

#[test]
fn pick_plan_routes_result_to_target_and_keeps_on_cancel() {
    let ok = |s: &str| Ok::<String, String>(s.to_string());
    assert_eq!(
        pick_plan("form-add", ok("C:\\a;D:\\b")),
        PickPlan::FormAdd("C:\\a;D:\\b".into())
    );
    for t in ["form-repo", "restore-folder", "offsite:nas1"] {
        assert_eq!(
            pick_plan(t, ok("E:\\x")),
            PickPlan::Field(t.into(), "E:\\x".into())
        );
    }
    assert_eq!(pick_plan("form-repo", ok("")), PickPlan::Keep);
    assert_eq!(pick_plan("form-add", ok("  ")), PickPlan::Keep);
    assert_eq!(pick_plan("", ok("C:\\a")), PickPlan::Keep);
    assert_eq!(
        pick_plan("form-repo", Err("x".into())),
        PickPlan::Error("선택 창을 열지 못했습니다: x".into())
    );
}

#[test]
fn missing_and_clean_use_given_exists() {
    let s = " C:\\a ; \\\\nas\\gone ;;C:\\b";
    let ex = |p: &str| !p.contains("gone");
    assert_eq!(missing_count_with(s, ex), 1);
    assert_eq!(keep_existing_with(s, ex), "C:\\a;C:\\b");
    assert_eq!(missing_count_with("", ex), 0);
}

#[test]
fn prog_candidates_skips_programs_already_in_sources() {
    let found = vec![
        (
            "Tailscale".to_string(),
            vec!["C:\\Program Files\\Tailscale".to_string()],
        ),
        (
            "Git".to_string(),
            vec!["C:\\Program Files\\Git".to_string()],
        ),
    ];
    let have = "C:\\Users\\a\\Desktop;C:\\Users\\a\\AppData\\Local\\Tailscale";
    let names: Vec<String> = prog_candidates(found, have)
        .into_iter()
        .map(|(n, _, c)| {
            assert!(!c);
            n
        })
        .collect();
    assert_eq!(names, ["Git"]);
}

#[test]
fn busy_gate_blocks_second_start_until_end() {
    let g = BusyGate::default();
    let g2 = g.clone();
    assert!(g.try_begin());
    assert!(!g2.try_begin(), "진행 중에는 다시 시작하지 않는다");
    std::thread::spawn(move || g2.end()).join().unwrap();
    assert!(g.try_begin(), "끝나면 다시 시작할 수 있다");
}

#[test]
fn source_rows_groups_programs_by_name_and_keeps_folders() {
    let s = "C:\\Users\\a\\Desktop;C:\\Users\\a\\Desktop\\sub;C:\\Users\\a\\AppData\\Local\\Temp\\keep;\
             C:\\Program Files\\Tailscale;C:\\Users\\a\\AppData\\Local\\Tailscale;C:\\Users\\a\\AppData\\Roaming\\tailscale;\
             C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Tailscale.lnk;\
             C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Git\\Git Bash.lnk;\
             C:\\Users\\a\\AppData\\Local\\antigravity-updater;C:\\Users\\a\\AppData\\Local\\Programs\\antigravity;c:\\users\\a\\desktop";
    let r = source_rows_with(s, |p| !p.contains("keep"));
    let titles: Vec<(i32, &str)> = r.iter().map(|x| (x.0, x.1.as_str())).collect();
    assert_eq!(
        titles,
        vec![
            (0, "폴더·파일 (3개)"),
            (1, "Desktop"),
            (1, "sub"),
            (1, "keep"),
            (0, "프로그램 (3개)"),
            (2, "Tailscale"),
            (2, "Git"),
            (2, "antigravity-updater"),
        ]
    );
    assert_eq!(
        r[3].2,
        "찾을 수 없음 · C:\\Users\\a\\AppData\\Local\\Temp\\keep"
    );
    assert_eq!(r[5].2, "4개 항목");
    assert_eq!(r[7].2, "2개 항목");
    assert_eq!(r[5].3, "prog:tailscale");
}

#[test]
fn apply_settings_validates_and_preserves_other_fields() {
    let dir = std::env::temp_dir().join(format!("kova_set_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    let mut s = store.settings();
    s.offsite_remote_path = "keep".into();
    s.extra.insert("unknown_key".into(), 7.into());
    store.save_settings(&s).unwrap();

    assert!(apply_settings(&store, "abc", true, false, true, false, false, false, false).is_err());
    assert!(apply_settings(&store, "-1", true, false, true, false, false, false, false).is_err());
    assert!(
        apply_settings(&store, "999999", true, false, true, false, false, false, false).is_err()
    );
    assert_eq!(store.settings().offsite_remote_path, "keep");

    assert!(apply_settings(&store, " 25 ", false, false, false, true, true, true, true).is_ok());
    let after = store.settings();
    assert_eq!(after.min_free_disk_gb, 25);
    assert!(!after.enable_ransomware_protection);
    assert!(!after.use_vss);
    assert!(after.pack_blobs);
    assert!(after.encrypt_manifests);
    assert!(after.preserve_acl);
    assert!(after.incremental_images);
    assert_eq!(after.offsite_remote_path, "keep");
    assert_eq!(after.extra.get("unknown_key"), Some(&7.into()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_watch_settings_validates_and_saves() {
    let dir = std::env::temp_dir().join(format!("kova_watch_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    assert!(apply_watch_settings(&store, "x", "3").is_err());
    assert!(apply_watch_settings(&store, "7", "400").is_err());
    assert!(apply_watch_settings(&store, "14", "0").is_ok());
    let s = store.settings();
    assert_eq!((s.auto_drill_days, s.stale_warn_days), (14, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_ops_settings_validates_and_saves() {
    let dir = std::env::temp_dir().join(format!("kova_ops_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    assert!(apply_ops_settings(&store, "ftp://bad", "2", "10", false, "").is_err());
    assert!(apply_ops_settings(&store, "", "99", "10", false, "").is_err());
    assert!(apply_ops_settings(&store, "", "2", "99999", false, "").is_err());
    assert!(apply_ops_settings(&store, "", "2", "10", false, "ftp://bad-fleet").is_err());
    assert!(apply_ops_settings(
        &store,
        "https://hooks.example.com/1",
        "4",
        "50",
        true,
        "https://fleet.example.com/hb"
    )
    .is_ok());
    let s = store.settings();
    assert_eq!(s.webhook_url, "https://hooks.example.com/1");
    assert_eq!(s.max_cpu_threads, 4);
    assert_eq!(s.offsite_bw_limit_mbps, 50);
    assert!(s.pause_on_battery);
    assert_eq!(s.fleet_endpoint, "https://fleet.example.com/hb");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn build_pe_ps_args_includes_drivers_only_when_given() {
    let a = build_pe_ps_args(
        std::path::Path::new("C:\\Program Files\\Kova2\\make_pe.ps1"),
        std::path::Path::new("D:\\O'Brien\\out.iso"),
        std::path::Path::new("C:\\Program Files\\Kova2\\kova-pe.exe"),
        "",
    );
    assert!(a.contains("-File \"C:\\Program Files\\Kova2\\make_pe.ps1\""));
    assert!(a.contains("-Out \"D:\\O''Brien\\out.iso\"") && !a.contains("-DriversDir"));
    assert!(a.contains("-Exe \"C:\\Program Files\\Kova2\\kova-pe.exe\""));
    let b = build_pe_ps_args(
        std::path::Path::new("C:\\Kova2\\make_pe.ps1"),
        std::path::Path::new("D:\\out.iso"),
        std::path::Path::new("C:\\Kova2\\kova-pe.exe"),
        "C:\\Drivers\\NVMe",
    );
    assert!(b.contains("-DriversDir \"C:\\Drivers\\NVMe\""));
}

#[test]
fn run_export_drivers_handles_custom_destination() {
    let tmp = std::env::temp_dir().join(format!("kova_drv_test_{}", std::process::id()));
    let res = run_export_drivers(Some(&tmp));
    let msg = match res {
        Ok(m) | Err(m) => m,
    };
    assert!(!msg.is_empty());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn search_all_repos_finds_files_across_snapshots_with_chosung() {
    let base = std::env::temp_dir().join(format!("kova_gsearch_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let src = base.join("src");
    let repo = base.join("repo");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("품질보고서.txt"), "v1").unwrap();
    let no = std::sync::atomic::AtomicBool::new(false);
    kova_engine::ops::run_backup(
        &kova_engine::ops::BackupOptions {
            sources: vec![src.clone()],
            repo: repo.clone(),
            session_id: Some("20261119_010000".into()),
            zstd_level: 3,
            exclude: vec![],
            profile_id: Some("p1".into()),
            scan_from: None,
            ..Default::default()
        },
        &|_| {},
        &no,
    )
    .unwrap();
    std::fs::write(src.join("품질보고서.txt"), "v2-updated").unwrap();
    kova_engine::ops::run_backup(
        &kova_engine::ops::BackupOptions {
            sources: vec![src],
            repo: repo.clone(),
            session_id: Some("20261119_020000".into()),
            zstd_level: 3,
            exclude: vec![],
            profile_id: Some("p1".into()),
            scan_from: None,
            ..Default::default()
        },
        &|_| {},
        &no,
    )
    .unwrap();

    let store = kova_core::config::ConfigStore::new(base.join("cfg"));
    let mut p = kova_core::config::Profile::new("p1", "문서");
    p.repo_dir = repo.to_string_lossy().into();
    store.upsert(p).unwrap();

    let res = search_all_repos(&store, "ㅍㅈㅂㄱㅅ");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, "품질보고서.txt");
    assert_eq!(res[0].4, 2, "2개 시점 버전이 집계되어야 함");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn parse_service_stopped_detects_stopped_and_missing() {
    assert!(parse_service_stopped(
        "        STATE              : 1  STOPPED"
    ));
    assert!(parse_service_stopped(
        "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:"
    ));
    assert!(!parse_service_stopped(
        "        STATE              : 3  STOP_PENDING"
    ));
    assert!(!parse_service_stopped(
        "        STATE              : 4  RUNNING"
    ));
}

#[test]
fn running_list_tracks_events() {
    use kova_ipc::Event as E;
    let name = |id: &str| format!("P-{id}");
    let mut rows: Vec<RunInfo> = vec![];
    let start = |job_id, kind: &str| E::JobStarted {
        job_id,
        profile_id: "a".into(),
        kind: kind.into(),
    };
    update_running(&mut rows, &start(1, "backup"), &name);
    update_running(&mut rows, &start(2, "verify"), &name);
    assert_eq!(rows.len(), 2);
    assert!(rows[0].cancellable && !rows[1].cancellable);
    assert_eq!(rows[0].name, "P-a");
    assert_eq!(rows[0].kind, "backup");
    assert_eq!(rows[1].kind, "verify");
    update_running(
        &mut rows,
        &E::Progress {
            job_id: 1,
            percent: 250,
            current: "f.txt".into(),
        },
        &name,
    );
    assert_eq!((rows[0].pct, rows[0].current.as_str()), (100, "f.txt"));
    let fin = update_running(
        &mut rows,
        &E::JobFinished {
            job_id: 1,
            profile_id: "a".into(),
            ok: true,
            message: String::new(),
            snapshot_id: None,
        },
        &name,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, 2);
    assert_eq!(fin.map(|f| f.kind), Some("backup".into()));
    update_running(&mut rows, &start(3, "image:C"), &name);
    assert!(rows[1].cancellable);
}

#[test]
fn alert_and_size_formatting() {
    assert_eq!(shorten_alert("짧은 알림"), "짧은 알림");
    let long = "가".repeat(300);
    let out = shorten_alert(&long);
    assert!(out.starts_with(&"가".repeat(90)) && out.contains("눌러서 펼치기"));
    assert_eq!(human_mb(5 * 1_048_576), "5.0MB");
    assert_eq!(human_mb(3 * 1_073_741_824), "3.0GB");
}

#[test]
fn parse_picked_joins_lines_and_strips_bom() {
    assert_eq!(
        parse_picked("\u{feff}C:\\a\r\nD:\\b b\r\n\r\n"),
        "C:\\a;D:\\b b"
    );
    assert_eq!(parse_picked(""), "");
    assert_eq!(parse_picked("  \r\n"), "");
}

#[test]
fn install_result_roundtrip_and_legacy() {
    assert_eq!(
        decode_install_result(&encode_install_result(true, "v1 설치 완료\n둘째 줄")),
        (true, "v1 설치 완료\n둘째 줄".into())
    );
    assert_eq!(
        decode_install_result(&encode_install_result(false, "이미 최신입니다")),
        (false, "이미 최신입니다".into())
    );
    assert_eq!(
        decode_install_result("v3 설치 완료(2개 파일)"),
        (false, "v3 설치 완료(2개 파일)".into())
    );
}

#[test]
fn resolve_profile_id_lookup() {
    let dir = std::env::temp_dir().join(format!("kova_test_resolve_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    let mut p = kova_core::config::Profile::new("prof_test", "테스트");
    p.repo_dir = dir.join("repo").to_string_lossy().to_string();
    store.upsert(p).unwrap();

    assert_eq!(
        resolve_profile_id(&store, "prof_test"),
        Some("prof_test".into())
    );
    assert_eq!(
        resolve_profile_id(&store, &dir.join("repo").to_string_lossy()),
        Some("prof_test".into())
    );
    assert_eq!(
        resolve_profile_id(&store, "default"),
        Some("prof_test".into())
    );
    assert_eq!(resolve_profile_id(&store, ""), Some("prof_test".into()));
    assert_eq!(resolve_profile_id(&store, "   "), Some("prof_test".into()));

    let snap_dir = dir.join("repo").join("snapshots");
    std::fs::create_dir_all(&snap_dir).unwrap();
    std::fs::write(snap_dir.join("20261121_103641.json"), "{}").unwrap();
    assert_eq!(
        resolve_profile_id(&store, "20261121_103641"),
        Some("prof_test".into())
    );

    let mut p2 = kova_core::config::Profile::new("prof_second", "두번째");
    p2.repo_dir = dir.join("repo").to_string_lossy().to_string();
    store.upsert(p2).unwrap();
    std::fs::write(
        snap_dir.join("snap_for_second.json"),
        r#"{"id":"snap_for_second","profile_id":"prof_second","files":[{"path":"b","size":1}]}"#,
    )
    .unwrap();
    assert_eq!(
        resolve_profile_id(&store, "snap_for_second"),
        Some("prof_second".into())
    );

    std::fs::write(snap_dir.join("snap_enc_second.json.enc"), b"cipher_content").unwrap();
    let repo_path = dir.join("repo");
    let _ = kova_core::history::History::open(&repo_path).unwrap();
    let conn = kova_core::rusqlite::Connection::open(repo_path.join("metadata.db")).unwrap();
    conn.execute(
        "INSERT INTO snapshots_meta (id, profile_id) VALUES (?1, ?2)",
        kova_core::rusqlite::params!["snap_enc_second", "prof_second"],
    )
    .unwrap();
    assert_eq!(
        resolve_profile_id(&store, "snap_enc_second"),
        Some("prof_second".into())
    );

    assert_eq!(resolve_profile_id(&store, "unknown_12345"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pick_script_folder_vs_file() {
    let one = build_pick_script("folder");
    let many = build_pick_script("folders");
    assert!(
        one.contains("[FP]::Pick($false,$f.Handle)")
            && many.contains("[FP]::Pick($true,$f.Handle)")
    );
    assert!(
        one.contains("$f.TopMost=$true"),
        "소유 창은 PowerShell 프로세스 안의 TopMost 폼이어야 한다"
    );
    assert!(one.contains("-OutputAssembly"));
    let f = build_pick_script("qblk-open");
    assert!(f.contains("OpenFileDialog") && f.contains("*.qblk"));
    assert!(build_pick_script("qblk-save").contains("SaveFileDialog"));
}

#[test]
fn kind_label_hides_internal_kinds() {
    assert_eq!(kind_label("backup"), "백업");
    assert_eq!(kind_label("verify"), "무결성 검사");
    assert_eq!(kind_label("gc"), "저장소 정리");
    assert_eq!(kind_label("image:C"), "C: 드라이브 이미지 백업");
    assert_eq!(kind_label("image"), "디스크 이미지 백업");
    assert_eq!(kind_label("image_inc:D"), "D: 드라이브 증분 이미지 백업");
    assert_eq!(kind_label("delsnap:20261121_000000"), "스냅샷 삭제");
}

#[test]
fn send_failure_reports_ipc_and_service_errors() {
    use kova_ipc::Event as E;
    let down: std::io::Result<Vec<E>> = Err(std::io::Error::other("pipe"));
    assert!(send_failure(&down)
        .unwrap()
        .contains("서비스에 연결할 수 없습니다"));
    let refused: std::io::Result<Vec<E>> = Ok(vec![E::Error {
        message: "프로파일 없음".into(),
    }]);
    assert_eq!(send_failure(&refused).as_deref(), Some("프로파일 없음"));
    let queued: std::io::Result<Vec<E>> = Ok(vec![E::Queued {
        job_id: 1,
        merged: false,
    }]);
    assert_eq!(send_failure(&queued), None);
}

#[test]
fn gc_target_resolves_real_profile_and_honours_lock() {
    let dir = std::env::temp_dir().join(format!("kova_test_gc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    assert!(gc_target(false, &store, "").is_err());
    assert!(gc_target(false, &store, "C:\\Kova백업").is_err());
    let mut p = kova_core::config::Profile::new("prof_gc", "정리");
    p.repo_dir = dir.join("repo").to_string_lossy().to_string();
    store.upsert(p).unwrap();
    assert_eq!(gc_target(false, &store, ""), Ok("prof_gc".into()));
    assert_eq!(
        gc_target(false, &store, &dir.join("repo").to_string_lossy()),
        Ok("prof_gc".into())
    );
    assert_eq!(gc_target(false, &store, "prof_gc"), Ok("prof_gc".into()));
    assert_eq!(
        gc_target(true, &store, "prof_gc"),
        Err(LOCKED_MSG.to_string())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_profile_id_does_not_create_missing_repo() {
    let dir = std::env::temp_dir().join(format!("kova_test_nocreate_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);
    let mut p = kova_core::config::Profile::new("prof_x", "없는 저장소");
    let repo = dir.join("no_such_repo");
    p.repo_dir = repo.to_string_lossy().to_string();
    store.upsert(p).unwrap();
    assert_eq!(resolve_profile_id(&store, "20990101_000000"), None);
    assert!(
        !repo.exists(),
        "조회만으로 저장소 폴더·metadata.db 를 만들면 안 된다"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn try_begin_allows_only_one_at_a_time() {
    let f = std::sync::atomic::AtomicBool::new(false);
    assert!(try_begin(&f));
    assert!(!try_begin(&f));
    f.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(try_begin(&f));
}

#[test]
fn set_offsite_provider_toggles_offsite_enabled() {
    let dir = std::env::temp_dir().join(format!("kova_offsite_prov_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);

    set_offsite_provider_in(&store, "gdrive");
    let s = store.settings();
    assert_eq!(s.offsite_provider, "gdrive");
    assert!(s.offsite_enabled);

    set_offsite_provider_in(&store, "s3");
    let s = store.settings();
    assert_eq!(s.offsite_provider, "s3");
    assert!(s.offsite_enabled);

    set_offsite_provider_in(&store, "local");
    let s = store.settings();
    assert_eq!(s.offsite_provider, "local");
    assert!(!s.offsite_enabled);

    set_offsite_provider_in(&store, "gdrive");
    assert!(store.settings().offsite_enabled);
    set_offsite_provider_in(&store, "");
    let s = store.settings();
    assert_eq!(s.offsite_provider, "");
    assert!(!s.offsite_enabled);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn try_clear_idle_running_respects_event_seq_and_clears_zombies() {
    let running = std::sync::Mutex::new(vec![RunInfo {
        id: 1,
        name: "테스트".into(),
        pct: 50,
        current: "a.txt".into(),
        cancellable: true,
        kind: "backup".into(),
    }]);
    let seq = std::sync::atomic::AtomicU64::new(5);

    assert!(!try_clear_idle_running(&running, &seq, 4));
    assert_eq!(running.lock().unwrap().len(), 1);

    assert!(try_clear_idle_running(&running, &seq, 5));
    assert!(running.lock().unwrap().is_empty());
}

#[test]
fn busy_gate_lock_releases_on_drop() {
    let g = BusyGate::default();
    {
        let guard = g.lock();
        assert!(guard.is_some());
        assert!(g.lock().is_none(), "가드가 살아 있는 동안 재진입 불가");
    }
    assert!(g.lock().is_some(), "가드 드롭 후 재진입 가능");
}

#[test]
fn repo_drive_usage_handles_empty_and_existing_paths() {
    assert_eq!(repo_drive_usage(""), (String::new(), 0));
    assert_eq!(repo_drive_usage("   "), (String::new(), 0));
    #[cfg(windows)]
    {
        let tmp = std::env::temp_dir().join("kova_nonexistent_subdir_for_usage");
        let (free, pct) = repo_drive_usage(&tmp.to_string_lossy());
        assert!(free.ends_with("GB 여유"), "got: {free}");
        assert!((0..=100).contains(&pct));
    }
}

#[test]
fn system_drive_letter_returns_uppercase_ascii() {
    let ch = system_drive_letter();
    assert!(ch.is_ascii_uppercase());
}

// ───────────────────── Phase 1–3 신규 단위 테스트 ─────────────────────

#[test]
fn apply_fleet_endpoint_validates_and_toggles() {
    let dir = std::env::temp_dir().join(format!("kova_fleet_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = kova_core::config::ConfigStore::new(&dir);

    assert!(apply_fleet_endpoint(&store, "ftp://invalid").is_err());
    assert!(apply_fleet_endpoint(&store, "https://fleet.company.local/hb").is_ok());
    assert_eq!(
        store.settings().fleet_endpoint,
        "https://fleet.company.local/hb"
    );
    assert!(apply_fleet_endpoint(&store, "   ").is_ok());
    assert!(store.settings().fleet_endpoint.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_image_dir_detects_qblk_enc_and_qchain() {
    let dir = std::env::temp_dir().join(format!("kova_imgscan_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let plain = dir.join("C_20261124_010000.qblk");
    let inc = dir.join("C_20261124_020000.qblk");
    let enc = dir.join("C_20261124_030000.qblk.enc");
    let ignored = dir.join("notes.txt");
    std::fs::write(&plain, b"plain-data").unwrap();
    std::fs::write(&inc, b"inc-data").unwrap();
    std::fs::write(kova_image::incremental::chain_path_for(&inc), b"{}").unwrap();
    std::fs::write(&enc, b"QENC\x02\x00\x00\x00payload").unwrap();
    std::fs::write(&ignored, b"ignore").unwrap();

    assert!(is_kova_image_path(&plain));
    assert!(is_kova_image_path(&enc));
    assert!(!is_kova_image_path(&ignored));

    let rows: Vec<_> = scan_image_dir(&dir).into_iter().map(|(_, r)| r).collect();
    assert_eq!(rows.len(), 3);

    let r_plain = rows
        .iter()
        .find(|r| r.name == "C_20261124_010000.qblk")
        .unwrap();
    assert!(!r_plain.encrypted && !r_plain.chained);

    let r_inc = rows
        .iter()
        .find(|r| r.name == "C_20261124_020000.qblk")
        .unwrap();
    assert!(!r_inc.encrypted && r_inc.chained);

    let r_enc = rows
        .iter()
        .find(|r| r.name == "C_20261124_030000.qblk.enc")
        .unwrap();
    assert!(r_enc.encrypted && !r_enc.chained);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn schedule_mode_validation_and_formatting() {
    assert_eq!(schedule_mode_from_type("interval_hours"), 0);
    assert_eq!(schedule_mode_from_type("daily"), 1);
    assert_eq!(schedule_mode_from_type("weekly"), 2);
    assert_eq!(schedule_mode_from_type("monthly"), 3);

    let base = kova_core::config::Profile::new("p1", "테스트");

    let iv = apply_schedule_mode(base.clone(), true, 0, "6", "*.tmp").unwrap();
    assert_eq!(iv.schedule_type, "interval_hours");
    assert_eq!(iv.schedule_value, "6");
    assert_eq!(kova_core::profile_form::schedule_text(&iv), "6시간마다");
    assert!(apply_schedule_mode(base.clone(), true, 0, "02:00", "").is_err());

    let dy = apply_schedule_mode(base.clone(), true, 1, "2:30", "").unwrap();
    assert_eq!(dy.schedule_type, "daily");
    assert_eq!(dy.schedule_value, "02:30");
    assert_eq!(kova_core::profile_form::schedule_text(&dy), "매일 02:30");
    assert!(apply_schedule_mode(base.clone(), true, 1, "15@02:30", "").is_err());

    let wk = apply_schedule_mode(base.clone(), true, 2, "mon,wed@3:00", "").unwrap();
    assert_eq!(wk.schedule_type, "weekly");
    assert_eq!(wk.schedule_value, "MON,WED@03:00");
    assert_eq!(
        kova_core::profile_form::schedule_text(&wk),
        "매주 MON,WED 03:00"
    );
    assert!(apply_schedule_mode(base.clone(), true, 2, "15@03:00", "").is_err());
    assert!(apply_schedule_mode(base.clone(), true, 2, "03:00", "").is_err());

    let mo = apply_schedule_mode(base.clone(), true, 3, "15@2:30", "").unwrap();
    assert_eq!(mo.schedule_type, "monthly");
    assert_eq!(mo.schedule_value, "15@02:30");
    assert_eq!(
        kova_core::profile_form::schedule_text(&mo),
        "매월 15일 02:30"
    );
    assert!(apply_schedule_mode(base.clone(), true, 3, "MON@02:30", "").is_err());
    assert!(apply_schedule_mode(base, true, 3, "29@02:30", "").is_err());
}

#[test]
fn fmt_size_formats_all_units() {
    assert_eq!(fmt_size(512), "512B");
    assert_eq!(fmt_size(2048), "2.0KB");
    assert_eq!(fmt_size(5 * 1024 * 1024), "5.0MB");
    assert_eq!(fmt_size(2 * 1024 * 1024 * 1024), "2.00GB");
}

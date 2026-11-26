//! 복구 모의훈련: 프로파일의 가장 최근 스냅샷을 임시 폴더에 실제로 복원해 본다.
//! 복원 과정에서 블롭마다 해시를 확인하므로, 통과하면 "지금 이 백업으로 복구가 된다"는 뜻이다.
//! 원본·저장소는 읽기만 하고, 임시 폴더는 끝나면 지운다.
//! 디스크·백신 부하를 줄이려고 파일 전체가 아니라 표본(파일 수·용량 상한)만 복원하고,
//! 2개 스레드의 백그라운드 우선순위(입출력 포함)로 돌린다.
use crate::config::Profile;
use crate::history::History;
use crate::lock::{LockError, RepoLock};
use kova_engine::ops::{run_restore, RestoreOptions};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

static DRILL_SEQ: AtomicU64 = AtomicU64::new(0);

/// 한 번의 훈련에서 복원하는 최대 파일 수
const SAMPLE_MAX_FILES: usize = 300;
/// 한 번의 훈련에서 복원하는 대략의 최대 용량(바이트)
const SAMPLE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const DRILL_PREFIX: &str = "kova_drill_";

/// 이전 실행이 도중에 끊겨 남긴 `kova_drill_*` 임시 폴더를 지운다. 훈련이 돌고 있지 않을 때(서비스 시작 시) 부른다.
/// 지운 폴더 수를 돌려준다.
pub fn cleanup_stale(scratch_root: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(scratch_root) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir && name.starts_with(DRILL_PREFIX) && std::fs::remove_dir_all(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// 현재 스레드를 백그라운드 모드(CPU·입출력 우선순위 낮춤)로 바꾼다. Windows 외에서는 아무것도 하지 않는다.
fn enter_background_mode() {
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
        };
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    }
}

pub fn run(p: &Profile, scratch_root: &Path) -> String {
    let repo = Path::new(&p.repo_dir);
    let _lock = match RepoLock::acquire_wait(repo, Duration::from_secs(30)) {
        Ok(l) => l,
        Err(LockError::Busy) => {
            return format!(
                "{}: 복구 훈련을 건너뜁니다: 다른 작업이 저장소를 사용 중입니다",
                p.name
            );
        }
        Err(LockError::Io(e)) => {
            return format!("{}: 저장소를 읽지 못했습니다 ({e})", p.name);
        }
    };
    let snap = match History::open(repo).and_then(|mut h| {
        h.sync_snapshots()?;
        h.list_snapshots()
    }) {
        Ok(v) => {
            let mut mine: Vec<_> = v.iter().filter(|s| s.profile_id == p.id).cloned().collect();
            if mine.is_empty() {
                mine = v.into_iter().filter(|s| s.profile_id.is_empty()).collect();
            }
            mine.sort_by(|a, b| a.created_at.total_cmp(&b.created_at));
            match mine.pop() {
                Some(s) => s,
                None => return format!("{}: 스냅샷이 없어 훈련할 수 없습니다", p.name),
            }
        }
        Err(e) => return format!("{}: 저장소를 읽지 못했습니다 ({e})", p.name),
    };
    let only = match kova_engine::ops::sample_snapshot_paths(
        repo,
        &snap.id,
        SAMPLE_MAX_FILES,
        SAMPLE_MAX_BYTES,
    ) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return format!("{}: 스냅샷에 파일이 없어 훈련할 수 없습니다", p.name),
        Err(e) => return format!("{}: 스냅샷을 읽지 못했습니다 ({e})", p.name),
    };
    // 표본만 복원하므로 필요한 공간은 표본 크기 기준(상한 + 여유 10%)
    let need = SAMPLE_MAX_BYTES.min(snap.total_bytes.max(0) as u64) / 10 * 11;
    if let Some(free) = crate::diskspace::free_bytes(scratch_root) {
        if free < need {
            return format!(
                "{}: 임시 공간이 모자라 건너뜁니다 (필요 약 {:.1} GB, 여유 {:.1} GB)",
                p.name,
                need as f64 / 1e9,
                free as f64 / 1e9
            );
        }
    }
    let seq = DRILL_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = scratch_root.join(format!(
        "{DRILL_PREFIX}{}_{}_{}",
        std::process::id(),
        seq,
        snap.id
    ));
    let opts = RestoreOptions {
        repo: repo.to_path_buf(),
        session_id: snap.id.clone(),
        only: Some(only),
        target: Some(tmp.clone()),
    };
    // 전용 풀(2스레드, 백그라운드 우선순위)에서 복원해 디스크·Defender 부하를 낮춘다
    let res = match rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .thread_name(|i| format!("kova-drill-{i}"))
        .start_handler(|_| enter_background_mode())
        .build()
    {
        Ok(pool) => pool.install(|| run_restore(&opts, &|_| {}, &AtomicBool::new(false))),
        Err(_) => run_restore(&opts, &|_| {}, &AtomicBool::new(false)),
    };
    // 이 함수가 만든 임시 폴더만 지운다
    if tmp
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with(DRILL_PREFIX))
    {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    match res {
        Ok(s) => format!(
            "{}: 복구 훈련 통과 — 최근 스냅샷에서 표본 {}개 항목을 {:.0}초에 복원·해시 확인",
            p.name, s.total_files, s.elapsed_seconds
        ),
        Err(e) => format!("{}: 복구 훈련 실패 — {e}", p.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kova_engine::ops::{run_backup, BackupOptions};

    #[test]
    fn drill_restores_latest_snapshot_cleans_up_and_catches_corruption() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), "hello drill").unwrap();
        let repo = d.path().join("repo");
        let opts = BackupOptions {
            sources: vec![src.clone()],
            repo: repo.clone(),
            session_id: None,
            zstd_level: 3,
            exclude: vec![],
            profile_id: None,
            scan_from: None,
            ..Default::default()
        };
        run_backup(&opts, &|_| {}, &AtomicBool::new(false)).unwrap();
        let mut p = Profile::new("p", "훈련");
        p.sources = vec![src.to_string_lossy().into()];
        p.repo_dir = repo.to_string_lossy().into();
        let scratch = d.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let ok = run(&p, &scratch);
        assert!(ok.contains("통과"), "{ok}");
        assert_eq!(
            std::fs::read_dir(&scratch).unwrap().count(),
            0,
            "임시 폴더가 남음"
        );
        // 블롭을 망가뜨리면 훈련이 실패해야 한다
        // 백업은 새 블롭을 팩으로 쓰므로 낱개 블롭 폴더와 팩 폴더를 모두 망가뜨린다
        for e in walk(&repo.join("blobs"))
            .into_iter()
            .chain(walk(&repo.join("packs")))
        {
            std::fs::write(e, b"garbage").unwrap();
        }
        let bad = run(&p, &scratch);
        assert!(bad.contains("실패"), "{bad}");
    }

    #[test]
    fn drill_picks_matching_profile_snapshot_in_shared_repo() {
        let d = tempfile::tempdir().unwrap();
        let src_a = d.path().join("src_a");
        std::fs::create_dir_all(&src_a).unwrap();
        std::fs::write(src_a.join("a.txt"), "profile a data").unwrap();
        let repo = d.path().join("repo");

        // prof_a 의 정상 스냅샷
        let opts = BackupOptions {
            sources: vec![src_a.clone()],
            repo: repo.clone(),
            session_id: Some("20261101_000000".into()),
            zstd_level: 3,
            exclude: vec![],
            profile_id: Some("prof_a".into()),
            scan_from: None,
            ..Default::default()
        };
        run_backup(&opts, &|_| {}, &AtomicBool::new(false)).unwrap();

        // 같은 저장소에 더 최신인 prof_b 스냅샷(블롭 누락)을 추가:
        // prof_a 훈련이 prof_b 스냅샷을 잘못 고르면 실패하므로 프로파일 분리가 검증된다.
        let missing_hash = "ff".repeat(32);
        std::fs::write(
            repo.join("snapshots").join("20261199_000000.json"),
            format!(
                r#"{{"id":"20261199_000000","created_at":9999999999.0,"profile_id":"prof_b","files":[{{"path":"broken.txt","size":10,"chunks":[{{"hash":"{missing_hash}","offset":0,"length":10,"compressed_length":10}}]}}]}}"#
            ),
        )
        .unwrap();

        let scratch = d.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let mut pa = Profile::new("prof_a", "프로파일A");
        pa.repo_dir = repo.to_string_lossy().into();
        let res_a = run(&pa, &scratch);
        assert!(res_a.contains("통과"), "{res_a}");

        let mut pb = Profile::new("prof_b", "프로파일B");
        pb.repo_dir = repo.to_string_lossy().into();
        let res_b = run(&pb, &scratch);
        assert!(res_b.contains("실패"), "{res_b}");

        let mut pc = Profile::new("prof_c", "프로파일C");
        pc.repo_dir = repo.to_string_lossy().into();
        let res_c = run(&pc, &scratch);
        assert!(res_c.contains("스냅샷이 없어"), "{res_c}");
    }

    #[test]
    fn drill_restores_only_a_bounded_sample_and_cleanup_removes_stale_dirs() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        for i in 0..10 {
            std::fs::write(src.join(format!("f{i}.txt")), format!("data {i}")).unwrap();
        }
        let repo = d.path().join("repo");
        let opts = BackupOptions {
            sources: vec![src.clone()],
            repo: repo.clone(),
            session_id: Some("20261101_000000".into()),
            zstd_level: 3,
            exclude: vec![],
            profile_id: None,
            scan_from: None,
            ..Default::default()
        };
        run_backup(&opts, &|_| {}, &AtomicBool::new(false)).unwrap();
        let a =
            kova_engine::ops::sample_snapshot_paths(&repo, "20261101_000000", 3, 1 << 20).unwrap();
        let b =
            kova_engine::ops::sample_snapshot_paths(&repo, "20261101_000000", 3, 1 << 20).unwrap();
        assert_eq!(a.len(), 3);
        assert_eq!(a, b, "표본은 결정적이어야 함");
        let all = kova_engine::ops::sample_snapshot_paths(&repo, "20261101_000000", 100, 1 << 20)
            .unwrap();
        assert_eq!(all.len(), 10);

        let scratch = d.path().join("scratch");
        std::fs::create_dir_all(scratch.join("kova_drill_1_0_x").join("sub")).unwrap();
        std::fs::create_dir_all(scratch.join("other_dir")).unwrap();
        assert_eq!(cleanup_stale(&scratch), 1);
        assert!(scratch.join("other_dir").exists());
        assert!(!scratch.join("kova_drill_1_0_x").exists());
    }

    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![];
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }
}

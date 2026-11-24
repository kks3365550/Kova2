//! 유지보수 작업(무결성 검증, 고아 블롭 정리, 스냅샷 삭제), 프로파일 해석, 고아 VSS 섀도 자동 정리.
use crate::{JobOutcome, Supervisor, SvcEvent, BUSY_PREFIX, REPO_LOCK_WAIT};
use chrono::Local;
use kova_core::config::Profile;
use kova_core::history::History;
use kova_core::jobs::Job;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 저장소 안의 이력 DB 를 이미 있을 때만 연다(조회 때문에 저장소 폴더·DB 를 새로 만들지 않는다).
fn open_history_if_exists(repo: &Path) -> Option<History> {
    if repo.join("metadata.db").is_file() {
        History::open(repo).ok()
    } else {
        None
    }
}

/// 마커 파일 내용에서 유효한 VSS 섀도 GUID 목록을 추출한다.
pub(crate) fn extract_vss_guids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for raw_tok in text.split_whitespace() {
        let tok = raw_tok
            .trim()
            .strip_prefix("shadow_id=")
            .unwrap_or(raw_tok.trim());
        let is_guid = tok.len() >= 36
            && tok.contains('-')
            && tok
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'));
        if is_guid && !ids.iter().any(|x| x == tok) {
            ids.push(tok.to_string());
        }
    }
    ids
}

impl Supervisor {
    /// 시작 시 호출: 이전 실행이 지우지 못한 VSS 섀도 복사본 마커를 점검한다.
    /// 기록에 유효한 섀도 GUID 가 들어 있으면 `kova_core::vss::cleanup_orphaned_shadows` 로 자동 정리하고,
    /// 로그에 경고를 남긴 뒤 마커 파일을 치운다.
    pub fn report_leftover_vss(&self) -> usize {
        let mut n = 0;
        let Ok(rd) = std::fs::read_dir(&self.0.config_dir) else {
            return 0;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !(name.starts_with("vss_inflight_") && name.ends_with(".txt")) {
                continue;
            }
            let what = std::fs::read_to_string(e.path()).unwrap_or_default();
            let first_line = what.lines().next().unwrap_or("").trim();
            let ids = extract_vss_guids(&what);
            let cleaned = if ids.is_empty() {
                0
            } else {
                kova_core::vss::cleanup_orphaned_shadows(&ids)
            };
            let msg = if cleaned > 0 {
                format!(
                    "이전 실행이 VSS 섀도 복사본을 정리하지 못했을 수 있습니다({first_line}). 기록된 섀도 GUID {cleaned}개 자동 정리를 실행했습니다"
                )
            } else {
                format!(
                    "이전 실행이 VSS 섀도 복사본을 정리하지 못했을 수 있습니다({}). 'vssadmin list shadows' 로 확인하세요",
                    what.trim()
                )
            };
            kova_core::applog::write(&self.0.config_dir, "WARN", &msg);
            let _ = std::fs::remove_file(e.path());
            n += 1;
        }
        n
    }

    /// 프로파일 ID, 저장소 경로, 스냅샷 ID 또는 "default"로부터 프로파일을 찾는다.
    pub(crate) fn resolve_profile(&self, id_or_target: &str) -> Option<Profile> {
        let t = id_or_target.trim();
        if t.is_empty() {
            return self.0.store.profiles().into_iter().next();
        }
        if let Some(p) = self.0.store.get(t) {
            return Some(p);
        }
        let profiles = self.0.store.profiles();
        if let Some(p) = profiles.iter().find(|p| p.repo_dir.eq_ignore_ascii_case(t)) {
            return Some(p.clone());
        }
        for p in &profiles {
            let repo = PathBuf::from(&p.repo_dir);
            let snap_json = repo.join("snapshots").join(format!("{t}.json"));
            let snap_enc = repo.join("snapshots").join(format!("{t}.json.enc"));
            if snap_json.exists() || snap_enc.exists() {
                if let Ok(cas) = kova_engine::storage::CasStorage::new(&repo) {
                    if let Ok(m) = cas.load_manifest(t) {
                        if let Some(ref pid) = m.profile_id {
                            if let Some(target) = profiles.iter().find(|pr| pr.id == *pid) {
                                return Some(target.clone());
                            }
                        }
                    }
                }
                if let Some(h) = open_history_if_exists(&repo) {
                    if let Ok(snaps) = h.list_snapshots() {
                        if let Some(s) = snaps.iter().find(|s| s.id == t) {
                            if !s.profile_id.is_empty() {
                                if let Some(target) =
                                    profiles.iter().find(|pr| pr.id == s.profile_id)
                                {
                                    return Some(target.clone());
                                }
                            }
                        }
                    }
                }
                return Some(p.clone());
            }
            if let Some(h) = open_history_if_exists(&repo) {
                if let Ok(snaps) = h.list_snapshots() {
                    if let Some(s) = snaps.iter().find(|s| s.id == t) {
                        if !s.profile_id.is_empty() {
                            if let Some(target) = profiles.iter().find(|pr| pr.id == s.profile_id) {
                                return Some(target.clone());
                            }
                        }
                        return Some(p.clone());
                    }
                }
            }
        }
        if t.eq_ignore_ascii_case("default") {
            return profiles.into_iter().next();
        }
        None
    }

    /// 스냅샷 삭제: 저장소는 프로파일 설정에서만 찾는다(요청자가 경로를 정하지 못한다).
    pub(crate) fn run_delete_snapshot_job(&self, job: &Job) -> JobOutcome {
        let Some(prof) = self.resolve_profile(&job.profile_id) else {
            return JobOutcome::fail(format!("프로파일 없음: {}", job.profile_id));
        };
        let repo = Path::new(&prof.repo_dir);
        let _smb = match kova_core::smb::SmbMountGuard::connect_if_needed(&self.0.config_dir, repo)
        {
            Ok(g) => g,
            Err(e) => return JobOutcome::fail(format!("저장소 SMB 연결 실패: {e}")),
        };
        match kova_core::retention::delete_snapshot(repo, &job.arg) {
            Ok(m) => JobOutcome {
                ok: true,
                message: m,
                snapshot_id: None,
                bytes: 0,
                files: 1,
            },
            Err(m) => JobOutcome::fail(m),
        }
    }

    pub(crate) fn run_gc_job(&self, job: &Job) -> JobOutcome {
        let Some(prof) = self.resolve_profile(&job.profile_id) else {
            return JobOutcome::fail(format!("프로파일 없음: {}", job.profile_id));
        };
        let repo = Path::new(&prof.repo_dir);
        let _smb = match kova_core::smb::SmbMountGuard::connect_if_needed(&self.0.config_dir, repo)
        {
            Ok(g) => g,
            Err(e) => {
                self.note_maint_failed(&prof.id);
                return JobOutcome::fail(format!("저장소 SMB 연결 실패: {e}"));
            }
        };
        let _repo_lock = match kova_core::lock::RepoLock::acquire_wait(repo, REPO_LOCK_WAIT) {
            Ok(l) => l,
            Err(kova_core::lock::LockError::Busy) => {
                return JobOutcome::fail(format!("{BUSY_PREFIX}이라 정리를 건너뛰었습니다"));
            }
            Err(e) => {
                self.note_maint_failed(&prof.id);
                return JobOutcome::fail(format!("저장소 잠금 실패: {e}"));
            }
        };
        self.emit(SvcEvent::Progress {
            job_id: job.id,
            percent: 50,
            current: "고아 블롭 및 저장소 정리 중...".into(),
        });
        // 1시간 미만의 새 블롭은 진행 중 백업 것일 수 있어 보호된다
        match kova_core::gc::prune_orphans(repo, kova_core::gc::DEFAULT_MIN_AGE_SECS) {
            Ok(r) => {
                self.clear_maint_failed(&prof.id);
                let now = Local::now().timestamp() as f64;
                // 최신 프로파일을 다시 읽어 갱신한다(작업 중 바뀐 설정을 덮어쓰거나 지운 프로파일을 되살리지 않음)
                if let Some(mut p) = self.0.store.get(&prof.id) {
                    p.extra.insert("last_gc_at".into(), now.into());
                    let _ = self.0.store.upsert(p);
                }
                self.emit(SvcEvent::Progress {
                    job_id: job.id,
                    percent: 100,
                    current: "정리 완료".into(),
                });
                JobOutcome {
                    ok: true,
                    message: format!(
                        "정리 완료: 고아 블롭 {}개, {}바이트 확보",
                        r.deleted_blobs, r.freed_bytes
                    ),
                    snapshot_id: None,
                    bytes: r.freed_bytes,
                    files: r.deleted_blobs as u64,
                }
            }
            Err(e) => {
                self.note_maint_failed(&prof.id);
                JobOutcome::fail(e.to_string())
            }
        }
    }

    pub(crate) fn run_verify_job(&self, job: &Job) -> JobOutcome {
        let Some(prof) = self.resolve_profile(&job.profile_id) else {
            return JobOutcome::fail(format!("프로파일 없음: {}", job.profile_id));
        };
        let repo = Path::new(&prof.repo_dir);
        let _smb = match kova_core::smb::SmbMountGuard::connect_if_needed(&self.0.config_dir, repo)
        {
            Ok(g) => g,
            Err(e) => {
                self.note_maint_failed(&prof.id);
                return JobOutcome::fail(format!("저장소 SMB 연결 실패: {e}"));
            }
        };
        let _repo_lock = match kova_core::lock::RepoLock::acquire_wait(repo, REPO_LOCK_WAIT) {
            Ok(l) => l,
            Err(kova_core::lock::LockError::Busy) => {
                return JobOutcome::fail(format!("{BUSY_PREFIX}이라 검증을 건너뛰었습니다"));
            }
            Err(e) => {
                self.note_maint_failed(&prof.id);
                return JobOutcome::fail(format!("저장소 잠금 실패: {e}"));
            }
        };
        let deep = match job.arg.as_str() {
            "deep" => true,
            "quick" => false,
            _ => self.0.store.settings().verify_deep,
        };
        let mode = if deep {
            "정밀 검증"
        } else {
            "빠른 검증"
        };
        self.emit(SvcEvent::Progress {
            job_id: job.id,
            percent: 50,
            current: format!("{mode} 수행 중..."),
        });
        let verify_result = kova_core::verify::verify_repo(repo, deep);
        let res = match &verify_result {
            Ok(r) if r.ok() => {
                self.emit(SvcEvent::Progress {
                    job_id: job.id,
                    percent: 100,
                    current: "검증 완료".into(),
                });
                JobOutcome {
                    ok: true,
                    message: format!(
                        "{mode} 통과: 스냅샷 {}개, 파일 {}개, 청크 {}개",
                        r.snapshots, r.files, r.unique_chunks
                    ),
                    snapshot_id: None,
                    bytes: 0,
                    files: r.files as u64,
                }
            }
            Ok(r) => JobOutcome {
                ok: false,
                message: format!(
                    "{mode} 문제 {}건 (첫 항목: {:?})",
                    r.problems.len(),
                    r.problems[0]
                ),
                snapshot_id: None,
                bytes: 0,
                files: r.files as u64,
            },
            Err(e) => JobOutcome::fail(e.to_string()),
        };
        // 화면의 "검증됨/오류 있음" 표시는 스냅샷 기록(metadata.db)을 읽으므로 검증 결과를 거기에 남긴다
        if let Ok(r) = &verify_result {
            let now = Local::now().timestamp() as f64;
            if let Ok(h) = History::open(repo) {
                let mut bad: HashMap<String, i64> = HashMap::new();
                for pr in &r.problems {
                    match pr {
                        kova_core::verify::Problem::MissingBlob { snapshot, .. } => {
                            *bad.entry(snapshot.clone()).or_default() += 1;
                        }
                        kova_core::verify::Problem::BadManifest { file, .. } => {
                            *bad.entry(file.trim_end_matches(".json").to_string())
                                .or_default() += 1;
                        }
                        // 어느 스냅샷의 문제인지 알 수 없는 손상 청크는 개별 표시를 바꾸지 않는다
                        kova_core::verify::Problem::CorruptBlob { .. } => {}
                    }
                }
                for rec in h.list_snapshots().unwrap_or_default() {
                    match bad.get(&rec.id) {
                        Some(n) => {
                            let _ = h.set_verification(&rec.id, false, *n, now);
                        }
                        None if r.ok() => {
                            let _ = h.set_verification(&rec.id, true, 0, now);
                        }
                        None => {}
                    }
                }
            }
            if r.ok() {
                self.clear_maint_failed(&prof.id);
            } else {
                self.note_maint_failed(&prof.id);
            }
            if let Some(mut p) = self.0.store.get(&prof.id) {
                p.extra.insert("last_verify_at".into(), now.into());
                let _ = self.0.store.upsert(p);
            }
        } else {
            self.note_maint_failed(&prof.id);
        }
        res
    }
}

//! 파일 백업 작업 실행: SMB 마운트, 저장소 잠금, VSS 스냅샷(GUID 영속화), 증분 백업,
//! 랜섬웨어 이상 징후 탐지, 보존 정책, 팩 압축, WORM 보호, 로컬/SMB·Google Drive·S3 오프사이트 복제.
use crate::{JobOutcome, Supervisor, SvcEvent, BUSY_PREFIX, REPO_LOCK_WAIT};
use chrono::Local;
use kova_core::history::History;
use kova_core::jobs::Job;
use kova_core::schedule::MAX_AUTO_RETRIES;
use kova_engine::ops::{run_backup_with_threads, BackupOptions, EngineError, Event as EngineEvent};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

impl Supervisor {
    pub(crate) fn run_backup_job(&self, job: &Job, cancel: &AtomicBool) -> JobOutcome {
        let Some(prof) = self.resolve_profile(&job.profile_id) else {
            return JobOutcome::fail(format!("프로파일 없음: {}", job.profile_id));
        };
        let repo_path = PathBuf::from(&prof.repo_dir);
        // 저장소가 UNC(SMB/NAS) 경로이고 저장된 자격 증명이 있으면 먼저 연결한다
        let _repo_smb = match kova_core::smb::SmbMountGuard::connect_if_needed(
            &self.0.config_dir,
            &repo_path,
        ) {
            Ok(g) => g,
            Err(e) => return JobOutcome::fail(format!("저장소 SMB 연결 실패: {e}")),
        };
        // 같은 저장소에 백업·GC·검증·복원이 동시에 쓰지 못하게 OS 파일 잠금을 먼저 잡는다
        let _repo_lock = match kova_core::lock::RepoLock::acquire_wait(&repo_path, REPO_LOCK_WAIT) {
            Ok(l) => l,
            Err(kova_core::lock::LockError::Busy) => {
                return JobOutcome::fail(format!("{BUSY_PREFIX}입니다. 잠시 후 다시 시도하세요"));
            }
            Err(e) => return JobOutcome::fail(format!("저장소 잠금 실패: {e}")),
        };
        let settings = self.0.store.settings();
        let encrypt_manifest =
            settings.encrypt_manifests && kova_core::repocrypto::is_enabled(&repo_path);
        let mut opts = BackupOptions {
            sources: prof.sources.iter().map(PathBuf::from).collect(),
            repo: repo_path,
            zstd_level: prof.compression_level,
            exclude: prof.exclude_patterns.clone(),
            profile_id: Some(prof.id.clone()),
            encrypt_manifest,
            preserve_metadata: true,
            preserve_acl: settings.preserve_acl,
            ..Default::default()
        };
        // 원본이 없으면(드라이브 분리 등) 엔진은 빈 백업을 "성공"으로 끝내므로 여기서 실패로 막는다
        let missing: Vec<String> = opts
            .sources
            .iter()
            .filter(|s| !s.exists())
            .map(|s| s.display().to_string())
            .collect();
        // 일부만 없으면(임시 폴더·바로가기 등) 있는 것만 백업하고 메시지에 남긴다. 전부 없으면 실패로 막는다
        let partial_missing = !missing.is_empty() && missing.len() < opts.sources.len();
        if partial_missing {
            opts.sources.retain(|s| s.exists());
        }
        let last_pct = Mutex::new(u64::MAX);
        let id = job.id;
        let on_event = |e: EngineEvent| {
            if let EngineEvent::Progress(p) = e {
                let mut l = last_pct.lock().unwrap();
                // 파일 백업 단계는 0~95%로 매핑하여 후속 정리(팩·보호·복제) 단계와 진행률이 겹치거나 뒤로 가지 않게 한다
                let scaled = (p.percent * 95 / 100).min(95);
                if *l == u64::MAX || scaled > *l {
                    *l = scaled;
                    self.emit(SvcEvent::Progress {
                        job_id: id,
                        percent: scaled,
                        current: p.current_file,
                    });
                }
            }
        };
        // 저장소 드라이브 여유 공간이 설정의 최소 기준보다 적으면 시작하지 않는다(디스크가 가득 차 백업이 중간에 깨지는 것을 막는다)
        let space_check = kova_core::diskspace::check_min_free(
            kova_core::diskspace::free_bytes(&opts.repo),
            settings.min_free_disk_gb,
        );
        // 암호화가 켜져 있는데 이 저장소가 아직 암호화되지 않았으면 평문으로 쓰지 않고 멈춘다(복구 코드는 설정 화면에서 켤 때만 보여 준다)
        let encrypt_missing =
            settings.encrypt_backups && !kova_core::repocrypto::is_enabled(&opts.repo);
        // VSS: 원본 드라이브를 스냅샷해 잠긴 파일도 같은 시점으로 읽는다. 못 만들면(권한·파일시스템) 직접 읽고 메시지에 남긴다
        let mut vss_note = String::new();
        let shadows = if settings.use_vss
            && space_check.is_ok()
            && !encrypt_missing
            && (missing.is_empty() || partial_missing)
        {
            let vss_what = format!("파일 백업 profile={} sources={:?}", prof.id, opts.sources);
            self.mark_vss(job.id, &vss_what, &[]);
            match kova_core::vss::ShadowSet::create_for(&opts.sources) {
                Ok(set) => {
                    // 비정상 종료 시 고아 섀도를 자동 정리할 수 있도록 실제 섀도 GUID 목록을 기록한다
                    self.mark_vss(job.id, &vss_what, set.shadow_ids());
                    opts.scan_from = Some(opts.sources.iter().map(|p| set.map(p)).collect());
                    vss_note = format!(", VSS 스냅샷 {}개 사용", set.count());
                    Some(set)
                }
                Err(e) => {
                    vss_note = format!(", VSS 사용 못 해 직접 읽음({e})");
                    None
                }
            }
        } else {
            None
        };
        let res = if let Err(why) = space_check {
            Err(EngineError::Msg(why))
        } else if encrypt_missing {
            Err(EngineError::Msg(
                "백업 암호화가 켜져 있지만 이 저장소는 아직 암호화되지 않았습니다. 설정에서 저장을 눌러 암호화를 시작하세요"
                    .into(),
            ))
        } else if missing.is_empty() || partial_missing {
            let max_threads = settings.max_cpu_threads as usize;
            run_backup_with_threads(&opts, max_threads, &on_event, cancel)
        } else {
            Err(EngineError::Msg(format!(
                "원본 경로를 찾을 수 없음: {}",
                missing.join(", ")
            )))
        };
        drop(shadows); // 백업이 끝났으니 섀도 복사본 삭제
        self.unmark_vss(job.id);
        // 보존 정책·오프사이트 설정은 최신 프로파일에서 읽고, 상태·스냅샷·시각 반영은 모든 후속 업로드가 끝난 직전에
        // 다시 읽어 적용한다(긴 오프사이트/구글 드라이브 업로드 중 바꾼 설정을 덮어쓰거나 삭제된 프로파일을 되살리지 않음).
        let prof = self.0.store.get(&prof.id).unwrap_or(prof);
        let mut user_cancelled = false;
        let out = match res {
            Ok(s) => {
                let had_previous = prof.last_snapshot_id.is_some();
                let manifest_path = opts
                    .repo
                    .join("snapshots")
                    .join(format!("{}.json", s.session_id));
                let suspect_cnt = kova_core::anomaly::count_suspect_in_manifest(&manifest_path);
                let anomaly = kova_core::anomaly::detect(
                    s.total_files,
                    s.new_files,
                    s.modified_files,
                    suspect_cnt,
                    had_previous,
                    &kova_core::anomaly::AnomalyConfig::default(),
                );
                // 보존 정책: 랜섬웨어 이상 징후가 감지되면 정상 옛 스냅샷이 밀려 삭제되지 않도록 자동 보류한다
                let ret = if let Some(ref a) = anomaly {
                    kova_core::applog::write(
                        &self.0.config_dir,
                        "WARN",
                        &format!(
                            "랜섬웨어 이상 징후 감지로 보존 정리 보류: profile={} reason={}",
                            prof.id,
                            a.summary()
                        ),
                    );
                    kova_core::retention::RetentionResult::default()
                } else {
                    let policy = kova_core::retention::Policy {
                        retention_count: Some(prof.retention_count as usize),
                        retention_days: Some(prof.retention_days),
                        keep_daily: prof
                            .extra
                            .get("keep_daily")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        keep_weekly: prof
                            .extra
                            .get("keep_weekly")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        keep_monthly: prof
                            .extra
                            .get("keep_monthly")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        keep_yearly: prof
                            .extra
                            .get("keep_yearly")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                    };
                    kova_core::retention::apply_for_profile(&opts.repo, &prof.id, policy)
                };
                if let Ok(mut h) = History::open(&opts.repo) {
                    let _ = h.sync_snapshots();
                }
                let st_now = self.0.store.settings();
                // 팩 컨테이너: 1시간 이상 된 낱개 블롭을 묶는다(이미 상단에서 _repo_lock 보유 중).
                let pack_note = if st_now.pack_blobs {
                    self.emit(SvcEvent::Progress {
                        job_id: id,
                        percent: 96,
                        current: "블롭 팩 압축 정리 중...".into(),
                    });
                    match kova_core::packer::compact(
                        &opts.repo,
                        kova_core::gc::DEFAULT_MIN_AGE_SECS,
                        kova_core::packer::DEFAULT_PACK_BYTES,
                    ) {
                        Ok(r) if r.packed_blobs > 0 => {
                            format!(", 블롭 {}개를 팩 {}개로 묶음", r.packed_blobs, r.packs)
                        }
                        Ok(_) => String::new(),
                        Err(e) => format!(", 팩 묶기 실패: {e}"),
                    }
                } else {
                    String::new()
                };
                // 랜섬웨어 보호: 이번 백업으로 생긴 매니페스트·블롭을 읽기 전용(+매니페스트는 삭제 거부 ACL)으로 잠근다.
                // 삭제는 보존 정책·정리가 승인 경로(worm::remove_protected)로만 한다
                let protected = if st_now.enable_ransomware_protection {
                    self.emit(SvcEvent::Progress {
                        job_id: id,
                        percent: 97,
                        current: "랜섬웨어 변조 차단 보호 적용 중...".into(),
                    });
                    let st = kova_core::worm::protect_new_files(&opts.repo);
                    Some(st.blobs + st.snapshots)
                } else {
                    None
                };
                let mut msg = if s.skipped_files.is_empty() {
                    format!("완료: {}개 항목, {}바이트", s.total_files, s.total_bytes)
                } else {
                    // 건너뛴 파일은 경로만 보인다(운영체제 오류 원문은 로그에 있으므로 메시지에서 뺀다)
                    let denied = s
                        .skipped_files
                        .iter()
                        .filter(|f| f.contains("os error 5") || f.contains("os error 32"))
                        .count();
                    format!(
                        "완료(건너뜀 {}개{}: {}{}): {}개 항목",
                        s.skipped_files.len(),
                        if denied > 0 {
                            format!(", 시스템이 잠근 파일 {denied}개")
                        } else {
                            String::new()
                        },
                        s.skipped_files
                            .iter()
                            .take(3)
                            .map(|f| f.split(" (").next().unwrap_or(f).to_string())
                            .collect::<Vec<_>>()
                            .join("; "),
                        if s.skipped_files.len() > 3 {
                            " 외"
                        } else {
                            ""
                        },
                        s.total_files
                    )
                };
                // 오프사이트(폴더/SMB) 복제: 설정돼 있으면 백업 직후 이어서 복제. 실패해도 로컬 백업은 성공으로 두고 메시지에 남긴다
                if let Some(dest) = prof
                    .extra
                    .get("offsite_dir")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    self.emit(SvcEvent::Progress {
                        job_id: id,
                        percent: 98,
                        current: "오프사이트 백업 복제 중...".into(),
                    });
                    let dest_path = Path::new(dest);
                    match kova_core::smb::SmbMountGuard::connect_if_needed(
                        &self.0.config_dir,
                        dest_path,
                    ) {
                        Ok(_offsite_smb) => {
                            let bw_limit =
                                (st_now.offsite_bw_limit_mbps as u64).saturating_mul(1024 * 1024);
                            match kova_core::offsite::replicate_with_limit(
                                &opts.repo, dest_path, cancel, bw_limit,
                            ) {
                                Ok(r) => {
                                    msg.push_str(&format!(
                                        ", 오프사이트 복제 {}개 스냅샷/{}개 블롭",
                                        r.snapshots_copied, r.blobs_copied
                                    ));
                                    if let Some(w) = r.warning() {
                                        msg.push_str(&format!(" (경고: {w})"));
                                    }
                                }
                                Err(e) => msg.push_str(&format!(", 오프사이트 복제 실패: {e}")),
                            }
                        }
                        Err(e) => msg.push_str(&format!(", 오프사이트 복제 실패(SMB 연결): {e}")),
                    }
                }
                // 구글 드라이브 오프사이트: 앱에서 연결(로그인)돼 있고 제공자가 gdrive 일 때만. 실패해도 로컬 백업은 성공으로 둔다
                if st_now.offsite_enabled
                    && st_now.offsite_provider == "gdrive"
                    && kova_core::gdrive::is_connected(&self.0.store.dir)
                {
                    self.emit(SvcEvent::Progress {
                        job_id: id,
                        percent: 99,
                        current: "구글 드라이브 클라우드 복제 중...".into(),
                    });
                    let bw_limit_mbps = st_now.offsite_bw_limit_mbps;
                    let r = kova_core::gdrive::load_client(&self.0.store.dir).and_then(|creds| {
                        let mut c = kova_core::gdrive::DriveClient::open(
                            &self.0.store.dir,
                            kova_core::gdrive::Endpoints::default(),
                            creds,
                        )?;
                        kova_core::gdrive::replicate_to_drive_with_limit(
                            &opts.repo,
                            &mut c,
                            &["Kova2 Backup", prof.id.as_str()],
                            bw_limit_mbps,
                            cancel,
                        )
                    });
                    match r {
                        Ok(r) => {
                            msg.push_str(&format!(
                                ", 구글 드라이브 복제 {}개 스냅샷/{}개 블롭",
                                r.snapshots_uploaded, r.blobs_uploaded
                            ));
                            if let Some(w) = r.warning() {
                                msg.push_str(&format!(" (경고: {w})"));
                            }
                        }
                        Err(e) => msg.push_str(&format!(", 구글 드라이브 복제 실패: {e}")),
                    }
                }
                // S3 호환 클라우드 오프사이트: 제공자가 s3 일 때만. 실패해도 로컬 백업은 성공으로 두고 메시지에 남긴다
                if st_now.offsite_enabled && st_now.offsite_provider == "s3" {
                    match kova_core::s3::load_config(&self.0.config_dir) {
                        Ok(Some(s3_cfg)) => {
                            self.emit(SvcEvent::Progress {
                                job_id: id,
                                percent: 99,
                                current: "S3 클라우드 복제 중...".into(),
                            });
                            match kova_core::s3::replicate_to_s3(&opts.repo, &s3_cfg, cancel) {
                                Ok(r) => {
                                    msg.push_str(&format!(
                                        ", S3 복제 {}개 스냅샷/{}개 블롭",
                                        r.snapshots_uploaded, r.blobs_uploaded
                                    ));
                                }
                                Err(e) => msg.push_str(&format!(", S3 복제 실패: {e}")),
                            }
                        }
                        Ok(None) => {
                            msg.push_str(", S3 복제 실패: S3 설정이 등록되어 있지 않습니다");
                        }
                        Err(e) => msg.push_str(&format!(", S3 복제 실패: {e}")),
                    }
                }
                msg.push_str(&vss_note);
                msg.push_str(&pack_note);
                if let Some(n) = protected.filter(|n| *n > 0) {
                    msg.push_str(&format!(", 랜섬웨어 보호 {n}개 잠금"));
                }
                if partial_missing {
                    msg.push_str(&format!(
                        ", 원본 {}개 없어 제외: {}",
                        missing.len(),
                        missing.join(", ")
                    ));
                }
                if !ret.deleted_snapshots.is_empty() {
                    msg.push_str(&format!(
                        ", 보존 정책으로 옛 스냅샷 {}개 정리",
                        ret.deleted_snapshots.len()
                    ));
                }
                if let Some(a) = anomaly {
                    msg.push_str(&format!(
                        ", 랜섬웨어 이상 징후 감지(보존 정리 보류): {}",
                        a.summary()
                    ));
                }
                self.emit(SvcEvent::Progress {
                    job_id: id,
                    percent: 100,
                    current: "백업 완료".into(),
                });
                JobOutcome {
                    ok: true,
                    message: msg,
                    snapshot_id: Some(s.session_id),
                    bytes: s.total_bytes,
                    files: s.total_files as u64,
                }
            }
            Err(e) => {
                // 사용자 취소는 재시도하지 않는다(서비스 중지로 인한 취소는 다음 시작 후 재시도한다)
                user_cancelled =
                    matches!(e, EngineError::Cancelled) && !self.0.stopping.load(Ordering::SeqCst);
                let msg = if matches!(e, EngineError::Cancelled) {
                    "취소됨".to_string()
                } else {
                    e.to_string()
                };
                JobOutcome::fail(msg)
            }
        };
        let now = Local::now().timestamp() as f64;
        if let Some(mut fresh) = self.0.store.get(&prof.id) {
            if out.ok {
                if let Some(ref sid) = out.snapshot_id {
                    fresh.last_status = "success".into();
                    fresh.last_snapshot_id = Some(sid.clone());
                    fresh.extra.insert("retry_count".into(), 0.into());
                    fresh.extra.insert("last_success_at".into(), now.into());
                    fresh
                        .extra
                        .entry("last_drill_at")
                        .or_insert_with(|| now.into());
                    fresh
                        .extra
                        .entry("last_verify_at")
                        .or_insert_with(|| now.into());
                    fresh
                        .extra
                        .entry("last_gc_at")
                        .or_insert_with(|| now.into());
                }
            } else {
                fresh.last_status = "failed".into();
                let rc = if user_cancelled {
                    MAX_AUTO_RETRIES as u64
                } else {
                    fresh
                        .extra
                        .get("retry_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        + 1
                };
                fresh.extra.insert("retry_count".into(), rc.into());
            }
            fresh.last_run = Some(now);
            let _ = self.0.store.upsert(fresh);
        } else {
            kova_core::applog::write(
                &self.0.config_dir,
                "INFO",
                &format!(
                    "작업 중 프로파일이 삭제되어 결과를 저장하지 않음: {}",
                    prof.id
                ),
            );
        }
        out
    }
}

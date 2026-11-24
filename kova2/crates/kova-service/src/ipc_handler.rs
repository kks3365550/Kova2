//! IPC 요청 처리기(`kova_ipc::Handler` 구현) 및 강화된 권한 경계 검증.
use crate::restore::RestoreParams;
use crate::{Supervisor, SvcEvent, REPO_LOCK_WAIT};
use kova_core::jobs::{Enqueue, Kind};
use kova_ipc::{
    Caller, ClientToken, DiffEntryRow, Event, Handler, JobRunRow, RecoveryEntry, Reply, Request,
    Secret, SmbCredInfo,
};
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;

/// kova-ipc 의 요청을 Supervisor 로 연결한다.
pub struct IpcHandler(pub Supervisor);

/// 일반 사용자도 요청할 수 있는 작업인가(읽기·상태·백업·검증). 나머지(삭제·정리·이미지)는 관리자/SYSTEM 만.
fn allowed_for_unprivileged(k: Kind) -> bool {
    matches!(k, Kind::Backup | Kind::Verify)
}

pub(crate) fn kind_name(k: Kind) -> String {
    match k {
        Kind::Backup => "backup",
        Kind::Verify => "verify",
        Kind::Gc => "gc",
        Kind::Image(d) => return format!("image:{d}"),
        Kind::DeleteSnapshot => "delsnap",
    }
    .to_string()
}

/// 내부 이벤트를 IPC 이벤트로 바꾼다. 작업 번호에는 `base`(시각 기반 시작값)를 더한다.
pub(crate) fn to_wire(e: SvcEvent, base: u64) -> Event {
    match e {
        SvcEvent::JobStarted {
            job_id,
            profile_id,
            kind,
        } => Event::JobStarted {
            job_id: job_id + base,
            profile_id,
            kind: kind_name(kind),
        },
        SvcEvent::Progress {
            job_id,
            percent,
            current,
        } => Event::Progress {
            job_id: job_id + base,
            percent,
            current,
        },
        SvcEvent::JobFinished {
            job_id,
            profile_id,
            ok,
            message,
            snapshot_id,
        } => Event::JobFinished {
            job_id: job_id + base,
            profile_id,
            ok,
            message,
            snapshot_id,
        },
    }
}

const PRIVILEGE_REQUIRED: &str = "관리자 권한이 필요한 요청입니다(암호화·키·클라우드/SMB/SMTP 설정·스냅샷 삭제·저장소 정리·볼륨 이미지·작업 취소·복구 코드 내보내기). Kova2 앱을 관리자 권한으로 실행한 뒤 다시 시도하세요";

impl IpcHandler {
    pub(crate) fn refuse(&self, what: &str) -> Reply {
        kova_core::applog::write(
            &self.0 .0.config_dir,
            "WARN",
            &format!("권한 없는 IPC 요청 거부: {what}"),
        );
        Reply::Once(vec![Event::Error {
            message: PRIVILEGE_REQUIRED.into(),
        }])
    }

    fn handle_cloud_prune(&self, profile_id: String) -> Reply {
        if profile_id.trim().is_empty() {
            return Reply::Once(vec![Event::Error {
                message: "프로파일을 지정하지 않은 원격 정리 요청은 처리하지 않습니다".into(),
            }]);
        }
        let Some(prof) = self.0.resolve_profile(&profile_id) else {
            return Reply::Once(vec![Event::Error {
                message: format!("프로파일 없음: {profile_id}"),
            }]);
        };
        let (guard, cancel) = match self.0.try_begin_bg_cancellable("클라우드 원격 정리") {
            Ok(v) => v,
            Err(message) => return Reply::Once(vec![Event::Error { message }]),
        };
        let cfg = self.0 .0.config_dir.clone();
        let settings = self.0 .0.store.settings();
        let repo = PathBuf::from(&prof.repo_dir);
        let pid = prof.id;
        let (tx, rx) = sync_channel(1);
        std::thread::spawn(move || {
            let _guard = guard;
            let run = || -> Result<String, String> {
                let _smb = kova_core::smb::SmbMountGuard::connect_if_needed(&cfg, &repo)
                    .map_err(|e| format!("저장소 SMB 연결 실패: {e}"))?;
                let _lock = match kova_core::lock::RepoLock::acquire_wait(&repo, REPO_LOCK_WAIT) {
                    Ok(l) => l,
                    Err(kova_core::lock::LockError::Busy) => {
                        return Err(
                            "다른 작업이 저장소를 사용 중입니다. 잠시 후 다시 시도하세요".into(),
                        )
                    }
                    Err(e) => return Err(format!("저장소 잠금 실패: {e}")),
                };
                match settings.offsite_provider.as_str() {
                    "s3" => {
                        let s3_cfg = kova_core::s3::load_config(&cfg)?
                            .ok_or_else(|| "S3 설정이 등록되어 있지 않습니다".to_string())?;
                        let r = kova_core::s3::prune_s3_orphans(&s3_cfg, &repo, &cancel)?;
                        Ok(format!(
                            "S3 원격 정리 완료: {}개 객체, {}바이트 확보",
                            r.deleted_objects, r.freed_bytes
                        ))
                    }
                    "gdrive" => {
                        if !kova_core::gdrive::is_connected(&cfg) {
                            return Err("구글 드라이브가 연결되어 있지 않습니다".into());
                        }
                        let creds = kova_core::gdrive::load_client(&cfg)?;
                        let mut client = kova_core::gdrive::DriveClient::open(
                            &cfg,
                            kova_core::gdrive::Endpoints::default(),
                            creds,
                        )?;
                        let r = kova_core::gdrive::prune_drive_orphans(
                            &mut client,
                            &["Kova2 Backup", pid.as_str()],
                            &repo,
                            &cancel,
                        )?;
                        Ok(format!(
                            "구글 드라이브 원격 정리 완료: {}개 파일, {}바이트 확보",
                            r.trashed_files, r.freed_bytes
                        ))
                    }
                    other => Err(format!(
                        "원격 정리를 지원하지 않는 오프사이트 제공자입니다: {other}"
                    )),
                }
            };
            let res = run();
            kova_core::applog::write(
                &cfg,
                if res.is_ok() { "INFO" } else { "WARN" },
                &format!(
                    "클라우드 원격 정리(profile={pid}): {}",
                    match &res {
                        Ok(m) => m.as_str(),
                        Err(e) => e.as_str(),
                    }
                ),
            );
            let _ = tx.send(match res {
                Ok(message) => Event::Done { message },
                Err(message) => Event::Error { message },
            });
        });
        Reply::Stream(rx)
    }

    fn handle_diff_snapshots(
        &self,
        repo: String,
        base_id: String,
        target_id: String,
        limit: usize,
        caller: Caller,
    ) -> Reply {
        if !self.is_registered_repo(&repo) {
            return Reply::Once(vec![Event::Error {
                message: "등록된 프로파일의 저장소만 비교할 수 있습니다".into(),
            }]);
        }
        let repo_path = PathBuf::from(&repo);
        let _smb = match kova_core::smb::SmbMountGuard::connect_if_needed(
            &self.0 .0.config_dir,
            &repo_path,
        ) {
            Ok(g) => g,
            Err(e) => {
                return Reply::Once(vec![Event::Error {
                    message: format!("저장소 SMB 연결 실패: {e}"),
                }]);
            }
        };
        if kova_core::repocrypto::is_enabled(&repo_path) && !caller.privileged {
            return self.refuse("DiffSnapshots(암호화 저장소)");
        }
        let map_row = |it: kova_engine::ops::DiffItem| DiffEntryRow {
            path: it.path,
            size: it.size,
            old_size: it.old_size,
            is_dir: it.is_dir,
        };
        match kova_engine::ops::diff_snapshots(&repo_path, &base_id, &target_id, limit) {
            Ok(diff) => Reply::Once(vec![Event::DiffResult {
                added: diff.added.into_iter().map(map_row).collect(),
                modified: diff.modified.into_iter().map(map_row).collect(),
                deleted: diff.deleted.into_iter().map(map_row).collect(),
                unchanged_count: diff.unchanged_count,
            }]),
            Err(e) => Reply::Once(vec![Event::Error {
                message: e.to_string(),
            }]),
        }
    }
}

impl Handler for IpcHandler {
    fn on_error(&self, message: &str) {
        kova_core::applog::write(&self.0 .0.config_dir, "WARN", &format!("IPC: {message}"));
    }

    fn handle(&self, req: Request, caller: Caller) -> Reply {
        let base = self.0 .0.id_base;
        match req {
            Request::Ping => Reply::Once(vec![Event::Pong {
                pid: std::process::id(),
            }]),
            Request::Status => {
                let (waiting, running) = self.0.counts();
                Reply::Once(vec![Event::Status { waiting, running }])
            }
            Request::Info => Reply::Once(vec![Event::Info {
                protocol_version: kova_ipc::PROTOCOL_VERSION,
                service_version: env!("CARGO_PKG_VERSION").into(),
            }]),
            Request::RunNow { profile_id, kind } => {
                // 빈 ID 는 "첫 프로파일"로 풀리므로 엉뚱한 프로파일에 작업이 걸리지 않게 거부한다
                if profile_id.trim().is_empty() {
                    return Reply::Once(vec![Event::Error {
                        message: "프로파일을 지정하지 않은 작업 요청은 처리하지 않습니다".into(),
                    }]);
                }
                let mut arg = String::new();
                let k = match kind.as_str() {
                    "backup" => Kind::Backup,
                    "verify" => Kind::Verify,
                    "gc" => Kind::Gc,
                    s if s.starts_with("delsnap:") => {
                        arg = s.strip_prefix("delsnap:").unwrap_or("").to_string();
                        Kind::DeleteSnapshot
                    }
                    s if s.len() == 7
                        && s.starts_with("image:")
                        && s.as_bytes()[6].is_ascii_alphabetic() =>
                    {
                        Kind::Image(s.as_bytes()[6].to_ascii_uppercase() as char)
                    }
                    s if s.len() == 11
                        && s.starts_with("image_inc:")
                        && s.as_bytes()[10].is_ascii_alphabetic() =>
                    {
                        arg = "incremental".to_string();
                        Kind::Image(s.as_bytes()[10].to_ascii_uppercase() as char)
                    }
                    other => {
                        return Reply::Once(vec![Event::Error {
                            message: format!("알 수 없는 작업 종류: {other}"),
                        }])
                    }
                };
                // 일반 사용자 프로그램도 파이프에 접속할 수 있으므로 파괴적 작업은 관리자/SYSTEM 호출자만 받는다
                if !allowed_for_unprivileged(k) && !caller.privileged {
                    return self.refuse(&format!("RunNow {} profile={profile_id}", kind_name(k)));
                }
                let pid = self
                    .0
                    .resolve_profile(&profile_id)
                    .map(|p| p.id)
                    .unwrap_or(profile_id);
                Reply::Once(vec![match self.0.enqueue_with(&pid, k, &arg) {
                    Enqueue::Queued(job_id) => Event::Queued {
                        job_id: job_id + base,
                        merged: false,
                    },
                    Enqueue::Merged(job_id) => Event::Queued {
                        job_id: job_id + base,
                        merged: true,
                    },
                }])
            }
            Request::Cancel { job_id } => {
                // 일반 사용자 앱의 취소 버튼이 동작하도록 백업·검증 취소는 허용하고, 이미지·정리·삭제 취소는 관리자만 한다
                let light = job_id
                    .checked_sub(base)
                    .filter(|i| *i > 0)
                    .and_then(|i| self.0.job_kind(i))
                    .is_some_and(|k| matches!(k, Kind::Backup | Kind::Verify));
                if !caller.privileged && !light {
                    return self.refuse(&format!("Cancel job={job_id}"));
                }
                let found = job_id
                    .checked_sub(base)
                    .filter(|i| *i > 0)
                    .is_some_and(|i| self.0.cancel(i));
                Reply::Once(vec![Event::Cancelled { job_id, found }])
            }
            Request::Subscribe => Reply::Stream(self.0.subscribe_wire()),
            // 구글 드라이브 토큰: 상태 조회만 누구나, 저장·해제는 관리자/SYSTEM 전용
            Request::GdriveStatus => Reply::Once(vec![Event::GdriveStatus {
                connected: kova_core::gdrive::is_connected(&self.0 .0.config_dir),
            }]),
            Request::GdriveStoreToken { token } => {
                if !caller.privileged {
                    return self.refuse("GdriveStoreToken");
                }
                let cfg = &self.0 .0.config_dir;
                Reply::Once(vec![match kova_core::gdrive::store_token(cfg, &token.0) {
                    Ok(()) => {
                        kova_core::applog::write(cfg, "INFO", "구글 드라이브 연결: 토큰 저장");
                        Event::Done {
                            message: "구글 드라이브를 연결했습니다".into(),
                        }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::GdriveDisconnect => {
                if !caller.privileged {
                    return self.refuse("GdriveDisconnect");
                }
                // 토큰 폐기는 네트워크 요청이라 IPC 작업 스레드를 막지 않게 따로 돌린다
                let cfg = self.0 .0.config_dir.clone();
                let (tx, rx) = sync_channel(1);
                std::thread::spawn(move || {
                    kova_core::gdrive::disconnect(&cfg, &kova_core::gdrive::Endpoints::default());
                    kova_core::applog::write(&cfg, "INFO", "구글 드라이브 연결 해제");
                    let _ = tx.send(Event::Done {
                        message: "연결을 해제했습니다.".into(),
                    });
                });
                Reply::Stream(rx)
            }
            // 저장소 키: 켜기·복원·내보내기 모두 관리자/SYSTEM 전용(코드는 기록하지 않는다)
            Request::EnableEncryption => {
                if !caller.privileged {
                    return self.refuse("EnableEncryption");
                }
                let cfg = &self.0 .0.config_dir;
                Reply::Once(vec![
                    match kova_core::repocrypto::enable_all(&self.0 .0.store) {
                        Ok(codes) => {
                            kova_core::applog::write(
                                cfg,
                                "INFO",
                                &format!("저장소 암호화 켜기: 새로 켠 저장소 {}곳", codes.len()),
                            );
                            Event::Encrypted {
                                codes: codes.into_iter().map(Secret).collect(),
                            }
                        }
                        Err(e) => Event::Error { message: e },
                    },
                ])
            }
            Request::RestoreKey { code } => {
                if !caller.privileged {
                    return self.refuse("RestoreKey");
                }
                Reply::Once(vec![match kova_core::repocrypto::restore_keys(
                    &self.0 .0.store,
                    &code.0,
                ) {
                    Ok(m) => {
                        kova_core::applog::write(&self.0 .0.config_dir, "INFO", &m);
                        Event::Done { message: m }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::ExportRecoveryCodes => {
                if !caller.privileged {
                    return self.refuse("ExportRecoveryCodes");
                }
                Reply::Once(vec![
                    match kova_core::repocrypto::recovery_entries(&self.0 .0.store) {
                        Ok(v) => {
                            kova_core::applog::write(
                                &self.0 .0.config_dir,
                                "INFO",
                                &format!("복구 코드 내보내기(관리자): 저장소 {}곳", v.len()),
                            );
                            Event::RecoveryCodes {
                                entries: v
                                    .into_iter()
                                    .map(|(name, repo, code)| RecoveryEntry {
                                        name,
                                        repo,
                                        code: Secret(code),
                                    })
                                    .collect(),
                            }
                        }
                        Err(e) => Event::Error { message: e },
                    },
                ])
            }
            // 가장 토큰이 없는 경로로 온 복원도 동일한 권한 검사 뒤 토큰 부재로 거부한다
            Request::Restore {
                repo,
                session_id,
                target,
                only,
                recovery_code,
            } => self.start_restore(
                RestoreParams {
                    repo,
                    session_id,
                    target,
                    only,
                    recovery_code,
                },
                caller,
                None,
            ),
            Request::Drill { profile_id } => {
                let Some(p) = self.0 .0.store.get(&profile_id) else {
                    return Reply::Once(vec![Event::Error {
                        message: format!("프로파일 없음: {profile_id}"),
                    }]);
                };
                let guard = match self.0.try_begin_drill(&p.id) {
                    Ok(g) => g,
                    Err(msg) => {
                        return Reply::Once(vec![Event::Error {
                            message: msg.into(),
                        }]);
                    }
                };
                // 서비스 임시 폴더(SYSTEM 전용)에 복원해 보고 지운다. 오래 걸리므로 따로 돌린다
                let (tx, rx) = sync_channel(1);
                std::thread::spawn(move || {
                    let _guard = guard;
                    let text = kova_core::drill::run(&p, &std::env::temp_dir());
                    let _ = tx.send(Event::Done { message: text });
                });
                Reply::Stream(rx)
            }
            // ── S3 호환 클라우드 ──
            Request::S3Status => {
                let s = kova_core::s3::status(&self.0 .0.config_dir);
                Reply::Once(vec![Event::S3Status {
                    configured: s.configured,
                    endpoint: s.endpoint,
                    region: s.region,
                    bucket: s.bucket,
                    prefix: s.prefix,
                }])
            }
            Request::S3SaveConfig {
                endpoint,
                region,
                bucket,
                prefix,
                access_key,
                secret_key,
            } => {
                if !caller.privileged {
                    return self.refuse("S3SaveConfig");
                }
                let cfg_dir = &self.0 .0.config_dir;
                let s3_cfg = kova_core::s3::S3Config {
                    endpoint,
                    region,
                    bucket,
                    prefix,
                    access_key,
                    secret_key: secret_key.0,
                };
                Reply::Once(vec![match kova_core::s3::save_config(cfg_dir, &s3_cfg) {
                    Ok(()) => {
                        kova_core::applog::write(cfg_dir, "INFO", "S3 오프사이트 설정 저장");
                        Event::Done {
                            message: "S3 설정을 저장했습니다".into(),
                        }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::S3DeleteConfig => {
                if !caller.privileged {
                    return self.refuse("S3DeleteConfig");
                }
                let cfg_dir = &self.0 .0.config_dir;
                Reply::Once(vec![match kova_core::s3::delete_config(cfg_dir) {
                    Ok(()) => {
                        kova_core::applog::write(cfg_dir, "INFO", "S3 오프사이트 설정 삭제");
                        Event::Done {
                            message: "S3 설정을 삭제했습니다".into(),
                        }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::S3TestConnection => {
                if !caller.privileged {
                    return self.refuse("S3TestConnection");
                }
                let cfg_dir = self.0 .0.config_dir.clone();
                let (tx, rx) = sync_channel(1);
                std::thread::spawn(move || {
                    let ev = match kova_core::s3::load_config(&cfg_dir) {
                        Ok(Some(s3_cfg)) => match kova_core::s3::test_connection(&s3_cfg) {
                            Ok(()) => Event::Done {
                                message: "S3 연결 시험에 성공했습니다".into(),
                            },
                            Err(e) => Event::Error { message: e },
                        },
                        Ok(None) => Event::Error {
                            message: "S3 설정이 등록되어 있지 않습니다".into(),
                        },
                        Err(e) => Event::Error { message: e },
                    };
                    let _ = tx.send(ev);
                });
                Reply::Stream(rx)
            }
            // ── SMB/NAS 자격 증명 ──
            Request::SmbListCreds => {
                let creds = kova_core::smb::list_creds(&self.0 .0.config_dir)
                    .into_iter()
                    .map(|c| SmbCredInfo {
                        share: c.share,
                        username: c.username,
                    })
                    .collect();
                Reply::Once(vec![Event::SmbCreds { creds }])
            }
            Request::SmbSaveCred {
                share,
                username,
                password,
            } => {
                if !caller.privileged {
                    return self.refuse("SmbSaveCred");
                }
                let cfg_dir = &self.0 .0.config_dir;
                Reply::Once(vec![match kova_core::smb::save_cred(
                    cfg_dir,
                    &share,
                    &username,
                    &password.0,
                ) {
                    Ok(()) => {
                        kova_core::applog::write(
                            cfg_dir,
                            "INFO",
                            &format!("SMB 자격 증명 저장: {share}"),
                        );
                        Event::Done {
                            message: "SMB 자격 증명을 저장했습니다".into(),
                        }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::SmbDeleteCred { share } => {
                if !caller.privileged {
                    return self.refuse("SmbDeleteCred");
                }
                let cfg_dir = &self.0 .0.config_dir;
                Reply::Once(vec![match kova_core::smb::delete_cred(cfg_dir, &share) {
                    Ok(true) => {
                        kova_core::applog::write(
                            cfg_dir,
                            "INFO",
                            &format!("SMB 자격 증명 삭제: {share}"),
                        );
                        Event::Done {
                            message: "SMB 자격 증명을 삭제했습니다".into(),
                        }
                    }
                    Ok(false) => Event::Done {
                        message: "삭제할 SMB 자격 증명이 없습니다".into(),
                    },
                    Err(e) => Event::Error { message: e },
                }])
            }
            // ── 클라우드 재해 복구 / 원격 정리 ──
            Request::CloudPull {
                provider,
                dest_repo,
            } => {
                if !caller.privileged {
                    return self.refuse("CloudPull");
                }
                self.start_cloud_pull(provider, dest_repo)
            }
            Request::CloudPrune { profile_id } => {
                if !caller.privileged {
                    return self.refuse("CloudPrune");
                }
                self.handle_cloud_prune(profile_id)
            }
            // ── SMTP 이메일 알림 ──
            Request::SmtpStatus => {
                let s = kova_core::smtp::status(&self.0 .0.config_dir);
                Reply::Once(vec![Event::SmtpStatus {
                    configured: s.configured,
                    host: s.host,
                    port: s.port,
                    username: s.username,
                    from: s.from,
                    to: s.to,
                    use_tls: s.use_tls,
                }])
            }
            Request::SmtpSaveConfig {
                host,
                port,
                username,
                password,
                from,
                to,
                use_tls,
            } => {
                if !caller.privileged {
                    return self.refuse("SmtpSaveConfig");
                }
                let cfg_dir = &self.0 .0.config_dir;
                let smtp_cfg = kova_core::smtp::SmtpConfig {
                    host,
                    port,
                    username,
                    password: password.0,
                    from,
                    to,
                    use_tls,
                };
                Reply::Once(vec![
                    match kova_core::smtp::save_config(cfg_dir, &smtp_cfg) {
                        Ok(()) => {
                            kova_core::applog::write(cfg_dir, "INFO", "SMTP 이메일 알림 설정 저장");
                            Event::Done {
                                message: "SMTP 설정을 저장했습니다".into(),
                            }
                        }
                        Err(e) => Event::Error { message: e },
                    },
                ])
            }
            Request::SmtpDeleteConfig => {
                if !caller.privileged {
                    return self.refuse("SmtpDeleteConfig");
                }
                let cfg_dir = &self.0 .0.config_dir;
                Reply::Once(vec![match kova_core::smtp::delete_config(cfg_dir) {
                    Ok(()) => {
                        kova_core::applog::write(cfg_dir, "INFO", "SMTP 이메일 알림 설정 삭제");
                        Event::Done {
                            message: "SMTP 설정을 삭제했습니다".into(),
                        }
                    }
                    Err(e) => Event::Error { message: e },
                }])
            }
            Request::SmtpTest => {
                if !caller.privileged {
                    return self.refuse("SmtpTest");
                }
                let cfg_dir = self.0 .0.config_dir.clone();
                let (tx, rx) = sync_channel(1);
                std::thread::spawn(move || {
                    let ev = match kova_core::smtp::load_config(&cfg_dir) {
                        Ok(Some(smtp_cfg)) => match kova_core::smtp::send_email(
                            &smtp_cfg,
                            "[Kova2] SMTP 알림 시험 메일",
                            "Kova2 백업 서비스의 SMTP 이메일 알림 설정이 정상적으로 동작합니다.",
                        ) {
                            Ok(()) => Event::Done {
                                message: "SMTP 시험 메일을 발송했습니다".into(),
                            },
                            Err(e) => Event::Error { message: e },
                        },
                        Ok(None) => Event::Error {
                            message: "SMTP 설정이 등록되어 있지 않습니다".into(),
                        },
                        Err(e) => Event::Error { message: e },
                    };
                    let _ = tx.send(ev);
                });
                Reply::Stream(rx)
            }
            // ── 실행 이력·스냅샷 비교·플릿 상태 ──
            Request::JobHistory { limit } => {
                let capped = limit.min(1000);
                Reply::Once(vec![
                    match kova_core::history::JobHistoryDb::open(&self.0 .0.config_dir)
                        .and_then(|db| db.list(capped))
                    {
                        Ok(rows) => Event::JobHistory {
                            rows: rows
                                .into_iter()
                                .map(|r| JobRunRow {
                                    id: r.id,
                                    started_at: r.started_at,
                                    finished_at: r.finished_at,
                                    profile_id: r.profile_id,
                                    kind: r.kind,
                                    ok: r.ok,
                                    message: r.message,
                                    bytes: r.bytes,
                                    files: r.files,
                                })
                                .collect(),
                        },
                        Err(e) => Event::Error { message: e },
                    },
                ])
            }
            Request::DiffSnapshots {
                repo,
                base_id,
                target_id,
                limit,
            } => self.handle_diff_snapshots(repo, base_id, target_id, limit, caller),
            Request::FleetStatus => {
                let hb = kova_core::fleet::build_heartbeat(
                    &self.0 .0.config_dir,
                    env!("CARGO_PKG_VERSION"),
                );
                let settings = self.0 .0.store.settings();
                Reply::Once(vec![Event::FleetStatus {
                    hostname: hb.hostname,
                    service_version: hb.service_version,
                    profiles_total: hb.profiles_total,
                    healthy: hb.healthy,
                    stale: hb.stale,
                    last_backup_at: hb.last_backup_at,
                    unacked_alerts: hb.unacked_alerts,
                    fleet_endpoint: settings.fleet_endpoint,
                }])
            }
        }
    }

    fn handle_with_token(&self, req: Request, caller: Caller, token: Option<ClientToken>) -> Reply {
        match req {
            Request::Restore {
                repo,
                session_id,
                target,
                only,
                recovery_code,
            } => self.start_restore(
                RestoreParams {
                    repo,
                    session_id,
                    target,
                    only,
                    recovery_code,
                },
                caller,
                token,
            ),
            other => self.handle(other, caller),
        }
    }
}

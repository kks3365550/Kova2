//! 서비스 대행 파일 복원(가장 스레드 + 암호화 저장소 권한/복구 코드 인가) 및 클라우드 풀(Google Drive / S3).
use crate::ipc_handler::IpcHandler;
use kova_core::history::History;
use kova_engine::ops::Event as EngineEvent;
use kova_ipc::{Caller, ClientToken, Event, Reply, Secret};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const RESTORE_NEEDS_CALLER: &str =
    "복원을 요청한 사용자 권한을 확인하지 못했습니다. Kova2 앱을 최신 버전으로 업데이트하세요";
pub(crate) const ENCRYPTED_RESTORE_AUTH_REQUIRED: &str =
    "암호화된 저장소 복원은 관리자 권한 또는 복구 코드가 필요합니다";

pub(crate) fn same_path(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim().trim_end_matches(['\\', '/']).replace('/', "\\");
    n(a).eq_ignore_ascii_case(&n(b))
}

/// SYSTEM 권한으로 파일시스템을 조회하지 않도록, 가장 전에는 순수 문자열 형식만 선검사한다.
fn validate_absolute_target_syntax(t: &str, prefix: &str) -> Result<(), String> {
    let trimmed = t.trim().trim_matches('"').trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{prefix}: {}",
            kova_core::restore_target::TargetError::Empty
        ));
    }
    let norm = trimmed.replace('/', "\\");
    if norm.starts_with("\\\\.\\") || norm.starts_with("\\\\?\\") {
        return Err(format!(
            "{prefix}: {}",
            kova_core::restore_target::TargetError::Device
        ));
    }
    let b = norm.as_bytes();
    let unc = norm.starts_with("\\\\");
    if !unc && !(b.len() >= 3 && b[1] == b':' && b[2] == b'\\') {
        return Err(format!(
            "{prefix}: {}",
            kova_core::restore_target::TargetError::NotAbsolute
        ));
    }
    Ok(())
}

pub(crate) struct RestoreParams {
    pub repo: String,
    pub session_id: String,
    pub target: Option<String>,
    pub only: Option<Vec<String>>,
    pub recovery_code: Option<Secret>,
}

impl IpcHandler {
    pub(crate) fn is_registered_repo(&self, repo: &str) -> bool {
        self.0
             .0
            .store
            .profiles()
            .iter()
            .any(|p| !p.repo_dir.is_empty() && same_path(&p.repo_dir, repo))
    }

    /// 저장소 복원(서비스 대행): 암호화 저장소는 관리자 권한 또는 유효한 복구 코드가 있을 때만 허용한다.
    /// 키는 SYSTEM 으로 미리 잡아 두고, 실제 읽기·쓰기는 요청한 사용자로 가장한 스레드에서만 한다
    /// (일반 사용자가 SYSTEM 권한으로 아무 곳에나 쓰게 되지 않도록). 진행률을 흘리고 Done/Error 로 끝난다.
    pub(crate) fn start_restore(
        &self,
        params: RestoreParams,
        caller: Caller,
        token: Option<ClientToken>,
    ) -> Reply {
        let err = |m: String| Reply::Once(vec![Event::Error { message: m }]);
        if !self.is_registered_repo(&params.repo) {
            return err("등록된 프로파일의 저장소만 서비스가 복원합니다".into());
        }
        let repo_path = PathBuf::from(&params.repo);
        // 암호화 저장소 복원 인가: 관리자/SYSTEM 이거나 해당 저장소의 복구 코드가 일치해야 한다
        if kova_core::repocrypto::is_enabled(&repo_path) {
            let authorized = caller.privileged
                || params.recovery_code.as_ref().is_some_and(|code| {
                    kova_core::repocrypto::verify_recovery_code_for_repo(&repo_path, &code.0)
                        .unwrap_or(false)
                });
            if !authorized {
                kova_core::applog::write(
                    &self.0 .0.config_dir,
                    "WARN",
                    &format!(
                        "암호화 저장소 복원 거부(관리자 권한 또는 복구 코드 없음): {}",
                        repo_path.display()
                    ),
                );
                return err(ENCRYPTED_RESTORE_AUTH_REQUIRED.into());
            }
        }
        let Some(token) = token else {
            return err(RESTORE_NEEDS_CALLER.into());
        };
        // 실제 존재 여부·비어 있음·저장소 내부 여부는 아래 가장 스레드 안에서 restore_target::check 로 검사한다.
        if let Some(ref t) = params.target {
            if let Err(msg) = validate_absolute_target_syntax(t, "복원하지 않음") {
                return err(msg);
            }
        }
        let (guard, cancel) = match self.0.try_begin_restore() {
            Ok(v) => v,
            Err(msg) => return err(msg.into()),
        };
        let cfg = self.0 .0.config_dir.clone();
        let session_id = params.session_id;
        let target = params.target;
        let only = params.only;
        let (tx, rx) = sync_channel(64);
        std::thread::spawn(move || {
            let _guard = guard;
            let run = || -> Result<String, String> {
                let _smb = kova_core::smb::SmbMountGuard::connect_if_needed(&cfg, &repo_path)
                    .map_err(|e| format!("저장소 SMB 연결 실패: {e}"))?;
                let _lock = match kova_core::lock::RepoLock::acquire_wait(
                    &repo_path,
                    Duration::from_secs(5),
                ) {
                    Ok(l) => l,
                    Err(kova_core::lock::LockError::Busy) => {
                        return Err(
                            "다른 작업이 저장소를 사용 중입니다. 잠시 후 다시 시도하세요".into(),
                        )
                    }
                    Err(e) => return Err(format!("저장소 잠금 오류({e})")),
                };
                // 암호화 저장소인 경우 가장 스레드는 키 파일을 열 수 없으므로 SYSTEM 으로 미리 읽어 둔다(작업이 끝나면 놓는다)
                let _key = if kova_core::repocrypto::is_enabled(&repo_path) {
                    Some(kova_core::repocrypto::hold_key(&repo_path)?)
                } else {
                    None
                };
                let on_event = |ev: EngineEvent| {
                    if let EngineEvent::RestoreProgress { done, total } = ev {
                        if let Err(TrySendError::Disconnected(_)) =
                            tx.try_send(Event::RestoreProgress {
                                done: done as u64,
                                total: total as u64,
                            })
                        {
                            cancel.store(true, Ordering::SeqCst); // 앱이 연결을 끊음
                        }
                    }
                };
                let token = Arc::new(token);
                kova_core::secrets::run_in_setup_pool(
                    move || token.impersonate_current_thread(),
                    || -> Result<String, String> {
                        let checked_target = match target.as_deref() {
                            Some(t) => Some(
                                kova_core::restore_target::check(t, &repo_path)
                                    .map_err(|e| format!("복원하지 않음: {e}"))?,
                            ),
                            None => None,
                        };
                        let opts = kova_engine::ops::RestoreOptions {
                            repo: repo_path.clone(),
                            session_id: session_id.clone(),
                            only,
                            target: checked_target.clone(),
                        };
                        let s = kova_engine::ops::run_restore(&opts, &on_event, &cancel)
                            .map_err(|e| e.to_string())?;
                        Ok(match &checked_target {
                            Some(t) => format!(
                                "복원 완료: {} (항목 {}개, {:.0}초)",
                                t.display(),
                                s.total_files,
                                s.elapsed_seconds
                            ),
                            None => format!(
                                "원래 위치로 복원 완료 (항목 {}개, {:.0}초)",
                                s.total_files, s.elapsed_seconds
                            ),
                        })
                    },
                )?
            };
            let r = run();
            kova_core::applog::write(
                &cfg,
                if r.is_ok() { "INFO" } else { "WARN" },
                &format!(
                    "복원(서비스 대행, 요청 사용자 권한) {} {session_id}: {}",
                    repo_path.display(),
                    match &r {
                        Ok(m) => m.as_str(),
                        Err(e) => e.as_str(),
                    }
                ),
            );
            let _ = tx.send(match r {
                Ok(message) => Event::Done { message },
                Err(e) if e.starts_with("복원하지 않음:") => Event::Error { message: e },
                Err(e) => Event::Error {
                    message: format!("복원 실패: {e}"),
                },
            });
        });
        Reply::Stream(rx)
    }

    /// 클라우드(Google Drive / S3) 오프사이트 저장소를 로컬 저장소 폴더로 스트리밍 풀(재해 복구)한다.
    /// 호출자 관리자 권한 검증은 `IpcHandler::handle` 에서 선행한다.
    pub(crate) fn start_cloud_pull(&self, provider: String, dest_repo: String) -> Reply {
        let err = |m: String| Reply::Once(vec![Event::Error { message: m }]);
        if let Err(msg) = validate_absolute_target_syntax(&dest_repo, "클라우드 복구 대상 오류")
        {
            return err(msg);
        }
        let (guard, cancel) = match self.0.try_begin_bg_cancellable("클라우드 복구") {
            Ok(v) => v,
            Err(msg) => return err(msg),
        };
        let cfg = self.0 .0.config_dir.clone();
        let profiles = self.0 .0.store.profiles();
        let dest_path = PathBuf::from(dest_repo.trim());
        let (tx, rx) = sync_channel(64);
        std::thread::spawn(move || {
            let _guard = guard;
            let on_progress = |done: u64, total: u64, _label: &str| {
                if let Err(TrySendError::Disconnected(_)) =
                    tx.try_send(Event::RestoreProgress { done, total })
                {
                    cancel.store(true, Ordering::SeqCst);
                }
            };
            let run = || -> Result<String, String> {
                let _smb = kova_core::smb::SmbMountGuard::connect_if_needed(&cfg, &dest_path)
                    .map_err(|e| format!("대상 SMB 연결 실패: {e}"))?;
                let prov_trimmed = provider.trim();
                let prov_lower = prov_trimmed.to_ascii_lowercase();
                if prov_lower == "s3" {
                    let s3_cfg = kova_core::s3::load_config(&cfg)?
                        .ok_or_else(|| "S3 설정이 등록되어 있지 않습니다".to_string())?;
                    let rep =
                        kova_core::s3::pull_from_s3(&s3_cfg, &dest_path, &cancel, &on_progress)?;
                    sync_pulled_history(&dest_path);
                    Ok(format!(
                        "S3 클라우드 복구 완료: 스냅샷 {}개, 팩 {}개, 블롭 {}개 ({}바이트)",
                        rep.snapshots_downloaded,
                        rep.packs_downloaded,
                        rep.blobs_downloaded,
                        rep.bytes_downloaded
                    ))
                } else if prov_lower == "gdrive" || prov_lower.starts_with("gdrive:") {
                    if !kova_core::gdrive::is_connected(&cfg) {
                        return Err("구글 드라이브가 연결되어 있지 않습니다".into());
                    }
                    let creds = kova_core::gdrive::load_client(&cfg)?;
                    let mut client = kova_core::gdrive::DriveClient::open(
                        &cfg,
                        kova_core::gdrive::Endpoints::default(),
                        creds,
                    )?;
                    let explicit_sub = prov_trimmed
                        .split_once(':')
                        .map(|(_, sub)| sub.trim())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    let folder_name = match explicit_sub {
                        Some(sub) => sub,
                        None => resolve_gdrive_folder(&mut client, &profiles, &dest_path)?,
                    };
                    let rep = kova_core::gdrive::pull_from_drive(
                        &mut client,
                        &["Kova2 Backup", folder_name.as_str()],
                        &dest_path,
                        &cancel,
                        &on_progress,
                    )?;
                    sync_pulled_history(&dest_path);
                    Ok(format!(
                        "구글 드라이브 복구 완료({folder_name}): 스냅샷 {}개, 팩 {}개, 블롭 {}개 ({}바이트)",
                        rep.snapshots_downloaded,
                        rep.packs_downloaded,
                        rep.blobs_downloaded,
                        rep.bytes_downloaded
                    ))
                } else {
                    Err(format!("지원하지 않는 클라우드 제공자입니다: {provider}"))
                }
            };
            let r = run();
            kova_core::applog::write(
                &cfg,
                if r.is_ok() { "INFO" } else { "WARN" },
                &format!(
                    "클라우드 풀({}) {}: {}",
                    provider,
                    dest_path.display(),
                    match &r {
                        Ok(m) => m.as_str(),
                        Err(e) => e.as_str(),
                    }
                ),
            );
            let _ = tx.send(match r {
                Ok(message) => Event::Done { message },
                Err(message) => Event::Error { message },
            });
        });
        Reply::Stream(rx)
    }
}

fn sync_pulled_history(dest_repo: &Path) {
    if let Ok(mut h) = History::open(dest_repo) {
        let _ = h.sync_snapshots();
    }
}

fn resolve_gdrive_folder(
    client: &mut kova_core::gdrive::DriveClient,
    profiles: &[kova_core::config::Profile],
    dest_path: &Path,
) -> Result<String, String> {
    let dest_str = dest_path.to_string_lossy();
    if let Some(p) = profiles
        .iter()
        .find(|p| !p.repo_dir.is_empty() && same_path(&p.repo_dir, &dest_str))
    {
        return Ok(p.id.clone());
    }
    let subfolders = client.child_folder_names(&["Kova2 Backup"])?;
    if subfolders.len() == 1 {
        return Ok(subfolders[0].clone());
    }
    if let Some(p) = profiles.iter().find(|p| subfolders.contains(&p.id)) {
        return Ok(p.id.clone());
    }
    subfolders
        .into_iter()
        .next()
        .ok_or_else(|| "구글 드라이브 'Kova2 Backup' 폴더에 복구할 백업이 없습니다".to_string())
}

//! 볼륨 이미지(`.qblk` / 증분 체인 / `.qlayout.json` / `.qblk.enc` 암호화) 캡처 작업.
use crate::{JobOutcome, Supervisor, SvcEvent};
use chrono::Local;
use kova_core::jobs::Job;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 이미지를 만드는 중간 파일 폴더(`images` 아래). 끝나면 `images` 로 옮겨 미완성 파일이 이미지 목록에 보이지 않게 한다.
const IMAGE_PARTIAL_DIR: &str = "_partial";
/// 이 시간보다 오래 손대지 않은 중간 이미지 파일은 이전 실행이 남긴 것으로 보고 지운다.
const STALE_PARTIAL_SECS: u64 = 3600;
/// 증분 이미지 체인의 최대 깊이(풀 1 + 증분 13).
const MAX_INCREMENTAL_CHAIN_DEPTH: usize = 14;

fn is_fixed_drive(d: char) -> bool {
    #[cfg(windows)]
    {
        extern "system" {
            fn GetDriveTypeW(root: *const u16) -> u32;
        }
        let w: Vec<u16> = format!("{d}:\\").encode_utf16().chain(Some(0)).collect();
        // SAFETY: 널 종료 UTF-16 문자열
        unsafe { GetDriveTypeW(w.as_ptr()) == 3 } // DRIVE_FIXED
    }
    #[cfg(not(windows))]
    {
        let _ = d;
        false
    }
}

/// 이미지 폴더는 볼륨 전체 내용을 담으므로 SYSTEM·Administrators 만 접근하게 한다(상속 끊기).
fn restrict_to_admins(dir: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let o = std::process::Command::new("icacls.exe")
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "/Q",
            ])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("icacls 실행 실패: {e}"))?;
        if !o.status.success() {
            return Err(format!(
                "icacls 실패({:?}): {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).trim()
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        Ok(())
    }
}

/// 이전 실행이 남긴 중간 이미지 파일(오래 손대지 않은 것)을 지운다. 진행 중인 다른 작업의 파일은 계속 쓰이므로 남는다.
pub(crate) fn remove_stale_partials(dir: &Path, older_than: Duration) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let stale = e
                .metadata()
                .ok()
                .filter(|m| m.is_file())
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= older_than);
            if stale && std::fs::remove_file(&p).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// 진행 문구 뒤에 붙일 속도·남은 시간. 1초 미만이거나 읽은 양이 없으면 빈 문자열.
pub(crate) fn speed_note(done: u64, total: u64, secs: f64) -> String {
    if secs < 1.0 || done == 0 {
        return String::new();
    }
    let bps = done as f64 / secs;
    let mut s = if bps >= 1e9 {
        format!(" · {:.1}GB/s", bps / 1e9)
    } else {
        format!(" · {:.0}MB/s", bps / 1e6)
    };
    if total > done {
        let min = ((total - done) as f64 / bps / 60.0).ceil() as u64;
        if min >= 60 {
            s.push_str(&format!(" · 약 {}시간 {}분 남음", min / 60, min % 60));
        } else {
            s.push_str(&format!(" · 약 {}분 남음", min.max(1)));
        }
    }
    s
}

/// 암호화된 저장소의 32바이트 키를 읽는다(키가 없거나 암호화 미사용이면 None).
fn load_repo_key_bytes(repo: &Path) -> Option<[u8; 32]> {
    if !kova_core::repocrypto::is_enabled(repo) {
        return None;
    }
    let code = kova_core::repocrypto::export_recovery_code(repo).ok()?;
    let clean: String = code.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let raw = kova_core::crypto::unhex(&clean)?;
    raw.try_into().ok()
}

struct ImageCaptureDone {
    used_clusters: u64,
    compressed_bytes: u64,
    inc_note: String,
}

impl Supervisor {
    /// 볼륨 이미지: 저장 위치는 프로파일 저장소 아래 `images` 폴더로 고정하고 이름도 서비스가 정한다
    /// (이 서비스는 SYSTEM 권한이라 요청자가 출력 경로를 고르게 하지 않는다).
    pub(crate) fn run_image_job(&self, job: &Job, drive: char, cancel: &AtomicBool) -> JobOutcome {
        let Some(prof) = self.resolve_profile(&job.profile_id) else {
            return JobOutcome::fail(format!("프로파일 없음: {}", job.profile_id));
        };
        // 폴더를 만들기 전에 거부할 수 있는 것은 먼저 거부한다(없는·이동식 드라이브)
        if !is_fixed_drive(drive) {
            return JobOutcome::fail(format!(
                "{drive}: 는 내장(고정) 드라이브가 아니라 이미지로 만들 수 없습니다"
            ));
        }
        let repo_path = PathBuf::from(&prof.repo_dir);
        let _smb = match kova_core::smb::SmbMountGuard::connect_if_needed(
            &self.0.config_dir,
            &repo_path,
        ) {
            Ok(g) => g,
            Err(e) => return JobOutcome::fail(format!("저장소 SMB 연결 실패: {e}")),
        };
        let dir = repo_path.join("images");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return JobOutcome::fail(format!("이미지 폴더를 만들 수 없음: {e}"));
        }
        // 볼륨 전체(다른 사용자 파일 포함)가 담기므로 SYSTEM·관리자만 읽게 한다. 못 하면 만들지 않는다.
        if let Err(e) = restrict_to_admins(&dir) {
            return JobOutcome::fail(format!("이미지 폴더 권한 설정 실패: {e}"));
        }
        let partial_dir = dir.join(IMAGE_PARTIAL_DIR);
        if let Err(e) = std::fs::create_dir_all(&partial_dir) {
            return JobOutcome::fail(format!("이미지 폴더를 만들 수 없음: {e}"));
        }
        let stale = remove_stale_partials(&partial_dir, Duration::from_secs(STALE_PARTIAL_SECS));
        if stale > 0 {
            kova_core::applog::write(
                &self.0.config_dir,
                "INFO",
                &format!("이전 실행이 남긴 미완성 이미지 {stale}개 정리"),
            );
        }
        let settings = self.0.store.settings();
        if let Err(why) = kova_core::diskspace::check_min_free(
            kova_core::diskspace::free_bytes(&dir),
            settings.min_free_disk_gb,
        ) {
            return JobOutcome::fail(why);
        }
        let name = format!("{}_{}.qblk", drive, Local::now().format("%Y%m%d_%H%M%S"));
        let out = dir.join(&name);
        if out.exists() {
            return JobOutcome::fail(format!("같은 이름의 이미지가 이미 있음: {name}"));
        }
        let id = job.id;
        let last = Mutex::new(u64::MAX);
        let started = Instant::now();
        let on_progress = |s: &kova_image::Stats| {
            let gb = s.raw_bytes >> 30;
            let mut l = last.lock().unwrap();
            if *l != gb {
                *l = gb;
                let total_gb = s.total_raw_bytes >> 30;
                let percent = (s.raw_bytes * 100)
                    .checked_div(s.total_raw_bytes)
                    .map_or(0, |p| p.min(98));
                self.emit(SvcEvent::Progress {
                    job_id: id,
                    percent,
                    current: format!(
                        "{gb}GB / {total_gb}GB 읽음{}",
                        speed_note(
                            s.raw_bytes,
                            s.total_raw_bytes,
                            started.elapsed().as_secs_f64()
                        )
                    ),
                });
            }
        };
        let use_incremental = job.arg == "incremental" || settings.incremental_images;
        self.mark_vss(job.id, &format!("볼륨 이미지 {drive}:"), &[]);
        let capture_res: Result<ImageCaptureDone, String> = if use_incremental {
            let base_image = kova_image::incremental::find_latest_base_image(
                &dir,
                drive,
                MAX_INCREMENTAL_CHAIN_DEPTH,
            );
            kova_image::volume::capture_volume_incremental(
                &format!("{drive}:"),
                &out,
                base_image.as_deref(),
                3,
                cancel,
                &on_progress,
            )
            .map(|(h, s, inc)| {
                let inc_note = if base_image.is_some()
                    && kova_image::incremental::chain_path_for(&out).is_file()
                {
                    format!(
                        ", 증분(변경 클러스터 {}, 건너뜀 {})",
                        inc.changed_clusters, inc.skipped_clusters
                    )
                } else {
                    ", 풀 기준 이미지(.qmap 저장)".to_string()
                };
                ImageCaptureDone {
                    used_clusters: h.used_clusters,
                    compressed_bytes: s.compressed_bytes,
                    inc_note,
                }
            })
            .map_err(|e| e.to_string())
        } else {
            // 미완성 파일은 `_partial` 에 쓰고 끝난 뒤 옮긴다(중간에 서비스가 죽어도 완성 이미지처럼 보이지 않게)
            let part = partial_dir.join(&name);
            kova_image::volume::capture_volume(&format!("{drive}:"), &part, 3, cancel, &on_progress)
                .map_err(|e| e.to_string())
                .and_then(|(h, s)| {
                    std::fs::rename(&part, &out)
                        .map(|()| ImageCaptureDone {
                            used_clusters: h.used_clusters,
                            compressed_bytes: s.compressed_bytes,
                            inc_note: String::new(),
                        })
                        .map_err(|e| {
                            let _ = std::fs::remove_file(&part);
                            format!("완성된 이미지를 옮기지 못함: {e}")
                        })
                })
        };
        self.unmark_vss(job.id);
        let done = match capture_res {
            Ok(d) => d,
            Err(e) => return JobOutcome::fail(e),
        };
        // 베어메탈 복원용 디스크·파티션 레이아웃 사이드카(.qlayout.json)를 최선 노력으로 함께 저장한다
        let layout_note = match kova_image::layout::capture_disk_layout(drive) {
            Ok(layout) => match kova_image::layout::save_layout(&out, &layout) {
                Ok(()) => ", 파티션 레이아웃 저장",
                Err(e) => {
                    kova_core::applog::write(
                        &self.0.config_dir,
                        "WARN",
                        &format!("파티션 레이아웃 저장 실패: {e}"),
                    );
                    ""
                }
            },
            Err(e) => {
                kova_core::applog::write(
                    &self.0.config_dir,
                    "WARN",
                    &format!("파티션 레이아웃 조회 실패({drive}:): {e}"),
                );
                ""
            }
        };
        // 백업 암호화가 켜져 있고 저장소 키가 있으면 .qblk → .qblk.enc 로 스트리밍 암호화한다
        let mut final_path = out.clone();
        let mut enc_note = "";
        if settings.encrypt_backups {
            if let Some(key) = load_repo_key_bytes(&repo_path) {
                self.emit(SvcEvent::Progress {
                    job_id: id,
                    percent: 99,
                    current: "볼륨 이미지 AES-256-GCM 암호화 중...".into(),
                });
                let enc_out = PathBuf::from(format!("{}.enc", out.display()));
                if let Err(e) = kova_image::crypto::encrypt_file(&out, &enc_out, &key, cancel) {
                    let _ = std::fs::remove_file(&out);
                    let _ = std::fs::remove_file(kova_image::incremental::map_path_for(&out));
                    let _ = std::fs::remove_file(kova_image::incremental::chain_path_for(&out));
                    let _ = std::fs::remove_file(kova_image::layout::layout_path_for(&out));
                    return JobOutcome::fail(format!("이미지 암호화 실패: {e}"));
                }
                let _ = std::fs::remove_file(&out);
                final_path = enc_out;
                enc_note = ", AES-256-GCM 암호화";
            }
        }
        let mut worm_note = "";
        if settings.enable_ransomware_protection && kova_core::worm::protect_file(&final_path, true)
        {
            worm_note = ", 랜섬웨어 보호 잠금";
        }
        let final_size = std::fs::metadata(&final_path)
            .map(|m| m.len())
            .unwrap_or(done.compressed_bytes);
        self.emit(SvcEvent::Progress {
            job_id: id,
            percent: 100,
            current: "이미지 완료".into(),
        });
        JobOutcome {
            ok: true,
            message: format!(
                "이미지 완료: {} (사용 클러스터 {}, 압축 {}바이트{}{layout_note}{enc_note}{worm_note})",
                final_path.display(),
                done.used_clusters,
                final_size,
                done.inc_note
            ),
            snapshot_id: None,
            bytes: final_size,
            files: 1,
        }
    }
}

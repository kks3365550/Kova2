//! SMB/NAS 공유 자격 증명(DPAPI 암호화 보관) 및 자동 연결 가드.
//! - 자격 증명은 `cfg_dir/smb_creds.bin` 에 DPAPI(머신 범위) + 제한 ACL(`secrets::write_private`)로 저장한다.
//! - 백업·오프사이트·복원 직전 `SmbMountGuard::connect_if_needed` 로 UNC 공유에 연결하고,
//!   이 가드가 새로 연 연결만 `Drop` 시 해제한다(이미 연결된 세션은 건드리지 않는다).
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub(crate) const CREDS_FILE: &str = "smb_creds.bin";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmbCredential {
    pub share: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for SmbCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbCredential")
            .field("share", &self.share)
            .field("username", &self.username)
            .field(
                "password",
                &if self.password.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmbCredSummary {
    pub share: String,
    pub username: String,
}

/// UNC 경로(`\\server\share\...`, `\\?\UNC\server\share\...`, `//server/share/...`)에서
/// 정규화된 소문자 공유 루트(`\\server\share`)를 추출한다.
/// 로컬 드라이브·장치 경로(`\\.\...`)·불완전한 경로는 `None`.
pub fn extract_unc_share(path: &Path) -> Option<String> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let norm = trimmed.replace('/', "\\");
    if norm.starts_with("\\\\.\\") {
        return None;
    }
    let rest = if let Some(after_q) = norm.strip_prefix("\\\\?\\") {
        // `\\?\UNC\server\share` (대소문자 무관)만 UNC 로 인정하고 `\\?\C:\`·`\\?\Volume{}` 는 제외
        if after_q.len() < 4 || !after_q[..4].eq_ignore_ascii_case("UNC\\") {
            return None;
        }
        &after_q[4..]
    } else {
        norm.strip_prefix("\\\\")?
    };

    let mut parts = rest.split('\\');
    let server = parts.next().unwrap_or("").trim();
    let share = parts.next().unwrap_or("").trim();
    if server.is_empty()
        || share.is_empty()
        || server == "."
        || server == "?"
        || server == ".."
        || share == "."
        || share == ".."
        || server.contains(':')
        || share.contains(':')
    {
        return None;
    }
    Some(format!(
        "\\\\{}\\{}",
        server.to_lowercase(),
        share.to_lowercase()
    ))
}

fn normalize_share(share: &str) -> Result<String, String> {
    extract_unc_share(Path::new(share.trim()))
        .ok_or_else(|| "올바른 UNC 공유 경로(\\\\서버\\공유)를 입력하세요".to_string())
}

fn creds_path(cfg_dir: &Path) -> std::path::PathBuf {
    cfg_dir.join(CREDS_FILE)
}

fn lock_creds(cfg_dir: &Path) -> Option<fs::File> {
    crate::config::lock_shared(&cfg_dir.join(".smb_creds.lock"))
}

fn load_all(cfg_dir: &Path) -> Result<Vec<SmbCredential>, String> {
    let path = creds_path(cfg_dir);
    let enc = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("SMB 자격 증명 읽기 실패: {e}")),
    };
    let raw = crate::repocrypto::dpapi_unprotect(&enc)?;
    serde_json::from_slice(&raw).map_err(|e| format!("SMB 자격 증명 형식 오류: {e}"))
}

fn save_all(cfg_dir: &Path, creds: &[SmbCredential]) -> Result<(), String> {
    fs::create_dir_all(cfg_dir).map_err(|e| format!("설정 폴더 생성 실패: {e}"))?;
    let path = creds_path(cfg_dir);
    if creds.is_empty() {
        return match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("SMB 자격 증명 파일 삭제 실패: {e}")),
        };
    }
    let json = serde_json::to_vec(creds).map_err(|e| format!("SMB 자격 증명 직렬화 실패: {e}"))?;
    let enc = crate::repocrypto::dpapi_protect(&json)?;
    crate::secrets::write_private(&path, &enc).map_err(|e| format!("SMB 자격 증명 저장 실패: {e}"))
}

/// 공유 경로에 대한 SMB 자격 증명을 DPAPI 로 암호화해 저장(이미 있으면 갱신)한다.
pub fn save_cred(
    cfg_dir: &Path,
    share: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let norm = normalize_share(share)?;
    let _g = lock_creds(cfg_dir);
    let mut all = load_all(cfg_dir)?;
    let cred = SmbCredential {
        share: norm.clone(),
        username: username.trim().to_string(),
        password: password.to_string(),
    };
    match all
        .iter_mut()
        .find(|c| extract_unc_share(Path::new(&c.share)).as_deref() == Some(norm.as_str()))
    {
        Some(slot) => *slot = cred,
        None => all.push(cred),
    }
    all.sort_by(|a, b| a.share.cmp(&b.share));
    save_all(cfg_dir, &all)
}

/// 저장된 SMB 자격 증명 목록(비밀번호 제외)을 돌려준다.
pub fn list_creds(cfg_dir: &Path) -> Vec<SmbCredSummary> {
    let Ok(mut all) = load_all(cfg_dir) else {
        return Vec::new();
    };
    all.sort_by(|a, b| a.share.cmp(&b.share));
    all.into_iter()
        .map(|c| SmbCredSummary {
            share: c.share,
            username: c.username,
        })
        .collect()
}

/// 지정 공유의 SMB 자격 증명을 삭제한다. 삭제했으면 `Ok(true)`, 없었으면 `Ok(false)`.
pub fn delete_cred(cfg_dir: &Path, share: &str) -> Result<bool, String> {
    let norm = normalize_share(share)?;
    let _g = lock_creds(cfg_dir);
    let mut all = load_all(cfg_dir)?;
    let before = all.len();
    all.retain(|c| extract_unc_share(Path::new(&c.share)).as_deref() != Some(norm.as_str()));
    let removed = all.len() != before;
    if removed {
        save_all(cfg_dir, &all)?;
    }
    Ok(removed)
}

/// 경로가 UNC 공유이면 일치하는 저장 자격 증명을 찾아 돌려준다.
pub fn find_cred_for_path(cfg_dir: &Path, path: &Path) -> Option<SmbCredential> {
    let share = extract_unc_share(path)?;
    let all = load_all(cfg_dir).ok()?;
    all.into_iter()
        .find(|c| extract_unc_share(Path::new(&c.share)).as_deref() == Some(share.as_str()))
}

/// UNC 경로 작업 동안 SMB 공유 세션을 유지하는 RAII 가드.
/// 이 가드가 직접 연결을 수립한 경우에만 `Drop` 시 `WNetCancelConnection2W` 를 호출한다.
pub struct SmbMountGuard {
    #[cfg_attr(not(windows), allow(dead_code))]
    remote_name: Option<String>,
}

impl SmbMountGuard {
    /// `path` 가 UNC 경로이고 `cfg_dir` 에 저장된 자격 증명이 있으면 공유에 연결한다.
    /// 로컬 경로이거나 저장된 자격 증명이 없으면 아무것도 하지 않고 성공을 돌려준다.
    pub fn connect_if_needed(cfg_dir: &Path, path: &Path) -> Result<Self, String> {
        let Some(cred) = find_cred_for_path(cfg_dir, path) else {
            return Ok(Self { remote_name: None });
        };
        #[cfg(windows)]
        {
            let established = win_net::connect(&cred)?;
            Ok(Self {
                remote_name: established.then_some(cred.share),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = cred;
            Ok(Self { remote_name: None })
        }
    }
}

impl Drop for SmbMountGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(ref remote) = self.remote_name {
            win_net::disconnect(remote);
        }
    }
}

#[cfg(windows)]
mod win_net {
    use super::SmbCredential;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const RESOURCETYPE_DISK: u32 = 1;
    const NO_ERROR: u32 = 0;
    const ERROR_ALREADY_ASSIGNED: u32 = 85;
    const ERROR_SESSION_CREDENTIAL_CONFLICT: u32 = 1219;

    #[repr(C)]
    struct NetResourceW {
        dw_scope: u32,
        dw_type: u32,
        dw_display_type: u32,
        dw_usage: u32,
        lp_local_name: *mut u16,
        lp_remote_name: *mut u16,
        lp_comment: *mut u16,
        lp_provider: *mut u16,
    }

    #[link(name = "mpr")]
    extern "system" {
        fn WNetAddConnection2W(
            lp_net_resource: *const NetResourceW,
            lp_password: *const u16,
            lp_username: *const u16,
            dw_flags: u32,
        ) -> u32;
        fn WNetCancelConnection2W(lp_name: *const u16, dw_flags: u32, f_force: i32) -> u32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain([0]).collect()
    }

    /// 연결을 새로 맺었으면 `Ok(true)`, 이미 연결된 세션을 재사용하면 `Ok(false)`.
    pub fn connect(cred: &SmbCredential) -> Result<bool, String> {
        let mut remote_w = to_wide(&cred.share);
        let user_w = (!cred.username.is_empty()).then(|| to_wide(&cred.username));
        let pass_w = (!cred.username.is_empty() || !cred.password.is_empty())
            .then(|| to_wide(&cred.password));
        let nr = NetResourceW {
            dw_scope: 0,
            dw_type: RESOURCETYPE_DISK,
            dw_display_type: 0,
            dw_usage: 0,
            lp_local_name: std::ptr::null_mut(),
            lp_remote_name: remote_w.as_mut_ptr(),
            lp_comment: std::ptr::null_mut(),
            lp_provider: std::ptr::null_mut(),
        };
        let rc = unsafe {
            WNetAddConnection2W(
                &nr,
                pass_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                user_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                0,
            )
        };
        match rc {
            NO_ERROR => Ok(true),
            ERROR_ALREADY_ASSIGNED | ERROR_SESSION_CREDENTIAL_CONFLICT => Ok(false),
            code => Err(format!(
                "SMB 공유 연결 실패({}, Windows 오류 코드 {code})",
                cred.share
            )),
        }
    }

    pub fn disconnect(remote: &str) {
        let remote_w = to_wide(remote);
        unsafe {
            let _ = WNetCancelConnection2W(remote_w.as_ptr(), 0, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_unc_share_handles_standard_extended_and_invalid_paths() {
        assert_eq!(
            extract_unc_share(Path::new(r"\\NAS01\Backups\kova\repo")).as_deref(),
            Some(r"\\nas01\backups")
        );
        assert_eq!(
            extract_unc_share(Path::new(r"\\192.168.0.10\ShareName")).as_deref(),
            Some(r"\\192.168.0.10\sharename")
        );
        assert_eq!(
            extract_unc_share(Path::new(r"\\?\UNC\MyServer\Data\sub\file.txt")).as_deref(),
            Some(r"\\myserver\data")
        );
        assert_eq!(
            extract_unc_share(Path::new(r"\\?\unc\MyServer\Data")).as_deref(),
            Some(r"\\myserver\data")
        );
        assert_eq!(
            extract_unc_share(Path::new("//FileSrv/Public/dir")).as_deref(),
            Some(r"\\filesrv\public")
        );

        for invalid in [
            r"C:\Backups\repo",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\very\long\path",
            r"\\?\Volume{1234}\foo",
            r"\\onlyserver",
            r"\\onlyserver\",
            r"\\\emptyserver",
            "",
        ] {
            assert_eq!(extract_unc_share(Path::new(invalid)), None, "{invalid}");
        }
    }

    #[test]
    fn credential_debug_redacts_password() {
        let c = SmbCredential {
            share: r"\\nas\backup".into(),
            username: "admin".into(),
            password: "SuperSecretPassword!".into(),
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("SuperSecretPassword"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("admin"), "{dbg}");
    }

    #[test]
    #[cfg(windows)]
    fn save_list_find_delete_creds_roundtrip_encrypted() {
        let d = tempfile::tempdir().unwrap();
        assert!(list_creds(d.path()).is_empty());
        assert!(find_cred_for_path(d.path(), Path::new(r"\\nas\share\sub")).is_none());

        // 잘못된 공유 경로는 거부
        assert!(save_cred(d.path(), r"D:\local", "u", "p").is_err());

        save_cred(d.path(), r"\\NAS-01\Backup\extra", "svc_user", "P@ss1").unwrap();
        save_cred(d.path(), r"\\nas-02\archive", "archive_u", "P@ss2").unwrap();

        // 파일에 평문 비밀번호가 노출되지 않아야 한다
        let raw = fs::read(d.path().join(CREDS_FILE)).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"P@ss1"));
        assert!(!raw.windows(5).any(|w| w == b"P@ss2"));

        let list = list_creds(d.path());
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].share, r"\\nas-01\backup");
        assert_eq!(list[0].username, "svc_user");
        assert_eq!(list[1].share, r"\\nas-02\archive");

        // 대소문자·확장 UNC 접두사·하위 폴더 모두 매칭
        let found =
            find_cred_for_path(d.path(), Path::new(r"\\?\UNC\nas-01\BACKUP\pc1\repo")).unwrap();
        assert_eq!(found.username, "svc_user");
        assert_eq!(found.password, "P@ss1");

        // 같은 공유 재저장 시 갱신(중복 생성 안 함)
        save_cred(d.path(), r"\\nas-01\backup", "svc_user2", "NewPass").unwrap();
        assert_eq!(list_creds(d.path()).len(), 2);
        assert_eq!(
            find_cred_for_path(d.path(), Path::new(r"\\NAS-01\backup\x"))
                .unwrap()
                .password,
            "NewPass"
        );

        // 삭제
        assert!(delete_cred(d.path(), r"\\NAS-01\backup").unwrap());
        assert!(!delete_cred(d.path(), r"\\NAS-01\backup").unwrap());
        assert_eq!(list_creds(d.path()).len(), 1);
        assert!(delete_cred(d.path(), r"\\nas-02\archive").unwrap());
        assert!(list_creds(d.path()).is_empty());

        // 로컬 경로나 자격 증명 없는 UNC 경로는 no-op 가드 반환
        let g1 = SmbMountGuard::connect_if_needed(d.path(), Path::new(r"C:\Temp")).unwrap();
        assert!(g1.remote_name.is_none());
        let g2 =
            SmbMountGuard::connect_if_needed(d.path(), Path::new(r"\\unknown\share\sub")).unwrap();
        assert!(g2.remote_name.is_none());
    }
}

//! 파일 백업용 VSS(볼륨 섀도 복사): 원본이 있는 드라이브를 잠깐 스냅샷해 열려 있거나 잠긴 파일도 같은 시점으로 읽는다.
//! 관리자(서비스) 권한과 NTFS 같은 VSS 지원 드라이브가 필요하다. 만들 수 없으면 호출자가 직접 읽기로 되돌아간다.
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_VSS_ATTEMPTS: usize = 3;
pub const DEFAULT_VSS_RETRY_DELAY: Duration = Duration::from_secs(2);

/// 만들어 둔 섀도 복사본 묶음. 지워질 때(Drop) 모두 삭제한다.
pub struct ShadowSet {
    /// (드라이브 "X:" 대문자, 섀도 ID, 장치 경로)
    shadows: Vec<(String, String, String)>,
    /// `shadow_ids()` 슬라이스 반환용 ID 목록
    ids: Vec<String>,
}

/// `C:\dir\x` → "C:" (드라이브 문자 경로가 아니면 None).
fn drive_of(p: &Path) -> Option<String> {
    let s = p.to_string_lossy();
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s);
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        Some(format!("{}:", (b[0] as char).to_ascii_uppercase()))
    } else {
        None
    }
}

/// 장치 경로 + 원래 경로(드라이브 뒤 부분) → 섀도 안의 경로.
fn join_device(device: &str, p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s);
    let rest = s[2..].replace('/', "\\");
    PathBuf::from(format!(
        "{}{}{}",
        device.trim_end_matches('\\'),
        if rest.starts_with('\\') { "" } else { "\\" },
        rest
    ))
}

impl ShadowSet {
    /// 경로들이 있는 드라이브마다 섀도 복사본을 하나씩 만든다. 일시적 VSS 실패 시 기본 3회(2초 간격) 재시도한다.
    pub fn create_for(paths: &[PathBuf]) -> Result<ShadowSet, String> {
        Self::create_for_with_retry(paths, DEFAULT_VSS_ATTEMPTS, DEFAULT_VSS_RETRY_DELAY)
    }

    /// 지정된 횟수·간격으로 섀도 복사본 생성을 재시도한다. 하나라도 실패하면 만든 것을 지우고 오류를 돌려준다.
    pub fn create_for_with_retry(
        paths: &[PathBuf],
        attempts: usize,
        delay: Duration,
    ) -> Result<ShadowSet, String> {
        let mut drives: Vec<String> = paths.iter().filter_map(|p| drive_of(p)).collect();
        drives.sort();
        drives.dedup();
        if drives.is_empty() {
            return Err("드라이브 문자 경로가 아니어서 섀도 복사를 쓸 수 없음".into());
        }
        create_with_retry_fn(&drives, attempts.max(1), delay, imp::create)
    }

    /// 원래 경로를 섀도 안의 경로로 바꾼다. 섀도가 없는 드라이브면 그대로 돌려준다.
    pub fn map(&self, p: &Path) -> PathBuf {
        match drive_of(p).and_then(|d| self.shadows.iter().find(|s| s.0 == d)) {
            Some((_, _, device)) => join_device(device, p),
            None => p.to_path_buf(),
        }
    }

    pub fn count(&self) -> usize {
        self.shadows.len()
    }

    /// 현재 유지 중인 섀도 복사본 GUID 목록(충돌 복구용 기록 등에 사용).
    pub fn shadow_ids(&self) -> &[String] {
        &self.ids
    }
}

pub(crate) fn is_valid_guid(id: &str) -> bool {
    id.len() >= 36
        && id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'))
}

/// 비정상 종료 등으로 남은 고아 VSS 섀도 복사본 GUID 들을 정리한다.
/// 유효한 GUID 형식만 `imp::delete` 로 삭제 시도하며, 처리한 유효 GUID 개수를 돌려준다.
pub fn cleanup_orphaned_shadows(ids: &[String]) -> usize {
    let mut cleaned = 0usize;
    for raw in ids {
        let id = raw.trim();
        if is_valid_guid(id) {
            imp::delete(id);
            cleaned += 1;
        }
    }
    cleaned
}

impl Drop for ShadowSet {
    fn drop(&mut self) {
        for (_, id, _) in &self.shadows {
            imp::delete(id);
        }
    }
}

fn create_with_retry_fn<F>(
    drives: &[String],
    attempts: usize,
    delay: Duration,
    mut creator: F,
) -> Result<ShadowSet, String>
where
    F: FnMut(&str) -> Result<(String, String), String>,
{
    let mut last_err = String::new();
    for attempt in 1..=attempts.max(1) {
        let mut set = ShadowSet {
            shadows: vec![],
            ids: vec![],
        };
        let mut failed = None;
        for d in drives {
            match creator(d) {
                Ok((id, device)) => {
                    set.ids.push(id.clone());
                    set.shadows.push((d.clone(), id, device));
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if let Some(err) = failed {
            drop(set); // 앞서 만든 섀도 복사본 즉시 정리
            last_err = err;
            if attempt < attempts {
                std::thread::sleep(delay);
            }
        } else {
            return Ok(set);
        }
    }
    Err(format!("{last_err} ({attempts}회 시도)"))
}

#[cfg(windows)]
mod imp {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    fn ps(script: &str) -> Result<String, String> {
        let o = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("PowerShell 실행 실패: {e}"))?;
        if !o.status.success() {
            return Err(format!(
                "섀도 복사 실패: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    /// drive 는 호출 전에 "X:" 로 검증된 값이라 스크립트에 넣어도 안전하다.
    pub fn create(drive: &str) -> Result<(String, String), String> {
        let script = format!(
            "$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{drive}\\';Context='ClientAccessible'}}; \
             if ($r.ReturnValue -ne 0) {{ throw ('VSS create failed: ' + $r.ReturnValue) }}; \
             $id = $r.ShadowID; \
             try {{ \
                 $s = Get-CimInstance Win32_ShadowCopy -Filter \"ID='$id'\" -ErrorAction Stop; \
                 Write-Output ($id + '|' + $s.DeviceObject) \
             }} catch {{ \
                 Get-CimInstance Win32_ShadowCopy -Filter \"ID='$id'\" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue; \
                 throw \
             }}"
        );
        let out = ps(&script)?;
        let line = out.lines().last().unwrap_or("");
        let (id, device) = line
            .split_once('|')
            .ok_or_else(|| format!("섀도 복사본 응답을 해석할 수 없음: {line}"))?;
        let (id, device) = (id.trim(), device.trim());
        // 삭제 스크립트에 들어가므로 GUID 모양만 허용한다
        let guid_ok = id.len() >= 36
            && id
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'));
        if !guid_ok {
            return Err(format!("섀도 복사본 정보가 이상함: {line}"));
        }
        if !device.starts_with("\\\\?\\GLOBALROOT\\Device\\") {
            delete(id);
            return Err(format!("섀도 복사본 정보가 이상함: {line}"));
        }
        Ok((id.to_string(), device.to_string()))
    }

    pub fn delete(id: &str) {
        let _ = ps(&format!(
            "Get-CimInstance Win32_ShadowCopy -Filter \"ID='{id}'\" | Remove-CimInstance"
        ));
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn create(_: &str) -> Result<(String, String), String> {
        Err("VSS 는 Windows 전용".into())
    }
    pub fn delete(_: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_and_path_mapping() {
        assert_eq!(drive_of(Path::new("c:\\a\\b")).as_deref(), Some("C:"));
        assert_eq!(drive_of(Path::new("\\\\?\\D:\\x")).as_deref(), Some("D:"));
        assert_eq!(drive_of(Path::new("\\\\server\\share")), None);
        let dev = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7";
        assert_eq!(
            join_device(dev, Path::new("C:\\data\\a.txt")),
            PathBuf::from("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7\\data\\a.txt")
        );
        assert_eq!(
            join_device(dev, Path::new("C:")),
            PathBuf::from("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7\\")
        );
        assert_eq!(
            join_device(dev, Path::new("C:/data/sub/a.txt")),
            PathBuf::from("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7\\data\\sub\\a.txt")
        );
        assert!(!join_device(dev, Path::new("C:/data/sub/a.txt"))
            .to_string_lossy()
            .contains('/'));
        let set = ShadowSet {
            shadows: vec![("C:".into(), "x".into(), dev.into())],
            ids: vec!["x".into()],
        };
        assert_eq!(set.shadow_ids(), &["x".to_string()]);
        assert_eq!(set.map(Path::new("D:\\q")), PathBuf::from("D:\\q"));
        assert!(ShadowSet::create_for(&[PathBuf::from("\\\\srv\\s")]).is_err());
        std::mem::forget(set); // 가짜 ID 를 지우려고 PowerShell 을 부르지 않게 한다
    }

    #[test]
    fn retry_recovers_after_transient_failure() {
        let mut calls = 0usize;
        let set = create_with_retry_fn(&["C:".into()], 3, Duration::from_millis(1), |_| {
            calls += 1;
            if calls < 3 {
                Err("transient busy".into())
            } else {
                Ok((
                    "{11111111-1111-1111-1111-111111111111}".into(),
                    "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy9".into(),
                ))
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(set.count(), 1);
        assert_eq!(
            set.shadow_ids(),
            &["{11111111-1111-1111-1111-111111111111}".to_string()]
        );
        std::mem::forget(set);
    }

    #[test]
    fn cleanup_orphaned_shadows_ignores_invalid_guids() {
        let bad = vec![
            String::new(),
            "short".into(),
            "'; Remove-Item C:\\ -Recurse".into(),
        ];
        assert_eq!(cleanup_orphaned_shadows(&bad), 0);
        assert!(is_valid_guid("{11111111-1111-1111-1111-111111111111}"));
        assert!(!is_valid_guid("not-a-guid"));
    }

    #[test]
    fn retry_exhaustion_reports_attempt_count() {
        let mut calls = 0usize;
        let err = create_with_retry_fn(&["C:".into()], 2, Duration::from_millis(1), |_| {
            calls += 1;
            Err("writer error".into())
        })
        .err()
        .unwrap();
        assert_eq!(calls, 2);
        assert!(err.contains("writer error") && err.contains("2회 시도"));
    }

    /// 실제 섀도 복사본을 만든다(관리자 권한 필요): `cargo test -p kova-core vss -- --ignored`
    #[test]
    #[ignore]
    #[cfg(windows)]
    fn real_shadow_reads_a_file_held_open_exclusively() {
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("locked.txt");
        std::fs::write(&f, b"before-lock").unwrap();
        let set = ShadowSet::create_for(std::slice::from_ref(&f)).expect("관리자 권한/VSS 필요");
        // 섀도를 만든 뒤 독점으로 열어 내용을 바꾼다: 직접 읽기는 막히고 섀도는 이전 시점을 돌려준다
        let mut w = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .share_mode(0)
            .open(&f)
            .unwrap();
        w.write_all(b"after-change").unwrap();
        w.flush().unwrap();
        assert!(
            std::fs::read(&f).is_err(),
            "독점으로 열려 직접 읽기는 실패해야 함"
        );
        assert_eq!(std::fs::read(set.map(&f)).unwrap(), b"before-lock");
        drop(w);
        drop(set);
    }
}

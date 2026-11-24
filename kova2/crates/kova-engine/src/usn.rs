//! Windows NTFS USN Journal 조회 및 증분 변경 감지 모듈.
//! 관리자/SYSTEM 권한의 NTFS 볼륨에서는 `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` 로
//! 마지막 백업 이후 변경된 항목을 빠르게 조회할 수 있으며, 권한 부족·비-NTFS·저널 초기화 시에는
//! 호출자가 안전하게 전체 `WalkDir` 스캔으로 폴백할 수 있도록 신호를 돌려준다.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

/// 볼륨별 NTFS USN 저널 체크포인트(매니페스트에 직렬화된다).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsnCheckpoint {
    /// 볼륨 문자열(예: `"C:"`)
    pub volume: String,
    pub journal_id: u64,
    pub next_usn: i64,
}

/// 마지막 체크포인트 이후의 USN 저널 변경 내역.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnDelta {
    pub next_checkpoint: UsnCheckpoint,
    /// 변경된 파일·폴더 이름 집합
    pub changed_names: HashSet<String>,
    /// 저널 ID 변경·저널 덮어쓰기(`ERROR_JOURNAL_ENTRY_DELETED`)·비활성·레코드 상한 초과 시 `true`
    pub fallback_required: bool,
}

/// `FSCTL_READ_USN_JOURNAL` 출력 버퍼(앞 8바이트 `next_usn` + `USN_RECORD_V2`/`V3` 연속)를 파싱한다.
/// 반환: `Some((next_usn, 파일/폴더 이름 목록))`. 버퍼가 8바이트 미만이면 `None`.
pub fn parse_usn_buffer(buf: &[u8]) -> Option<(i64, Vec<String>)> {
    if buf.len() < 8 {
        return None;
    }
    let next_usn = i64::from_le_bytes(buf[0..8].try_into().ok()?);
    let mut names = Vec::new();
    let mut offset = 8usize;

    while offset + 8 <= buf.len() {
        let rec_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
        if rec_len < 60 {
            break;
        }
        let Some(end) = offset.checked_add(rec_len) else {
            break;
        };
        if end > buf.len() {
            break;
        }
        let rec = &buf[offset..end];
        let major_ver = u16::from_le_bytes([rec[4], rec[5]]);
        let name_meta = match major_ver {
            2 => Some((
                u16::from_le_bytes([rec[56], rec[57]]) as usize,
                u16::from_le_bytes([rec[58], rec[59]]) as usize,
            )),
            3 if rec_len >= 76 => Some((
                u16::from_le_bytes([rec[72], rec[73]]) as usize,
                u16::from_le_bytes([rec[74], rec[75]]) as usize,
            )),
            _ => None,
        };

        if let Some((name_len, name_off)) = name_meta {
            if name_len > 0
                && name_len.is_multiple_of(2)
                && name_off.checked_add(name_len).is_some_and(|e| e <= rec_len)
            {
                let name_bytes = &rec[name_off..name_off + name_len];
                let units: Vec<u16> = name_bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .collect();
                let name = String::from_utf16_lossy(&units);
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
        offset = end;
    }

    Some((next_usn, names))
}

/// 대상 드라이브(`'C'` 등)의 현재 NTFS USN 저널 체크포인트를 조회한다.
/// 권한 부족(비관리자)·비-NTFS·비-Windows 환경에서는 오류를 돌려주며 호출자는 일반 스캔으로 폴백한다.
pub fn query_journal(drive_letter: char) -> io::Result<UsnCheckpoint> {
    #[cfg(windows)]
    {
        win::query_journal(drive_letter)
    }
    #[cfg(not(windows))]
    {
        let _ = drive_letter;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NTFS USN journal is only supported on Windows",
        ))
    }
}

/// 지정한 `checkpoint` 이후의 USN 저널 변경 레코드를 읽는다.
/// 저널 ID 변경·덮어쓰기·비활성·`max_records` 초과 시 `fallback_required = true` 를 반환한다.
pub fn read_changes_since(checkpoint: &UsnCheckpoint, max_records: usize) -> io::Result<UsnDelta> {
    #[cfg(windows)]
    {
        win::read_changes_since(checkpoint, max_records)
    }
    #[cfg(not(windows))]
    {
        let _ = (checkpoint, max_records);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NTFS USN journal is only supported on Windows",
        ))
    }
}

/// 원본 경로 목록에서 고유 드라이브 문자를 추출해 조회 가능한 USN 체크포인트만 모은다(최선 노력, 실패 무시).
pub fn collect_checkpoints(sources: &[PathBuf]) -> Vec<UsnCheckpoint> {
    let mut drives: Vec<char> = Vec::new();
    for src in sources {
        if let Some(d) = extract_drive_letter(src) {
            if !drives.contains(&d) {
                drives.push(d);
            }
        }
    }
    drives.sort_unstable();
    let mut out = Vec::new();
    for d in drives {
        if let Ok(cp) = query_journal(d) {
            out.push(cp);
        }
    }
    out
}

fn extract_drive_letter(path: &std::path::Path) -> Option<char> {
    let clean = crate::longpath::strip_extended(path);
    let s = clean.to_str()?;
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some((bytes[0] as char).to_ascii_uppercase())
    } else {
        None
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_JOURNAL_ENTRY_DELETED, ERROR_JOURNAL_NOT_ACTIVE,
        GENERIC_READ, HANDLE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{
        FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0,
        USN_JOURNAL_DATA_V0,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn win_err_to_io(err: windows::core::Error) -> io::Error {
        let code = err.code();
        if code == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
            io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
        } else {
            io::Error::other(err.to_string())
        }
    }

    fn open_volume(drive: char) -> io::Result<OwnedHandle> {
        if !drive.is_ascii_alphabetic() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid drive letter: {drive}"),
            ));
        }
        let drive = drive.to_ascii_uppercase();
        let vol = format!(r"\\.\{drive}:");
        let wide: Vec<u16> = Path::new(&vol)
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE::default(),
            )
        }
        .map_err(win_err_to_io)?;
        Ok(OwnedHandle(handle))
    }

    fn query_journal_handle(handle: HANDLE) -> Result<USN_JOURNAL_DATA_V0, windows::core::Error> {
        let mut data = USN_JOURNAL_DATA_V0::default();
        let mut returned: u32 = 0;
        unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some(std::ptr::from_mut(&mut data).cast::<c_void>()),
                size_of::<USN_JOURNAL_DATA_V0>() as u32,
                Some(&mut returned),
                None,
            )?;
        }
        Ok(data)
    }

    pub(super) fn query_journal(drive_letter: char) -> io::Result<UsnCheckpoint> {
        let drive = drive_letter.to_ascii_uppercase();
        let handle = open_volume(drive)?;
        let data = query_journal_handle(handle.0).map_err(win_err_to_io)?;
        Ok(UsnCheckpoint {
            volume: format!("{drive}:"),
            journal_id: data.UsnJournalID,
            next_usn: data.NextUsn,
        })
    }

    pub(super) fn read_changes_since(
        checkpoint: &UsnCheckpoint,
        max_records: usize,
    ) -> io::Result<UsnDelta> {
        let drive = checkpoint
            .volume
            .chars()
            .next()
            .filter(|c| c.is_ascii_alphabetic())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid checkpoint volume: {}", checkpoint.volume),
                )
            })?
            .to_ascii_uppercase();

        let handle = open_volume(drive)?;
        let current = match query_journal_handle(handle.0) {
            Ok(d) => d,
            Err(e) if e.code() == HRESULT::from_win32(ERROR_JOURNAL_NOT_ACTIVE.0) => {
                return Ok(UsnDelta {
                    next_checkpoint: checkpoint.clone(),
                    changed_names: HashSet::new(),
                    fallback_required: true,
                });
            }
            Err(e) => return Err(win_err_to_io(e)),
        };

        let latest_cp = UsnCheckpoint {
            volume: format!("{drive}:"),
            journal_id: current.UsnJournalID,
            next_usn: current.NextUsn,
        };

        if current.UsnJournalID != checkpoint.journal_id || checkpoint.next_usn < current.FirstUsn {
            return Ok(UsnDelta {
                next_checkpoint: latest_cp,
                changed_names: HashSet::new(),
                fallback_required: true,
            });
        }

        if checkpoint.next_usn >= current.NextUsn {
            return Ok(UsnDelta {
                next_checkpoint: latest_cp,
                changed_names: HashSet::new(),
                fallback_required: false,
            });
        }

        let mut read_data = READ_USN_JOURNAL_DATA_V0 {
            StartUsn: checkpoint.next_usn,
            ReasonMask: 0xFFFF_FFFF,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: checkpoint.journal_id,
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut changed_names = HashSet::new();
        let mut total_records = 0usize;
        let mut cur_usn = checkpoint.next_usn;

        loop {
            read_data.StartUsn = cur_usn;
            let mut returned: u32 = 0;
            let ioctl_res = unsafe {
                DeviceIoControl(
                    handle.0,
                    FSCTL_READ_USN_JOURNAL,
                    Some(std::ptr::from_ref(&read_data).cast::<c_void>()),
                    size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                    Some(buf.as_mut_ptr().cast::<c_void>()),
                    buf.len() as u32,
                    Some(&mut returned),
                    None,
                )
            };
            if let Err(err) = ioctl_res {
                let code = err.code();
                if code == HRESULT::from_win32(ERROR_JOURNAL_ENTRY_DELETED.0)
                    || code == HRESULT::from_win32(ERROR_JOURNAL_NOT_ACTIVE.0)
                {
                    return Ok(UsnDelta {
                        next_checkpoint: latest_cp,
                        changed_names: HashSet::new(),
                        fallback_required: true,
                    });
                }
                return Err(win_err_to_io(err));
            }

            let n = returned as usize;
            if n <= 8 {
                break;
            }
            let Some((next_usn, names)) = parse_usn_buffer(&buf[..n]) else {
                break;
            };
            if names.is_empty() || next_usn <= cur_usn {
                if next_usn > cur_usn {
                    cur_usn = next_usn;
                }
                break;
            }
            total_records += names.len();
            changed_names.extend(names);
            cur_usn = next_usn;

            if max_records > 0 && total_records > max_records {
                return Ok(UsnDelta {
                    next_checkpoint: latest_cp,
                    changed_names: HashSet::new(),
                    fallback_required: true,
                });
            }
            if cur_usn >= current.NextUsn {
                break;
            }
        }

        Ok(UsnDelta {
            next_checkpoint: UsnCheckpoint {
                volume: format!("{drive}:"),
                journal_id: checkpoint.journal_id,
                next_usn: cur_usn,
            },
            changed_names,
            fallback_required: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 합성 `USN_RECORD_V2` 레코드 1개를 8바이트 정렬로 직렬화한다.
    fn make_v2_record(usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = utf16.len() * 2;
        let name_offset: u16 = 60;
        let raw_len = (name_offset as usize) + name_bytes_len;
        let aligned_len = (raw_len + 7) & !7;
        let mut rec = vec![0u8; aligned_len];
        rec[0..4].copy_from_slice(&(aligned_len as u32).to_le_bytes());
        rec[4..6].copy_from_slice(&2u16.to_le_bytes()); // MajorVersion = 2
        rec[6..8].copy_from_slice(&0u16.to_le_bytes()); // MinorVersion = 0
        rec[24..32].copy_from_slice(&usn.to_le_bytes());
        rec[40..44].copy_from_slice(&reason.to_le_bytes());
        rec[56..58].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        rec[58..60].copy_from_slice(&name_offset.to_le_bytes());
        for (i, unit) in utf16.iter().enumerate() {
            let pos = (name_offset as usize) + i * 2;
            rec[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
        }
        rec
    }

    #[test]
    fn usn_checkpoint_serialization_roundtrip() {
        let cp = UsnCheckpoint {
            volume: "C:".into(),
            journal_id: 0x01DB_1234_5678_9ABC,
            next_usn: 987_654_321,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let decoded: UsnCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(cp, decoded);
    }

    #[test]
    fn parse_usn_buffer_parses_synthetic_v2_records() {
        let mut buf = Vec::new();
        let next_usn: i64 = 42_000;
        buf.extend_from_slice(&next_usn.to_le_bytes());
        buf.extend_from_slice(&make_v2_record(40_100, 0x0000_0100, "report.xlsx"));
        buf.extend_from_slice(&make_v2_record(41_200, 0x0000_0002, "품질규격서.docx"));

        let (parsed_next, names) = parse_usn_buffer(&buf).unwrap();
        assert_eq!(parsed_next, next_usn);
        assert_eq!(names, vec!["report.xlsx", "품질규격서.docx"]);

        // 8바이트 미만·빈 버퍼·잘린 레코드도 패닉 없이 처리한다
        assert!(parse_usn_buffer(&[]).is_none());
        assert!(parse_usn_buffer(&[1, 2, 3]).is_none());
        let (only_usn, empty) = parse_usn_buffer(&99i64.to_le_bytes()).unwrap();
        assert_eq!(only_usn, 99);
        assert!(empty.is_empty());

        let mut truncated = buf[..buf.len() - 4].to_vec();
        // 첫 레코드만 정상 파싱되고 잘린 두 번째 레코드는 안전하게 중단
        let (t_next, t_names) = parse_usn_buffer(&truncated).unwrap();
        assert_eq!(t_next, next_usn);
        assert_eq!(t_names, vec!["report.xlsx"]);
        // RecordLength = 0 인 손상 버퍼도 무한 루프 없이 종료
        truncated.truncate(8);
        truncated.extend_from_slice(&[0u8; 64]);
        let (_, z_names) = parse_usn_buffer(&truncated).unwrap();
        assert!(z_names.is_empty());
    }
}

//! WinPE 복원용 순수 로직: diskpart 출력 파싱, 스크립트 생성, 안전 검사. (디스크를 직접 건드리지 않는다)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskEntry {
    pub num: u32,
    pub status: String,
    pub bytes: u64,
}

pub fn parse_size(num: &str, unit: &str) -> Option<u64> {
    let n: u64 = num.parse().ok()?;
    let mul: u64 = match unit.to_ascii_uppercase().as_str() {
        "B" => 1,
        "KB" => 1 << 10,
        "MB" => 1 << 20,
        "GB" => 1 << 30,
        "TB" => 1 << 40,
        _ => return None,
    };
    n.checked_mul(mul)
}

/// `list disk` 출력에서 디스크 목록을 읽는다. (영문·한글 diskpart 및 공백 포함 상태 문자열 지원)
pub fn parse_list_disk(out: &str) -> Vec<DiskEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let t: Vec<&str> = line
            .trim_start_matches([' ', '*'])
            .split_whitespace()
            .collect();
        if t.len() >= 5 && (t[0].eq_ignore_ascii_case("disk") || t[0] == "디스크") {
            if let Ok(num) = t[1].parse::<u32>() {
                for i in 3..t.len().saturating_sub(1) {
                    if let Some(bytes) = parse_size(t[i], t[i + 1]) {
                        v.push(DiskEntry {
                            num,
                            status: t[2..i].join(" "),
                            bytes,
                        });
                        break;
                    }
                }
            }
        }
    }
    v
}

/// `select volume X` + `detail volume` 출력에서 그 볼륨이 놓인 디스크 번호들을 읽는다.
pub fn parse_detail_volume_disks(out: &str) -> Vec<u32> {
    let mut v = Vec::new();
    for line in out.lines() {
        let t: Vec<&str> = line
            .trim_start_matches([' ', '*'])
            .split_whitespace()
            .collect();
        if t.len() >= 2 && (t[0].eq_ignore_ascii_case("disk") || t[0] == "디스크") {
            if let Ok(n) = t[1].parse::<u32>() {
                v.push(n);
            }
        }
    }
    v
}

pub fn disk_selected_ok(
    disk: &DiskEntry,
    image_disks: &[u32],
    image_bytes: u64,
) -> Result<(), String> {
    disk_selected_ok_ext(disk, image_disks, image_bytes, false)
}

pub fn disk_selected_ok_ext(
    disk: &DiskEntry,
    image_disks: &[u32],
    image_bytes: u64,
    allow_remote_image: bool,
) -> Result<(), String> {
    // 이미지가 놓인 디스크를 못 알아냈으면 어느 디스크도 지우지 않는다(이미지 디스크를 지우는 것을 막을 수 없으므로).
    // 단, SMB 등 원격 공유 이미지는 로컬 물리 디스크가 없으므로 allow_remote_image=true 일 때 빈 목록을 허용한다.
    if image_disks.is_empty() && !allow_remote_image {
        return Err(
            "could not determine which disk holds the restore image; refusing to erase any disk"
                .into(),
        );
    }
    if image_disks.contains(&disk.num) {
        return Err(format!(
            "disk {} holds the restore image and cannot be erased",
            disk.num
        ));
    }
    if !(disk.status.eq_ignore_ascii_case("online") || disk.status == "온라인") {
        return Err(format!("disk {} is not online ({})", disk.num, disk.status));
    }
    // EFI 260MB + MSR 16MB + 여유 = 512MB
    let need = image_bytes.saturating_add(512 << 20);
    if disk.bytes < need {
        return Err(format!(
            "disk {} size ({} MB) is smaller than image ({} MB) + boot area",
            disk.num,
            disk.bytes >> 20,
            image_bytes >> 20
        ));
    }
    Ok(())
}

/// 64자리 16진수 AES-256 키 문자열을 파싱한다(공백·하이픈 구분 허용).
pub fn parse_hex_key(input: &str) -> Result<[u8; 32], String> {
    let mut hex = Vec::with_capacity(64);
    for ch in input.chars() {
        if ch.is_whitespace() || ch == '-' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return Err(format!("invalid hex character in key: {ch:?}"));
        }
        hex.push(ch as u8);
    }
    if hex.len() != 64 {
        return Err(format!(
            "invalid key length: expected 64 hex characters, got {}",
            hex.len()
        ));
    }
    let mut key = [0u8; 32];
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| "invalid utf8 in key".to_string())?;
        key[i] =
            u8::from_str_radix(s, 16).map_err(|e| format!("failed to parse hex byte {i}: {e}"))?;
    }
    Ok(key)
}

pub fn confirm_phrase(disk: u32) -> String {
    format!("ERASE DISK {disk}")
}

/// 크기(MB)가 정확히 같은 디스크가 하나뿐일 때만 돌려준다.
pub fn find_disk_by_mb(disks: &[DiskEntry], mb: u64) -> Option<&DiskEntry> {
    let mut it = disks.iter().filter(|d| d.bytes >> 20 == mb);
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

pub fn confirm_phrase_mb(mb: u64) -> String {
    format!("ERASE DISK {mb} MB")
}

/// `detail disk` 출력에서 디스크 고유 ID(GPT GUID 또는 MBR 서명)를 읽는다. (영문·한글 diskpart 지원)
pub fn parse_disk_id(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        let key = k.trim();
        (key.eq_ignore_ascii_case("disk id") || key == "디스크 ID" || key == "디스크 id")
            .then(|| v.trim().trim_matches(['{', '}']).to_uppercase())
            .filter(|s| !s.is_empty())
    })
}

pub fn confirm_phrase_id(id: &str) -> String {
    format!(
        "ERASE DISK ID {}",
        id.trim_matches(['{', '}']).to_uppercase()
    )
}

pub fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

/// UEFI/GPT: EFI(S:) + MSR + NTFS(T:)
pub fn script_gpt(disk: u32, efi: char, os: char) -> String {
    format!(
        "select disk {disk}\nclean\nconvert gpt\ncreate partition efi size=260\nformat quick fs=fat32 label=\"EFI\"\nassign letter={efi}\ncreate partition msr size=16\ncreate partition primary\nformat quick fs=ntfs label=\"KOVA_TARGET\"\nassign letter={os}\nexit\n"
    )
}

/// BIOS/MBR: 시스템 예약(S:, active) + NTFS(T:)
pub fn script_mbr(disk: u32, sys: char, os: char) -> String {
    format!(
        "select disk {disk}\nclean\nconvert mbr\ncreate partition primary size=500\nformat quick fs=ntfs label=\"SYSTEM\"\nassign letter={sys}\nactive\ncreate partition primary\nformat quick fs=ntfs label=\"KOVA_TARGET\"\nassign letter={os}\nexit\n"
    )
}

/// 저장된 파티션 레이아웃(`.qlayout.json`)을 바탕으로 diskpart 스크립트를 생성한다.
/// 레이아웃이 비어 있거나 GPT/MBR이 아니거나 대상 디스크가 레이아웃을 수용할 수 없으면 `None`을 반환한다.
pub fn script_from_layout(
    disk: u32,
    layout: &kova_image::layout::DiskLayout,
    sys: char,
    os: char,
    disk_bytes: u64,
) -> Option<String> {
    if !sys.is_ascii_alphabetic()
        || !os.is_ascii_alphabetic()
        || sys.eq_ignore_ascii_case(&os)
        || layout.partitions.is_empty()
        || disk_bytes == 0
    {
        return None;
    }
    let sys = sys.to_ascii_uppercase();
    let os = os.to_ascii_uppercase();
    let disk_mb = disk_bytes >> 20;

    let os_part = layout
        .partitions
        .iter()
        .find(|p| {
            p.kind.eq_ignore_ascii_case("Basic")
                && p.size_bytes > 0
                && p.drive_letter
                    .is_some_and(|c| c.eq_ignore_ascii_case(&layout.captured_drive))
        })
        .or_else(|| {
            layout
                .partitions
                .iter()
                .filter(|p| p.kind.eq_ignore_ascii_case("Basic") && p.size_bytes > 0)
                .max_by_key(|p| p.size_bytes)
        })?;
    let os_min_mb = os_part.size_bytes.div_ceil(1 << 20).max(1);

    let recovery_mb = layout
        .partitions
        .iter()
        .find(|p| p.kind.eq_ignore_ascii_case("Recovery") && p.size_bytes > 0)
        .map(|p| (p.size_bytes >> 20).clamp(256, 4096));

    const OVERHEAD_MB: u64 = 16;

    if layout.partition_style.eq_ignore_ascii_case("GPT") {
        let efi_mb = layout
            .partitions
            .iter()
            .find(|p| p.kind.eq_ignore_ascii_case("EFI") && p.size_bytes > 0)
            .map(|p| (p.size_bytes >> 20).clamp(100, 1024))
            .unwrap_or(260);
        let msr_mb: u64 = 16;

        let min_without_rec = efi_mb
            .checked_add(msr_mb)?
            .checked_add(os_min_mb)?
            .checked_add(OVERHEAD_MB)?;
        if disk_mb < min_without_rec {
            return None;
        }

        let include_rec = recovery_mb.filter(|&rec_mb| {
            min_without_rec
                .checked_add(rec_mb)
                .and_then(|v| v.checked_add(OVERHEAD_MB))
                .is_some_and(|need| disk_mb >= need)
        });

        let mut s = format!(
            "select disk {disk}\nclean\nconvert gpt\n\
             create partition efi size={efi_mb}\n\
             format quick fs=fat32 label=\"EFI\"\n\
             assign letter={sys}\n\
             create partition msr size={msr_mb}\n"
        );
        if let Some(rec_mb) = include_rec {
            let os_size_mb = disk_mb - efi_mb - msr_mb - rec_mb - OVERHEAD_MB;
            s.push_str(&format!(
                "create partition primary size={os_size_mb}\n\
                 format quick fs=ntfs label=\"KOVA_TARGET\"\n\
                 assign letter={os}\n\
                 create partition primary\n\
                 format quick fs=ntfs label=\"Recovery\"\n\
                 set id=\"de94bba4-06d1-4d40-a16a-bfd50179d6ac\"\n\
                 gpt attributes=0x8000000000000001\n\
                 exit\n"
            ));
        } else {
            s.push_str(&format!(
                "create partition primary\n\
                 format quick fs=ntfs label=\"KOVA_TARGET\"\n\
                 assign letter={os}\n\
                 exit\n"
            ));
        }
        Some(s)
    } else if layout.partition_style.eq_ignore_ascii_case("MBR") {
        let sys_mb = layout
            .partitions
            .iter()
            .find(|p| {
                p.number != os_part.number
                    && !p.kind.eq_ignore_ascii_case("Recovery")
                    && p.size_bytes > 0
                    && p.size_bytes <= (2u64 << 30)
            })
            .map(|p| (p.size_bytes >> 20).clamp(100, 1024))
            .unwrap_or(500);

        let min_without_rec = sys_mb.checked_add(os_min_mb)?.checked_add(OVERHEAD_MB)?;
        if disk_mb < min_without_rec {
            return None;
        }

        let include_rec = recovery_mb.filter(|&rec_mb| {
            min_without_rec
                .checked_add(rec_mb)
                .and_then(|v| v.checked_add(OVERHEAD_MB))
                .is_some_and(|need| disk_mb >= need)
        });

        let mut s = format!(
            "select disk {disk}\nclean\nconvert mbr\n\
             create partition primary size={sys_mb}\n\
             format quick fs=ntfs label=\"SYSTEM\"\n\
             assign letter={sys}\n\
             active\n"
        );
        if let Some(rec_mb) = include_rec {
            let os_size_mb = disk_mb - sys_mb - rec_mb - OVERHEAD_MB;
            s.push_str(&format!(
                "create partition primary size={os_size_mb}\n\
                 format quick fs=ntfs label=\"KOVA_TARGET\"\n\
                 assign letter={os}\n\
                 create partition primary\n\
                 format quick fs=ntfs label=\"Recovery\"\n\
                 set id=27\n\
                 exit\n"
            ));
        } else {
            s.push_str(&format!(
                "create partition primary\n\
                 format quick fs=ntfs label=\"KOVA_TARGET\"\n\
                 assign letter={os}\n\
                 exit\n"
            ));
        }
        Some(s)
    } else {
        None
    }
}

pub fn script_detail_volume(letter: char) -> String {
    format!("select volume {letter}\ndetail volume\nexit\n")
}

/// 복원 후 NTFS 를 파티션 끝까지 넓힌다(이미지가 파티션보다 작을 때). 실패해도 무방.
pub fn script_extend(os: char) -> String {
    format!("select volume {os}\nextend filesystem\nexit\n")
}

pub fn bcdboot_args(os: char, sys: char, uefi: bool) -> Vec<String> {
    vec![
        format!("{os}:\\Windows"),
        "/s".into(),
        format!("{sys}:"),
        "/f".into(),
        if uefi { "UEFI".into() } else { "BIOS".into() },
    ]
}

/// 한 번 시도한 자동 모드 파일을 바꿔 둘 이름(재부팅마다 디스크를 다시 지우지 않게).
pub const AUTO_DONE_NAME: &str = "KOVA_AUTO.done.txt";

/// 자동 모드의 대상 디스크: 디스크 고유 ID(`disk_id=`)만 받는다. 번호(`disk=`)·크기(`disk_mb=`)는
/// 디스크 순서·구성이 바뀌면 다른 디스크를 지울 수 있어 거부한다.
pub fn auto_disk_id(m: &std::collections::HashMap<String, String>) -> Result<String, String> {
    let id = m
        .get("disk_id")
        .map(|s| s.trim().trim_matches(['{', '}']).to_uppercase())
        .unwrap_or_default();
    if id.is_empty() {
        return Err(if m.contains_key("disk") || m.contains_key("disk_mb") {
            "auto mode accepts only disk_id=<unique disk ID>; disk= and disk_mb= are refused".into()
        } else {
            "auto mode needs disk_id=<unique disk ID> (see diskpart 'detail disk')".into()
        });
    }
    if !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(format!("auto mode disk_id is not a disk ID: {id}"));
    }
    Ok(id)
}

/// 자동 모드 파일(KOVA_AUTO.txt)의 `key=value` 줄을 읽는다.
pub fn parse_auto(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim().trim_start_matches('\u{feff}');
            if l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

/// dism.exe 명령 인자 목록 생성
#[allow(dead_code)]
pub fn dism_export_driver_args(dest: &std::path::Path) -> Vec<String> {
    vec![
        "/online".into(),
        "/export-driver".into(),
        format!("/destination:{}", dest.display()),
    ]
}

/// 오프라인 복원된 Windows 볼륨에 서드파티 드라이버(.inf)를 주입하기 위한 dism.exe 인자 생성
pub fn dism_inject_offline_args(os_letter: char, drivers_dir: &std::path::Path) -> Vec<String> {
    let letter = os_letter.to_ascii_uppercase();
    vec![
        format!("/Image:{letter}:\\"),
        "/Add-Driver".into(),
        format!("/Driver:{}", drivers_dir.display()),
        "/Recurse".into(),
        "/ForceUnsigned".into(),
    ]
}

/// 기본 드라이버 자동 수집 대상 폴더 (%ProgramData%\Kova2\drivers)
#[allow(dead_code)]
pub fn default_driver_export_dir() -> std::path::PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\ProgramData"));
    base.join("Kova2").join("drivers")
}

/// 수집된 드라이버 폴더에 .inf 파일이 존재하는지 검사하여 유효한 드라이버 경로를 반환한다.
#[allow(dead_code)]
pub fn find_collected_drivers(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    if !dir.is_dir() {
        return None;
    }
    // 폴더 내 직접 또는 1단계 하위 폴더에 .inf 파일이 있는지 확인
    let has_inf = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .any(|entry| {
            let p = entry.path();
            if p.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("inf"))
            {
                return true;
            }
            if p.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&p) {
                    return sub.filter_map(|e| e.ok()).any(|se| {
                        se.path()
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("inf"))
                    });
                }
            }
            false
        });

    if has_inf {
        Some(dir.to_path_buf())
    } else {
        None
    }
}

/// dism.exe /online /export-driver /destination:<폴더> 명령으로
/// 현재 PC의 서드파티(NVMe, 네트워크 등) 드라이버를 자동 덤프한다.
#[allow(dead_code)]
#[cfg(windows)]
pub fn export_drivers(dest_dir: &std::path::Path) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    std::fs::create_dir_all(dest_dir).map_err(|e| format!("폴더 생성 실패: {e}"))?;

    let dest_str = dest_dir.to_string_lossy();
    let out = std::process::Command::new("dism.exe")
        .args([
            "/online",
            "/export-driver",
            &format!("/destination:{dest_str}"),
        ])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("dism.exe 실행 실패: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        let msg = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        if msg.contains("740") || msg.contains("권한") || msg.contains("administrative") {
            return Err("드라이버 수집 실패: 관리자 권한으로 실행해야 합니다".into());
        }
        return Err(format!(
            "dism 드라이버 수집 실패 (종료 코드 {:?}): {}",
            out.status.code(),
            msg
        ));
    }

    Ok(format!("드라이버 자동 수집 완료: {}", dest_dir.display()))
}

#[cfg(not(windows))]
pub fn export_drivers(dest_dir: &std::path::Path) -> Result<String, String> {
    std::fs::create_dir_all(dest_dir).map_err(|e| format!("폴더 생성 실패: {e}"))?;
    Ok(format!(
        "(모의) 드라이버 자동 수집 완료: {}",
        dest_dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "\n  Disk ###  Status         Size     Free     Dyn  Gpt\n  --------  -------------  -------  -------  ---  ---\n  Disk 0    Online          931 GB  1024 KB        *\n* Disk 1    Online           60 GB      0 B        *\n  Disk 2    Offline         500 MB      0 B\n";

    #[test]
    fn list_disk() {
        let d = parse_list_disk(LIST);
        assert_eq!(d.len(), 3);
        assert_eq!(
            d[1],
            DiskEntry {
                num: 1,
                status: "Online".into(),
                bytes: 60 << 30
            }
        );
        assert_eq!(d[2].bytes, 500 << 20);
    }

    #[test]
    fn detail_volume() {
        let o = "Volume 3\n\n  Disk ###  Status   Size  Free\n  --------  -------\n* Disk 2    Online\n";
        assert_eq!(parse_detail_volume_disks(o), vec![2]);
        assert!(parse_detail_volume_disks("Disk ###").is_empty());
    }

    #[test]
    fn disk_checks() {
        let d = DiskEntry {
            num: 1,
            status: "Online".into(),
            bytes: 60 << 30,
        };
        assert!(disk_selected_ok(&d, &[0], 20 << 30).is_ok());
        assert!(disk_selected_ok(&d, &[1], 20 << 30).is_err());
        assert!(disk_selected_ok(&d, &[], 60 << 30).is_err());
        let off = DiskEntry {
            status: "Offline".into(),
            ..d.clone()
        };
        assert!(disk_selected_ok(&off, &[], 1 << 30).is_err());
        // 이미지 디스크를 못 알아내면(빈 목록) 정상 디스크라도 거부한다
        assert!(disk_selected_ok(&d, &[], 20 << 30)
            .unwrap_err()
            .contains("could not determine"));
    }

    #[test]
    fn auto_mode_accepts_only_disk_id() {
        let ok = parse_auto("image=a.qblk\ndisk_id={919f469d-68f8-4433-9d35-34531b929926}\n");
        assert_eq!(
            auto_disk_id(&ok).as_deref(),
            Ok("919F469D-68F8-4433-9D35-34531B929926")
        );
        assert_eq!(
            auto_disk_id(&parse_auto("disk_id=1A2B3C4D")).as_deref(),
            Ok("1A2B3C4D")
        );
        for bad in [
            "disk=1\nconfirm=ERASE DISK 1",
            "disk_mb=61440\nconfirm=ERASE DISK 61440 MB",
            "image=a.qblk",
            "disk_id=",
            "disk_id=1 or 2",
        ] {
            assert!(auto_disk_id(&parse_auto(bad)).is_err(), "{bad}");
        }
        assert!(auto_disk_id(&parse_auto("disk=1"))
            .unwrap_err()
            .contains("refused"));
    }

    #[test]
    fn scripts_and_phrase() {
        let s = script_gpt(1, 'S', 'T');
        assert!(s.contains("select disk 1\nclean") && s.contains("assign letter=T"));
        assert!(script_mbr(1, 'S', 'T').contains("active"));
        assert_eq!(norm("  erase   disk 1 "), confirm_phrase(1));
        assert_eq!(
            bcdboot_args('T', 'S', true),
            vec!["T:\\Windows", "/s", "S:", "/f", "UEFI"]
        );
    }

    #[test]
    fn disk_by_mb() {
        let d = parse_list_disk(LIST);
        assert_eq!(find_disk_by_mb(&d, 60 << 10).map(|x| x.num), Some(1));
        assert!(find_disk_by_mb(&d, 123).is_none());
        let mut two = d.clone();
        two.push(DiskEntry {
            num: 9,
            status: "Online".into(),
            bytes: 60 << 30,
        });
        assert!(find_disk_by_mb(&two, 60 << 10).is_none());
        assert_eq!(norm("erase disk 61440 mb"), confirm_phrase_mb(61440));
    }

    #[test]
    fn disk_id() {
        let o = "Netac NVMe SSD 1TB
Disk ID: {919F469D-68F8-4433-9D35-34531B929926}
Type   : NVMe
";
        assert_eq!(
            parse_disk_id(o).as_deref(),
            Some("919F469D-68F8-4433-9D35-34531B929926")
        );
        assert_eq!(parse_disk_id("Type : NVMe"), None);
        assert_eq!(
            norm("erase disk id 919f469d-68f8-4433-9d35-34531b929926"),
            confirm_phrase_id("{919F469D-68F8-4433-9D35-34531B929926}")
        );
    }

    #[test]
    fn auto_file() {
        let m = parse_auto("\u{feff}image=a.qblk\n# c\ndisk = 1\nconfirm=ERASE DISK 1\n");
        assert_eq!(m["image"], "a.qblk");
        assert_eq!(m["disk"], "1");
        assert_eq!(m["confirm"], "ERASE DISK 1");
    }

    #[test]
    fn test_dism_export_driver_args() {
        let p = std::path::Path::new("C:\\TestDrivers");
        let args = dism_export_driver_args(p);
        assert_eq!(args[0], "/online");
        assert_eq!(args[1], "/export-driver");
        assert!(args[2].contains("C:\\TestDrivers"));
    }

    #[test]
    fn test_default_driver_export_dir() {
        let d = default_driver_export_dir();
        assert!(d.ends_with("Kova2\\drivers") || d.ends_with("Kova2/drivers"));
    }

    #[test]
    fn test_find_collected_drivers() {
        let tmp = tempfile::tempdir().unwrap();
        // 비어있는 폴더 -> None
        assert_eq!(find_collected_drivers(tmp.path()), None);

        // 하위 폴더에 inf 파일 생성 -> Some
        let sub = tmp.path().join("nvme_driver");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("nvme.inf"), "mock inf").unwrap();

        assert_eq!(
            find_collected_drivers(tmp.path()),
            Some(tmp.path().to_path_buf())
        );
    }

    #[test]
    fn korean_and_multiword_diskpart_outputs_are_parsed() {
        let ko_list = "\n  디스크 ###  상태           크기     사용 가능  Dyn  Gpt\n  ----------  -------------  -------  ---------  ---  ---\n  디스크 0    온라인          931 GB  1024 KB        *\n* 디스크 1    오프라인         60 GB      0 B        *\n  디스크 2    미디어 없음         0 B      0 B\n";
        let d = parse_list_disk(ko_list);
        assert_eq!(d.len(), 3);
        assert_eq!(
            d[0],
            DiskEntry {
                num: 0,
                status: "온라인".into(),
                bytes: 931 << 30
            }
        );
        assert_eq!(d[1].status, "오프라인");
        assert_eq!(d[2].status, "미디어 없음");
        assert_eq!(d[2].bytes, 0);

        let en_multi = "\n  Disk 0    Online (Errors)  500 GB      0 B\n  Disk 1    No Media           0 B      0 B\n";
        let dm = parse_list_disk(en_multi);
        assert_eq!(dm.len(), 2);
        assert_eq!(dm[0].status, "Online (Errors)");
        assert_eq!(dm[0].bytes, 500 << 30);
        assert_eq!(dm[1].status, "No Media");
        assert_eq!(dm[1].bytes, 0);

        let ko_vol =
            "볼륨 3\n\n  디스크 ###  상태     크기\n  ----------  -------\n* 디스크 2    온라인\n";
        assert_eq!(parse_detail_volume_disks(ko_vol), vec![2]);

        let ko_id =
            "Samsung SSD 980\n디스크 ID: {919F469D-68F8-4433-9D35-34531B929926}\n유형   : NVMe\n";
        assert_eq!(
            parse_disk_id(ko_id).as_deref(),
            Some("919F469D-68F8-4433-9D35-34531B929926")
        );

        assert!(disk_selected_ok(&d[0], &[1], 100 << 30).is_ok());
        assert!(disk_selected_ok(&d[1], &[0], 1 << 30).is_err());
        assert!(disk_selected_ok(&dm[0], &[1], 1 << 30).is_err());
        assert_eq!(parse_size("99999999999999999", "TB"), None);
        assert!(disk_selected_ok(&d[0], &[1], u64::MAX).is_err());
    }

    #[test]
    fn test_parse_hex_key() {
        let raw = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let expected: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(parse_hex_key(raw), Ok(expected));

        let formatted =
            " 0001-0203 0405-0607\t0809-0A0B 0C0D-0E0F\n1011-1213 1415-1617 1819-1A1B 1C1D-1E1F ";
        assert_eq!(parse_hex_key(formatted), Ok(expected));

        // 너무 짧거나 긴 키
        assert!(parse_hex_key("").is_err());
        assert!(parse_hex_key("00112233").is_err());
        assert!(parse_hex_key(&format!("{raw}00")).is_err());
        // 16진수가 아닌 문자 포함
        let bad_char = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1z";
        assert!(parse_hex_key(bad_char).is_err());
    }

    #[test]
    fn test_script_from_layout() {
        use kova_image::layout::{DiskLayout, PartitionInfo, LAYOUT_VERSION};

        let gpt_layout = DiskLayout {
            version: LAYOUT_VERSION,
            disk_number: 0,
            partition_style: "GPT".into(),
            disk_size_bytes: 256 << 30,
            captured_drive: 'C',
            partitions: vec![
                PartitionInfo {
                    number: 1,
                    offset_bytes: 1 << 20,
                    size_bytes: 200 << 20,
                    style: "GPT".into(),
                    kind: "EFI".into(),
                    drive_letter: None,
                    label: "SYSTEM".into(),
                    file_system: "FAT32".into(),
                },
                PartitionInfo {
                    number: 2,
                    offset_bytes: 201 << 20,
                    size_bytes: 16 << 20,
                    style: "GPT".into(),
                    kind: "MSR".into(),
                    drive_letter: None,
                    label: String::new(),
                    file_system: String::new(),
                },
                PartitionInfo {
                    number: 3,
                    offset_bytes: 217 << 20,
                    size_bytes: 100 << 30,
                    style: "GPT".into(),
                    kind: "Basic".into(),
                    drive_letter: Some('C'),
                    label: "Windows".into(),
                    file_system: "NTFS".into(),
                },
                PartitionInfo {
                    number: 4,
                    offset_bytes: (100 << 30) + (217 << 20),
                    size_bytes: 900 << 20,
                    style: "GPT".into(),
                    kind: "Recovery".into(),
                    drive_letter: None,
                    label: "Recovery".into(),
                    file_system: "NTFS".into(),
                },
            ],
        };

        // GPT + EFI + MSR + Basic + Recovery (충분한 디스크 크기)
        let s = script_from_layout(1, &gpt_layout, 's', 't', 256 << 30)
            .expect("GPT layout should produce script");
        assert!(s.contains("select disk 1\nclean\nconvert gpt"));
        assert!(s.contains("create partition efi size=200"));
        assert!(s.contains("assign letter=S"));
        assert!(s.contains("create partition msr size=16"));
        assert!(s.contains("assign letter=T"));
        assert!(s.contains("set id=\"de94bba4-06d1-4d40-a16a-bfd50179d6ac\""));
        assert!(s.contains("gpt attributes=0x8000000000000001"));

        // 대상 디스크가 OS 파티션보다 작으면 None (oversized layout fallback)
        assert_eq!(script_from_layout(1, &gpt_layout, 'S', 'T', 50 << 30), None);

        // Recovery 공간만 빠듯한 경우 Recovery 없이 OS 파티션만 생성
        let tight_bytes = (100 << 30) + (300 << 20);
        let s_tight = script_from_layout(1, &gpt_layout, 'S', 'T', tight_bytes)
            .expect("tight disk should still fit without recovery");
        assert!(!s_tight.contains("de94bba4-06d1-4d40-a16a-bfd50179d6ac"));
        assert!(s_tight.contains("assign letter=T"));

        // MBR 레이아웃
        let mbr_layout = DiskLayout {
            version: LAYOUT_VERSION,
            disk_number: 0,
            partition_style: "MBR".into(),
            disk_size_bytes: 120 << 30,
            captured_drive: 'C',
            partitions: vec![
                PartitionInfo {
                    number: 1,
                    offset_bytes: 1 << 20,
                    size_bytes: 350 << 20,
                    style: "MBR".into(),
                    kind: "Basic".into(),
                    drive_letter: None,
                    label: "System Reserved".into(),
                    file_system: "NTFS".into(),
                },
                PartitionInfo {
                    number: 2,
                    offset_bytes: 351 << 20,
                    size_bytes: 80 << 30,
                    style: "MBR".into(),
                    kind: "Basic".into(),
                    drive_letter: Some('C'),
                    label: "Windows".into(),
                    file_system: "NTFS".into(),
                },
            ],
        };
        let sm = script_from_layout(2, &mbr_layout, 'S', 'T', 120 << 30)
            .expect("MBR layout should produce script");
        assert!(sm.contains("select disk 2\nclean\nconvert mbr"));
        assert!(sm.contains("create partition primary size=350"));
        assert!(sm.contains("assign letter=S\nactive"));
        assert!(sm.contains("assign letter=T"));
        assert_eq!(script_from_layout(2, &mbr_layout, 'S', 'T', 40 << 30), None);

        // 알 수 없는 스타일은 None
        let mut bad = mbr_layout.clone();
        bad.partition_style = "RAW".into();
        assert_eq!(script_from_layout(2, &bad, 'S', 'T', 120 << 30), None);
    }

    #[test]
    fn test_disk_selected_ok_ext() {
        let d = DiskEntry {
            num: 0,
            status: "Online".into(),
            bytes: 100 << 30,
        };
        // 로컬 이미지(allow_remote_image=false)는 image_disks가 비어 있으면 거부
        assert!(disk_selected_ok_ext(&d, &[], 20 << 30, false).is_err());
        // 원격 SMB 이미지(allow_remote_image=true)는 image_disks가 비어 있어도 허용
        assert!(disk_selected_ok_ext(&d, &[], 20 << 30, true).is_ok());
        // 원격 이미지라도 오프라인/용량 부족 디스크는 여전히 거부
        let off = DiskEntry {
            status: "Offline".into(),
            ..d.clone()
        };
        assert!(disk_selected_ok_ext(&off, &[], 20 << 30, true).is_err());
        assert!(disk_selected_ok_ext(&d, &[], 100 << 30, true).is_err());
    }

    #[test]
    fn test_dism_inject_offline_args() {
        let dir = std::path::Path::new("D:\\KovaDrivers");
        assert_eq!(
            dism_inject_offline_args('t', dir),
            vec![
                "/Image:T:\\",
                "/Add-Driver",
                "/Driver:D:\\KovaDrivers",
                "/Recurse",
                "/ForceUnsigned",
            ]
        );
    }
}

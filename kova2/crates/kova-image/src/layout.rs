//! 디스크·파티션 레이아웃 사이드카(`<image>.qlayout.json`).
//! WinPE 베어메탈 복원 시 단일 NTFS 파티션으로 고정하지 않고 원래의 GPT/MBR 다중 파티션(EFI/MSR/Basic/Recovery)을
//! 그대로 재구성할 수 있도록 백업 시점의 디스크 구조를 JSON 사이드카로 저장한다.
use crate::qblk::QblkError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const LAYOUT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartitionInfo {
    pub number: u32,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub style: String, // "GPT" | "MBR"
    pub kind: String,  // "EFI" | "MSR" | "Basic" | "Recovery" | "Other"
    pub drive_letter: Option<char>,
    pub label: String,
    pub file_system: String, // "NTFS" | "FAT32" | ""
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskLayout {
    pub version: u32,
    pub disk_number: u32,
    pub partition_style: String, // "GPT" | "MBR"
    pub disk_size_bytes: u64,
    pub captured_drive: char,
    pub partitions: Vec<PartitionInfo>,
}

/// 이미지 경로에 대응하는 레이아웃 사이드카 경로(`<image>.qlayout.json`).
pub fn layout_path_for(image: &Path) -> PathBuf {
    PathBuf::from(format!("{}.qlayout.json", image.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), QblkError> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = PathBuf::from(format!(
        "{}.{}.{}.tmp",
        path.display(),
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(QblkError::from)
}

/// 디스크 레이아웃 사이드카를 원자적으로 저장한다(`.tmp` → `sync_all` → `rename`).
pub fn save_layout(image: &Path, layout: &DiskLayout) -> Result<(), QblkError> {
    let json = serde_json::to_string_pretty(layout)
        .map_err(|e| QblkError::Io(io::Error::other(e.to_string())))?;
    write_atomic(&layout_path_for(image), json.as_bytes())
}

/// 디스크 레이아웃 사이드카를 읽는다. 파일이 없으면 `Ok(None)`.
pub fn load_layout(image: &Path) -> Result<Option<DiskLayout>, QblkError> {
    let path = layout_path_for(image);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(QblkError::from(e)),
    };
    let layout =
        serde_json::from_str(&raw).map_err(|e| QblkError::Io(io::Error::other(e.to_string())))?;
    Ok(Some(layout))
}

fn normalize_style(val: Option<&Value>) -> String {
    match val {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(1) => "MBR".to_string(),
            _ => "GPT".to_string(),
        },
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.eq_ignore_ascii_case("mbr") {
                "MBR".to_string()
            } else if t.eq_ignore_ascii_case("gpt") || t.is_empty() {
                "GPT".to_string()
            } else {
                t.to_ascii_uppercase()
            }
        }
        _ => "GPT".to_string(),
    }
}

fn normalize_kind(type_str: &str, gpt_type: &str, mbr_type: Option<u64>) -> String {
    let guid = gpt_type
        .trim()
        .trim_matches(['{', '}'])
        .to_ascii_lowercase();
    match guid.as_str() {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => return "EFI".to_string(),
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => return "MSR".to_string(),
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => return "Basic".to_string(),
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => return "Recovery".to_string(),
        _ => {}
    }
    let ty = type_str.trim().to_ascii_lowercase();
    match ty.as_str() {
        "system" | "efi" | "efi system" => return "EFI".to_string(),
        "reserved" | "msr" | "microsoft reserved" => return "MSR".to_string(),
        "basic" | "ifs" | "fat32" | "xint13" | "fat16" | "primary" => return "Basic".to_string(),
        "recovery" => return "Recovery".to_string(),
        _ => {}
    }
    match mbr_type {
        Some(0xEF) => "EFI".to_string(),
        Some(0x27) => "Recovery".to_string(),
        Some(0x06 | 0x07 | 0x0B | 0x0C | 0x0E) => "Basic".to_string(),
        _ => "Other".to_string(),
    }
}

fn parse_drive_letter(val: Option<&Value>) -> Option<char> {
    match val {
        Some(Value::String(s)) => s
            .trim()
            .chars()
            .next()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_uppercase()),
        Some(Value::Number(n)) => {
            let code = n.as_u64()?;
            if code <= 0x7F {
                let c = code as u8 as char;
                c.is_ascii_alphabetic().then(|| c.to_ascii_uppercase())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn normalize_fs(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("unknown") {
        String::new()
    } else {
        t.to_ascii_uppercase()
    }
}

fn value_u64(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn value_str(v: Option<&Value>) -> &str {
    match v {
        Some(Value::String(s)) => s.as_str(),
        _ => "",
    }
}

fn parse_partition_entry(obj: &Value, default_style: &str) -> Result<PartitionInfo, String> {
    let number = value_u64(obj.get("PartitionNumber").or_else(|| obj.get("number")))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| "파티션 번호(PartitionNumber)가 없거나 올바르지 않음".to_string())?;
    let offset_bytes = value_u64(obj.get("Offset").or_else(|| obj.get("offset_bytes")))
        .ok_or_else(|| format!("파티션 {number} 오프셋(Offset) 누락"))?;
    let size_bytes = value_u64(obj.get("Size").or_else(|| obj.get("size_bytes")))
        .ok_or_else(|| format!("파티션 {number} 크기(Size) 누락"))?;
    let gpt_type = value_str(obj.get("GptType"));
    let mbr_type = value_u64(obj.get("MbrType"));
    let type_str = value_str(obj.get("Type").or_else(|| obj.get("kind")));
    let style = if let Some(sv) = obj.get("PartitionStyle").or_else(|| obj.get("style")) {
        normalize_style(Some(sv))
    } else if !gpt_type.trim().is_empty() {
        "GPT".to_string()
    } else if mbr_type.is_some() {
        "MBR".to_string()
    } else {
        default_style.to_string()
    };
    let kind = normalize_kind(type_str, gpt_type, mbr_type);
    let drive_letter =
        parse_drive_letter(obj.get("DriveLetter").or_else(|| obj.get("drive_letter")));
    let label = value_str(obj.get("FileSystemLabel").or_else(|| obj.get("label"))).to_string();
    let file_system = normalize_fs(value_str(
        obj.get("FileSystem")
            .or_else(|| obj.get("FileSystemType"))
            .or_else(|| obj.get("file_system")),
    ));
    Ok(PartitionInfo {
        number,
        offset_bytes,
        size_bytes,
        style,
        kind,
        drive_letter,
        label,
        file_system,
    })
}

/// PowerShell `Get-Disk`/`Get-Partition`/`Get-Volume` JSON 출력을 `DiskLayout`으로 파싱한다.
/// 통합 JSON 객체(`{ DiskNumber, PartitionStyle, DiskSize, Partitions }`)와
/// 단순 `Get-Partition | ConvertTo-Json` 배열·단일 객체 출력 모두를 처리한다.
pub fn parse_disk_layout_json(json: &str, captured_drive: char) -> Result<DiskLayout, String> {
    if !captured_drive.is_ascii_alphabetic() {
        return Err(format!("드라이브 문자가 올바르지 않음: {captured_drive:?}"));
    }
    let captured_drive = captured_drive.to_ascii_uppercase();
    let root: Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("파티션 JSON 파싱 실패: {e}"))?;

    // 1) 통합 객체 형식: { DiskNumber, PartitionStyle, DiskSize, Partitions: [...] | {...} }
    if let Some(obj) = root.as_object() {
        if obj.contains_key("Partitions") || obj.contains_key("DiskSize") {
            let disk_number = value_u64(obj.get("DiskNumber"))
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| "DiskNumber 필드 누락".to_string())?;
            let partition_style = normalize_style(obj.get("PartitionStyle"));
            let disk_size_bytes =
                value_u64(obj.get("DiskSize")).ok_or_else(|| "DiskSize 필드 누락".to_string())?;
            let raw_parts: Vec<&Value> = match obj.get("Partitions") {
                Some(Value::Array(arr)) => arr.iter().collect(),
                Some(v @ Value::Object(_)) => vec![v],
                Some(Value::Null) | None => vec![],
                _ => return Err("Partitions 필드 형식이 올바르지 않음".to_string()),
            };
            let mut partitions = Vec::with_capacity(raw_parts.len());
            for p in raw_parts {
                partitions.push(parse_partition_entry(p, &partition_style)?);
            }
            partitions.sort_by_key(|p| p.number);
            return Ok(DiskLayout {
                version: LAYOUT_VERSION,
                disk_number,
                partition_style,
                disk_size_bytes,
                captured_drive,
                partitions,
            });
        }
    }

    // 2) 단순 `Get-Partition | ConvertTo-Json` 배열 또는 단일 파티션 객체
    let raw_parts: Vec<&Value> = match &root {
        Value::Array(arr) => arr.iter().collect(),
        v @ Value::Object(_) => vec![v],
        _ => return Err("예상하지 못한 파티션 JSON 루트 형식".to_string()),
    };
    if raw_parts.is_empty() {
        return Err("파티션 목록이 비어 있음".to_string());
    }
    let disk_number = value_u64(raw_parts[0].get("DiskNumber"))
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    let has_gpt = raw_parts
        .iter()
        .any(|p| !value_str(p.get("GptType")).trim().is_empty());
    let has_mbr = raw_parts
        .iter()
        .any(|p| value_u64(p.get("MbrType")).is_some());
    let inferred_style = if !has_gpt && has_mbr {
        "MBR".to_string()
    } else {
        "GPT".to_string()
    };
    let mut partitions = Vec::with_capacity(raw_parts.len());
    for p in raw_parts {
        partitions.push(parse_partition_entry(p, &inferred_style)?);
    }
    partitions.sort_by_key(|p| p.number);
    let disk_size_bytes = partitions
        .iter()
        .map(|p| p.offset_bytes.saturating_add(p.size_bytes))
        .max()
        .unwrap_or(0);
    Ok(DiskLayout {
        version: LAYOUT_VERSION,
        disk_number,
        partition_style: inferred_style,
        disk_size_bytes,
        captured_drive,
        partitions,
    })
}

/// 지정한 드라이브 문자가 속한 물리 디스크의 전체 파티션 레이아웃을 조회한다.
/// Windows에서는 PowerShell `Get-Partition`/`Get-Disk`/`Get-Volume`을 무창(`CREATE_NO_WINDOW`)으로 호출한다.
#[cfg(windows)]
pub fn capture_disk_layout(drive: char) -> Result<DiskLayout, String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    if !drive.is_ascii_alphabetic() {
        return Err(format!("드라이브 문자가 올바르지 않음: {drive:?}"));
    }
    let letter = drive.to_ascii_uppercase();
    let script = format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); \
         $p = Get-Partition -DriveLetter '{letter}' -ErrorAction Stop | Select-Object -First 1; \
         $d = Get-Disk -Number $p.DiskNumber -ErrorAction Stop; \
         $parts = @(Get-Partition -DiskNumber $d.Number -ErrorAction Stop | Sort-Object PartitionNumber | ForEach-Object {{ \
             $v = $null; \
             try {{ $v = $_ | Get-Volume -ErrorAction SilentlyContinue }} catch {{}}; \
             $dl = if ($_.DriveLetter -and [int][char]$_.DriveLetter -ne 0) {{ [string]$_.DriveLetter }} else {{ $null }}; \
             [PSCustomObject]@{{ \
                 PartitionNumber = [uint32]$_.PartitionNumber; \
                 Offset = [uint64]$_.Offset; \
                 Size = [uint64]$_.Size; \
                 Type = [string]$_.Type; \
                 GptType = if ($_.GptType) {{ [string]$_.GptType }} else {{ '' }}; \
                 MbrType = if ($null -ne $_.MbrType) {{ [int]$_.MbrType }} else {{ $null }}; \
                 DriveLetter = $dl; \
                 FileSystemLabel = if ($v -and $v.FileSystemLabel) {{ [string]$v.FileSystemLabel }} else {{ '' }}; \
                 FileSystem = if ($v -and $v.FileSystem) {{ [string]$v.FileSystem }} else {{ '' }} \
             }} \
         }}); \
         [PSCustomObject]@{{ \
             DiskNumber = [uint32]$d.Number; \
             PartitionStyle = [string]$d.PartitionStyle; \
             DiskSize = [uint64]$d.Size; \
             Partitions = $parts \
         }} | ConvertTo-Json -Depth 4 -Compress"
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("PowerShell 실행 실패: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "디스크 레이아웃 조회 실패: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_disk_layout_json(&stdout, letter)
}

#[cfg(not(windows))]
pub fn capture_disk_layout(drive: char) -> Result<DiskLayout, String> {
    let _ = drive;
    Err("디스크 파티션 레이아웃 조회는 Windows에서만 지원됩니다".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_layout_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("C_20261124.qblk");
        assert_eq!(
            layout_path_for(&img),
            dir.path().join("C_20261124.qblk.qlayout.json")
        );
        assert_eq!(load_layout(&img).unwrap(), None);

        let layout = DiskLayout {
            version: LAYOUT_VERSION,
            disk_number: 0,
            partition_style: "GPT".to_string(),
            disk_size_bytes: 512_110_190_592,
            captured_drive: 'C',
            partitions: vec![
                PartitionInfo {
                    number: 1,
                    offset_bytes: 1_048_576,
                    size_bytes: 104_857_600,
                    style: "GPT".to_string(),
                    kind: "EFI".to_string(),
                    drive_letter: None,
                    label: "SYSTEM".to_string(),
                    file_system: "FAT32".to_string(),
                },
                PartitionInfo {
                    number: 2,
                    offset_bytes: 105_906_176,
                    size_bytes: 16_777_216,
                    style: "GPT".to_string(),
                    kind: "MSR".to_string(),
                    drive_letter: None,
                    label: String::new(),
                    file_system: String::new(),
                },
                PartitionInfo {
                    number: 3,
                    offset_bytes: 122_683_392,
                    size_bytes: 511_000_000_000,
                    style: "GPT".to_string(),
                    kind: "Basic".to_string(),
                    drive_letter: Some('C'),
                    label: "Windows".to_string(),
                    file_system: "NTFS".to_string(),
                },
                PartitionInfo {
                    number: 4,
                    offset_bytes: 511_122_683_392,
                    size_bytes: 987_000_000,
                    style: "GPT".to_string(),
                    kind: "Recovery".to_string(),
                    drive_letter: None,
                    label: "복구".to_string(),
                    file_system: "NTFS".to_string(),
                },
            ],
        };

        save_layout(&img, &layout).unwrap();
        assert!(layout_path_for(&img).is_file());
        let loaded = load_layout(&img).unwrap().expect("layout must exist");
        assert_eq!(loaded, layout);
    }

    #[test]
    fn parses_combined_powershell_gpt_json() {
        let sample = r#"{
            "DiskNumber": 0,
            "PartitionStyle": "GPT",
            "DiskSize": 256060514304,
            "Partitions": [
                {
                    "PartitionNumber": 1,
                    "Offset": 1048576,
                    "Size": 104857600,
                    "Type": "System",
                    "GptType": "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}",
                    "MbrType": null,
                    "DriveLetter": null,
                    "FileSystemLabel": "ESP",
                    "FileSystem": "FAT32"
                },
                {
                    "PartitionNumber": 2,
                    "Offset": 105906176,
                    "Size": 16777216,
                    "Type": "Reserved",
                    "GptType": "{e3c9e316-0b5c-4db8-817d-f92df00215ae}",
                    "MbrType": null,
                    "DriveLetter": "\u0000",
                    "FileSystemLabel": "",
                    "FileSystem": "Unknown"
                },
                {
                    "PartitionNumber": 3,
                    "Offset": 122683392,
                    "Size": 255000000000,
                    "Type": "Basic",
                    "GptType": "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}",
                    "MbrType": null,
                    "DriveLetter": "c",
                    "FileSystemLabel": "시스템",
                    "FileSystem": "NTFS"
                },
                {
                    "PartitionNumber": 4,
                    "Offset": 255122683392,
                    "Size": 937000000,
                    "Type": "Recovery",
                    "GptType": "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}",
                    "MbrType": null,
                    "DriveLetter": 0,
                    "FileSystemLabel": "",
                    "FileSystem": "NTFS"
                }
            ]
        }"#;
        let layout = parse_disk_layout_json(sample, 'c').unwrap();
        assert_eq!(layout.version, LAYOUT_VERSION);
        assert_eq!(layout.disk_number, 0);
        assert_eq!(layout.partition_style, "GPT");
        assert_eq!(layout.disk_size_bytes, 256_060_514_304);
        assert_eq!(layout.captured_drive, 'C');
        assert_eq!(layout.partitions.len(), 4);
        assert_eq!(layout.partitions[0].kind, "EFI");
        assert_eq!(layout.partitions[0].file_system, "FAT32");
        assert_eq!(layout.partitions[0].drive_letter, None);
        assert_eq!(layout.partitions[1].kind, "MSR");
        assert_eq!(layout.partitions[1].file_system, "");
        assert_eq!(layout.partitions[1].drive_letter, None);
        assert_eq!(layout.partitions[2].kind, "Basic");
        assert_eq!(layout.partitions[2].drive_letter, Some('C'));
        assert_eq!(layout.partitions[2].label, "시스템");
        assert_eq!(layout.partitions[3].kind, "Recovery");
        assert_eq!(layout.partitions[3].drive_letter, None);
    }

    #[test]
    fn parses_raw_get_partition_array_and_single_object_mbr() {
        // PowerShell 5.1 raw Get-Partition | ConvertTo-Json (DriveLetter as char code 68 = 'D')
        let raw_arr = r#"[
            {
                "DiskNumber": 1,
                "PartitionNumber": 2,
                "Offset": 105906176,
                "Size": 50000000000,
                "Type": "IFS",
                "MbrType": 7,
                "DriveLetter": 68,
                "FileSystemLabel": "DATA",
                "FileSystem": "NTFS"
            },
            {
                "DiskNumber": 1,
                "PartitionNumber": 1,
                "Offset": 1048576,
                "Size": 104857600,
                "Type": "Recovery",
                "MbrType": 39,
                "DriveLetter": 0
            }
        ]"#;
        let layout = parse_disk_layout_json(raw_arr, 'D').unwrap();
        assert_eq!(layout.disk_number, 1);
        assert_eq!(layout.partition_style, "MBR");
        assert_eq!(layout.partitions.len(), 2);
        // Sorted by partition number
        assert_eq!(layout.partitions[0].number, 1);
        assert_eq!(layout.partitions[0].kind, "Recovery");
        assert_eq!(layout.partitions[0].style, "MBR");
        assert_eq!(layout.partitions[1].number, 2);
        assert_eq!(layout.partitions[1].kind, "Basic");
        assert_eq!(layout.partitions[1].drive_letter, Some('D'));
        assert_eq!(layout.partitions[1].file_system, "NTFS");

        // Single-partition object quirk in PowerShell 5.1 when Partitions has 1 item
        let single_part = r#"{
            "DiskNumber": 2,
            "PartitionStyle": 1,
            "DiskSize": 1000000000,
            "Partitions": {
                "PartitionNumber": 1,
                "Offset": 1048576,
                "Size": 998000000,
                "Type": "Basic",
                "MbrType": 7,
                "DriveLetter": "E",
                "FileSystemLabel": "USB",
                "FileSystem": "ntfs"
            }
        }"#;
        let single = parse_disk_layout_json(single_part, 'E').unwrap();
        assert_eq!(single.partition_style, "MBR");
        assert_eq!(single.partitions.len(), 1);
        assert_eq!(single.partitions[0].drive_letter, Some('E'));
        assert_eq!(single.partitions[0].file_system, "NTFS");
    }
}

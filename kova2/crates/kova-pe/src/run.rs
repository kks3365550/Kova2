use kova_image::verify;
use kova_image::volume_restore::{confirmation_phrase, restore_image_to_volume, volume_info};
use kova_pe::plan::*;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

struct Log(Vec<String>);
impl Log {
    fn say(&mut self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
        self.0.push(s.as_ref().to_string());
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn MultiByteToWideChar(
        code_page: u32,
        flags: u32,
        src: *const u8,
        src_len: i32,
        dst: *mut u16,
        dst_len: i32,
    ) -> i32;
    fn GetLogicalDrives() -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sec: *mut core::ffi::c_void,
        disp: u32,
        flags: u32,
        template: *mut core::ffi::c_void,
    ) -> isize;
    fn DeviceIoControl(
        device: isize,
        ioctl: u32,
        in_buf: *mut core::ffi::c_void,
        in_len: u32,
        out_buf: *mut core::ffi::c_void,
        out_len: u32,
        bytes_returned: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CloseHandle(h: isize) -> i32;
}

const CP_OEMCP: u32 = 1;

fn decode_oem(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    if bytes.is_empty() {
        return String::new();
    }
    let Ok(src_len) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    // SAFETY: 유효한 바이트 슬라이스와 길이를 넘겨 필요한 UTF-16 길이를 먼저 조회한 뒤 변환한다.
    unsafe {
        let needed = MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            src_len,
            std::ptr::null_mut(),
            0,
        );
        if needed <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; needed as usize];
        let written = MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            src_len,
            wide.as_mut_ptr(),
            needed,
        );
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..written as usize])
    }
}

fn physical_disk_bytes(num: u32) -> Option<u64> {
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: isize = -1;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;

    let wide: Vec<u16> = format!(r"\\.\PhysicalDrive{num}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: 널 종료 UTF-16 장치 경로로 읽기 전용 핸들을 열고 IOCTL_DISK_GET_LENGTH_INFO(i64)를 조회한 뒤 닫는다.
    unsafe {
        let h = CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_ALL,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut length: i64 = 0;
        let mut returned: u32 = 0;
        let ok = DeviceIoControl(
            h,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null_mut(),
            0,
            (&mut length as *mut i64).cast(),
            std::mem::size_of::<i64>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        );
        CloseHandle(h);
        if ok != 0 && returned as usize >= std::mem::size_of::<i64>() && length > 0 {
            Some(length as u64)
        } else {
            None
        }
    }
}

fn diskpart(script: &str) -> String {
    let dir = std::env::var("TEMP").unwrap_or_else(|_| "X:\\".into());
    let f = Path::new(&dir).join(format!("kova_dp_{}.txt", std::process::id()));
    if let Err(e) = std::fs::write(&f, script) {
        return format!("diskpart script write failed: {e}");
    }
    let out = Command::new("diskpart").arg("/s").arg(&f).output();
    let _ = std::fs::remove_file(&f);
    match out {
        Ok(o) => {
            let stdout = decode_oem(&o.stdout);
            if o.status.success() {
                stdout
            } else {
                let stderr = decode_oem(&o.stderr);
                let code = o
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".into());
                if stderr.trim().is_empty() {
                    format!("diskpart exited with code {code}\n{stdout}")
                } else {
                    format!("diskpart exited with code {code}\n{stdout}\n{stderr}")
                }
            }
        }
        Err(e) => format!("diskpart failed: {e}"),
    }
}

fn exists_letter(l: char) -> bool {
    let up = l.to_ascii_uppercase();
    if !up.is_ascii_uppercase() {
        return false;
    }
    let bit = (up as u32) - ('A' as u32);
    // SAFETY: 인자가 없는 Win32 조회 함수다.
    let mask = unsafe { GetLogicalDrives() };
    (mask & (1u32 << bit)) != 0
}

fn image_matches(p: &Path, want: &str) -> bool {
    let want = want.trim();
    if want.is_empty() {
        return false;
    }
    let want_norm = want.replace('/', "\\");
    if want_norm.contains('\\') {
        let full = p.to_string_lossy().replace('/', "\\");
        if full.eq_ignore_ascii_case(&want_norm) {
            return true;
        }
        let rel = want_norm.trim_start_matches('\\');
        let suffix = format!("\\{rel}");
        full.len() >= suffix.len()
            && full
                .get(full.len() - suffix.len()..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(&suffix))
    } else {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&want_norm))
    }
}

fn find_images() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for l in 'C'..='Z' {
        if l == 'X' {
            continue;
        }
        for sub in ["Kova2_Repository\\images", "KovaImages"] {
            let d = PathBuf::from(format!("{l}:\\{sub}"));
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("qblk"))
                    {
                        v.push(p);
                    }
                }
            }
        }
    }
    v
}

type Auto = std::collections::HashMap<String, String>;

fn drive_of(p: &Path) -> Option<char> {
    p.to_string_lossy()
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
}

/// 자동 모드 파일은 이미지 폴더가 있는 드라이브의 루트에서만 찾는다(아무 USB·디스크 루트의 파일로 켜지지 않게).
fn read_auto(image_drives: &[char]) -> Option<(PathBuf, Auto)> {
    for l in image_drives {
        let p = PathBuf::from(format!("{l}:\\KOVA_AUTO.txt"));
        if let Ok(t) = std::fs::read_to_string(&p) {
            return Some((p, parse_auto(&t)));
        }
    }
    None
}

fn is_uefi() -> bool {
    Command::new("reg")
        .args([
            "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control",
            "/v",
            "PEFirmwareType",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x2"))
        .unwrap_or(true)
}

fn ask(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn free_letters() -> Vec<char> {
    ['S', 'T', 'U', 'V', 'W', 'Y', 'Z']
        .into_iter()
        .filter(|l| !exists_letter(*l))
        .collect()
}

fn save_log(log: &Log, image: Option<&Path>) {
    let text = log.0.join("\r\n");
    let _ = std::fs::write("X:\\kova-pe.log", &text);
    if let Some(root) = image.and_then(|p| p.ancestors().last()) {
        let _ = std::fs::write(root.join("KOVA_PE_LOG.txt"), &text);
    }
}

fn finish(log: &mut Log, image: Option<&Path>, code: i32, auto: bool) -> i32 {
    log.say(if code == 0 {
        "RESULT: OK"
    } else {
        "RESULT: FAILED"
    });
    save_log(log, image);
    if auto {
        let _ = Command::new("wpeutil").arg("shutdown").status();
    } else {
        let _ = ask("Press Enter to reboot (on failure, Shift+F10 opens a command prompt).");
        let _ = Command::new("wpeutil").arg("reboot").status();
    }
    code
}

pub fn main() -> i32 {
    let mut log = Log(Vec::new());
    log.say("=== Kova2 WinPE system restore ===");

    // 1) 이미지 선택
    let images = find_images();
    if images.is_empty() {
        log.say("ERROR: no .qblk image found on any drive (Kova2_Repository\\images, KovaImages).");
        return finish(&mut log, None, 1, false);
    }
    let mut image_drives: Vec<char> = images.iter().filter_map(|p| drive_of(p)).collect();
    image_drives.sort();
    image_drives.dedup();
    let auto_file = read_auto(&image_drives);
    let auto = auto_file.as_ref().map(|(_, m)| m);
    let is_auto = auto.is_some();
    if let Some((p, _)) = &auto_file {
        log.say(format!("Auto mode file: {}", p.display()));
    }
    let image: PathBuf = if let Some(m) = auto {
        let want = m.get("image").cloned().unwrap_or_default();
        // 자동 모드 이미지는 자동 모드 파일과 같은 드라이브에 있는 것만 고른다
        let auto_drive = auto_file.as_ref().and_then(|(p, _)| drive_of(p));
        let hit = images
            .iter()
            .find(|p| drive_of(p) == auto_drive && image_matches(p, &want));
        match hit {
            Some(p) => p.clone(),
            None => {
                log.say(format!("ERROR: auto mode image={want} not found."));
                return finish(&mut log, None, 1, true);
            }
        }
    } else {
        for (i, p) in images.iter().enumerate() {
            let mb = std::fs::metadata(p).map(|m| m.len() >> 20).unwrap_or(0);
            println!("  [{}] {} ({} MB)", i + 1, p.display(), mb);
        }
        let n: usize = ask("Image number to restore: ").parse().unwrap_or(0);
        match images.get(n.wrapping_sub(1)) {
            Some(p) => p.clone(),
            None => {
                log.say("ERROR: invalid number");
                return finish(&mut log, None, 1, false);
            }
        }
    };
    log.say(format!("Image: {}", image.display()));

    // 2) 이미지 검증 (디스크를 건드리기 전)
    log.say("Verifying the whole image...");
    let verified = File::open(&image).map_err(|e| e.to_string()).and_then(|f| {
        verify(
            BufReader::with_capacity(8 << 20, f),
            &AtomicBool::new(false),
            &|_| {},
        )
        .map_err(|e| e.to_string())
    });
    let header = match verified {
        Ok((h, s)) => {
            log.say(format!(
                "Verify OK: clusters {} / used {} / chunks {}",
                h.total_clusters, h.used_clusters, s.chunks
            ));
            h
        }
        Err(e) => {
            log.say(format!(
                "ERROR: image verification failed, nothing was changed: {e}"
            ));
            return finish(&mut log, Some(&image), 1, is_auto);
        }
    };
    let Some(image_bytes) = header
        .total_clusters
        .checked_mul(header.cluster_size as u64)
    else {
        log.say("ERROR: image size overflow in header; nothing was changed.");
        return finish(&mut log, Some(&image), 1, is_auto);
    };

    // 3) 대상 디스크
    let mut disks = parse_list_disk(&diskpart("list disk\nexit\n"));
    for d in &mut disks {
        if let Some(exact) = physical_disk_bytes(d.num) {
            d.bytes = exact;
        }
    }
    let img_letter = image.to_string_lossy().chars().next().unwrap_or('C');
    let image_disks = parse_detail_volume_disks(&diskpart(&script_detail_volume(img_letter)));
    if image_disks.is_empty() {
        log.say(format!(
            "ERROR: could not find which disk holds {img_letter}: (diskpart detail volume); nothing was changed."
        ));
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    // 자동 모드는 디스크 고유 ID(disk_id)로만 지정한다. 번호(disk=)·크기(disk_mb=)는 거부한다.
    let auto_id: Option<String> = match auto.map(auto_disk_id) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(e)) => {
            log.say(format!("ERROR: {e}. Nothing was changed."));
            return finish(&mut log, Some(&image), 1, true);
        }
    };
    let disk_num: u32 = if let Some(id) = &auto_id {
        // 디스크 고유 ID 가 정확히 하나의 디스크와 일치할 때만 선택한다.
        let hits: Vec<u32> = disks
            .iter()
            .filter(|d| {
                parse_disk_id(&diskpart(&format!(
                    "select disk {}
detail disk
exit
",
                    d.num
                )))
                .is_some_and(|x| x == *id)
            })
            .map(|d| d.num)
            .collect();
        if hits.len() == 1 {
            hits[0]
        } else {
            u32::MAX
        }
    } else {
        for d in &disks {
            let tag = if image_disks.contains(&d.num) {
                "  <- holds the image (cannot select)"
            } else {
                ""
            };
            println!(
                "  Disk {}: {} MB, {}{}",
                d.num,
                d.bytes >> 20,
                d.status,
                tag
            );
        }
        ask("Disk number to ERASE: ").parse().unwrap_or(u32::MAX)
    };
    let Some(disk) = disks.iter().find(|d| d.num == disk_num) else {
        log.say(format!("ERROR: disk {disk_num} not found"));
        return finish(&mut log, Some(&image), 1, is_auto);
    };
    if let Err(e) = disk_selected_ok(disk, &image_disks, image_bytes) {
        log.say(format!("ERROR: {e}"));
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    let phrase = match &auto_id {
        Some(id) => confirm_phrase_id(id),
        None => confirm_phrase(disk.num),
    };
    let typed = if let Some(m) = auto {
        m.get("confirm").cloned().unwrap_or_default()
    } else {
        println!(
            "ALL data on disk {} ({} MB) will be erased.",
            disk.num,
            disk.bytes >> 20
        );
        ask(&format!("To continue type exactly [{phrase}]: "))
    };
    if norm(&typed) != phrase {
        log.say("ERROR: confirmation phrase does not match. Nothing was changed.");
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    // 디스크를 건드리기 직전에 자동 모드 파일 이름을 바꾼다: 복원이 성공하든 실패·정전이든 재부팅마다 다시 지우지 않게.
    // 이름을 못 바꾸면 반복 삭제 위험이 있으므로 시작하지 않는다.
    if let Some((p, _)) = &auto_file {
        let done = p.with_file_name(AUTO_DONE_NAME);
        let _ = std::fs::remove_file(&done);
        if let Err(e) = std::fs::rename(p, &done) {
            log.say(format!(
                "ERROR: cannot rename {} (auto mode would repeat on every boot): {e}. Nothing was changed.",
                p.display()
            ));
            return finish(&mut log, Some(&image), 1, true);
        }
        log.say(format!("Auto mode file renamed to {}", done.display()));
    }

    // 4) 파티션
    let uefi = is_uefi();
    let fl = free_letters();
    if fl.len() < 2 {
        log.say("ERROR: not enough free drive letters.");
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    let (sys, os) = (fl[0], fl[1]);
    log.say(format!(
        "Boot mode {}, system {sys}: target {os}: creating partitions",
        if uefi { "UEFI/GPT" } else { "BIOS/MBR" }
    ));
    let out = diskpart(&if uefi {
        script_gpt(disk.num, sys, os)
    } else {
        script_mbr(disk.num, sys, os)
    });
    if !exists_letter(os) || !exists_letter(sys) {
        log.say(format!("ERROR: partitioning failed\n{out}"));
        return finish(&mut log, Some(&image), 1, is_auto);
    }

    // 5) 복원
    let info = match volume_info(os) {
        Ok(i) => i,
        Err(e) => {
            log.say(format!("ERROR: target volume lookup failed: {e}"));
            return finish(&mut log, Some(&image), 1, is_auto);
        }
    };
    log.say(format!("Restore started -> {os}:"));
    let t = std::time::Instant::now();
    let res = restore_image_to_volume(
        &image,
        os,
        &confirmation_phrase(&info),
        &[],
        &AtomicBool::new(false),
        &|s| {
            if s.chunks % 200 == 0 {
                eprint!("\rchunks {} / {:.1} GB", s.chunks, s.raw_bytes as f64 / 1e9);
            }
        },
    );
    println!();
    if let Err(e) = res {
        log.say(format!("ERROR: restore failed: {e}"));
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    log.say(format!("Restore done ({:.0}s)", t.elapsed().as_secs_f64()));

    // 6) 확장·부팅 구성
    let _ = diskpart(&script_extend(os));
    if !Path::new(&format!("{os}:\\Windows\\System32")).exists() {
        log.say(format!(
            "ERROR: {os}:\\Windows\\System32 is missing; the image seems to contain no Windows."
        ));
        return finish(&mut log, Some(&image), 1, is_auto);
    }
    match Command::new("bcdboot")
        .args(bcdboot_args(os, sys, uefi))
        .output()
    {
        Ok(o) if o.status.success() => log.say("bcdboot OK: boot files created."),
        Ok(o) => {
            log.say(format!(
                "ERROR: bcdboot failed: {}{}",
                decode_oem(&o.stdout),
                decode_oem(&o.stderr)
            ));
            return finish(&mut log, Some(&image), 1, is_auto);
        }
        Err(e) => {
            log.say(format!("ERROR: bcdboot could not run: {e}"));
            return finish(&mut log, Some(&image), 1, is_auto);
        }
    }
    finish(&mut log, Some(&image), 0, is_auto)
}

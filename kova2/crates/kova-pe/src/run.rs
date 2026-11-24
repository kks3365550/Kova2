use kova_image::crypto::{decrypt_file, is_encrypted_image};
use kova_image::incremental::{load_chain_meta, verify_chain};
use kova_image::layout::{load_layout, DiskLayout};
use kova_image::verify;
use kova_image::volume_restore::{
    confirmation_phrase, restore_chain_to_volume, restore_image_to_volume, volume_info,
    RestorePhase, RestoreProgress,
};
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
    fn GetDriveTypeW(root: *const u16) -> u32;
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

fn is_remote_drive(letter: char) -> bool {
    const DRIVE_REMOTE: u32 = 4;
    let up = letter.to_ascii_uppercase();
    if !up.is_ascii_uppercase() {
        return false;
    }
    let root: Vec<u16> = format!("{up}:\\")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: 널 종료 UTF-16 드라이브 루트 경로를 넘겨 Win32 드라이브 유형을 조회한다.
    unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_REMOTE }
}

fn is_image_file(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase())
        .is_some_and(|lower| lower.ends_with(".qblk") || lower.ends_with(".qblk.enc"))
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

fn find_images(mapped_shares: &[(char, String)]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for l in 'C'..='Z' {
        if l == 'X' {
            continue;
        }
        let mut dirs = vec![
            PathBuf::from(format!("{l}:\\Kova2_Repository\\images")),
            PathBuf::from(format!("{l}:\\KovaImages")),
        ];
        if is_remote_drive(l) || mapped_shares.iter().any(|(c, _)| *c == l) {
            dirs.push(PathBuf::from(format!("{l}:\\")));
        }
        for d in dirs {
            if let Ok(rd) = std::fs::read_dir(&d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if is_image_file(&p) {
                        v.push(p);
                    }
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

type Auto = std::collections::HashMap<String, String>;

fn drive_of(p: &Path) -> Option<char> {
    p.to_string_lossy()
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic())
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

fn free_network_letter() -> Option<char> {
    [
        'Z', 'Y', 'W', 'V', 'U', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G',
    ]
    .into_iter()
    .find(|&l| !exists_letter(l))
}

fn connect_smb_share(log: &mut Log) -> Option<(char, String)> {
    let Some(letter) = free_network_letter() else {
        log.say("ERROR: no free drive letter available for network share.");
        return None;
    };
    let share = ask("UNC share path (e.g. \\\\server\\share, empty to cancel): ");
    if share.is_empty() {
        return None;
    }
    if !share.starts_with(r"\\") {
        log.say("ERROR: UNC share path must start with \\\\.");
        return None;
    }
    let user = ask("Username (leave empty if none): ");
    let pass = ask("Password (leave empty if none): ");

    let drive_arg = format!("{letter}:");
    let mut args: Vec<String> = vec!["use".into(), drive_arg, share.clone()];
    if !pass.is_empty() {
        args.push(pass);
    } else if !user.is_empty() {
        args.push(String::new());
    }
    if !user.is_empty() {
        args.push(format!("/user:{user}"));
    }
    args.push("/persistent:no".into());

    log.say(format!("Connecting network share {share} -> {letter}:..."));
    match Command::new("net").args(&args).output() {
        Ok(o) if o.status.success() => {
            log.say(format!("Connected {share} as {letter}:"));
            Some((letter, share))
        }
        Ok(o) => {
            log.say(format!(
                "ERROR: net use failed: {}{}",
                decode_oem(&o.stdout),
                decode_oem(&o.stderr)
            ));
            None
        }
        Err(e) => {
            log.say(format!("ERROR: net use could not run: {e}"));
            None
        }
    }
}

/// 원격 네트워크 드라이브(Z:\...) 위의 이미지는 UNC 경로(\\server\share\...)로 정규화해
/// `kova_image::volume_restore`의 볼륨 GUID 검사가 원격 공유로 정상 인식하도록 한다.
fn restore_source_path(path: &Path, mapped_shares: &[(char, String)]) -> PathBuf {
    let Some(drv) = drive_of(path) else {
        return path.to_path_buf();
    };
    let remote = is_remote_drive(drv) || mapped_shares.iter().any(|(c, _)| *c == drv);
    if !remote {
        return path.to_path_buf();
    }
    if let Ok(canon) = std::fs::canonicalize(path) {
        let s = canon.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if s.starts_with(r"\\") {
            return canon;
        }
    }
    if let Some((_, share)) = mapped_shares.iter().find(|(c, _)| *c == drv) {
        let raw = path.to_string_lossy();
        let rel = raw.get(2..).unwrap_or("").trim_start_matches(['\\', '/']);
        let base = share.trim_end_matches(['\\', '/']);
        if rel.is_empty() {
            return PathBuf::from(base);
        }
        return PathBuf::from(format!("{base}\\{rel}"));
    }
    path.to_path_buf()
}

fn load_image_layout(image: &Path) -> Result<Option<DiskLayout>, kova_image::QblkError> {
    if let Some(layout) = load_layout(image)? {
        return Ok(Some(layout));
    }
    let s = image.to_string_lossy();
    if let Some(stripped) = s
        .len()
        .checked_sub(4)
        .and_then(|idx| s.get(idx..))
        .filter(|tail| tail.eq_ignore_ascii_case(".enc"))
        .and_then(|_| s.get(..s.len() - 4))
    {
        return load_layout(Path::new(stripped));
    }
    Ok(None)
}

struct TempDecryptGuard {
    file: PathBuf,
    dir: Option<PathBuf>,
}

impl Drop for TempDecryptGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.file);
        if let Some(d) = &self.dir {
            let _ = std::fs::remove_dir(d);
        }
    }
}

fn dir_is_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".kova_probe_{}", std::process::id()));
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .is_ok();
    if ok {
        let _ = std::fs::remove_file(&probe);
    }
    ok
}

fn choose_decrypt_temp_dir(image: &Path) -> Result<PathBuf, String> {
    if let Some(parent) = image.parent() {
        let candidate = parent.join(".kova_pe_tmp");
        if dir_is_writable(&candidate) {
            return Ok(candidate);
        }
    }
    let fallback_base = std::env::var("TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("X:\\"));
    let fallback = fallback_base.join(".kova_pe_tmp");
    if dir_is_writable(&fallback) {
        return Ok(fallback);
    }
    Err(format!(
        "no writable temp directory for decryption (tried image folder and {})",
        fallback.display()
    ))
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
    let (image, code, is_auto) = run_restore(&mut log);
    finish(&mut log, image.as_deref(), code, is_auto)
}

fn run_restore(log: &mut Log) -> (Option<PathBuf>, i32, bool) {
    log.say("=== Kova2 WinPE system restore ===");

    // 1) 이미지 선택 (로컬 드라이브 + 선택적 SMB 네트워크 공유 연결)
    let mut mapped_shares: Vec<(char, String)> = Vec::new();
    let mut images = find_images(&mapped_shares);

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
                return (None, 1, true);
            }
        }
    } else {
        loop {
            if images.is_empty() {
                println!(
                    "No .qblk/.qblk.enc image found on local drives (Kova2_Repository\\images, KovaImages)."
                );
                let ans = ask("Connect network share (SMB)? [Y/n]: ");
                if ans.is_empty()
                    || ans.eq_ignore_ascii_case("y")
                    || ans.eq_ignore_ascii_case("yes")
                {
                    if let Some((drv, share)) = connect_smb_share(log) {
                        mapped_shares.push((drv, share));
                        images = find_images(&mapped_shares);
                        continue;
                    }
                    if images.is_empty() {
                        let retry = ask("Retry network share connection? [y/N]: ");
                        if retry.eq_ignore_ascii_case("y") || retry.eq_ignore_ascii_case("yes") {
                            continue;
                        }
                        log.say("ERROR: no .qblk/.qblk.enc image found.");
                        return (None, 1, false);
                    }
                } else {
                    log.say(
                        "ERROR: no .qblk/.qblk.enc image found on any drive (Kova2_Repository\\images, KovaImages).",
                    );
                    return (None, 1, false);
                }
            } else {
                for (i, p) in images.iter().enumerate() {
                    let mb = std::fs::metadata(p).map(|m| m.len() >> 20).unwrap_or(0);
                    println!("  [{}] {} ({} MB)", i + 1, p.display(), mb);
                }
                println!("  [N] Connect network share (SMB)");
                let choice = ask("Image number to restore (or N for network share): ");
                if choice.eq_ignore_ascii_case("n") {
                    if let Some((drv, share)) = connect_smb_share(log) {
                        mapped_shares.push((drv, share));
                        images = find_images(&mapped_shares);
                    }
                    continue;
                }
                let n: usize = choice.parse().unwrap_or(0);
                match images.get(n.wrapping_sub(1)) {
                    Some(p) => break p.clone(),
                    None => {
                        log.say("ERROR: invalid number");
                        return (None, 1, false);
                    }
                }
            }
        }
    };
    log.say(format!("Image: {}", image.display()));

    // 2) 이미지 검증 (디스크를 건드리기 전: 암호화 복호화·증분 체인·단일 이미지)
    let is_encrypted = is_encrypted_image(&image);
    let mut dec_guard: Option<TempDecryptGuard> = None;
    let is_chain = if is_encrypted {
        false
    } else {
        match load_chain_meta(&image) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                log.say(format!(
                    "ERROR: failed to read incremental chain metadata (.qchain.json), nothing was changed: {e}"
                ));
                return (Some(image), 1, is_auto);
            }
        }
    };

    let header = if is_encrypted {
        let raw_key = if let Some(m) = auto {
            let k = m.get("key").cloned().unwrap_or_default();
            if k.trim().is_empty() {
                log.say(
                    "ERROR: image is encrypted but KOVA_AUTO.txt has no key=; nothing was changed.",
                );
                return (Some(image), 1, true);
            }
            k
        } else {
            ask("Image is encrypted. Enter 64-hex key: ")
        };
        let key = match parse_hex_key(&raw_key) {
            Ok(k) => k,
            Err(e) => {
                log.say(format!(
                    "ERROR: invalid decryption key, nothing was changed: {e}"
                ));
                return (Some(image), 1, is_auto);
            }
        };
        let tmp_dir = match choose_decrypt_temp_dir(&image) {
            Ok(d) => d,
            Err(e) => {
                log.say(format!("ERROR: {e}; nothing was changed."));
                return (Some(image), 1, is_auto);
            }
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dec_path = tmp_dir.join(format!("kova_dec_{}_{}.qblk", std::process::id(), stamp));
        let _ = std::fs::remove_file(&dec_path);
        let guard = TempDecryptGuard {
            file: dec_path,
            dir: Some(tmp_dir),
        };
        log.say(format!(
            "Decrypting encrypted image to {} for verification...",
            guard.file.display()
        ));
        if let Err(e) = decrypt_file(&image, &guard.file, &key, &AtomicBool::new(false)) {
            log.say(format!(
                "ERROR: image decryption failed, nothing was changed: {e}"
            ));
            return (Some(image), 1, is_auto);
        }
        log.say("Verifying decrypted image...");
        let verified = File::open(&guard.file)
            .map_err(|e| e.to_string())
            .and_then(|f| {
                verify(
                    BufReader::with_capacity(8 << 20, f),
                    &AtomicBool::new(false),
                    &|_| {},
                )
                .map_err(|e| e.to_string())
            });
        match verified {
            Ok((h, s)) => {
                log.say(format!(
                    "Verify OK (encrypted): clusters {} / used {} / chunks {}",
                    h.total_clusters, h.used_clusters, s.chunks
                ));
                dec_guard = Some(guard);
                h
            }
            Err(e) => {
                log.say(format!(
                    "ERROR: decrypted image verification failed, nothing was changed: {e}"
                ));
                return (Some(image), 1, is_auto);
            }
        }
    } else if is_chain {
        log.say("Verifying incremental image chain...");
        match verify_chain(&image, &AtomicBool::new(false), &|_| {}) {
            Ok(links) => {
                if links.is_empty() {
                    log.say("ERROR: incremental chain is empty; nothing was changed.");
                    return (Some(image), 1, is_auto);
                }
                let first_geom = (links[0].1.cluster_size, links[0].1.total_clusters);
                if let Some((bad_path, bad_h, _)) = links
                    .iter()
                    .find(|(_, h, _)| (h.cluster_size, h.total_clusters) != first_geom)
                {
                    log.say(format!(
                        "ERROR: incremental chain geometry mismatch at {} (cluster_size={} total_clusters={}); nothing was changed.",
                        bad_path.display(),
                        bad_h.cluster_size,
                        bad_h.total_clusters
                    ));
                    return (Some(image), 1, is_auto);
                }
                log.say(format!("Incremental chain: {} links verified", links.len()));
                let (_, last_h, last_s) = links.last().expect("non-empty chain");
                log.say(format!(
                    "Verify OK: clusters {} / used {} / last-link chunks {}",
                    last_h.total_clusters, last_h.used_clusters, last_s.chunks
                ));
                last_h.clone()
            }
            Err(e) => {
                log.say(format!(
                    "ERROR: incremental chain verification failed, nothing was changed: {e}"
                ));
                return (Some(image), 1, is_auto);
            }
        }
    } else {
        log.say("Verifying the whole image...");
        let verified = File::open(&image).map_err(|e| e.to_string()).and_then(|f| {
            verify(
                BufReader::with_capacity(8 << 20, f),
                &AtomicBool::new(false),
                &|_| {},
            )
            .map_err(|e| e.to_string())
        });
        match verified {
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
                return (Some(image), 1, is_auto);
            }
        }
    };

    let Some(image_bytes) = header
        .total_clusters
        .checked_mul(header.cluster_size as u64)
    else {
        log.say("ERROR: image size overflow in header; nothing was changed.");
        return (Some(image), 1, is_auto);
    };

    // 3) 대상 디스크
    let mut disks = parse_list_disk(&diskpart("list disk\nexit\n"));
    for d in &mut disks {
        if let Some(exact) = physical_disk_bytes(d.num) {
            d.bytes = exact;
        }
    }
    let img_letter = drive_of(&image).unwrap_or('C');
    let remote_image =
        is_remote_drive(img_letter) || mapped_shares.iter().any(|(c, _)| *c == img_letter);
    let image_disks = if remote_image {
        log.say(format!(
            "Image resides on remote network drive {img_letter}: (no local physical disk)."
        ));
        Vec::new()
    } else {
        let found = parse_detail_volume_disks(&diskpart(&script_detail_volume(img_letter)));
        if found.is_empty() {
            log.say(format!(
                "ERROR: could not find which disk holds {img_letter}: (diskpart detail volume); nothing was changed."
            ));
            return (Some(image), 1, is_auto);
        }
        found
    };
    // 자동 모드는 디스크 고유 ID(disk_id)로만 지정한다. 번호(disk=)·크기(disk_mb=)는 거부한다.
    let auto_id: Option<String> = match auto.map(auto_disk_id) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(e)) => {
            log.say(format!("ERROR: {e}. Nothing was changed."));
            return (Some(image), 1, true);
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
        return (Some(image), 1, is_auto);
    };
    if let Err(e) = disk_selected_ok_ext(disk, &image_disks, image_bytes, remote_image) {
        log.say(format!("ERROR: {e}"));
        return (Some(image), 1, is_auto);
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
        return (Some(image), 1, is_auto);
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
            return (Some(image), 1, true);
        }
        log.say(format!("Auto mode file renamed to {}", done.display()));
    }

    // 4) 파티션 (저장된 .qlayout.json 우선, 없으면 기본 GPT/MBR 스크립트)
    let uefi = is_uefi();
    let fl = free_letters();
    if fl.len() < 2 {
        log.say("ERROR: not enough free drive letters.");
        return (Some(image), 1, is_auto);
    }
    let (sys, os) = (fl[0], fl[1]);
    let saved_layout = match load_image_layout(&image) {
        Ok(l) => l,
        Err(e) => {
            log.say(format!(
                "WARN: could not read .qlayout.json ({e}); using default partitioning."
            ));
            None
        }
    };
    let part_script = if let Some(layout) = &saved_layout {
        let style_matches = (uefi && layout.partition_style.eq_ignore_ascii_case("GPT"))
            || (!uefi && layout.partition_style.eq_ignore_ascii_case("MBR"));
        if !style_matches {
            log.say(format!(
                "WARN: saved partition layout style ({}) differs from boot mode ({}); using default partitioning.",
                layout.partition_style,
                if uefi { "UEFI/GPT" } else { "BIOS/MBR" }
            ));
            None
        } else if let Some(s) = script_from_layout(disk.num, layout, sys, os, disk.bytes) {
            log.say("Using saved partition layout (.qlayout.json)");
            Some(s)
        } else {
            log.say(
                "WARN: saved partition layout incompatible with target disk; using default partitioning.",
            );
            None
        }
    } else {
        None
    };
    log.say(format!(
        "Boot mode {}, system {sys}: target {os}: creating partitions",
        if uefi { "UEFI/GPT" } else { "BIOS/MBR" }
    ));
    let script = part_script.unwrap_or_else(|| {
        if uefi {
            script_gpt(disk.num, sys, os)
        } else {
            script_mbr(disk.num, sys, os)
        }
    });
    let out = diskpart(&script);
    if !exists_letter(os) || !exists_letter(sys) {
        log.say(format!("ERROR: partitioning failed\n{out}"));
        return (Some(image), 1, is_auto);
    }

    // 5) 복원 (암호화 복호화 임시 파일 / 증분 체인 / 단일 이미지)
    let info = match volume_info(os) {
        Ok(i) => i,
        Err(e) => {
            log.say(format!("ERROR: target volume lookup failed: {e}"));
            return (Some(image), 1, is_auto);
        }
    };
    log.say(format!("Restore started -> {os}:"));
    let t = std::time::Instant::now();
    let mut prot: Vec<char> = Vec::new();
    if !remote_image {
        prot.push(img_letter);
    }
    let res = if let Some(guard) = &dec_guard {
        let src_path = restore_source_path(&guard.file, &mapped_shares);
        restore_image_to_volume(
            &src_path,
            os,
            &confirmation_phrase(&info),
            &prot,
            &AtomicBool::new(false),
            &|s| {
                if s.chunks % 200 == 0 {
                    eprint!("\rchunks {} / {:.1} GB", s.chunks, s.raw_bytes as f64 / 1e9);
                }
            },
        )
    } else if is_chain {
        let src_path = restore_source_path(&image, &mapped_shares);
        restore_chain_to_volume(
            &src_path,
            os,
            &confirmation_phrase(&info),
            &[],
            &AtomicBool::new(false),
            &|p: &RestoreProgress| {
                if p.stats.chunks.is_multiple_of(200) {
                    let phase_str = match p.phase {
                        RestorePhase::Decrypt => "decrypt",
                        RestorePhase::Verify => "verify",
                        RestorePhase::Write => "write",
                    };
                    eprint!(
                        "\r[{phase_str} {}/{}] chunks {} / {:.1} GB",
                        p.link_index + 1,
                        p.link_count,
                        p.stats.chunks,
                        p.stats.raw_bytes as f64 / 1e9
                    );
                }
            },
        )
    } else {
        let src_path = restore_source_path(&image, &mapped_shares);
        restore_image_to_volume(
            &src_path,
            os,
            &confirmation_phrase(&info),
            &prot,
            &AtomicBool::new(false),
            &|s| {
                if s.chunks % 200 == 0 {
                    eprint!("\rchunks {} / {:.1} GB", s.chunks, s.raw_bytes as f64 / 1e9);
                }
            },
        )
    };
    println!();
    drop(dec_guard);
    if let Err(e) = res {
        log.say(format!("ERROR: restore failed: {e}"));
        return (Some(image), 1, is_auto);
    }
    log.say(format!("Restore done ({:.0}s)", t.elapsed().as_secs_f64()));

    // 6) 확장 · 오프라인 드라이버 주입 · 부팅 구성
    let _ = diskpart(&script_extend(os));
    if !Path::new(&format!("{os}:\\Windows\\System32")).exists() {
        log.say(format!(
            "ERROR: {os}:\\Windows\\System32 is missing; the image seems to contain no Windows."
        ));
        return (Some(image), 1, is_auto);
    }

    let mut driver_candidates: Vec<PathBuf> = Vec::new();
    if let Some(d) = auto
        .and_then(|m| m.get("drivers"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        driver_candidates.push(PathBuf::from(d));
    }
    driver_candidates.push(PathBuf::from(format!("{img_letter}:\\KovaDrivers")));
    driver_candidates.push(PathBuf::from("X:\\Drivers"));

    if let Some(drivers_dir) = driver_candidates
        .iter()
        .find_map(|d| find_collected_drivers(d))
    {
        log.say(format!(
            "Injecting offline drivers from {} into {os}:\\...",
            drivers_dir.display()
        ));
        let args = dism_inject_offline_args(os, &drivers_dir);
        match Command::new("dism.exe").args(&args).output() {
            Ok(o) if o.status.success() => log.say("Driver injection OK."),
            Ok(o) => {
                let code = o.status.code().unwrap_or(-1);
                let out_txt = decode_oem(&o.stdout);
                let err_txt = decode_oem(&o.stderr);
                let detail = if err_txt.trim().is_empty() {
                    out_txt.trim().to_string()
                } else {
                    format!("{}\n{}", out_txt.trim(), err_txt.trim())
                };
                if code == 2 || code == 50 {
                    log.say(format!(
                        "WARN: dism driver injection partial failure (exit code {code}); continuing to bcdboot.\n{detail}"
                    ));
                } else {
                    log.say(format!(
                        "WARN: dism driver injection failed (exit code {code}); continuing to bcdboot.\n{detail}"
                    ));
                }
            }
            Err(e) => {
                log.say(format!(
                    "WARN: dism.exe could not run ({e}); continuing to bcdboot."
                ));
            }
        }
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
            return (Some(image), 1, is_auto);
        }
        Err(e) => {
            log.say(format!("ERROR: bcdboot could not run: {e}"));
            return (Some(image), 1, is_auto);
        }
    }
    (Some(image), 0, is_auto)
}

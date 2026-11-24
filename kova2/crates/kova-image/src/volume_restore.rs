//! 볼륨 직접 복원(.qblk → `\\.\E:` 같은 비시스템 볼륨). 실제 디스크를 덮어쓰므로 안전장치를 모두 통과해야만 쓴다.
//!
//! 순서(어느 단계든 실패하면 볼륨에는 아무것도 쓰지 않는다): 먼저 이미지 전체 검증(`verify`),
//! 정책 검사(시스템·보호 볼륨, 크기), 사용자 확인 문구 대조, 볼륨 열기·잠금·마운트 해제
//! (잠금 실패는 사용 중이라는 뜻이므로 중단), 마지막으로 청크를 LCN 위치에 쓴다.
//! 파일 복원(`restore.rs`)과 달리 빈 구간을 0으로 채우지 않는다: NTFS 비트맵상 빈 클러스터라 정상 동작에는 영향이 없다(옛 데이터가 남을 수는 있음).
use crate::qblk::{restore_to, verify, Header, QblkError, Stats};
use std::fs::File;
use std::io::{self, BufReader, Seek, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;

#[derive(Debug)]
pub enum VolumeError {
    /// 정책·확인 문구·잠금 등으로 거부됨(볼륨에 쓰지 않음)
    Refused(String),
    Io(io::Error),
    Image(QblkError),
}
impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(s) => write!(f, "볼륨 복원 거부: {s}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Image(e) => write!(f, "{e}"),
        }
    }
}
impl From<io::Error> for VolumeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<QblkError> for VolumeError {
    fn from(e: QblkError) -> Self {
        Self::Image(e)
    }
}

/// 사용자에게 보여 주고 그대로 입력하게 할 볼륨 정보
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub letter: char,
    pub label: String,
    pub serial: u32,
}

/// 사용자가 직접 입력해야 하는 확인 문구: `E: 레이블 1A2B3C4D` (드라이브·레이블·시리얼이 모두 맞아야 한다)
pub fn confirmation_phrase(v: &VolumeInfo) -> String {
    format!(
        "{}: {} {:08X}",
        v.letter.to_ascii_uppercase(),
        v.label,
        v.serial
    )
}

pub fn check_confirmation(v: &VolumeInfo, typed: &str) -> Result<(), VolumeError> {
    let norm = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    if norm(typed) == norm(&confirmation_phrase(v)) {
        Ok(())
    } else {
        Err(VolumeError::Refused(
            "확인 문구가 일치하지 않음(드라이브·레이블·시리얼을 그대로 입력해야 함)".into(),
        ))
    }
}

/// 드라이브 문자만으로 거부할 수 있는 검사(순수 함수). 장치를 열기 전에 먼저 호출한다.
/// `protected`: 이미지·Kova 저장소·실행 파일이 있는 드라이브 문자.
pub fn check_letter(
    letter: char,
    system_drive: char,
    protected: &[char],
) -> Result<(), VolumeError> {
    let refuse = |why: String| Err(VolumeError::Refused(why));
    if !letter.is_ascii_alphabetic() {
        return refuse(format!("드라이브 문자가 아님: {letter:?}"));
    }
    let l = letter.to_ascii_uppercase();
    if l == system_drive.to_ascii_uppercase() {
        return refuse(format!(
            "{l}: 는 시스템 볼륨이라 실행 중에는 복원할 수 없음"
        ));
    }
    if protected.iter().any(|p| p.to_ascii_uppercase() == l) {
        return refuse(format!(
            "{l}: 에 이미지·저장소·실행 파일이 있어 대상이 될 수 없음"
        ));
    }
    Ok(())
}

/// 정책 검사(순수 함수): 드라이브 문자 검사와 대상 크기 검사.
pub fn check_policy(
    letter: char,
    system_drive: char,
    protected: &[char],
    volume_bytes: u64,
    header: &Header,
) -> Result<(), VolumeError> {
    check_letter(letter, system_drive, protected)?;
    let need = header
        .total_clusters
        .saturating_mul(header.cluster_size as u64);
    if volume_bytes < need {
        return Err(VolumeError::Refused(format!(
            "대상 볼륨이 이미지보다 작음(볼륨 {volume_bytes} < 필요 {need} 바이트)"
        )));
    }
    Ok(())
}

/// 볼륨 복원 진행 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePhase {
    Decrypt,
    Verify,
    Write,
}

/// 볼륨 복원 진행 상태(체인·암호화 복원용).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreProgress {
    pub phase: RestorePhase,
    pub link_index: usize,
    pub link_count: usize,
    pub stats: Stats,
}

fn combine_stats(base: &Stats, delta: &Stats, total_raw_bytes: u64) -> Stats {
    Stats {
        chunks: base.chunks + delta.chunks,
        clusters: base.clusters + delta.clusters,
        raw_bytes: base.raw_bytes + delta.raw_bytes,
        total_raw_bytes,
        compressed_bytes: base.compressed_bytes + delta.compressed_bytes,
        empty_chunks: base.empty_chunks + delta.empty_chunks,
        empty_clusters: base.empty_clusters + delta.empty_clusters,
        order_violations: base.order_violations + delta.order_violations,
    }
}

/// 핵심 흐름. 이미지 검증이 끝나기 전에는 `open` 을 호출하지 않으므로 깨진 이미지로는 장치를 열지도 않는다.
/// `open` 은 정책·확인 문구 검사와 장치 열기·잠금을 맡고, 실패하면 아무것도 쓰지 않은 채 오류를 돌려준다.
pub fn restore_verified<W: Write + Seek, F: FnOnce(&Header) -> Result<W, VolumeError>>(
    image: &Path,
    open: F,
    cancel: &AtomicBool,
    progress: &dyn Fn(&Stats),
) -> Result<(Header, Stats), VolumeError> {
    // 검증·복원에 같은 핸들을 쓴다: 검증 뒤 파일이 바뀌는 틈을 없애고, 이미지가 대상 볼륨에 있으면
    // 열린 핸들 때문에 잠금이 실패해(마운트 해제 전에) 중단된다.
    let mut f = File::open(image)?;
    // 진행 표시: 검증 단계는 total_raw_bytes 를 0 으로, 쓰기 단계는 예상 전체 바이트를 채워 보내 화면이 두 단계를 구분하게 한다
    let (header, _) = verify(BufReader::with_capacity(8 << 20, &f), cancel, &|s| {
        let mut t = s.clone();
        t.total_raw_bytes = 0;
        progress(&t)
    })?;
    f.rewind()?;
    let mut dev = open(&header)?;
    let expected = header
        .used_clusters
        .saturating_mul(header.cluster_size as u64)
        .max(1);
    let src = BufReader::with_capacity(8 << 20, &f);
    Ok(restore_to(src, &mut dev, cancel, &|s| {
        let mut t = s.clone();
        t.total_raw_bytes = expected;
        progress(&t)
    })?)
}

/// 풀+증분 체인의 모든 링크를 먼저 검증한 뒤 `open`으로 연 대상(`Write + Seek`)에 순서대로 쓴다.
/// 어느 한 링크라도 검증 또는 지오메트리(cluster_size·total_clusters) 검사에 실패하면 `open`을 호출하지 않는다.
pub fn restore_chain_to_volume_writer<
    W: Write + Seek,
    F: FnOnce(&Header) -> Result<W, VolumeError>,
>(
    image: &Path,
    open: F,
    cancel: &AtomicBool,
    progress: &dyn Fn(&RestoreProgress),
) -> Result<(Header, Stats), VolumeError> {
    let chain = crate::incremental::resolve_chain(image)?;
    if chain.is_empty() {
        return Err(QblkError::BadHeaderField("empty chain").into());
    }
    let mut files = Vec::with_capacity(chain.len());
    for p in &chain {
        files.push(File::open(p)?);
    }
    let link_count = files.len();
    let mut first_geom: Option<(u32, u64)> = None;
    let mut last_header: Option<Header> = None;
    let mut verify_accum = Stats::default();
    let mut total_expected: u64 = 0;

    for (idx, f) in files.iter().enumerate() {
        let (h, s) = verify(BufReader::with_capacity(8 << 20, f), cancel, &|cur| {
            progress(&RestoreProgress {
                phase: RestorePhase::Verify,
                link_index: idx,
                link_count,
                stats: combine_stats(&verify_accum, cur, 0),
            });
        })?;
        if let Some((cs, tc)) = first_geom {
            if h.cluster_size != cs || h.total_clusters != tc {
                return Err(QblkError::BadHeaderField("chain geometry mismatch").into());
            }
        } else {
            first_geom = Some((h.cluster_size, h.total_clusters));
        }
        verify_accum = combine_stats(&verify_accum, &s, 0);
        total_expected =
            total_expected.saturating_add(h.used_clusters.saturating_mul(h.cluster_size as u64));
        last_header = Some(h);
    }

    for f in &mut files {
        f.rewind()?;
    }
    let final_header = last_header.ok_or(QblkError::BadHeaderField("empty chain"))?;
    let mut dev = open(&final_header)?;

    let expected = total_expected.max(1);
    let mut write_accum = Stats::default();
    for (idx, f) in files.iter().enumerate() {
        let src = BufReader::with_capacity(8 << 20, f);
        let (_, s) = restore_to(src, &mut dev, cancel, &|cur| {
            progress(&RestoreProgress {
                phase: RestorePhase::Write,
                link_index: idx,
                link_count,
                stats: combine_stats(&write_accum, cur, expected),
            });
        })?;
        write_accum = combine_stats(&write_accum, &s, expected);
    }
    dev.flush()?;
    Ok((final_header, write_accum))
}

/// `\\?\E:\x` → `E:\x`, `\\?\UNC\srv\s` → `\\srv\s` (canonicalize 결과를 드라이브 문자로 비교할 수 있게).
fn normalize_path(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

/// 정규화한 경로의 드라이브 문자(대문자). UNC·상대 경로는 None.
fn drive_letter_of(p: &Path) -> Option<char> {
    let s = normalize_path(&p.to_string_lossy());
    let b = s.as_bytes();
    (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
        .then(|| (b[0] as char).to_ascii_uppercase())
}

fn is_unc(p: &Path) -> bool {
    normalize_path(&p.to_string_lossy()).starts_with(r"\\")
}

#[cfg(windows)]
pub use win::{
    restore_chain_to_volume, restore_encrypted_to_volume, restore_image_to_volume, volume_info,
};

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    extern "system" {
        fn DeviceIoControl(
            h: *mut core::ffi::c_void,
            code: u32,
            inb: *const u8,
            inlen: u32,
            outb: *mut u8,
            outlen: u32,
            ret: *mut u32,
            ov: *mut core::ffi::c_void,
        ) -> i32;
        fn GetVolumeInformationW(
            root: *const u16,
            name: *mut u16,
            name_len: u32,
            serial: *mut u32,
            max_comp: *mut u32,
            flags: *mut u32,
            fs_name: *mut u16,
            fs_len: u32,
        ) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetVolumePathNameW(file: *const u16, out: *mut u16, len: u32) -> i32;
        fn GetVolumeNameForVolumeMountPointW(mp: *const u16, out: *mut u16, len: u32) -> i32;
    }
    const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn ioctl(f: &File, code: u32, out: &mut [u8]) -> bool {
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                f.as_raw_handle() as *mut _,
                code,
                std::ptr::null(),
                0,
                if out.is_empty() {
                    std::ptr::null_mut()
                } else {
                    out.as_mut_ptr()
                },
                out.len() as u32,
                &mut ret,
                std::ptr::null_mut(),
            ) != 0
        }
    }

    /// 드라이브 문자의 레이블·시리얼과 종류(고정/이동식만 허용)를 읽는다.
    pub fn volume_info(letter: char) -> Result<VolumeInfo, VolumeError> {
        let l = letter.to_ascii_uppercase();
        let root = wide(&format!("{l}:\\"));
        let t = unsafe { GetDriveTypeW(root.as_ptr()) };
        if t != DRIVE_FIXED && t != DRIVE_REMOVABLE {
            return Err(VolumeError::Refused(format!(
                "{l}: 는 고정·이동식 디스크가 아님(종류 코드 {t})"
            )));
        }
        let mut name = [0u16; 262];
        let mut serial = 0u32;
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                name.as_mut_ptr(),
                name.len() as u32,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        if ok == 0 {
            return Err(VolumeError::Io(io::Error::last_os_error()));
        }
        let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        Ok(VolumeInfo {
            letter: l,
            label: String::from_utf16_lossy(&name[..n]),
            serial,
        })
    }

    fn from_wide(buf: &[u16]) -> String {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..n])
    }

    /// 마운트 지점(`E:\` 또는 폴더 마운트)의 볼륨 GUID 경로(`\\?\Volume{..}\`).
    fn guid_of_mount_point(mp: &str) -> Option<String> {
        let w = wide(mp);
        let mut out = [0u16; 128];
        let ok = unsafe {
            GetVolumeNameForVolumeMountPointW(w.as_ptr(), out.as_mut_ptr(), out.len() as u32)
        };
        (ok != 0).then(|| from_wide(&out).to_ascii_uppercase())
    }

    /// 파일이 실제로 들어 있는 볼륨의 GUID. 링크·폴더 마운트를 따라간다(canonicalize → GetVolumePathName).
    pub(super) fn volume_guid_of(p: &Path) -> Option<String> {
        let c = std::fs::canonicalize(p).ok()?;
        let w = wide(&c.to_string_lossy());
        let mut out = [0u16; 1024];
        let ok = unsafe { GetVolumePathNameW(w.as_ptr(), out.as_mut_ptr(), out.len() as u32) };
        if ok == 0 {
            return None;
        }
        let mut mp = normalize_path(&from_wide(&out));
        if !mp.ends_with('\\') {
            mp.push('\\');
        }
        guid_of_mount_point(&mp)
    }

    fn system_drive() -> char {
        std::env::var("SystemDrive")
            .ok()
            .and_then(|s| s.chars().next())
            .unwrap_or('C')
    }

    fn collect_protected_letters(extra_letters: &[char], paths: &[&Path]) -> Vec<char> {
        let mut prot: Vec<char> = extra_letters.to_vec();
        let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        for p in paths {
            prot.extend(drive_letter_of(&real(p)));
            prot.extend(drive_letter_of(p));
        }
        prot.extend(
            std::env::current_exe()
                .ok()
                .map(|e| real(&e))
                .as_deref()
                .and_then(drive_letter_of),
        );
        prot
    }

    /// 대상 볼륨이 이미지·보호 경로·실행 파일이 실제로 있는 볼륨과 같은지 GUID로 확인한다(폴더 마운트·링크 대비).
    fn check_paths_not_on_volume(
        letter: char,
        required_sources: &[&Path],
        extra_protected: &[&Path],
    ) -> Result<(), VolumeError> {
        let target = guid_of_mount_point(&format!("{letter}:\\")).ok_or_else(|| {
            VolumeError::Refused(format!("{letter}: 의 볼륨 ID를 확인할 수 없음"))
        })?;
        for src in required_sources {
            match volume_guid_of(src) {
                Some(g) if g == target => {
                    return Err(VolumeError::Refused(format!(
                        "이미지가 대상 볼륨 {letter}: 안에 있음"
                    )));
                }
                None if !is_unc(src) => {
                    return Err(VolumeError::Refused(
                        "이미지가 있는 볼륨을 확인할 수 없음".into(),
                    ));
                }
                _ => {}
            }
        }
        for p in extra_protected {
            if volume_guid_of(p).as_deref() == Some(target.as_str()) {
                return Err(VolumeError::Refused(format!(
                    "보호 경로가 대상 볼륨 {letter}: 안에 있음"
                )));
            }
        }
        if let Some(g) = std::env::current_exe()
            .ok()
            .and_then(|e| volume_guid_of(&e))
        {
            if g == target {
                return Err(VolumeError::Refused(format!(
                    "실행 중인 프로그램이 대상 볼륨 {letter}: 에 있음"
                )));
            }
        }
        Ok(())
    }

    fn open_locked_volume(
        letter: char,
        typed: &str,
        prot: &[char],
        required_sources: &[&Path],
        extra_protected: &[&Path],
        header: &Header,
    ) -> Result<Flush, VolumeError> {
        let system = system_drive();
        // 문자만으로 거부할 수 있는 건 장치를 열기 전에 거부한다
        check_letter(letter, system, prot)?;
        let info = volume_info(letter)?;
        check_paths_not_on_volume(info.letter, required_sources, extra_protected)?;
        let dev_path = format!(r"\\.\{}:", info.letter);
        // 크기·확인 문구를 통과하기 전에는 쓰기 권한 핸들을 만들지 않는다(읽기 전용으로 크기만 조회)
        let probe = OpenOptionsExt::share_mode(
            std::fs::OpenOptions::new().read(true),
            3, // FILE_SHARE_READ | FILE_SHARE_WRITE
        )
        .open(&dev_path)?;
        let mut len = [0u8; 8];
        if !ioctl(&probe, IOCTL_DISK_GET_LENGTH_INFO, &mut len) {
            return Err(VolumeError::Io(io::Error::last_os_error()));
        }
        let volume_bytes = u64::try_from(i64::from_le_bytes(len))
            .map_err(|_| VolumeError::Refused("음수 볼륨 크기".into()))?;
        check_policy(info.letter, system, prot, volume_bytes, header)?;
        check_confirmation(&info, typed)?;
        drop(probe);
        let dev = OpenOptionsExt::share_mode(std::fs::OpenOptions::new().read(true).write(true), 3)
            .open(&dev_path)?;
        // 잠금 실패 = 파일이 열려 있거나 페이지 파일 등 사용 중 → 쓰지 않고 중단
        if !ioctl(&dev, FSCTL_LOCK_VOLUME, &mut []) {
            return Err(VolumeError::Refused(format!(
                "{}: 를 잠글 수 없음(사용 중인 파일이 있음): {}",
                info.letter,
                io::Error::last_os_error()
            )));
        }
        if !ioctl(&dev, FSCTL_DISMOUNT_VOLUME, &mut []) {
            return Err(VolumeError::Refused(format!(
                "{}: 마운트 해제 실패: {}",
                info.letter,
                io::Error::last_os_error()
            )));
        }
        Ok(Flush(dev))
    }

    /// `letter` 볼륨에 image 를 직접 쓴다. `typed` 는 `confirmation_phrase(volume_info(letter))` 와 같아야 한다.
    /// `protected`: 대상이 될 수 없는 드라이브(Kova 저장소 등). 이미지·실행 파일·시스템 드라이브는 자동으로 보호된다.
    pub fn restore_image_to_volume(
        image: &Path,
        letter: char,
        typed: &str,
        protected: &[char],
        cancel: &AtomicBool,
        progress: &dyn Fn(&Stats),
    ) -> Result<(Header, Stats), VolumeError> {
        restore_verified(
            image,
            |header| {
                let prot = collect_protected_letters(protected, &[image]);
                open_locked_volume(letter, typed, &prot, &[image], &[], header)
            },
            cancel,
            progress,
        )
    }

    /// 풀+증분 `.qblk` 체인 전체를 검증한 뒤 대상 볼륨을 한 번 잠금·마운트 해제하고 `[base, inc1, ..., target]` 순으로 기록한다.
    pub fn restore_chain_to_volume(
        image: &Path,
        letter: char,
        typed_confirmation: &str,
        protected_paths: &[&Path],
        cancel: &AtomicBool,
        progress: &dyn Fn(&RestoreProgress),
    ) -> Result<(Header, Stats), VolumeError> {
        restore_chain_to_volume_writer(
            image,
            |header| {
                let mut all_paths: Vec<&Path> = Vec::with_capacity(protected_paths.len() + 1);
                all_paths.push(image);
                all_paths.extend_from_slice(protected_paths);
                let prot = collect_protected_letters(&[], &all_paths);
                open_locked_volume(
                    letter,
                    typed_confirmation,
                    &prot,
                    &[image],
                    protected_paths,
                    header,
                )
            },
            cancel,
            progress,
        )
    }

    struct TempFileGuard(std::path::PathBuf);
    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// 암호화된 `.qblk.enc` 이미지를 임시 폴더에 스트리밍 복호화한 뒤 대상 볼륨에 복원한다.
    /// 복호화 전에 `check_letter`, `volume_info`, `check_confirmation`을 먼저 검증하고 임시 평문 파일은 종료 시 반드시 삭제한다.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_encrypted_to_volume(
        image_enc: &Path,
        key: &[u8; 32],
        letter: char,
        typed_confirmation: &str,
        protected_paths: &[&Path],
        temp_dir: &Path,
        cancel: &AtomicBool,
        progress: &dyn Fn(&RestoreProgress),
    ) -> Result<(Header, Stats), VolumeError> {
        let mut all_paths: Vec<&Path> = Vec::with_capacity(protected_paths.len() + 2);
        all_paths.push(image_enc);
        all_paths.push(temp_dir);
        all_paths.extend_from_slice(protected_paths);
        let prot = collect_protected_letters(&[], &all_paths);
        let system = system_drive();
        // 대용량 복호화 전에 드라이브·볼륨·확인 문구를 먼저 검증한다(fail-fast).
        check_letter(letter, system, &prot)?;
        let info = volume_info(letter)?;
        check_paths_not_on_volume(info.letter, &[image_enc], protected_paths)?;
        if let Some(target_guid) = guid_of_mount_point(&format!("{}:\\", info.letter)) {
            if volume_guid_of(temp_dir).as_deref() == Some(target_guid.as_str()) {
                return Err(VolumeError::Refused(format!(
                    "임시 복호화 폴더가 대상 볼륨 {}: 안에 있음",
                    info.letter
                )));
            }
        }
        check_confirmation(&info, typed_confirmation)?;

        std::fs::create_dir_all(temp_dir)?;
        let mut rand_bytes = [0u8; 8];
        getrandom::getrandom(&mut rand_bytes)
            .map_err(|e| VolumeError::Io(io::Error::other(e.to_string())))?;
        let rand_u64 = u64::from_le_bytes(rand_bytes);
        static DEC_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = DEC_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_path = temp_dir.join(format!(
            "kova_dec_{}_{}_{:016x}.qblk",
            std::process::id(),
            seq,
            rand_u64
        ));
        let guard = TempFileGuard(tmp_path);

        progress(&RestoreProgress {
            phase: RestorePhase::Decrypt,
            link_index: 0,
            link_count: 1,
            stats: Stats::default(),
        });

        crate::crypto::decrypt_file(image_enc, &guard.0, key, cancel).map_err(|e| match e {
            crate::crypto::ImageCryptoError::Io(io_err) => VolumeError::Io(io_err),
            crate::crypto::ImageCryptoError::Cancelled => VolumeError::Image(QblkError::Cancelled),
            other => VolumeError::Refused(other.to_string()),
        })?;

        restore_image_to_volume(&guard.0, letter, typed_confirmation, &prot, cancel, &|s| {
            let phase = if s.total_raw_bytes == 0 {
                RestorePhase::Verify
            } else {
                RestorePhase::Write
            };
            progress(&RestoreProgress {
                phase,
                link_index: 0,
                link_count: 1,
                stats: s.clone(),
            });
        })
    }

    /// 쓰기를 마치고 닫기 전에 장치 버퍼를 비운다(`flush` 가 호출될 때마다 `sync_all`).
    struct Flush(File);
    impl Write for Flush {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.sync_all()
        }
    }
    impl Seek for Flush {
        fn seek(&mut self, p: io::SeekFrom) -> io::Result<u64> {
            self.0.seek(p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::restore_image_to_file;
    use std::cell::Cell;
    use std::fs;

    const PY: &[u8] = include_bytes!("../tests/fixtures/py_small.qblk");

    fn hdr() -> Header {
        let d = tempfile::tempdir().unwrap();
        let img = d.path().join("p.qblk");
        fs::write(&img, PY).unwrap();
        verify(File::open(&img).unwrap(), &AtomicBool::new(false), &|_| {})
            .unwrap()
            .0
    }

    #[test]
    fn policy_refuses_system_protected_small_and_non_letters() {
        let h = hdr();
        let need = h.total_clusters * h.cluster_size as u64;
        assert!(check_policy('E', 'C', &['D'], need, &h).is_ok());
        assert!(check_policy('e', 'C', &['D'], need + 1, &h).is_ok());
        for (l, sys, prot, size) in [
            ('C', 'C', vec![], need),
            ('c', 'C', vec![], need),
            ('D', 'C', vec!['d'], need),
            ('E', 'C', vec![], need - 1),
            ('1', 'C', vec![], need),
            (':', 'C', vec![], need),
        ] {
            assert!(
                matches!(
                    check_policy(l, sys, &prot, size, &h),
                    Err(VolumeError::Refused(_))
                ),
                "{l} {sys} {prot:?} {size}"
            );
        }
    }

    #[test]
    fn protected_paths_are_normalized_before_taking_the_drive_letter() {
        for (p, want) in [
            (r"E:\images\a.qblk", Some('E')),
            (r"e:\a.qblk", Some('E')),
            (r"\\?\E:\images\a.qblk", Some('E')),
            (r"\\?\d:\x", Some('D')),
            (r"\\?\UNC\srv\share\a.qblk", None),
            (r"\\srv\share\a.qblk", None),
            (r"images\a.qblk", None),
        ] {
            assert_eq!(drive_letter_of(Path::new(p)), want, "{p}");
        }
        assert!(is_unc(Path::new(r"\\?\UNC\srv\share\a")));
        assert!(is_unc(Path::new(r"\\srv\share\a")));
        assert!(!is_unc(Path::new(r"\\?\E:\a")));
        assert_eq!(normalize_path(r"\\?\UNC\srv\s\a"), r"\\srv\s\a");
    }

    #[cfg(windows)]
    #[test]
    fn file_volume_guid_matches_its_drive_root() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("x.qblk");
        fs::write(&f, b"x").unwrap();
        let l = drive_letter_of(&fs::canonicalize(&f).unwrap()).unwrap();
        let g = win::volume_guid_of(&f).expect("볼륨 GUID");
        assert!(g.starts_with(r"\\?\VOLUME{"), "{g}");
        assert_eq!(Some(g), win::volume_guid_of(Path::new(&format!("{l}:\\"))));
    }

    #[test]
    fn confirmation_needs_letter_label_and_serial() {
        let v = VolumeInfo {
            letter: 'e',
            label: "백업 디스크".into(),
            serial: 0x1A2B3C4D,
        };
        assert_eq!(confirmation_phrase(&v), "E: 백업 디스크 1A2B3C4D");
        assert!(check_confirmation(&v, "E: 백업 디스크 1A2B3C4D").is_ok());
        assert!(check_confirmation(&v, "  e:  백업 디스크  1a2b3c4d ").is_ok());
        for bad in [
            "",
            "E:",
            "F: 백업 디스크 1A2B3C4D",
            "E: 백업 디스크 1A2B3C4E",
            "E: 다른 1A2B3C4D",
        ] {
            assert!(
                matches!(check_confirmation(&v, bad), Err(VolumeError::Refused(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn writes_same_bytes_as_file_restore_into_preallocated_device() {
        let d = tempfile::tempdir().unwrap();
        let img = d.path().join("p.qblk");
        fs::write(&img, PY).unwrap();
        let want = d.path().join("want.img");
        let (h, _) = restore_image_to_file(&img, &want, &AtomicBool::new(false), &|_| {}).unwrap();
        // 장치처럼 이미 같은 크기로 존재하는(옛 데이터가 든) 파일에 쓴다
        let dev_path = d.path().join("dev.img");
        let full = h.total_clusters * h.cluster_size as u64;
        fs::write(&dev_path, vec![0xAAu8; full as usize]).unwrap();
        let dev = fs::OpenOptions::new().write(true).open(&dev_path).unwrap();
        let (_, st) =
            restore_verified(&img, |_| Ok(dev), &AtomicBool::new(false), &|_| {}).unwrap();
        assert_eq!(st.clusters, 6);
        let (got, exp) = (fs::read(&dev_path).unwrap(), fs::read(&want).unwrap());
        assert_eq!(got.len(), exp.len());
        // 이미지가 쓴 클러스터는 정확히 같고, 쓰지 않은 구간은 옛 데이터(0xAA)가 그대로 남는다
        let cs = h.cluster_size as usize;
        let mut written = 0;
        for (g, e) in got.chunks(cs).zip(exp.chunks(cs)) {
            if e.iter().any(|&b| b != 0) {
                assert_eq!(g, e);
                written += 1;
            } else {
                assert!(g == e || g.iter().all(|&b| b == 0xAA));
            }
        }
        assert!(written > 0);
    }

    #[test]
    fn progress_tells_verify_phase_from_write_phase() {
        use std::sync::Mutex;
        let d = tempfile::tempdir().unwrap();
        let img = d.path().join("p.qblk");
        fs::write(&img, PY).unwrap();
        let (h, _) = restore_image_to_file(
            &img,
            &d.path().join("w.img"),
            &AtomicBool::new(false),
            &|_| {},
        )
        .unwrap();
        let dev_path = d.path().join("dev.img");
        fs::write(
            &dev_path,
            vec![0u8; (h.total_clusters * h.cluster_size as u64) as usize],
        )
        .unwrap();
        let dev = fs::OpenOptions::new().write(true).open(&dev_path).unwrap();
        let seen = Mutex::new(Vec::<u64>::new());
        restore_verified(&img, |_| Ok(dev), &AtomicBool::new(false), &|s| {
            seen.lock().unwrap().push(s.total_raw_bytes)
        })
        .unwrap();
        let seen = seen.into_inner().unwrap();
        // 검증 단계(0)가 먼저, 그다음 쓰기 단계(0 이 아닌 예상 전체 바이트)
        assert_eq!(seen.first(), Some(&0));
        let first_write = seen
            .iter()
            .position(|&t| t > 0)
            .expect("쓰기 단계 진행 없음");
        assert!(seen[..first_write].iter().all(|&t| t == 0));
        assert!(seen[first_write..].iter().all(|&t| t > 0));
    }

    #[test]
    fn broken_image_never_opens_the_device_and_refusal_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let bad = d.path().join("bad.qblk");
        let mut b = PY.to_vec();
        let n = b.len();
        b[n - 5] ^= 0xFF;
        fs::write(&bad, b).unwrap();
        let opened = Cell::new(false);
        let r = restore_verified::<fs::File, _>(
            &bad,
            |_| {
                opened.set(true);
                Err(VolumeError::Refused("x".into()))
            },
            &AtomicBool::new(false),
            &|_| {},
        );
        assert!(matches!(r, Err(VolumeError::Image(_))));
        assert!(!opened.get(), "검증 실패 전에 장치를 열면 안 됨");

        let good = d.path().join("good.qblk");
        fs::write(&good, PY).unwrap();
        let r = restore_verified::<fs::File, _>(
            &good,
            |_| Err(VolumeError::Refused("정책".into())),
            &AtomicBool::new(false),
            &|_| {},
        );
        assert!(matches!(r, Err(VolumeError::Refused(_))));
    }

    #[test]
    fn restore_chain_to_volume_writer_restores_two_link_chain_exact_bytes() {
        use crate::incremental::{
            save_block_map, save_chain_meta, write_incremental_image, BlockMap, ChainMeta,
        };
        use std::collections::BTreeMap;
        use std::io::Cursor;
        use std::sync::Mutex;

        let d = tempfile::tempdir().unwrap();
        let cs = 4096usize;
        let total_clusters = 8u64;
        let bitmap = [0xFFu8];
        let mut disk = vec![0u8; cs * total_clusters as usize];
        for i in 0..8 {
            disk[i * cs..(i + 1) * cs].fill((i as u8) + 10);
        }
        let no = AtomicBool::new(false);
        let h_tmpl = Header {
            version: crate::qblk::VERSION,
            cluster_size: cs as u32,
            total_clusters,
            used_clusters: 0,
            vsn: "1234-5678".into(),
            source_label: "VOL".into(),
        };

        // Link 0: base (2-cluster blocks)
        let base_path = d.path().join("base.qblk");
        let base_map = {
            let f = File::create(&base_path).unwrap();
            let seed = BlockMap {
                version: 2,
                cluster_size: cs as u32,
                total_clusters,
                block_clusters: 2,
                hashes: BTreeMap::new(),
            };
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h_tmpl.clone(),
                &bitmap,
                Some(&seed),
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 8);
            save_block_map(&base_path, &map).unwrap();
            map
        };

        // Link 1: inc modifying clusters 2..4 and 6..8
        disk[2 * cs..4 * cs].fill(0xCC);
        disk[6 * cs..8 * cs].fill(0xDD);
        let inc_path = d.path().join("inc1.qblk");
        {
            let f = File::create(&inc_path).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h_tmpl.clone(),
                &bitmap,
                Some(&base_map),
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 4);
            assert_eq!(inc.skipped_clusters, 4);
            save_block_map(&inc_path, &map).unwrap();
            save_chain_meta(
                &inc_path,
                &ChainMeta {
                    version: 1,
                    parent: "base.qblk".into(),
                    changed_clusters: inc.changed_clusters,
                    skipped_clusters: inc.skipped_clusters,
                },
            )
            .unwrap();
        }

        // Target preallocated volume file with stale bytes
        let dev_path = d.path().join("target_vol.img");
        fs::write(&dev_path, vec![0x55u8; cs * total_clusters as usize]).unwrap();
        let open_count = Cell::new(0usize);
        let phases = Mutex::new(Vec::<(RestorePhase, usize, usize)>::new());

        let (hdr, st) = restore_chain_to_volume_writer(
            &inc_path,
            |_| {
                open_count.set(open_count.get() + 1);
                Ok(fs::OpenOptions::new().write(true).open(&dev_path).unwrap())
            },
            &no,
            &|p| {
                phases
                    .lock()
                    .unwrap()
                    .push((p.phase, p.link_index, p.link_count));
            },
        )
        .unwrap();

        assert_eq!(open_count.get(), 1, "볼륨 장치는 한 번만 열어야 함");
        assert_eq!(hdr.total_clusters, total_clusters);
        assert_eq!(st.clusters, 12); // 8(base) + 4(inc1)
        assert_eq!(fs::read(&dev_path).unwrap(), disk);

        let phases = phases.into_inner().unwrap();
        let first_write = phases
            .iter()
            .position(|(ph, _, _)| *ph == RestorePhase::Write)
            .expect("Write 단계 진행 보고가 있어야 함");
        assert!(first_write > 0);
        assert!(phases[..first_write]
            .iter()
            .all(|(ph, _, cnt)| *ph == RestorePhase::Verify && *cnt == 2));
        assert!(phases[first_write..]
            .iter()
            .all(|(ph, _, cnt)| *ph == RestorePhase::Write && *cnt == 2));
    }
}

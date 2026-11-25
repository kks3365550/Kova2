//! Windows 확장 길이 경로(`\\?\...`, `\\?\UNC\...`) 변환 및 제거 유틸리티.
//! Win32 기본 `MAX_PATH`(260자) 제한을 넘는 깊은 폴더·파일을 안전하게 열고 쓰기 위해 사용한다.

use std::path::{Path, PathBuf};

/// 이 길이(UTF-16 코드 단위) 이상인 절대 경로에 자동으로 `\\?\` 접두사를 붙인다.
#[cfg(windows)]
const LONG_PATH_THRESHOLD: usize = 240;

/// Windows에서 경로 길이가 240자 이상인 절대 경로(드라이브·UNC)를 확장 길이 경로로 변환한다.
/// 이미 `\\?\` 또는 `\\.\` 접두사가 있거나 상대 경로면 그대로 돌려준다.
/// 비-Windows 플랫폼에서는 입력 경로를 그대로 돌려준다.
pub fn to_extended(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        to_extended_inner(path, false)
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// Windows에서 길이에 관계없이 드라이브·UNC 절대 경로를 확장 길이 경로(`\\?\...`)로 변환한다.
/// 깊은 하위 트리를 탐색할 때(`WalkDir` 등) 시작 루트가 짧아도 하위에서 260자를 넘지 않도록 쓴다.
/// 이미 `\\?\` 또는 `\\.\` 접두사가 있거나 상대 경로면 그대로 돌려준다.
pub fn to_extended_always(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        to_extended_inner(path, true)
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn to_extended_inner(path: &Path, always: bool) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Prefix};

    let mut comps = path.components();
    let prefix = match comps.next() {
        Some(Component::Prefix(p)) => p,
        _ => return path.to_path_buf(),
    };

    match prefix.kind() {
        Prefix::Verbatim(_)
        | Prefix::VerbatimUNC(_, _)
        | Prefix::VerbatimDisk(_)
        | Prefix::DeviceNS(_) => path.to_path_buf(),
        Prefix::Disk(drive) => {
            // 드라이브 상대 경로(`C:foo`)는 건드리지 않는다.
            if !matches!(comps.next(), Some(Component::RootDir)) {
                return path.to_path_buf();
            }
            let stack = normalize_tail(comps);
            let mut norm = OsString::from(format!("{}:\\", drive as char));
            append_segments(&mut norm, &stack);

            if !always && norm.encode_wide().count() < LONG_PATH_THRESHOLD {
                return path.to_path_buf();
            }

            let mut ext = OsString::from(r"\\?\");
            ext.push(&norm);
            PathBuf::from(ext)
        }
        Prefix::UNC(server, share) => {
            let stack = normalize_tail(comps);
            let mut norm = OsString::from(r"\\");
            norm.push(server);
            norm.push(r"\");
            norm.push(share);
            if !stack.is_empty() {
                norm.push(r"\");
                append_segments(&mut norm, &stack);
            }

            if !always && norm.encode_wide().count() < LONG_PATH_THRESHOLD {
                return path.to_path_buf();
            }

            let mut ext = OsString::from(r"\\?\UNC\");
            ext.push(server);
            ext.push(r"\");
            ext.push(share);
            if !stack.is_empty() {
                ext.push(r"\");
                append_segments(&mut ext, &stack);
            }
            PathBuf::from(ext)
        }
    }
}

#[cfg(windows)]
fn normalize_tail<'a>(comps: std::path::Components<'a>) -> Vec<&'a std::ffi::OsStr> {
    use std::path::Component;

    let mut stack: Vec<&'a std::ffi::OsStr> = Vec::new();
    for c in comps {
        match c {
            Component::Normal(seg) => stack.push(seg),
            Component::ParentDir => {
                stack.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    stack
}

#[cfg(windows)]
fn append_segments(buf: &mut std::ffi::OsString, segments: &[&std::ffi::OsStr]) {
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            buf.push(r"\");
        }
        buf.push(seg);
    }
}

/// 표시·`strip_prefix` 용으로 확장 길이 접두사(`\\?\UNC\` → `\\`, `\\?\` → ``)를 제거한다.
/// `\\.\` 장치 경로는 건드리지 않는다.
pub fn strip_extended(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        const EXT_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        if wide.starts_with(&EXT_PREFIX) {
            let rest = &wide[4..];
            if rest.len() >= 4
                && (rest[0] == b'U' as u16 || rest[0] == b'u' as u16)
                && (rest[1] == b'N' as u16 || rest[1] == b'n' as u16)
                && (rest[2] == b'C' as u16 || rest[2] == b'c' as u16)
                && rest[3] == b'\\' as u16
            {
                let mut unc = Vec::with_capacity(rest.len() - 2);
                unc.push(b'\\' as u16);
                unc.push(b'\\' as u16);
                unc.extend_from_slice(&rest[4..]);
                return PathBuf::from(OsString::from_wide(&unc));
            }
            // `\\?\GLOBALROOT\Device\...`(VSS 섀도 장치 경로) 같은 비-드라이브 경로는 접두사가 있어야 열린다
            let is_drive = rest.len() >= 2
                && rest[0] < 128
                && (rest[0] as u8).is_ascii_alphabetic()
                && rest[1] == b':' as u16;
            if !is_drive {
                return path.to_path_buf();
            }
            return PathBuf::from(OsString::from_wide(rest));
        }
        path.to_path_buf()
    }
    #[cfg(not(windows))]
    {
        if let Some(s) = path.to_str() {
            if let Some(rest) = s.strip_prefix(r"\\?\") {
                if rest.len() >= 4
                    && rest[..3].eq_ignore_ascii_case("UNC")
                    && rest.as_bytes()[3] == b'\\'
                {
                    return PathBuf::from(format!(r"\\{}", &rest[4..]));
                }
                let b = rest.as_bytes();
                if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                    return PathBuf::from(rest);
                }
                return path.to_path_buf();
            }
        }
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_extended_roundtrip_and_device_paths() {
        assert_eq!(
            strip_extended(Path::new(r"\\?\C:\Users\test\file.txt")),
            PathBuf::from(r"C:\Users\test\file.txt")
        );
        assert_eq!(
            strip_extended(Path::new(r"\\?\UNC\server\share\dir\file.txt")),
            PathBuf::from(r"\\server\share\dir\file.txt")
        );
        // VSS 섀도 장치 경로는 접두사를 벗기면 열 수 없으므로 그대로 둔다
        assert_eq!(
            strip_extended(Path::new(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\a.txt"
            )),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\a.txt")
        );
        assert_eq!(
            strip_extended(Path::new(r"\\.\PhysicalDrive0")),
            PathBuf::from(r"\\.\PhysicalDrive0")
        );
        assert_eq!(
            strip_extended(Path::new(r"C:\short\a.txt")),
            PathBuf::from(r"C:\short\a.txt")
        );
    }

    #[cfg(windows)]
    #[test]
    fn to_extended_handles_short_long_drive_unc_device_and_relative() {
        // 짧은 드라이브 경로는 변경하지 않는다
        let short = Path::new(r"C:\Users\test\doc.txt");
        assert_eq!(to_extended(short), short);

        // 250자 초과 드라이브 경로는 \\?\ 접두사를 붙이고 . / .. 를 정규화한다
        let seg = "a".repeat(60);
        let long_drive_raw = format!(r"C:\root\.\drop\..\{seg}\{seg}\{seg}\{seg}\file.txt");
        let expected_clean = format!(r"C:\root\{seg}\{seg}\{seg}\{seg}\file.txt");
        assert!(expected_clean.len() > 250);
        let ext_drive = to_extended(Path::new(&long_drive_raw));
        assert_eq!(ext_drive, PathBuf::from(format!(r"\\?\{expected_clean}")));
        assert_eq!(strip_extended(&ext_drive), PathBuf::from(&expected_clean));

        // 250자 초과 UNC 경로는 \\?\UNC\ 접두사를 붙인다
        let long_unc = format!(r"\\filesrv\backup\{seg}\{seg}\{seg}\{seg}\data.bin");
        assert!(long_unc.len() > 250);
        let ext_unc = to_extended(Path::new(&long_unc));
        assert_eq!(
            ext_unc,
            PathBuf::from(format!(
                r"\\?\UNC\filesrv\backup\{seg}\{seg}\{seg}\{seg}\data.bin"
            ))
        );
        assert_eq!(strip_extended(&ext_unc), PathBuf::from(&long_unc));

        // 장치 경로(\\.\)와 이미 확장된 경로(\\?\)는 건드리지 않는다
        let device = format!(r"\\.\Volume\{{{seg}{seg}{seg}{seg}}}");
        assert_eq!(to_extended(Path::new(&device)), PathBuf::from(&device));
        let already = PathBuf::from(format!(r"\\?\{expected_clean}"));
        assert_eq!(to_extended(&already), already);

        // 상대 경로는 길어도 건드리지 않는다
        let rel = format!(r"sub\{seg}\{seg}\{seg}\{seg}\rel.txt");
        assert!(rel.len() > 250);
        assert_eq!(to_extended(Path::new(&rel)), PathBuf::from(&rel));

        // to_extended_always 는 짧은 절대 경로에도 \\?\ 를 붙인다
        assert_eq!(
            to_extended_always(short),
            PathBuf::from(r"\\?\C:\Users\test\doc.txt")
        );
        assert_eq!(
            to_extended_always(Path::new(r"\\srv\share\a.txt")),
            PathBuf::from(r"\\?\UNC\srv\share\a.txt")
        );
    }
}

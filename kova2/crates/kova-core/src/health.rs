//! 디스크 건강·BitLocker 점검(읽기 전용). 결과는 그대로 문장으로 돌려주며, 실패해도 진단을 막지 않는다.

/// 콘솔 명령 출력 바이트를 문자열로 복호화한다.
/// 유효한 UTF-8 이면 그대로 쓰고, 아니면 Windows 에서는 현재 OEM 코드페이지(CP949 등)로 변환한다.
pub(crate) fn decode_console_output(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    #[cfg(windows)]
    if let Some(s) = decode_oem_cp(bytes) {
        return s;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn decode_oem_cp(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    let in_len = i32::try_from(bytes.len()).ok()?;
    const CP_OEMCP: u32 = 1;
    #[link(name = "kernel32")]
    extern "system" {
        fn MultiByteToWideChar(
            code_page: u32,
            dw_flags: u32,
            lp_multi_byte_str: *const u8,
            cb_multi_byte: i32,
            lp_wide_char_str: *mut u16,
            cch_wide_char: i32,
        ) -> i32;
    }
    let needed = unsafe {
        MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), in_len, std::ptr::null_mut(), 0)
    };
    if needed <= 0 {
        return None;
    }
    let mut wide = vec![0u16; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            in_len,
            wide.as_mut_ptr(),
            needed,
        )
    };
    if written <= 0 {
        return None;
    }
    wide.truncate(written as usize);
    Some(String::from_utf16_lossy(&wide))
}

#[cfg(windows)]
fn ps(script: &str) -> String {
    use std::os::windows::process::CommandExt;
    let full = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8;{script}");
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &full])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output();
    match out {
        Ok(o) if o.status.success() => decode_console_output(&o.stdout).trim().to_string(),
        Ok(o) => format!(
            "(조회 실패: {})",
            decode_console_output(&o.stderr)
                .trim()
                .lines()
                .next()
                .unwrap_or("")
        ),
        Err(e) => format!("(PowerShell 실행 실패: {e})"),
    }
}

#[cfg(not(windows))]
fn ps(_script: &str) -> String {
    "(Windows에서만 조회합니다)".into()
}

/// 물리 디스크의 건강·운영 상태.
pub fn disks() -> String {
    ps("Get-PhysicalDisk | ForEach-Object { '{0} | {1} | 건강={2} | 상태={3} | {4:N0} GB' -f $_.FriendlyName, $_.MediaType, $_.HealthStatus, $_.OperationalStatus, ($_.Size/1GB) }")
}

/// 볼륨별 BitLocker 보호 상태(관리자 권한이 아니면 조회가 거부될 수 있다).
pub fn bitlocker() -> String {
    ps("Get-BitLockerVolume | ForEach-Object { '{0} | 보호={1} | 암호화={2}%' -f $_.MountPoint, $_.ProtectionStatus, $_.EncryptionPercentage }")
}

pub fn report() -> String {
    format!(
        "[디스크 건강]\n{}\n\n[BitLocker]\n{}\n",
        disks(),
        bitlocker()
    )
}

/// 48자리 BitLocker 숫자 복구 암호 형식 검사 (6자리 숫자 8블록, '-' 구분, 총 55자)
pub fn is_bitlocker_password(token: &str) -> bool {
    let t = token.trim();
    if t.len() != 55 {
        return false;
    }
    let parts: Vec<&str> = t.split('-').collect();
    if parts.len() != 8 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 6 && p.chars().all(|c| c.is_ascii_digit()))
}

/// BitLocker 복구 키 정보 (암호 및 선택적 GUID)
/// 보안 강화: Debug 출력 시 48자리 민감 복구 키는 [REDACTED]로 마스킹하여 로그 누출을 원천 차단한다.
#[derive(Clone, PartialEq, Eq)]
pub struct BitLockerKeyInfo {
    pub key: String,
    pub id: Option<String>,
}

impl std::fmt::Debug for BitLockerKeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitLockerKeyInfo")
            .field("key", &"[REDACTED]")
            .field("id", &self.id)
            .finish()
    }
}

/// manage-bde.exe 출력 문자열에서 48자리 BitLocker 복구 키를 파싱한다.
pub fn parse_bitlocker_recovery_key(text: &str) -> Option<String> {
    for token in text.split_whitespace() {
        let clean = token.trim_matches(['"', '\'', '(', ')', '[', ']', '.', ',', ';']);
        if is_bitlocker_password(clean) {
            return Some(clean.to_string());
        }
    }
    None
}

/// manage-bde.exe 출력에서 키와 식별자(ID) 정보를 함께 파싱한다.
pub fn parse_bitlocker_recovery_info(text: &str) -> Option<BitLockerKeyInfo> {
    let mut id = None;
    let mut key = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ID:") || trimmed.starts_with("식별자:") {
            let val = trimmed
                .split_once(':')
                .map(|(_, v)| v.trim().trim_matches(['{', '}']).to_string());
            if let Some(guid) = val {
                if !guid.is_empty() {
                    id = Some(guid);
                }
            }
        }
        for token in trimmed.split_whitespace() {
            let clean = token.trim_matches(['"', '\'', '(', ')', '[', ']', '.', ',', ';']);
            if is_bitlocker_password(clean) && key.is_none() {
                key = Some(clean.to_string());
            }
        }
    }

    key.map(|k| BitLockerKeyInfo { key: k, id })
}

/// Windows OS C: 드라이브의 BitLocker 48자리 복구 암호 조회
///
/// 내부적으로 `manage-bde.exe -protectors -get C:` 실행 및 파싱.
/// 보안 원칙: 실패 및 성공 시 로그에 48자리 민감 복구 키를 불필요하게 노출하지 않는다.
pub fn bitlocker_recovery_key_c() -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("manage-bde.exe")
            .args(["-protectors", "-get", "C:"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("manage-bde 실행 실패: {e}"))?;

        let stdout = decode_console_output(&out.stdout);
        let stderr = decode_console_output(&out.stderr);

        if let Some(key) = parse_bitlocker_recovery_key(&stdout) {
            return Ok(key);
        }

        if !out.status.success() {
            if stderr.contains("denied") || stdout.contains("denied") || stdout.contains("거부") {
                return Err("BitLocker 복구 키 조회 실패: 관리자 권한이 필요합니다".into());
            }
            return Err(format!(
                "manage-bde 조회 실패 (종료 코드 {:?})",
                out.status.code()
            ));
        }

        if stdout.contains("not turned on")
            || stdout.contains("보호기를 찾을 수 없습니다")
            || stdout.contains("No protectors")
        {
            return Err(
                "BitLocker가 C: 드라이브에 활성화되어 있지 않거나 숫자 암호 보호기가 없습니다"
                    .into(),
            );
        }

        Err("BitLocker 48자리 복구 키를 찾을 수 없습니다".into())
    }
    #[cfg(not(windows))]
    {
        Err("Windows에서만 BitLocker 복구 키를 조회할 수 있습니다".into())
    }
}

/// 정품 인증 정보 한 건(제품 이름, 키 끝 5자리, 인증 상태). 전체 제품 키는 다루지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseInfo {
    pub name: String,
    pub last5: String,
    pub status: String,
}

/// `이름|끝5자리|상태코드` 줄들을 읽는다. 형식이 맞지 않는 줄은 버린다.
pub fn parse_license_lines(text: &str) -> Vec<LicenseInfo> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.trim().splitn(3, '|');
            let name = it.next()?.trim();
            let last5 = it.next()?.trim();
            let code = it.next()?.trim();
            if name.is_empty() || last5.chars().count() != 5 {
                return None;
            }
            let status = match code {
                "1" => "인증됨",
                "0" => "인증 안 됨",
                "5" => "알림 모드(재인증 필요)",
                _ => "확인 필요",
            };
            Some(LicenseInfo {
                name: name.to_string(),
                last5: last5.to_string(),
                status: status.to_string(),
            })
        })
        .collect()
}

/// 이 PC의 Windows·Office 정품 인증 정보(끝 5자리·상태)를 조회한다. 실패하면 빈 목록.
pub fn license_summary() -> Vec<LicenseInfo> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;\
            foreach($c in 'SoftwareLicensingProduct','OfficeSoftwareProtectionProduct'){\
            Get-CimInstance $c -ErrorAction SilentlyContinue | Where-Object { $_.PartialProductKey } | \
            ForEach-Object { '{0}|{1}|{2}' -f $_.Name,$_.PartialProductKey,$_.LicenseStatus }}";
        match std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output()
        {
            Ok(o) => parse_license_lines(&String::from_utf8_lossy(&o.stdout)),
            Err(_) => Vec::new(),
        }
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_license_lines_keeps_only_wellformed_rows() {
        let v = parse_license_lines(
            "Windows(R), Professional edition|3V66T|1\nOffice 21|GRBFX|5\n깨진 줄\n|ABCDE|1\nx|123|1\n",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].last5, "3V66T");
        assert_eq!(v[0].status, "인증됨");
        assert_eq!(v[1].status, "알림 모드(재인증 필요)");
    }

    #[test]
    fn report_has_both_sections_and_never_panics() {
        let r = super::report();
        assert!(r.contains("[디스크 건강]") && r.contains("[BitLocker]"));
    }

    #[test]
    fn is_bitlocker_password_validates_48_digits() {
        let valid = "123456-234567-345678-456789-567890-678901-789012-890123";
        assert!(is_bitlocker_password(valid));

        // 자릿수 부족
        assert!(!is_bitlocker_password(
            "12345-234567-345678-456789-567890-678901-789012-890123"
        ));
        // 블록 부족
        assert!(!is_bitlocker_password("123456-234567-345678-456789-567890"));
        // 문자 포함
        assert!(!is_bitlocker_password(
            "12345A-234567-345678-456789-567890-678901-789012-890123"
        ));
        // 빈 문자열
        assert!(!is_bitlocker_password(""));
    }

    #[test]
    fn parse_bitlocker_recovery_key_english_output() {
        let text = r#"
BitLocker Drive Encryption: Configuration Tool version 10.0.26100
Volume C: [Windows]
All Key Protectors

    Numerical Password:
      ID: {12345678-1234-1234-1234-1234567890AB}
      Password:
        654321-111111-222222-333333-444444-555555-666666-777777
"#;
        let key = parse_bitlocker_recovery_key(text);
        assert_eq!(
            key.as_deref(),
            Some("654321-111111-222222-333333-444444-555555-666666-777777")
        );

        let info = parse_bitlocker_recovery_info(text).unwrap();
        assert_eq!(
            info.key,
            "654321-111111-222222-333333-444444-555555-666666-777777"
        );
        assert_eq!(
            info.id.as_deref(),
            Some("12345678-1234-1234-1234-1234567890AB")
        );
    }

    #[test]
    fn parse_bitlocker_recovery_key_korean_output() {
        let text = r#"
BitLocker 드라이브 암호화: 구성 도구 버전 10.0.26100
볼륨 C: [Windows]
모든 키 보호기

    숫자 암호:
      ID: {ABCDEF01-2345-6789-ABCD-EF0123456789}
      암호:
        999999-888888-777777-666666-555555-444444-333333-222222
"#;
        let key = parse_bitlocker_recovery_key(text);
        assert_eq!(
            key.as_deref(),
            Some("999999-888888-777777-666666-555555-444444-333333-222222")
        );

        let info = parse_bitlocker_recovery_info(text).unwrap();
        assert_eq!(
            info.key,
            "999999-888888-777777-666666-555555-444444-333333-222222"
        );
        assert_eq!(
            info.id.as_deref(),
            Some("ABCDEF01-2345-6789-ABCD-EF0123456789")
        );
    }

    #[test]
    fn parse_bitlocker_recovery_key_none_when_unencrypted() {
        let text = "BitLocker Drive Encryption is not turned on for volume C:.";
        assert_eq!(parse_bitlocker_recovery_key(text), None);
        assert_eq!(parse_bitlocker_recovery_info(text), None);
    }

    #[test]
    fn bitlocker_key_info_debug_redacts_sensitive_key() {
        let info = BitLockerKeyInfo {
            key: "123456-234567-345678-456789-567890-678901-789012-890123".into(),
            id: Some("11223344-5566-7788-9900-aabbccddeeff".into()),
        };
        let debug_str = format!("{info:?}");
        assert!(
            !debug_str.contains("123456"),
            "로그/디버그 출력에 평문 키가 노출되면 안 됩니다"
        );
        assert!(
            debug_str.contains("[REDACTED]"),
            "평문 키 대신 [REDACTED] 마스킹이 적용되어야 합니다"
        );
        assert!(debug_str.contains("11223344-5566-7788-9900-aabbccddeeff"));
    }

    #[test]
    fn decode_console_output_preserves_utf8_and_handles_non_utf8() {
        assert_eq!(
            decode_console_output("한글 출력 테스트".as_bytes()),
            "한글 출력 테스트"
        );
        assert_eq!(decode_console_output(b""), "");
        // 비-UTF8 바이트(CP949 "거부": 0xB0 0xC5 0xBA 0xCE)도 패닉 없이 복호화한다
        let decoded = decode_console_output(&[0xB0, 0xC5, 0xBA, 0xCE]);
        assert!(!decoded.is_empty());
    }
}

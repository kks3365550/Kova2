//! SMTP 이메일 알림 백엔드 (암묵적 TLS 465 / STARTTLS 587·25 / 평문 TCP).
//! - 설정은 `cfg_dir/smtp_config.bin` 에 DPAPI(머신 범위) + 제한 ACL(`secrets::write_private`)로 저장한다.
//! - 외부 메일 크레이트 없이 표준 `TcpStream` + `rustls` + `webpki-roots` 로 직접 구현한다.
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub(crate) const CONFIG_FILE: &str = "smtp_config.bin";
const SMTP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESP_LINES: usize = 64;
const MAX_LINE_BYTES: usize = 4096;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub from: String,
    pub to: String,
    #[serde(default = "d_true")]
    pub use_tls: bool,
}

fn d_true() -> bool {
    true
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field(
                "password",
                &if self.password.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("from", &self.from)
            .field("to", &self.to)
            .field("use_tls", &self.use_tls)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SmtpStatusSummary {
    pub configured: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from: String,
    pub to: String,
    pub use_tls: bool,
}

fn validate_no_crlf(label: &str, val: &str) -> Result<(), String> {
    if val.contains(['\r', '\n', '\0']) {
        return Err(format!(
            "{label} 에 줄바꿈이나 제어 문자를 넣을 수 없습니다"
        ));
    }
    Ok(())
}

fn parse_recipients(to: &str) -> Vec<String> {
    to.split([',', ';'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn validate_config(cfg: &SmtpConfig) -> Result<Vec<String>, String> {
    let host = cfg.host.trim();
    if host.is_empty() {
        return Err("SMTP 서버 주소(host)가 비어 있습니다".into());
    }
    validate_no_crlf("host", host)?;
    if cfg.port == 0 {
        return Err("SMTP 포트 번호가 올바르지 않습니다".into());
    }
    let from = cfg.from.trim();
    if from.is_empty() {
        return Err("보내는 주소(from)가 비어 있습니다".into());
    }
    validate_no_crlf("from", from)?;
    validate_no_crlf("to", &cfg.to)?;
    let rcpts = parse_recipients(&cfg.to);
    if rcpts.is_empty() {
        return Err("받는 주소(to)가 비어 있습니다".into());
    }
    Ok(rcpts)
}

pub fn save_config(cfg_dir: &Path, cfg: &SmtpConfig) -> Result<(), String> {
    validate_config(cfg)?;
    fs::create_dir_all(cfg_dir).map_err(|e| format!("설정 폴더 생성 실패: {e}"))?;
    let json = serde_json::to_vec(cfg).map_err(|e| format!("SMTP 설정 직렬화 실패: {e}"))?;
    let enc = crate::repocrypto::dpapi_protect(&json)?;
    crate::secrets::write_private(&cfg_dir.join(CONFIG_FILE), &enc)
        .map_err(|e| format!("SMTP 설정 저장 실패: {e}"))
}

pub fn load_config(cfg_dir: &Path) -> Result<Option<SmtpConfig>, String> {
    let path = cfg_dir.join(CONFIG_FILE);
    let enc = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("SMTP 설정 읽기 실패: {e}")),
    };
    let raw = crate::repocrypto::dpapi_unprotect(&enc)?;
    let cfg: SmtpConfig =
        serde_json::from_slice(&raw).map_err(|e| format!("SMTP 설정 형식 오류: {e}"))?;
    Ok(Some(cfg))
}

pub fn delete_config(cfg_dir: &Path) -> Result<(), String> {
    let path = cfg_dir.join(CONFIG_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("SMTP 설정 삭제 실패: {e}")),
    }
}

pub fn status(cfg_dir: &Path) -> SmtpStatusSummary {
    match load_config(cfg_dir) {
        Ok(Some(c)) => SmtpStatusSummary {
            configured: true,
            host: c.host,
            port: c.port,
            username: c.username,
            from: c.from,
            to: c.to,
            use_tls: c.use_tls,
        },
        _ => SmtpStatusSummary::default(),
    }
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("SMTP 주소 조회 실패({host}:{port}): {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("SMTP 서버 주소를 찾을 수 없습니다({host}:{port})"));
    }
    let mut last_err = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, SMTP_TIMEOUT) {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(SMTP_TIMEOUT));
                let _ = sock.set_write_timeout(Some(SMTP_TIMEOUT));
                return Ok(sock);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(format!("SMTP 연결 실패({host}:{port}): {last_err}"))
}

fn wrap_tls(
    tcp: TcpStream,
    host: &str,
) -> Result<Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>, String> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS 프로토콜 초기화 실패: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("TLS 서버 이름 오류({host}): {e}"))?;
    let conn = rustls::ClientConnection::new(Arc::new(tls_cfg), server_name)
        .map_err(|e| format!("TLS 연결 생성 실패: {e}"))?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

enum SmtpStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for SmtpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for SmtpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

impl SmtpStream {
    fn read_line(&mut self) -> Result<String, String> {
        let mut line = Vec::with_capacity(128);
        let mut b = [0u8; 1];
        loop {
            match self.read(&mut b) {
                Ok(0) => {
                    if line.is_empty() {
                        return Err("SMTP 서버가 연결을 닫았습니다".into());
                    }
                    break;
                }
                Ok(_) => {
                    if b[0] == b'\n' {
                        break;
                    }
                    if line.len() < MAX_LINE_BYTES {
                        line.push(b[0]);
                    }
                }
                Err(e) => return Err(format!("SMTP 응답 읽기 실패: {e}")),
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }

    fn read_response(&mut self) -> Result<(u16, String), String> {
        let mut lines = Vec::new();
        for _ in 0..MAX_RESP_LINES {
            let line = self.read_line()?;
            if line.len() < 3 || !line.as_bytes()[..3].iter().all(|c| c.is_ascii_digit()) {
                return Err(format!("알 수 없는 SMTP 응답: {line}"));
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| format!("SMTP 상태 코드 오류: {line}"))?;
            let cont = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line);
            if !cont {
                return Ok((code, lines.join("\n")));
            }
        }
        Err("SMTP 다중 줄 응답이 너무 깁니다".into())
    }

    fn send_cmd(&mut self, cmd: &str) -> Result<(u16, String), String> {
        self.write_all(cmd.as_bytes())
            .and_then(|()| self.write_all(b"\r\n"))
            .and_then(|()| self.flush())
            .map_err(|e| format!("SMTP 명령 전송 실패: {e}"))?;
        self.read_response()
    }
}

fn expect_code(step: &str, got: (u16, String), expected: &[u16]) -> Result<(), String> {
    if expected.contains(&got.0) {
        Ok(())
    } else {
        Err(format!("SMTP {step} 실패 (코드 {}): {}", got.0, got.1))
    }
}

/// SMTP 로 UTF-8 알림 이메일을 전송한다.
/// - `use_tls == true && port == 465`: 암묵적 TLS(SMTPS)
/// - `use_tls == true && port != 465`: 평문 연결 후 STARTTLS 업그레이드
/// - `use_tls == false`: 평문 TCP (사내 릴레이·로컬 모의 시험용)
pub fn send_email(cfg: &SmtpConfig, subject: &str, body: &str) -> Result<(), String> {
    let rcpts = validate_config(cfg)?;
    let host = cfg.host.trim();
    let from = cfg.from.trim();
    let tcp = connect_tcp(host, cfg.port)?;

    let mut stream = if cfg.use_tls && cfg.port == 465 {
        SmtpStream::Tls(wrap_tls(tcp, host)?)
    } else {
        SmtpStream::Plain(tcp)
    };

    expect_code("인사", stream.read_response()?, &[220])?;
    expect_code("EHLO", stream.send_cmd("EHLO kova2.local")?, &[250])?;

    if cfg.use_tls && cfg.port != 465 {
        expect_code("STARTTLS", stream.send_cmd("STARTTLS")?, &[220])?;
        let SmtpStream::Plain(tcp) = stream else {
            unreachable!();
        };
        stream = SmtpStream::Tls(wrap_tls(tcp, host)?);
        expect_code("EHLO(TLS)", stream.send_cmd("EHLO kova2.local")?, &[250])?;
    }

    if !cfg.username.is_empty() {
        let mut plain = Vec::with_capacity(cfg.username.len() + cfg.password.len() + 2);
        plain.push(0);
        plain.extend_from_slice(cfg.username.as_bytes());
        plain.push(0);
        plain.extend_from_slice(cfg.password.as_bytes());
        let auth_b64 = b64_encode(&plain);
        let (code, resp) = stream.send_cmd(&format!("AUTH PLAIN {auth_b64}"))?;
        if code == 334 {
            let (code2, resp2) = stream.send_cmd(&auth_b64)?;
            if code2 != 235 {
                return Err(format!("SMTP 인증 실패 (코드 {code2}): {resp2}"));
            }
        } else if code != 235 {
            return Err(format!("SMTP 인증 실패 (코드 {code}): {resp}"));
        }
    }

    expect_code(
        "MAIL FROM",
        stream.send_cmd(&format!("MAIL FROM:<{from}>"))?,
        &[250],
    )?;
    for rcpt in &rcpts {
        expect_code(
            "RCPT TO",
            stream.send_cmd(&format!("RCPT TO:<{rcpt}>"))?,
            &[250, 251],
        )?;
    }
    expect_code("DATA", stream.send_cmd("DATA")?, &[354])?;

    let clean_subject = subject.replace(['\r', '\n'], " ");
    let subj_b64 = b64_encode(clean_subject.as_bytes());
    let body_b64 = b64_encode(body.as_bytes());
    let date = chrono::Utc::now().to_rfc2822();
    let to_header = rcpts.join(", ");

    let mut msg = String::with_capacity(256 + body_b64.len() + body_b64.len() / 38);
    msg.push_str(&format!("From: {from}\r\n"));
    msg.push_str(&format!("To: {to_header}\r\n"));
    msg.push_str(&format!("Subject: =?UTF-8?B?{subj_b64}?=\r\n"));
    msg.push_str(&format!("Date: {date}\r\n"));
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    msg.push_str("Content-Transfer-Encoding: base64\r\n");
    msg.push_str("\r\n");
    for line in body_b64.as_bytes().chunks(76) {
        msg.push_str(std::str::from_utf8(line).unwrap_or(""));
        msg.push_str("\r\n");
    }
    msg.push_str(".\r\n");

    stream
        .write_all(msg.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("SMTP 본문 전송 실패: {e}"))?;
    expect_code("본문 수락", stream.read_response()?, &[250])?;

    let _ = stream.send_cmd("QUIT");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn b64_encode_matches_rfc4648() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn smtp_config_debug_redacts_password_and_rejects_header_injection() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            username: "bot@example.com".into(),
            password: "MySuperSecretPassword".into(),
            from: "bot@example.com".into(),
            to: "admin@example.com".into(),
            use_tls: true,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("MySuperSecretPassword"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");

        let mut bad = cfg.clone();
        bad.from = "a@b.com\r\nBcc: evil@attacker.com".into();
        assert!(send_email(&bad, "subj", "body").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn smtp_config_dpapi_roundtrip_and_status() {
        let d = tempfile::tempdir().unwrap();
        assert!(!status(d.path()).configured);
        assert!(load_config(d.path()).unwrap().is_none());

        let cfg = SmtpConfig {
            host: "smtp.office365.com".into(),
            port: 587,
            username: "alerts@company.kr".into(),
            password: "AppPassword!99".into(),
            from: "alerts@company.kr".into(),
            to: "ops@company.kr".into(),
            use_tls: true,
        };
        save_config(d.path(), &cfg).unwrap();
        // 디스크에 평문 비밀번호가 없어야 한다
        let raw = fs::read(d.path().join(CONFIG_FILE)).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"AppPassword"));

        let loaded = load_config(d.path()).unwrap().unwrap();
        assert_eq!(loaded, cfg);

        let st = status(d.path());
        assert!(st.configured);
        assert_eq!(st.host, "smtp.office365.com");
        assert_eq!(st.port, 587);
        assert_eq!(st.username, "alerts@company.kr");

        delete_config(d.path()).unwrap();
        assert!(!status(d.path()).configured);
    }

    #[test]
    fn send_email_completes_full_smtp_conversation_against_mock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut writer = sock.try_clone().unwrap();
            let mut reader = BufReader::new(sock);

            let mut commands = Vec::new();
            let mut data_buf = String::new();

            writer
                .write_all(b"220 mock.smtp.local ESMTP ready\r\n")
                .unwrap();
            writer.flush().unwrap();

            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).unwrap();
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                commands.push(trimmed.clone());
                if trimmed.starts_with("EHLO ") {
                    writer
                        .write_all(b"250-mock.smtp.local\r\n250 AUTH PLAIN\r\n")
                        .unwrap();
                } else if trimmed.starts_with("AUTH PLAIN ") {
                    writer
                        .write_all(b"235 2.7.0 Authentication successful\r\n")
                        .unwrap();
                } else if trimmed.starts_with("MAIL FROM:") || trimmed.starts_with("RCPT TO:") {
                    writer.write_all(b"250 2.1.0 Ok\r\n").unwrap();
                } else if trimmed == "DATA" {
                    writer
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .unwrap();
                    writer.flush().unwrap();
                    loop {
                        let mut dl = String::new();
                        let dn = reader.read_line(&mut dl).unwrap();
                        if dn == 0 {
                            break;
                        }
                        if dl == ".\r\n" || dl == ".\n" {
                            break;
                        }
                        data_buf.push_str(&dl);
                    }
                    writer.write_all(b"250 2.0.0 Queued\r\n").unwrap();
                } else if trimmed == "QUIT" {
                    writer.write_all(b"221 Bye\r\n").unwrap();
                    writer.flush().unwrap();
                    break;
                } else {
                    writer.write_all(b"500 Unknown\r\n").unwrap();
                }
                writer.flush().unwrap();
            }
            (commands, data_buf)
        });

        let cfg = SmtpConfig {
            host: "127.0.0.1".into(),
            port: addr.port(),
            username: "kova".into(),
            password: "secret".into(),
            from: "kova@company.local".into(),
            to: "admin1@company.local, admin2@company.local".into(),
            use_tls: false,
        };
        send_email(
            &cfg,
            "[Kova2] 백업 실패 알림",
            "디스크 여유 공간이 부족합니다.",
        )
        .unwrap();

        let (cmds, raw_data) = server.join().unwrap();
        assert_eq!(cmds[0], "EHLO kova2.local");
        let expected_auth = format!("AUTH PLAIN {}", b64_encode(b"\0kova\0secret"));
        assert_eq!(cmds[1], expected_auth);
        assert_eq!(cmds[2], "MAIL FROM:<kova@company.local>");
        assert_eq!(cmds[3], "RCPT TO:<admin1@company.local>");
        assert_eq!(cmds[4], "RCPT TO:<admin2@company.local>");
        assert_eq!(cmds[5], "DATA");
        assert_eq!(cmds[6], "QUIT");

        let expected_subj = format!(
            "Subject: =?UTF-8?B?{}?=",
            b64_encode("[Kova2] 백업 실패 알림".as_bytes())
        );
        assert!(raw_data.contains(&expected_subj), "{raw_data}");
        assert!(
            raw_data.contains("Content-Transfer-Encoding: base64"),
            "{raw_data}"
        );
        assert!(
            raw_data.contains(&b64_encode("디스크 여유 공간이 부족합니다.".as_bytes())),
            "{raw_data}"
        );
    }
}

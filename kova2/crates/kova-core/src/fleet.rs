//! 다중 PC 플릿(Fleet) 하트비트: 이 PC의 프로파일 백업 상태·미확인 알림 수를 모아
//! 중앙 모니터링 엔드포인트로 JSON POST 전송한다.
use crate::alerts::AlertLog;
use crate::config::ConfigStore;
use crate::notify::{redact, validate_webhook_url};
use crate::schedule::{last_success_at, stale_days};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetProfileSummary {
    pub id: String,
    pub name: String,
    pub last_status: String,
    pub last_run: Option<f64>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FleetHeartbeat {
    pub hostname: String,
    pub service_version: String,
    pub timestamp: f64,
    pub profiles_total: usize,
    pub healthy: usize,
    pub stale: usize,
    pub last_backup_at: Option<f64>,
    pub unacked_alerts: usize,
    pub profiles: Vec<FleetProfileSummary>,
}

/// 설정 폴더(`profiles.json`, `app_settings.json`, `alerts.json`)에서 현재 PC의 하트비트 요약을 만든다.
pub fn build_heartbeat(config_dir: &Path, service_version: &str) -> FleetHeartbeat {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "UNKNOWN".into());
    let now_dt = chrono::Local::now();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_else(|_| now_dt.timestamp() as f64);

    let store = ConfigStore::new(config_dir);
    let settings = store.settings();
    let profiles = store.profiles();
    let unacked_alerts = AlertLog::new(config_dir).unacknowledged();

    let mut healthy = 0usize;
    let mut stale = 0usize;
    let mut last_backup_at: Option<f64> = None;
    let mut summaries = Vec::with_capacity(profiles.len());

    for p in profiles {
        let is_stale = stale_days(&p, now_dt, settings.stale_warn_days).is_some();
        if is_stale {
            stale += 1;
        }
        if p.last_status == "success" && !is_stale {
            healthy += 1;
        }
        if let Some(ts) = last_success_at(&p) {
            last_backup_at = Some(match last_backup_at {
                Some(prev) => prev.max(ts),
                None => ts,
            });
        }
        summaries.push(FleetProfileSummary {
            id: p.id,
            name: p.name,
            last_status: p.last_status,
            last_run: p.last_run,
            stale: is_stale,
        });
    }

    FleetHeartbeat {
        hostname,
        service_version: service_version.to_string(),
        timestamp,
        profiles_total: summaries.len(),
        healthy,
        stale,
        last_backup_at,
        unacked_alerts,
        profiles: summaries,
    }
}

/// 하트비트 JSON 을 중앙 플릿 엔드포인트로 POST 한다. 오류 문구에는 URL 쿼리·인증 토큰을 가린다.
pub fn send_heartbeat(endpoint: &str, hb: &FleetHeartbeat) -> Result<(), String> {
    let url = validate_webhook_url(endpoint)
        .map_err(|_| "Fleet 엔드포인트는 http:// 또는 https:// 로 시작해야 합니다".to_string())?;
    let body = serde_json::to_string(hb).map_err(|e| format!("하트비트 직렬화 실패: {e}"))?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(HEARTBEAT_TIMEOUT)
        .timeout_read(HEARTBEAT_TIMEOUT)
        .timeout_write(HEARTBEAT_TIMEOUT)
        .build();
    let resp = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| redact(&format!("Fleet 하트비트 전송 실패: {e}"), url))?;
    let status = resp.status();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("Fleet 하트비트 응답 오류: HTTP {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::Alert;
    use crate::config::Profile;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn build_heartbeat_summarizes_healthy_stale_and_alerts() {
        let d = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(d.path());
        let now = chrono::Local::now().timestamp() as f64;
        let day = 86_400.0;

        let mut p_ok = Profile::new("p1", "문서");
        p_ok.last_status = "success".into();
        p_ok.last_run = Some(now - 3600.0);

        let mut p_stale = Profile::new("p2", "회계");
        p_stale.last_status = "success".into();
        p_stale.last_run = Some(now - 10.0 * day);

        let mut p_fail = Profile::new("p3", "도면");
        p_fail.last_status = "failed".into();
        p_fail.last_run = Some(now - 1800.0);

        store.save_profiles(&[p_ok, p_stale, p_fail]).unwrap();

        let alerts = AlertLog::new(d.path());
        alerts
            .push(Alert {
                at: now,
                profile_id: "p3".into(),
                level: "error".into(),
                message: "실패".into(),
                acknowledged: false,
            })
            .unwrap();

        let hb = build_heartbeat(d.path(), "2.5.0");
        assert_eq!(hb.service_version, "2.5.0");
        assert_eq!(hb.profiles_total, 3);
        assert_eq!(hb.healthy, 1);
        assert_eq!(hb.stale, 1);
        assert_eq!(hb.unacked_alerts, 1);
        assert!(hb.last_backup_at.is_some());
        assert!((hb.last_backup_at.unwrap() - (now - 3600.0)).abs() < 1.0);
        assert_eq!(hb.profiles.len(), 3);
        assert!(!hb.profiles[0].stale);
        assert!(hb.profiles[1].stale);
    }

    #[test]
    fn send_heartbeat_posts_json_and_masks_secret_query_on_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let hdr = String::from_utf8_lossy(&data[..pos]);
                    let cl: usize = hdr
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if data.len() >= pos + 4 + cl {
                        let body = data[pos + 4..pos + 4 + cl].to_vec();
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                        let _ = sock.flush();
                        return body;
                    }
                }
            }
            Vec::new()
        });

        let d = tempfile::tempdir().unwrap();
        let hb = build_heartbeat(d.path(), "2.5.0-test");
        let url = format!("http://{addr}/api/heartbeat?token=TOPSECRET");
        send_heartbeat(&url, &hb).unwrap();

        let body = srv.join().unwrap();
        let parsed: FleetHeartbeat = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.service_version, "2.5.0-test");
        assert_eq!(parsed.profiles_total, 0);

        // 연결 거부 시 오류에 비밀 쿼리 토큰이 드러나지 않는다
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let err = send_heartbeat(
            &format!("http://127.0.0.1:{dead_port}/hb?api_key=SECRET_KEY_123"),
            &hb,
        )
        .unwrap_err();
        assert!(!err.contains("SECRET_KEY_123"), "{err}");
    }
}

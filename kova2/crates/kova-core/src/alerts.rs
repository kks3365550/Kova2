//! 알림 기록: 실패·경고를 `alerts.json` 에 남겨 앱(트레이·화면)이 읽어 보여 준다.
//! 서비스는 화면이 없으므로 "남기기"만 하고, 표시와 확인(읽음) 처리는 앱이 한다. 최근 100건만 유지.
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

const MAX_ALERTS: usize = 100;
/// 미성공 경고 메시지에 들어가는 표식(서비스가 만들고 성공 시 자동 해제에 쓴다).
pub const STALE_MARK: &str = "일째 백업 성공 기록이 없습니다";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub at: f64,
    pub profile_id: String,
    /// "error" | "warning"
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub acknowledged: bool,
}

pub struct AlertLog(PathBuf);

impl AlertLog {
    pub fn new(config_dir: &Path) -> Self {
        Self(config_dir.join("alerts.json"))
    }

    pub fn list(&self) -> Vec<Alert> {
        crate::config::try_read_json(&self.0)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// 수정용 읽기: 손상 파일은 `.json.bak` 으로 보존된 뒤 빈 목록에서 다시 시작한다(알림은 새로 쌓여야 하므로).
    /// 읽기 자체가 실패하면(권한·잠김) 덮어쓰지 않고 오류.
    fn load_for_update(&self) -> io::Result<Vec<Alert>> {
        match crate::config::try_read_json(&self.0) {
            Ok(v) => Ok(v.unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn lock(&self) -> Option<std::fs::File> {
        crate::config::lock_shared(&self.0.with_file_name(".alerts.lock"))
    }

    fn save(&self, v: &[Alert]) -> io::Result<()> {
        crate::config::atomic_write_shared(
            &self.0,
            &serde_json::to_vec_pretty(v).map_err(io::Error::other)?,
        )
    }

    pub fn push(&self, a: Alert) -> io::Result<()> {
        let _g = self.lock();
        let mut v = self.load_for_update()?;
        v.push(a);
        let n = v.len();
        if n > MAX_ALERTS {
            v.drain(0..n - MAX_ALERTS);
        }
        self.save(&v)
    }

    pub fn unacknowledged(&self) -> usize {
        self.list().iter().filter(|a| !a.acknowledged).count()
    }

    /// 백업이 다시 성공하면 그 프로파일의 "N일째 백업 성공 기록이 없습니다" 경고를 자동으로 확인 처리한다.
    /// 성공했는데도 배너에 낡은 경고가 남는 문제를 막는다. 해제한 건수를 돌려준다.
    pub fn resolve_stale(&self, profile_id: &str) -> io::Result<usize> {
        let _g = self.lock();
        let mut v = self.load_for_update()?;
        let mut n = 0;
        for a in v.iter_mut().filter(|a| {
            !a.acknowledged && a.profile_id == profile_id && a.message.contains(STALE_MARK)
        }) {
            a.acknowledged = true;
            n += 1;
        }
        if n > 0 {
            self.save(&v)?;
        }
        Ok(n)
    }

    pub fn acknowledge_all(&self) -> io::Result<()> {
        let _g = self.lock();
        let mut v = self.load_for_update()?;
        v.iter_mut().for_each(|a| a.acknowledged = true);
        self.save(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(i: usize) -> Alert {
        Alert {
            at: i as f64,
            profile_id: "p".into(),
            level: "error".into(),
            message: format!("m{i}"),
            acknowledged: false,
        }
    }

    #[test]
    fn push_list_ack_and_cap() {
        let d = tempfile::tempdir().unwrap();
        let l = AlertLog::new(d.path());
        assert!(l.list().is_empty());
        for i in 0..105 {
            l.push(a(i)).unwrap();
        }
        let v = l.list();
        assert_eq!(v.len(), 100);
        assert_eq!(v[0].message, "m5", "오래된 것부터 버린다");
        assert_eq!(l.unacknowledged(), 100);
        l.acknowledge_all().unwrap();
        assert_eq!(l.unacknowledged(), 0);
    }

    #[test]
    fn resolve_stale_only_clears_that_profiles_stale_warnings() {
        let d = tempfile::tempdir().unwrap();
        let l = AlertLog::new(d.path());
        let mk = |pid: &str, msg: &str| Alert {
            at: 1.0,
            profile_id: pid.into(),
            level: "warning".into(),
            message: msg.into(),
            acknowledged: false,
        };
        l.push(mk("p", &format!("P: 4{STALE_MARK}"))).unwrap();
        l.push(mk("q", &format!("Q: 4{STALE_MARK}"))).unwrap();
        l.push(mk("p", "복제 실패")).unwrap();
        assert_eq!(l.resolve_stale("p").unwrap(), 1);
        assert_eq!(l.unacknowledged(), 2);
        assert_eq!(l.resolve_stale("p").unwrap(), 0);
    }

    #[test]
    fn corrupt_file_reads_as_empty_and_recovers() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("alerts.json"), b"{broken").unwrap();
        let l = AlertLog::new(d.path());
        assert!(l.list().is_empty());
        l.push(a(1)).unwrap();
        assert_eq!(l.list().len(), 1);
        // 손상 파일은 덮어쓰기 전에 .bak 으로 보존된다
        assert_eq!(
            std::fs::read(d.path().join("alerts.json.bak")).unwrap(),
            b"{broken"
        );
    }

    #[test]
    fn concurrent_pushes_from_many_threads_lose_nothing() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_path_buf();
        let hs: Vec<_> = (0..8)
            .map(|t| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let l = AlertLog::new(&dir);
                    for i in 0..5 {
                        l.push(a(t * 10 + i)).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(AlertLog::new(&dir).list().len(), 40);
        // 임시 파일이 남지 않는다
        assert!(!std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp")));
    }
}

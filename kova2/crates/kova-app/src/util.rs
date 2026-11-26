//! 공통 포맷·경로·잠금·상태 도우미.
use crate::{AlertRow, DriveRow};
use kova_core::config::ConfigStore;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 이번 실행에서 마스터 비밀번호로 잠금을 푼 상태인가.
static UNLOCKED: AtomicBool = AtomicBool::new(false);

pub(crate) const LOCKED_MSG: &str =
    "마스터 비밀번호로 잠겨 있습니다. 환경설정 > '보안 & 보호' 탭에서 잠금을 먼저 해제하세요";

/// 꺼져 있으면 켜고 true, 이미 켜져 있으면(진행 중) false.
pub(crate) fn try_begin(flag: &AtomicBool) -> bool {
    flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// 진행 중 플래그: 선택 창·스캔이 끝나기 전에 같은 동작을 다시 시작하지 않게 한다(스레드 간 공유).
#[derive(Clone, Default)]
pub(crate) struct BusyGate(Arc<AtomicBool>);

pub(crate) struct GateGuard(BusyGate);

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.0.end();
    }
}

impl BusyGate {
    /// 비어 있으면 진행 중으로 바꾸고 true, 이미 진행 중이면 false.
    pub(crate) fn try_begin(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    pub(crate) fn end(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
    /// 비어 있으면 진행 중으로 바꾸고 자동 해제 가드를 돌려준다.
    pub(crate) fn lock(&self) -> Option<GateGuard> {
        self.try_begin().then(|| GateGuard(self.clone()))
    }
}

/// 마스터 비밀번호가 설정돼 있고 아직 풀지 않았으면 true.
pub(crate) fn app_locked() -> bool {
    kova_core::applock::is_set(&kova_service::default_config_dir())
        && !UNLOCKED.load(Ordering::SeqCst)
}

pub(crate) fn set_unlocked(v: bool) {
    UNLOCKED.store(v, Ordering::SeqCst);
}

pub(crate) fn lock_status() -> String {
    if !kova_core::applock::is_set(&kova_service::default_config_dir()) {
        String::new()
    } else if app_locked() {
        "잠김: 마스터 비밀번호를 넣고 [잠금 해제]를 누르세요".into()
    } else {
        "해제됨: 이번 실행 동안 잠긴 동작을 할 수 있습니다".into()
    }
}

/// 시작 마법사용 폴더 위치. 문서·사진 등은 OneDrive로 옮겨져 있으면 그쪽을 쓴다.
pub(crate) fn known_folder(kind: &str) -> String {
    let home = std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let pick = |names: &[&str]| -> String {
        for n in names {
            let p = home.join(n);
            if p.is_dir() {
                return p.to_string_lossy().into_owned();
            }
        }
        home.join(names[names.len() - 1])
            .to_string_lossy()
            .into_owned()
    };
    match kind {
        "documents" => pick(&["OneDrive\\Documents", "OneDrive\\문서", "Documents"]),
        "pictures" => pick(&["OneDrive\\Pictures", "OneDrive\\사진", "Pictures"]),
        "desktop" => pick(&["OneDrive\\Desktop", "OneDrive\\바탕 화면", "Desktop"]),
        "downloads" => pick(&["Downloads"]),
        // 저장 위치 제안: 다른 드라이브가 있으면 그쪽, 없으면 내 폴더 안
        "backup" => {
            for l in 'D'..='Z' {
                let root = format!("{l}:\\");
                if Path::new(&root).exists() {
                    return format!("{root}Kova백업");
                }
            }
            home.join("Kova백업").to_string_lossy().into_owned()
        }
        "restore" => home
            .join("Desktop")
            .join("Kova 복원")
            .to_string_lossy()
            .into_owned(),
        _ => String::new(),
    }
}

/// 알림 한 줄 요약: 길면 앞부분만 보이고 "…"로 줄인다(전체는 행을 눌러 펼친다).
pub(crate) fn shorten_alert(s: &str) -> String {
    const MAX: usize = 90;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX).collect();
    format!("{}… (눌러서 펼치기)", head.trim_end())
}

/// 용량 표시: 1GB 이상이면 GB, 아니면 MB.
pub(crate) fn human_mb(bytes: u64) -> String {
    let mb = bytes as f64 / 1_048_576.0;
    if mb >= 1024.0 {
        format!("{:.1}GB", mb / 1024.0)
    } else {
        format!("{mb:.1}MB")
    }
}

/// 바이트 크기를 B / KB / MB / GB 단위로 읽기 쉽게 바꾼다.
pub(crate) fn fmt_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2}GB", b / GB)
    } else if b >= MB {
        format!("{:.1}MB", b / MB)
    } else if b >= KB {
        format!("{:.1}KB", b / KB)
    } else {
        format!("{bytes}B")
    }
}

pub(crate) fn chrono_fmt(ts: f64) -> String {
    // 외부 의존 없이 "N분/시간/일 전"으로 표시
    let secs = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
        - ts)
        .max(0.0) as u64;
    match secs {
        0..=59 => "방금".into(),
        60..=3599 => format!("{}분 전", secs / 60),
        3600..=86399 => format!("{}시간 전", secs / 3600),
        _ => format!("{}일 전", secs / 86400),
    }
}

/// 작업 종류(서비스 kind 문자열)를 화면에 보일 이름으로 바꾼다. "image:C" 같은 내부 표기를 그대로 보이지 않는다.
pub(crate) fn kind_label(kind: &str) -> String {
    match kind {
        k if k == "verify" || k.starts_with("verify:") => "무결성 검사".into(),
        "gc" => "저장소 정리".into(),
        k if k.starts_with("delsnap") => "스냅샷 삭제".into(),
        k if k.starts_with("image_inc") => match k.strip_prefix("image_inc:") {
            Some(d) if !d.is_empty() => format!("{d}: 드라이브 증분 이미지 백업"),
            _ => "디스크 증분 이미지 백업".into(),
        },
        k if k.starts_with("image") => match k.strip_prefix("image:") {
            Some(d) if !d.is_empty() => format!("{d}: 드라이브 이미지 백업"),
            _ => "디스크 이미지 백업".into(),
        },
        _ => "백업".into(),
    }
}

/// 현재 Windows 시스템 드라이브 문자(기본 'C').
pub(crate) fn system_drive_letter() -> char {
    std::env::var("SystemDrive")
        .ok()
        .and_then(|s| s.chars().next())
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('C')
}

/// 저장소 경로가 놓인 드라이브의 여유 공간 문구와 사용률(%)을 구한다.
pub(crate) fn repo_drive_usage(main_repo: &str) -> (String, i32) {
    let trimmed = main_repo.trim();
    if trimmed.is_empty() {
        return (String::new(), 0);
    }
    let path = Path::new(trimmed);
    let target = path.ancestors().find(|p| p.exists()).unwrap_or(path);
    let Some((total, avail)) = kova_core::diskspace::usage(target) else {
        return (String::new(), 0);
    };
    let used = total.saturating_sub(avail);
    let pct = ((used as f64 * 100.0 / total as f64).round() as i32).clamp(0, 100);
    let free = format!("{:.1} GB 여유", avail as f64 / 1_073_741_824.0);
    (free, pct)
}

/// 홈 화면의 "내 드라이브와 백업 보관함": 존재하는 드라이브별 사용률. 백업 저장소가 있는 드라이브를 표시한다.
pub(crate) fn drive_rows() -> Vec<DriveRow> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let repos: Vec<String> = store
        .profiles()
        .iter()
        .map(|p| p.repo_dir.to_uppercase())
        .collect();
    let sys_letter = system_drive_letter();
    let gb = |b: u64| format!("{:.1} GB", b as f64 / 1_073_741_824.0);
    let mut v = Vec::new();
    for l in b'C'..=b'Z' {
        let root = format!("{}:\\", l as char);
        if !Path::new(&root).exists() {
            continue;
        }
        let Some((total, avail)) = kova_core::diskspace::usage(Path::new(&root)) else {
            continue;
        };
        let used = total.saturating_sub(avail);
        let ch = l as char;
        v.push(DriveRow {
            name: format!("{ch}:").into(),
            pct: (used as f64 * 100.0 / total as f64).round() as i32,
            used: gb(used).into(),
            free: gb(avail).into(),
            repo: repos.iter().any(|r| r.starts_with(&format!("{ch}:"))),
            sys: ch.eq_ignore_ascii_case(&sys_letter),
        });
    }
    v
}

/// 직전과 같으면 None(화면을 건드리지 않음), 달라졌으면 Some(새 값)을 돌려주고 기억한다.
pub(crate) fn changed_only<T: PartialEq + Clone>(
    last: &mut Option<Vec<T>>,
    new: Vec<T>,
) -> Option<Vec<T>> {
    if last.as_ref() == Some(&new) {
        None
    } else {
        *last = Some(new.clone());
        Some(new)
    }
}

/// 이력 DB 가 이미 있을 때만 연다(조회만 하므로 없는 저장소 폴더·DB 를 새로 만들지 않는다).
pub(crate) fn open_history_if_exists(repo: &Path) -> Option<kova_core::history::History> {
    if !repo.join("metadata.db").is_file() {
        return None;
    }
    kova_core::history::History::open(repo).ok()
}

/// 프로파일 ID, 저장소 경로, 스냅샷 ID, 또는 "default"로부터 올바른 프로파일 ID를 찾는다.
pub(crate) fn resolve_profile_id(store: &ConfigStore, target: &str) -> Option<String> {
    let t = target.trim();
    if t.is_empty() {
        return store.profiles().first().map(|p| p.id.clone());
    }
    // 1. 직접 프로파일 ID 일치
    if store.get(t).is_some() {
        return Some(t.to_string());
    }
    let profiles = store.profiles();
    // 2. 저장소 경로 일치
    if let Some(p) = profiles.iter().find(|p| p.repo_dir.eq_ignore_ascii_case(t)) {
        return Some(p.id.clone());
    }
    // 3. 스냅샷 ID 일치 (파일 직접 확인 또는 History DB)
    for p in &profiles {
        let repo = std::path::PathBuf::from(&p.repo_dir);
        let snap_json = repo.join("snapshots").join(format!("{t}.json"));
        let snap_enc = repo.join("snapshots").join(format!("{t}.json.enc"));
        if snap_json.exists() || snap_enc.exists() {
            if let Ok(cas) = kova_engine::storage::CasStorage::new(&repo) {
                if let Ok(m) = cas.load_manifest(t) {
                    if let Some(ref pid) = m.profile_id {
                        if store.get(pid).is_some() {
                            return Some(pid.clone());
                        }
                    }
                }
            }
            if let Some(h) = open_history_if_exists(&repo) {
                if let Ok(snaps) = h.list_snapshots() {
                    if let Some(s) = snaps.iter().find(|s| s.id == t) {
                        if !s.profile_id.is_empty() && store.get(&s.profile_id).is_some() {
                            return Some(s.profile_id.clone());
                        }
                    }
                }
            }
            return Some(p.id.clone());
        }
        if let Some(h) = open_history_if_exists(&repo) {
            if let Ok(snaps) = h.list_snapshots() {
                if let Some(s) = snaps.iter().find(|s| s.id == t) {
                    if !s.profile_id.is_empty() && store.get(&s.profile_id).is_some() {
                        return Some(s.profile_id.clone());
                    }
                    return Some(p.id.clone());
                }
            }
        }
    }
    // 4. "default" 키워드 일치
    if t.eq_ignore_ascii_case("default") {
        return profiles.first().map(|p| p.id.clone());
    }
    None
}

pub(crate) fn profile_name(id: &str) -> String {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let resolved = resolve_profile_id(&store, id).unwrap_or_else(|| id.to_string());
    store
        .get(&resolved)
        .map(|p| p.name)
        .unwrap_or_else(|| id.to_string())
}

/// 저장소 정리 버튼이 넘긴 값(프로파일 ID, 저장소 경로, 빈 값=첫 프로파일)을 실제 프로파일 ID로 바꾼다.
/// 잠겨 있거나 해당 프로파일이 없으면 서비스에 보내지 않고 이유를 돌려준다.
pub(crate) fn gc_target(locked: bool, store: &ConfigStore, target: &str) -> Result<String, String> {
    if locked {
        return Err(LOCKED_MSG.into());
    }
    resolve_profile_id(store, target).ok_or_else(|| {
        "정리할 백업 프로파일을 찾지 못했습니다. 먼저 홈에서 백업을 설정하세요".to_string()
    })
}

pub(crate) fn alert_rows() -> Vec<AlertRow> {
    let mut v = kova_core::alerts::AlertLog::new(&kova_service::default_config_dir()).list();
    v.reverse();
    v.into_iter()
        .map(|a| {
            let name = profile_name(&a.profile_id);
            AlertRow {
                when: chrono_fmt(a.at).into(),
                level: a.level.into(),
                message: shorten_alert(&format!("{name}: {}", a.message)).into(),
                full: format!("{name}: {}", a.message).into(),
                ack: a.acknowledged,
            }
        })
        .collect()
}

/// 기본 브라우저로 주소를 연다(셸 해석 없이 rundll32 사용).
pub(crate) fn open_url(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x0800_0000)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = url;
    }
}

/// 윈도우 알림(토스트)을 띄운다. 제목·내용은 환경 변수로 넘겨 스크립트에 끼어들지 못하게 한다. 실패해도 조용히 넘어간다.
pub(crate) fn toast(title: &str, body: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const SCRIPT: &str = "$t=$env:KOVA_TOAST_T;$b=$env:KOVA_TOAST_B;\
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;\
$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);\
$n=$x.GetElementsByTagName('text');\
$n.Item(0).AppendChild($x.CreateTextNode($t))|Out-Null;\
$n.Item(1).AppendChild($x.CreateTextNode($b))|Out-Null;\
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))";
        let (t, b) = (
            title.to_string(),
            body.chars().take(200).collect::<String>(),
        );
        std::thread::spawn(move || {
            let _ = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
                .env("KOVA_TOAST_T", t)
                .env("KOVA_TOAST_B", b)
                .creation_flags(0x0800_0000)
                .status();
        });
    }
    #[cfg(not(windows))]
    {
        let _ = (title, body);
    }
}

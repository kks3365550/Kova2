//! 백업 프로파일 CRUD, 설치 프로그램 탐색, 마법사 및 주간·월간 스케줄 편집.
use crate::ipc::{send, send_sync};
use crate::util::{app_locked, chrono_fmt, known_folder, resolve_profile_id, BusyGate, LOCKED_MSG};
use crate::{MainWindow, ProfileRow, ProgPick, SrcRow};
use kova_core::config::{ConfigStore, Profile};
use slint::ComponentHandle;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 마법사가 새 백업에 넣는 제외 목록: 임시·캐시·개발 부산물은 백업할 필요가 없다.
const DEFAULT_EXCLUDES: &str =
    "*.tmp;*.temp;~$*;Thumbs.db;desktop.ini;$RECYCLE.BIN;node_modules;__pycache__;.venv";

/// 프로파일의 schedule_type 을 화면 스케줄 모드 번호로 바꾼다.
/// 0=시간마다(interval_hours), 1=매일(daily), 2=매주(weekly), 3=매월(monthly)
pub(crate) fn schedule_mode_from_type(schedule_type: &str) -> i32 {
    match schedule_type {
        "daily" => 1,
        "weekly" => 2,
        "monthly" => 3,
        _ => 0,
    }
}

/// 화면의 4가지 스케줄 모드(0=시간마다, 1=매일, 2=매주, 3=매월)를 검증한 뒤 `profile_form::apply_schedule` 로 반영한다.
pub(crate) fn apply_schedule_mode(
    p: Profile,
    auto: bool,
    mode: i32,
    value: &str,
    exclude: &str,
) -> Result<Profile, String> {
    let trimmed = value.trim();
    match mode {
        0 => {
            if trimmed.contains('@') || trimmed.contains(':') {
                return Err("시간 간격 모드에서는 숫자만 입력하세요 (예: 6 또는 12)".into());
            }
            kova_core::profile_form::apply_schedule(p, auto, false, trimmed, exclude)
        }
        1 => {
            if trimmed.contains('@') {
                return Err("매일 모드에서는 시:분만 입력하세요 (예: 02:00)".into());
            }
            kova_core::profile_form::apply_schedule(p, auto, true, trimmed, exclude)
        }
        2 => {
            let Some((left, _)) = trimmed.split_once('@') else {
                return Err(
                    "매주 스케줄은 요일@시:분 형식이어야 합니다 (예: MON,WED@03:00 또는 월,수@03:00)"
                        .into(),
                );
            };
            if left.trim().parse::<u32>().is_ok() {
                return Err(
                    "매주 스케줄은 숫자가 아니라 요일(MON,WED 또는 월,수)을 입력하세요".into(),
                );
            }
            kova_core::profile_form::apply_schedule(p, auto, true, trimmed, exclude)
        }
        3 => {
            let Some((left, _)) = trimmed.split_once('@') else {
                return Err("매월 스케줄은 일@시:분 형식이어야 합니다 (예: 15@02:30)".into());
            };
            if left.trim().parse::<u32>().is_err() {
                return Err(
                    "매월 스케줄은 1~28 사이의 날짜와 시각을 입력하세요 (예: 15@02:30)".into(),
                );
            }
            kova_core::profile_form::apply_schedule(p, auto, true, trimmed, exclude)
        }
        _ => kova_core::profile_form::apply_schedule(p, auto, false, trimmed, exclude),
    }
}

/// 마법사: 이름·보존 기본값으로 프로파일을 만들고 매일 02:00 자동 백업을 켠 뒤 바로 한 번 백업한다.
fn quick_start(weak: slint::Weak<MainWindow>, srcs: &str, repo: &str) -> Result<String, String> {
    if app_locked() {
        return Err(LOCKED_MSG.into());
    }
    let store = ConfigStore::new(kova_service::default_config_dir());
    let all = store.profiles();
    let id = format!(
        "prof_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let p = kova_core::profile_form::build(None, &id, "내 백업", srcs, repo, "30", "60", &all)
        .and_then(|p| {
            kova_core::profile_form::apply_schedule(p, true, true, "02:00", DEFAULT_EXCLUDES)
        })
        .and_then(|p| kova_core::profile_form::apply_keep(p, "0", "0"))?;
    store
        .upsert(p.clone())
        .map_err(|e| format!("저장 실패: {e}"))?;
    send(weak, "backup", p.id.clone());
    Ok(p.id)
}

/// 마법사의 '고른 폴더' 목록을 화면(목록 + 이어 붙인 문자열)에 반영한다.
fn set_wizard_sources(w: &MainWindow, list: &[String]) {
    w.set_wz_src(list.join(";").into());
    let model: Vec<slint::SharedString> = list.iter().map(|s| s.as_str().into()).collect();
    w.set_wz_list(std::rc::Rc::new(slint::VecModel::from(model)).into());
}

/// 현재 고른 폴더 목록(이어 붙인 문자열에서 복원).
fn wizard_sources(w: &MainWindow) -> Vec<String> {
    w.get_wz_src()
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 프로그램 이름 비교용 키: 글자·숫자만 소문자로, 끝의 'updater'는 뗀다(같은 프로그램의 갱신 폴더).
fn prog_norm(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    match s.strip_suffix("updater") {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => s,
    }
}

/// 경로가 어떤 프로그램의 것이면 (비교 키, 표시 이름), 일반 폴더면 None. 경로 모양만 본다.
fn program_of(path: &str) -> Option<(String, String)> {
    let p = path.trim().trim_end_matches('\\').replace('/', "\\");
    let low = p.to_ascii_lowercase(); // ASCII만 바꾸므로 바이트 위치가 p와 같다
    fn after<'a>(p: &'a str, low: &str, marker: &str) -> Option<&'a str> {
        let i = low.find(marker)? + marker.len();
        p.get(i..)
    }
    let first = |rest: &str| rest.split('\\').next().unwrap_or("").to_string();
    let name = if low.ends_with(".lnk") {
        let stem = |s: &str| s[..s.len() - 4].to_string();
        match after(&p, &low, "\\start menu\\programs\\") {
            Some(rest) if rest.contains('\\') => first(rest),
            Some(rest) => stem(rest),
            None => stem(p.rsplit('\\').next().unwrap_or("")),
        }
    } else if let Some(r) =
        after(&p, &low, "\\program files (x86)\\").or_else(|| after(&p, &low, "\\program files\\"))
    {
        first(r)
    } else if let Some(r) = after(&p, &low, "\\appdata\\local\\programs\\") {
        first(r)
    } else if let Some(r) = after(&p, &low, "\\appdata\\local\\microsoft\\winget\\packages\\") {
        first(r).split('_').next().unwrap_or("").to_string()
    } else if low.contains("\\appdata\\local\\temp") {
        return None;
    } else {
        let r = after(&p, &low, "\\appdata\\roaming\\")
            .or_else(|| after(&p, &low, "\\appdata\\local\\"))
            .or_else(|| after(&p, &low, "\\programdata\\"))?;
        first(r)
    };
    let key = prog_norm(&name);
    if key.is_empty() {
        None
    } else {
        Some((key, name))
    }
}

/// 백업 대상 경로를 화면 줄로 바꾼다: 0=구분 제목, 1=폴더/파일, 2=프로그램.
pub(crate) fn source_rows(joined: &str) -> Vec<(i32, String, String, String)> {
    source_rows_with(joined, |p| std::path::Path::new(p).exists())
}

/// `source_rows`와 같되, 경로가 실제로 있는지 보는 방법을 받는다(시험용). 없는 경로는 '찾을 수 없음'으로 표시한다.
pub(crate) fn source_rows_with(
    joined: &str,
    exists: impl Fn(&str) -> bool,
) -> Vec<(i32, String, String, String)> {
    let mut folders = vec![];
    let mut programs: Vec<(String, String, usize, usize)> = vec![];
    let mut seen: std::collections::HashSet<String> = Default::default();
    for p in joined.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if !seen.insert(p.to_lowercase()) {
            continue;
        }
        if let Some((key, name)) = program_of(p) {
            let gone = usize::from(!exists(p));
            match programs.iter_mut().find(|x| x.0 == key) {
                Some(x) => {
                    x.2 += 1;
                    x.3 += gone;
                }
                None => programs.push((key, name, 1, gone)),
            }
        } else {
            let name = p
                .trim_end_matches(['\\', '/'])
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(p)
                .to_string();
            let sub = if exists(p) {
                p.to_string()
            } else {
                format!("찾을 수 없음 · {p}")
            };
            folders.push((1, name, sub, p.to_string()));
        }
    }
    let mut out = vec![];
    if !folders.is_empty() {
        out.push((
            0,
            format!("폴더·파일 ({}개)", folders.len()),
            String::new(),
            String::new(),
        ));
        out.extend(folders);
    }
    if !programs.is_empty() {
        out.push((
            0,
            format!("프로그램 ({}개)", programs.len()),
            String::new(),
            String::new(),
        ));
        for (key, name, n, gone) in programs {
            let sub = if gone > 0 {
                format!("{n}개 항목 · 찾을 수 없는 항목 {gone}개")
            } else {
                format!("{n}개 항목")
            };
            out.push((2, name, sub, format!("prog:{key}")));
        }
    }
    out
}

/// 원본 목록 중 없는 경로 수(있는지 보는 방법은 받는다: 시험용).
pub(crate) fn missing_count_with(joined: &str, exists: impl Fn(&str) -> bool) -> usize {
    joined
        .split(';')
        .map(str::trim)
        .filter(|x| !x.is_empty() && !exists(x))
        .count()
}

/// '없는 항목 정리': 있는 경로만 남겨 ';' 로 잇는다.
pub(crate) fn keep_existing_with(joined: &str, exists: impl Fn(&str) -> bool) -> String {
    joined
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty() && exists(s))
        .collect::<Vec<_>>()
        .join(";")
}

/// 찾은 설치 프로그램 중 원본 목록에 아직 없는 것만 (이름, 경로들, 체크 안 함)으로.
pub(crate) fn prog_candidates(
    found: Vec<(String, Vec<String>)>,
    sources: &str,
) -> Vec<(String, Vec<String>, bool)> {
    let have: std::collections::HashSet<String> = sources
        .split(';')
        .filter_map(|s| program_of(s).map(|x| x.0))
        .collect();
    found
        .into_iter()
        .filter(|(n, _)| !have.contains(&prog_norm(n)))
        .map(|(n, p)| (n, p, false))
        .collect()
}

/// 이 PC에 설치된 프로그램(이름, 백업할 경로들). 시작 메뉴·Program Files·AppData 폴더 이름으로 찾는다.
pub(crate) fn installed_programs() -> Vec<(String, Vec<String>)> {
    let env = |k: &str| std::env::var_os(k).map(std::path::PathBuf::from);
    let mut map: std::collections::BTreeMap<String, (String, Vec<String>)> = Default::default();
    let mut add = |path: &std::path::Path, only_known: bool| {
        let s = path.to_string_lossy().into_owned();
        let Some((key, name)) = program_of(&s) else {
            return;
        };
        if only_known && !map.contains_key(&key) {
            return;
        }
        let e = map.entry(key).or_insert((name, vec![]));
        if !e.1.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
            e.1.push(s);
        }
    };
    let dirs = |root: &std::path::Path| -> Vec<std::path::PathBuf> {
        std::fs::read_dir(root)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default()
    };
    fn lnks(root: &std::path::Path, depth: u32, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(root) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if depth > 0 {
                    lnks(&p, depth - 1, out);
                }
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                out.push(p);
            }
        }
    }
    for k in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(r) = env(k) {
            for d in dirs(&r) {
                add(&d, false);
            }
        }
    }
    if let Some(r) = env("LOCALAPPDATA") {
        for d in dirs(&r.join("Programs")) {
            add(&d, false);
        }
    }
    let mut menu = vec![];
    if let Some(r) = env("ProgramData") {
        lnks(
            &r.join(r"Microsoft\Windows\Start Menu\Programs"),
            3,
            &mut menu,
        );
    }
    if let Some(r) = env("APPDATA") {
        lnks(
            &r.join(r"Microsoft\Windows\Start Menu\Programs"),
            3,
            &mut menu,
        );
    }
    for l in &menu {
        add(l, false);
    }
    for k in ["APPDATA", "LOCALAPPDATA", "ProgramData"] {
        if let Some(r) = env(k) {
            for d in dirs(&r) {
                add(&d, true);
            }
        }
    }
    const SYSTEM: &[&str] = &[
        "common",
        "commonfiles",
        "accessibility",
        "accessories",
        "administrativetools",
        "systemtools",
        "startup",
        "windowspowershell",
        "windowsapps",
        "modifiablewindowsapps",
        "windowsnt",
        "windowsmail",
        "windowsdefender",
        "windowsmediaplayer",
        "windowsportabledevices",
        "windowssecurity",
        "internetexplorer",
        "uninstallinformation",
        "referenceassemblies",
        "microsoft",
        "packages",
    ];
    map.retain(|k, _| !SYSTEM.contains(&k.as_str()));
    let mut v: Vec<(String, Vec<String>)> = map.into_values().collect();
    v.sort_by_key(|x| x.0.to_lowercase());
    v
}

pub(crate) fn rows() -> Vec<ProfileRow> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    store
        .profiles()
        .into_iter()
        .map(|p| ProfileRow {
            id: p.id.clone().into(),
            name: p.name.clone().into(),
            detail: format!(
                "원본 {} → {} · 보존 {}개/{}일 · {}",
                p.sources.join(", "),
                p.repo_dir,
                p.retention_count,
                p.retention_days,
                kova_core::profile_form::schedule_text(&p)
            )
            .into(),
            size: "".into(),
            next: kova_core::profile_form::schedule_text(&p).into(),
            stale: p.last_run.is_some_and(|t| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64() - t > 3.0 * 86400.0)
                    .unwrap_or(false)
            }),
            last: match (p.last_status.as_str(), p.last_run) {
                ("", _) | (_, None) => "기록 없음".to_string(),
                (s, Some(t)) => format!(
                    "{} · {}",
                    if s == "success" { "성공" } else { "실패" },
                    chrono_fmt(t)
                ),
            }
            .into(),
        })
        .collect()
}

pub(crate) fn wire(w: &MainWindow, banner_gen: &Arc<AtomicU64>) {
    w.set_wz_repo(known_folder("backup").into());
    w.set_default_restore(known_folder("restore").into());
    w.on_known_folder(|k| known_folder(&k).into());

    {
        let weak = w.as_weak();
        w.on_wz_add(move |paths| {
            let Some(w) = weak.upgrade() else { return };
            let mut list = wizard_sources(&w);
            for p in paths.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if !list.iter().any(|x| x.eq_ignore_ascii_case(p)) {
                    list.push(p.to_string());
                }
            }
            set_wizard_sources(&w, &list);
        });

        let weak = w.as_weak();
        w.on_wz_remove(move |i| {
            let Some(w) = weak.upgrade() else { return };
            let mut list = wizard_sources(&w);
            if (i as usize) < list.len() {
                list.remove(i as usize);
            }
            set_wizard_sources(&w, &list);
        });

        let weak = w.as_weak();
        w.on_quick_start(move |srcs, repo| {
            let text = match quick_start(weak.clone(), srcs.trim(), repo.trim()) {
                Ok(_) => {
                    "설정했습니다. 백업을 시작합니다. 진행 상황은 아래에 표시됩니다.".to_string()
                }
                Err(e) => format!("시작하지 못했습니다: {e}"),
            };
            if let Some(w) = weak.upgrade() {
                w.set_wz_text(text.into());
            }
        });
    }

    {
        let weak = w.as_weak();
        w.on_sync_form_list(move |s| {
            let (weak, s) = (weak.clone(), s.to_string());
            std::thread::spawn(move || {
                let rows = source_rows(&s);
                let missing = missing_count_with(&s, |p| std::path::Path::new(p).exists());
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    if w.get_form_sources() != s.as_str() {
                        return;
                    }
                    let list: Vec<SrcRow> = rows
                        .into_iter()
                        .map(|(kind, title, sub, key)| SrcRow {
                            kind,
                            title: title.into(),
                            sub: sub.into(),
                            key: key.into(),
                        })
                        .collect();
                    w.set_form_list(std::rc::Rc::new(slint::VecModel::from(list)).into());
                    w.set_form_missing(missing as i32);
                });
            });
        });

        let weak = w.as_weak();
        let gate = BusyGate::default();
        w.on_form_clean(move || {
            let Some(w) = weak.upgrade() else { return };
            if !gate.try_begin() {
                return;
            }
            let (weak, gate) = (weak.clone(), gate.clone());
            let s = w.get_form_sources().to_string();
            std::thread::spawn(move || {
                let keep = keep_existing_with(&s, |p| std::path::Path::new(p).exists());
                let _ = slint::invoke_from_event_loop(move || {
                    gate.end();
                    let Some(w) = weak.upgrade() else { return };
                    if w.get_form_sources() == s.as_str() {
                        w.set_form_sources(keep.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_form_add(move |paths| {
            let Some(w) = weak.upgrade() else { return };
            let mut list: Vec<String> = w
                .get_form_sources()
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            for p in paths.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if !list.iter().any(|x| x.eq_ignore_ascii_case(p)) {
                    list.push(p.to_string());
                }
            }
            w.set_form_sources(list.join(";").into());
        });

        let weak = w.as_weak();
        w.on_form_remove(move |key| {
            let Some(w) = weak.upgrade() else { return };
            let list: Vec<String> = w
                .get_form_sources()
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .filter(|s| match key.strip_prefix("prog:") {
                    Some(k) => program_of(s).map(|x| x.0).as_deref() != Some(k),
                    None => !s.eq_ignore_ascii_case(&key),
                })
                .collect();
            w.set_form_sources(list.join(";").into());
        });

        type Picks = Arc<std::sync::Mutex<Vec<(String, Vec<String>, bool)>>>;
        let picks: Picks = Default::default();
        let show_picks = |w: &MainWindow, p: &[(String, Vec<String>, bool)]| {
            let rows: Vec<ProgPick> = p
                .iter()
                .map(|(n, paths, c)| ProgPick {
                    name: n.as_str().into(),
                    sub: format!("{}개 항목", paths.len()).into(),
                    checked: *c,
                })
                .collect();
            w.set_prog_count(p.iter().filter(|x| x.2).count() as i32);
            w.set_prog_list(std::rc::Rc::new(slint::VecModel::from(rows)).into());
        };

        let (weak, pk) = (w.as_weak(), picks.clone());
        let gate = BusyGate::default();
        w.on_prog_open(move || {
            if !gate.try_begin() {
                return;
            }
            let (weak, pk, gate) = (weak.clone(), pk.clone(), gate.clone());
            std::thread::spawn(move || {
                let found = installed_programs();
                let _ = slint::invoke_from_event_loop(move || {
                    gate.end();
                    let Some(w) = weak.upgrade() else { return };
                    let list = prog_candidates(found, &w.get_form_sources());
                    show_picks(&w, &list);
                    *pk.lock().unwrap() = list;
                    w.set_prog_shown(true);
                });
            });
        });

        let (weak, pk) = (w.as_weak(), picks.clone());
        w.on_prog_toggle(move |i| {
            let Some(w) = weak.upgrade() else { return };
            let mut list = pk.lock().unwrap();
            if let Some(x) = list.get_mut(i as usize) {
                x.2 = !x.2;
            }
            show_picks(&w, &list);
        });

        let (weak, pk) = (w.as_weak(), picks);
        w.on_prog_apply(move || {
            let Some(w) = weak.upgrade() else { return };
            let mut cur: Vec<String> = w
                .get_form_sources()
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            for (_, paths, checked) in pk.lock().unwrap().iter() {
                if *checked {
                    for p in paths {
                        if !cur.iter().any(|x| x.eq_ignore_ascii_case(p)) {
                            cur.push(p.clone());
                        }
                    }
                }
            }
            w.set_form_sources(cur.join(";").into());
            w.set_prog_shown(false);
        });

        let weak = w.as_weak();
        w.on_prog_close(move || {
            if let Some(w) = weak.upgrade() {
                w.set_prog_shown(false);
            }
        });
    }

    {
        let weak = w.as_weak();
        let bg = banner_gen.clone();
        w.on_run_backup(move |id| {
            bg.fetch_add(1, Ordering::SeqCst);
            if let Some(w) = weak.upgrade() {
                w.set_job_completed_show(false);
            }
            let (weak, id) = (weak.clone(), id.to_string());
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                let pid = resolve_profile_id(&store, &id).unwrap_or(id);
                send_sync(weak, "backup".into(), pid);
            });
        });

        let weak = w.as_weak();
        let bg = banner_gen.clone();
        w.on_run_verify(move |id, snap_id| {
            bg.fetch_add(1, Ordering::SeqCst);
            if let Some(w) = weak.upgrade() {
                w.set_job_completed_show(false);
            }
            let (weak, id) = (weak.clone(), id.to_string());
            let kind = format!("verify:{snap_id}");
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                let pid = resolve_profile_id(&store, &id).unwrap_or(id);
                send_sync(weak, kind, pid);
            });
        });

        let weak = w.as_weak();
        let bg = banner_gen.clone();
        w.on_dismiss_completed(move || {
            bg.fetch_add(1, Ordering::SeqCst);
            if let Some(w) = weak.upgrade() {
                w.set_job_completed_show(false);
            }
        });

        let weak = w.as_weak();
        w.on_open_repo_dir(move |dir| {
            let target = dir.trim().to_string();
            if target.is_empty() || !std::path::Path::new(&target).is_dir() {
                if let Some(w) = weak.upgrade() {
                    w.set_pick_error(
                        if target.is_empty() {
                            "아직 백업 저장소가 없습니다. 먼저 백업을 설정하세요".to_string()
                        } else {
                            format!("저장소 폴더가 아직 없습니다: {target}")
                        }
                        .into(),
                    );
                }
                return;
            }
            if let Some(w) = weak.upgrade() {
                w.set_pick_error("".into());
            }
            std::thread::spawn(move || {
                #[cfg(windows)]
                {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(&target)
                        .spawn();
                }
            });
        });
    }

    {
        let weak = w.as_weak();
        w.on_edit_profile(move |id| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            if let (Some(p), Some(w)) = (store.get(&id), weak.upgrade()) {
                w.set_form_id(p.id.clone().into());
                w.set_form_name(p.name.clone().into());
                w.set_form_sources(p.sources.join(";").into());
                w.set_form_repo(p.repo_dir.clone().into());
                w.set_form_count(p.retention_count.to_string().into());
                w.set_form_days(p.retention_days.to_string().into());
                w.set_form_auto(p.auto_backup_enabled);
                w.set_form_sched_mode(schedule_mode_from_type(&p.schedule_type));
                w.set_form_sched(p.schedule_value.clone().into());
                w.set_form_exclude(p.exclude_patterns.join(";").into());
                let keep = |k: &str| p.extra.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
                w.set_form_weekly(keep("keep_weekly").to_string().into());
                w.set_form_monthly(keep("keep_monthly").to_string().into());
                w.set_form_daily(keep("keep_daily").to_string().into());
                w.set_form_yearly(keep("keep_yearly").to_string().into());
                w.set_form_text("".into());
            }
        });

        let weak = w.as_weak();
        w.on_estimate_size(move |id| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            let Some(p) = store.get(&id) else {
                if let Some(w) = weak.upgrade() {
                    w.set_form_text("저장된 프로파일만 예측할 수 있습니다. 목록에서 수정을 누르거나 먼저 저장하세요".into());
                }
                return;
            };
            if let Some(w) = weak.upgrade() {
                w.set_form_text("원본을 훑는 중입니다…".into());
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let text = kova_core::estimate::describe(&kova_core::estimate::estimate(&p));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_form_text(text.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_save_profile(
            move |id,
                  name,
                  srcs,
                  repo,
                  count,
                  days,
                  auto,
                  sched_mode,
                  sched,
                  exclude,
                  weekly,
                  monthly,
                  daily,
                  yearly| {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        w.set_form_text(LOCKED_MSG.into());
                    }
                    return;
                }
                let store = ConfigStore::new(kova_service::default_config_dir());
                let all = store.profiles();
                let base = all.iter().find(|p| p.id == id.as_str());
                let new_id = format!(
                    "prof_{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0)
                );
                let built = kova_core::profile_form::build(
                    base, &new_id, &name, &srcs, &repo, &count, &days, &all,
                )
                .and_then(|p| apply_schedule_mode(p, auto, sched_mode, &sched, &exclude))
                .and_then(|p| kova_core::profile_form::apply_keep(p, &weekly, &monthly))
                .and_then(|p| kova_core::profile_form::apply_keep_extra(p, &daily, &yearly));
                let msg = match built {
                    Ok(p) => match store.upsert(p.clone()) {
                        Ok(()) => {
                            if let Some(w) = weak.upgrade() {
                                w.set_form_id(p.id.into());
                            }
                            "저장했습니다".to_string()
                        }
                        Err(e) => format!("저장 실패: {e}"),
                    },
                    Err(e) => format!("저장하지 않음: {e}"),
                };
                if let Some(w) = weak.upgrade() {
                    w.set_form_text(msg.into());
                }
            },
        );

        let weak = w.as_weak();
        w.on_delete_profile(move |id| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            let locked = app_locked();
            let msg = match if locked {
                Err(())
            } else {
                store.delete(&id).map_err(|_| ())
            } {
                Err(()) if locked => LOCKED_MSG,
                Ok(true) => "프로파일 설정을 삭제했습니다 (저장소의 백업 파일은 그대로입니다)",
                Ok(false) => "이미 없는 프로파일입니다",
                Err(_) => "삭제하지 못했습니다",
            };
            if let Some(w) = weak.upgrade() {
                if !locked && w.get_form_id() == id {
                    w.set_form_id("".into());
                    w.set_form_name("".into());
                    w.set_form_sources("".into());
                    w.set_form_repo("".into());
                    w.set_form_count("30".into());
                    w.set_form_days("60".into());
                    w.set_form_auto(false);
                    w.set_form_sched_mode(0);
                    w.set_form_sched("12".into());
                    w.set_form_exclude("".into());
                    w.set_form_weekly("0".into());
                    w.set_form_monthly("0".into());
                    w.set_form_daily("0".into());
                    w.set_form_yearly("0".into());
                }
                w.set_form_text(msg.into());
            }
        });
    }
}

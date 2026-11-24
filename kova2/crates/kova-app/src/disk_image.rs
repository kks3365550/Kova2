//! 디스크 이미지(.qblk / .qblk.enc / 증분 체인), 볼륨 직접 복원, WinPE ISO 제작, `.qblk` NTFS 파일 브라우저.
use crate::ipc::send;
use crate::util::{
    app_locked, chrono_fmt, fmt_size, known_folder, system_drive_letter, BusyGate, LOCKED_MSG,
};
use crate::{ImageRow, ImgBrowseRow, MainWindow};
use kova_core::config::ConfigStore;
use slint::ComponentHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// 경로가 Kova 디스크 이미지(`.qblk` 또는 `.qblk.enc`)인지 판별한다.
pub(crate) fn is_kova_image_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    name.ends_with(".qblk") || name.ends_with(".qblk.enc")
}

/// 경로가 암호화된 이미지(`.qblk.enc` 확장자 또는 `QENC` 매직)인지 판별한다.
pub(crate) fn is_encrypted_image_path(path: &Path) -> bool {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    lower.ends_with(".qblk.enc") || kova_image::crypto::is_encrypted_image(path)
}

/// 경로에 증분 체인 메타(`.qchain.json`)가 존재하는지 판별한다.
pub(crate) fn has_chain_meta(path: &Path) -> bool {
    if kova_image::incremental::chain_path_for(path).is_file() {
        return true;
    }
    // `.qblk.enc` 인 경우 대응 `.qblk.qchain.json` 도 함께 확인
    let raw = path.to_string_lossy();
    raw.strip_suffix(".enc").is_some_and(|stripped| {
        kova_image::incremental::chain_path_for(Path::new(stripped)).is_file()
    })
}

/// 무결성 검사 통과 표시 파일(`<이미지>.verified`). 이미지의 크기·수정시각이 그대로일 때만 "검증됨"으로 본다.
pub(crate) fn verified_marker(img: &Path) -> PathBuf {
    let mut n = img.as_os_str().to_os_string();
    n.push(".verified");
    PathBuf::from(n)
}

fn image_sig(img: &Path) -> Option<String> {
    let md = std::fs::metadata(img).ok()?;
    let secs = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(format!("{} {}", md.len(), secs))
}

pub(crate) fn mark_verified(img: &Path) {
    if let Some(sig) = image_sig(img) {
        let _ = std::fs::write(verified_marker(img), sig);
    }
}

pub(crate) fn is_verified(img: &Path) -> bool {
    match (
        image_sig(img),
        std::fs::read_to_string(verified_marker(img)),
    ) {
        (Some(a), Ok(b)) => a == b.trim(),
        _ => false,
    }
}

/// 단일 `images` 폴더에서 `.qblk` 및 `.qblk.enc` 이미지를 읽어 `ImageRow` 목록으로 변환한다(테스트 가능).
pub(crate) fn scan_image_dir(dir: &Path) -> Vec<(SystemTime, ImageRow)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let path = e.path();
        if !is_kova_image_path(&path) {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        let mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
        let ts = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let encrypted = is_encrypted_image_path(&path);
        let chained = has_chain_meta(&path);
        out.push((
            mtime,
            ImageRow {
                name: e.file_name().to_string_lossy().to_string().into(),
                path: path.to_string_lossy().to_string().into(),
                size: format!("{:.1} GB", md.len() as f64 / 1_073_741_824.0).into(),
                when: chrono_fmt(ts).into(),
                verified: is_verified(&path),
                encrypted,
                chained,
            },
        ));
    }
    out
}

/// 백업 보관함의 images 폴더에서 저장된 디스크 이미지(`.qblk`, `.qblk.enc`)를 최신순으로 찾는다.
pub(crate) fn image_rows() -> Vec<ImageRow> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let mut seen = std::collections::HashSet::new();
    let mut all: Vec<(SystemTime, ImageRow)> = Vec::new();
    for p in store.profiles() {
        let dir = Path::new(&p.repo_dir).join("images");
        for item in scan_image_dir(&dir) {
            if seen.insert(item.1.path.to_string()) {
                all.push(item);
            }
        }
    }
    all.sort_by_key(|x| std::cmp::Reverse(x.0));
    all.into_iter().take(20).map(|x| x.1).collect()
}

/// 변환할 만한 디스크 이미지(.img/.raw/.bin/.vhd, 100MB 이상)를 사용자 폴더와 각 드라이브 앞쪽 폴더에서 찾는다.
fn convert_candidates() -> Vec<ImageRow> {
    const SKIP: [&str; 9] = [
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "$recycle.bin",
        "system volume information",
        "appdata",
        "node_modules",
        ".git",
    ];
    let store = ConfigStore::new(kova_service::default_config_dir());
    let repos: Vec<PathBuf> = store
        .profiles()
        .iter()
        .map(|p| PathBuf::from(&p.repo_dir))
        .collect();
    let mut roots: Vec<(PathBuf, u32)> = Vec::new();
    if let Some(h) = std::env::var_os("USERPROFILE") {
        let h = PathBuf::from(h);
        for d in ["Downloads", "Desktop", "Documents"] {
            roots.push((h.join(d), 3));
        }
    }
    for l in b'C'..=b'Z' {
        let r = PathBuf::from(format!("{}:\\", l as char));
        if r.exists() {
            roots.push((r, 2));
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<(SystemTime, ImageRow)> = Vec::new();
    let mut stack: Vec<(PathBuf, u32)> = roots;
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        visited += 1;
        if visited > 20000 || out.len() >= 40 {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if depth > 1 && !SKIP.contains(&name.as_str()) && !repos.iter().any(|r| r == &path)
                {
                    stack.push((path, depth - 1));
                }
                continue;
            }
            let ext = path
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x.to_ascii_lowercase())
                .unwrap_or_default();
            if !matches!(ext.as_str(), "img" | "raw" | "bin" | "vhd")
                || md.len() < 100 * 1024 * 1024
                || !seen.insert(path.clone())
            {
                continue;
            }
            let mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
            out.push((
                mtime,
                ImageRow {
                    name: e.file_name().to_string_lossy().to_string().into(),
                    path: path.to_string_lossy().to_string().into(),
                    size: format!("{:.1} GB", md.len() as f64 / 1_073_741_824.0).into(),
                    when: "".into(),
                    verified: false,
                    encrypted: false,
                    chained: false,
                },
            ));
        }
    }
    out.sort_by_key(|x| std::cmp::Reverse(x.0));
    out.into_iter().take(20).map(|x| x.1).collect()
}

fn scan_convert_async(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let rows = convert_candidates();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_conv_cands(std::rc::Rc::new(slint::VecModel::from(rows)).into());
            }
        });
    });
}

/// 저장해 둔 이미지(`.qblk` / `.qblk.enc`) 한 개를 지운다. 백업 보관함의 images 폴더 안 파일만 허용한다.
fn delete_image_file(path: &str) -> Result<(), String> {
    if app_locked() {
        return Err(LOCKED_MSG.into());
    }
    let target = Path::new(path);
    if !is_kova_image_path(target) {
        return Err("이미지(.qblk / .qblk.enc) 파일만 지울 수 있습니다".into());
    }
    let store = ConfigStore::new(kova_service::default_config_dir());
    let canon = std::fs::canonicalize(target).map_err(|e| format!("파일을 찾을 수 없음: {e}"))?;
    let allowed = store.profiles().iter().any(|p| {
        std::fs::canonicalize(Path::new(&p.repo_dir).join("images"))
            .map(|d| canon.parent() == Some(d.as_path()))
            .unwrap_or(false)
    });
    if !allowed {
        return Err("백업 보관함의 images 폴더 밖 파일은 지우지 않습니다".into());
    }
    if let Err(e) = std::fs::remove_file(&canon) {
        if let Err(e2) = kova_core::worm::remove_protected(&canon) {
            if e2.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(
                    "랜섬웨어 보호(WORM)로 잠긴 이미지입니다. 관리자 권한으로 앱을 실행해 삭제해 주세요"
                        .into(),
                );
            }
            return Err(format!("지우지 못했습니다: {e2} ({e})"));
        }
    }
    let _ = kova_core::worm::remove_protected(&verified_marker(&canon));
    let _ = kova_core::worm::remove_protected(&kova_image::incremental::map_path_for(&canon));
    let _ = kova_core::worm::remove_protected(&kova_image::incremental::chain_path_for(&canon));
    Ok(())
}

/// 변환 결과를 둘 위치: 첫 프로파일 저장소의 images 폴더에 `<원본이름>.qblk`(있으면 번호)
fn auto_convert_target(src: &str) -> Option<String> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let p = store.profiles().into_iter().next()?;
    let dir = Path::new(&p.repo_dir).join("images");
    std::fs::create_dir_all(&dir).ok()?;
    let stem = Path::new(src)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image");
    let mut cand = dir.join(format!("{stem}.qblk"));
    let mut n = 2;
    while cand.exists() {
        cand = dir.join(format!("{stem}_{n}.qblk"));
        n += 1;
    }
    Some(cand.to_string_lossy().to_string())
}

/// 이미지 검증/복원: 단일 `.qblk` 및 증분 체인(`.qchain.json`)을 모두 지원한다.
fn image_job(weak: slint::Weak<MainWindow>, image: String, target: Option<String>, gate: BusyGate) {
    let Some(guard) = gate.lock() else {
        if let Some(w) = weak.upgrade() {
            w.set_image_text("이미 이미지 작업이 진행 중입니다.".into());
        }
        return;
    };
    std::thread::spawn(move || {
        let _guard = guard;
        let show = |w: &slint::Weak<MainWindow>, t: String| {
            let w = w.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w.upgrade() {
                    w.set_image_text(t.into());
                }
            });
        };
        let cancel = AtomicBool::new(false);
        let last = Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(5));
        let w2 = weak.clone();
        let progress = |s: &kova_image::Stats| {
            let mut l = last.lock().unwrap();
            if l.elapsed() >= std::time::Duration::from_secs(1) {
                *l = std::time::Instant::now();
                show(
                    &w2,
                    format!("진행 중… {:.1}GB 처리", s.raw_bytes as f64 / 1e9),
                );
            }
        };
        let res: Result<String, String> = (|| {
            let img = Path::new(&image);
            if is_encrypted_image_path(img) {
                return Err(
                    "암호화된 이미지(.qblk.enc)는 복구 키가 필요하므로 WinPE 복구 환경 또는 키 복호화 도구를 사용하세요"
                        .into(),
                );
            }
            let is_chain = kova_image::incremental::chain_path_for(img).is_file();
            match &target {
                None => {
                    if is_chain {
                        let links = kova_image::incremental::verify_chain(img, &cancel, &progress)
                            .map_err(|e| e.to_string())?;
                        let total_chunks: u64 = links.iter().map(|(_, _, s)| s.chunks).sum();
                        let total_bytes: u64 = links.iter().map(|(_, _, s)| s.raw_bytes).sum();
                        mark_verified(img);
                        return Ok(format!(
                            "증분 체인 검증 통과 ({}개 링크, 총 청크 {}개, {:.2}GB)",
                            links.len(),
                            total_chunks,
                            total_bytes as f64 / 1e9
                        ));
                    }
                    let f = std::fs::File::open(img).map_err(|e| e.to_string())?;
                    let (h, s) = kova_image::verify(
                        std::io::BufReader::with_capacity(8 << 20, f),
                        &cancel,
                        &progress,
                    )
                    .map_err(|e| e.to_string())?;
                    mark_verified(img);
                    Ok(format!(
                        "검증 통과: 청크 {}개, 원본 {:.2}GB, 클러스터 {}/{}{}",
                        s.chunks,
                        s.raw_bytes as f64 / 1e9,
                        s.clusters,
                        h.used_clusters,
                        if s.empty_chunks > 0 {
                            format!(
                                " (비어 있는 청크 {}개: 그 구간은 복원되지 않음)",
                                s.empty_chunks
                            )
                        } else {
                            String::new()
                        }
                    ))
                }
                Some(t) => {
                    let (_, s) = if is_chain {
                        kova_image::incremental::restore_chain_to_file(
                            img,
                            Path::new(t),
                            &cancel,
                            &progress,
                        )
                        .map_err(|e| e.to_string())?
                    } else {
                        kova_image::restore::restore_image_to_file(
                            img,
                            Path::new(t),
                            &cancel,
                            &progress,
                        )
                        .map_err(|e| e.to_string())?
                    };
                    Ok(format!(
                        "복원 완료: {t} (청크 {}개, {:.2}GB)",
                        s.chunks,
                        s.raw_bytes as f64 / 1e9
                    ))
                }
            }
        })();
        show(&weak, res.unwrap_or_else(|e| format!("실패: {e}")));
    });
}

/// 파일 원본을 .qblk 로 만든다(읽기 전용 원본, 새 파일만 출력).
fn capture_job(weak: slint::Weak<MainWindow>, source: String, out: String, gate: BusyGate) {
    let Some(guard) = gate.lock() else {
        if let Some(w) = weak.upgrade() {
            w.set_image_text("이미 이미지 작업이 진행 중입니다.".into());
        }
        return;
    };
    std::thread::spawn(move || {
        let _guard = guard;
        let show = |w: &slint::Weak<MainWindow>, t: String| {
            let w = w.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = w.upgrade() {
                    w.set_image_text(t.into());
                }
            });
        };
        let clean = |s: &str| s.trim().trim_matches('"').trim().to_string();
        let (source, out) = (clean(&source), clean(&out));
        if source.is_empty() || out.is_empty() {
            show(
                &weak,
                "원본 파일과 만들 .qblk 경로를 모두 입력하세요".into(),
            );
            return;
        }
        let cancel = AtomicBool::new(false);
        let last = Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(5));
        let w2 = weak.clone();
        let progress = |s: &kova_image::Stats| {
            let mut l = last.lock().unwrap();
            if l.elapsed() >= std::time::Duration::from_secs(1) {
                *l = std::time::Instant::now();
                show(
                    &w2,
                    format!("만드는 중… 사용 구간 {:.2}GB", s.raw_bytes as f64 / 1e9),
                );
            }
        };
        show(&weak, "만들기 시작…".into());
        let label = Path::new(&source)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = match kova_image::capture::capture_file(
            Path::new(&source),
            Path::new(&out),
            4096,
            3,
            &label,
            &cancel,
            &progress,
        ) {
            Ok((h, s)) => {
                show(&weak, "만들기 완료, 무결성 검사 중…".into());
                let last_verify =
                    Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(5));
                let w3 = weak.clone();
                let verify_progress = |vs: &kova_image::Stats| {
                    let mut l = last_verify.lock().unwrap();
                    if l.elapsed() >= std::time::Duration::from_secs(1) {
                        *l = std::time::Instant::now();
                        show(
                            &w3,
                            format!("무결성 검사 중… {:.2}GB 확인", vs.raw_bytes as f64 / 1e9),
                        );
                    }
                };
                let ok = std::fs::File::open(&out)
                    .ok()
                    .and_then(|f| {
                        kova_image::verify(
                            std::io::BufReader::with_capacity(8 << 20, f),
                            &cancel,
                            &verify_progress,
                        )
                        .ok()
                    })
                    .is_some();
                if ok {
                    mark_verified(Path::new(&out));
                }
                format!(
                    "만들기 완료: {out} (전체 {}클러스터 중 사용 {}, 청크 {}개, 무결성 {})",
                    h.total_clusters,
                    h.used_clusters,
                    s.chunks,
                    if ok {
                        "검증 통과"
                    } else {
                        "검증 실패 - 이미지를 다시 확인하세요"
                    }
                )
            }
            Err(e) => format!("만들지 않음: {e}"),
        };
        show(&weak, text);
    });
}

// ───────────────────── .qblk NTFS 파일 브라우저 & 단일 파일 추출 ─────────────────────

#[derive(Default)]
struct ImgBrowseState {
    image: Option<kova_image::browse::NtfsImage>,
    dir: String,
    seq: u64,
}
type ImgBrowse = Arc<Mutex<ImgBrowseState>>;

fn map_img_entries(entries: Vec<kova_image::browse::ImageFileEntry>) -> Vec<ImgBrowseRow> {
    entries
        .into_iter()
        .map(|e| ImgBrowseRow {
            name: e.name.into(),
            path: e.path.into(),
            is_dir: e.is_dir,
            info: if e.is_dir {
                "폴더".into()
            } else {
                fmt_size(e.size).into()
            },
        })
        .collect()
}

fn img_parent_dir(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => String::new(),
        Some((p, _)) => p.to_string(),
    }
}

fn open_img_browse_job(weak: slint::Weak<MainWindow>, st: ImgBrowse, path: String) {
    let clean = path.trim().trim_matches('"').to_string();
    if clean.is_empty() {
        let _ = weak.upgrade_in_event_loop(|w| {
            w.set_image_text("탐색할 디스크 이미지(.qblk)를 먼저 선택하세요".into())
        });
        return;
    }
    if is_encrypted_image_path(Path::new(&clean)) {
        let _ = weak.upgrade_in_event_loop(|w| {
            w.set_image_text(
                "암호화된 이미지(.qblk.enc)는 직접 파일 탐색을 지원하지 않습니다".into(),
            )
        });
        return;
    }
    let title = Path::new(&clean)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| clean.clone());
    let seq = {
        let mut s = st.lock().unwrap();
        s.seq += 1;
        s.image = None;
        s.dir.clear();
        s.seq
    };
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_img_browse_title(title.into());
        w.set_img_browse_dir("/".into());
        w.set_img_browse_items(std::rc::Rc::new(slint::VecModel::<ImgBrowseRow>::default()).into());
        w.set_img_browse_status("NTFS 파일 목록($MFT)을 읽는 중…".into());
        w.set_img_browse_open(true);
    });
    std::thread::spawn(move || {
        let opened = kova_image::browse::NtfsImage::open(Path::new(&clean));
        match opened {
            Ok(img) => {
                let rows = map_img_entries(img.list_dir(""));
                let count = rows.len();
                {
                    let mut s = st.lock().unwrap();
                    if s.seq != seq {
                        return;
                    }
                    s.image = Some(img);
                    s.dir.clear();
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_img_browse_dir("/".into());
                        w.set_img_browse_items(
                            std::rc::Rc::new(slint::VecModel::from(rows)).into(),
                        );
                        w.set_img_browse_status(format!("루트 항목 {count}개").into());
                    }
                });
            }
            Err(e) => {
                let msg = format!("이미지 NTFS 탐색 실패: {e}");
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_img_browse_status(msg.into());
                });
            }
        }
    });
}

fn img_browse_list_dir(weak: slint::Weak<MainWindow>, st: ImgBrowse, dir: String) {
    let (rows, display_dir) = {
        let mut s = st.lock().unwrap();
        let Some(ref img) = s.image else {
            return;
        };
        let list = img.list_dir(&dir);
        s.dir = dir.clone();
        let display = if dir.is_empty() { "/".to_string() } else { dir };
        (map_img_entries(list), display)
    };
    let count = rows.len();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(w) = weak.upgrade() {
            w.set_img_browse_dir(display_dir.into());
            w.set_img_browse_items(std::rc::Rc::new(slint::VecModel::from(rows)).into());
            w.set_img_browse_status(format!("{count}개 항목").into());
        }
    });
}

fn img_browse_search_items(weak: slint::Weak<MainWindow>, st: ImgBrowse, query: String) {
    let q = query.trim().to_string();
    if q.is_empty() {
        let cur = st.lock().unwrap().dir.clone();
        img_browse_list_dir(weak, st, cur);
        return;
    }
    let rows = {
        let s = st.lock().unwrap();
        let Some(ref img) = s.image else {
            return;
        };
        map_img_entries(img.search(&q, 200))
    };
    let count = rows.len();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(w) = weak.upgrade() {
            w.set_img_browse_dir(format!("검색: {q}").into());
            w.set_img_browse_items(std::rc::Rc::new(slint::VecModel::from(rows)).into());
            w.set_img_browse_status(format!("'{q}' 검색 결과 {count}건").into());
        }
    });
}

fn img_browse_extract_job(
    weak: slint::Weak<MainWindow>,
    st: ImgBrowse,
    img_path: String,
    file_name: String,
    dest_dir: String,
) {
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_img_browse_status(format!("파일 추출 중: {file_name}…").into());
    });
    std::thread::spawn(move || {
        let out_dir = if dest_dir.trim().is_empty() {
            PathBuf::from(known_folder("restore"))
        } else {
            PathBuf::from(dest_dir.trim())
        };
        let safe_name = Path::new(&img_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "extracted.bin".into());
        let res = (|| -> Result<String, String> {
            std::fs::create_dir_all(&out_dir).map_err(|e| format!("대상 폴더 생성 실패: {e}"))?;
            let mut dest = out_dir.join(&safe_name);
            if dest.exists() {
                let stem = Path::new(&safe_name)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("extracted");
                let ext = Path::new(&safe_name).extension().and_then(|s| s.to_str());
                let mut n = 2u32;
                loop {
                    let cand_name = match ext {
                        Some(e) => format!("{stem}_{n}.{e}"),
                        None => format!("{stem}_{n}"),
                    };
                    let cand = out_dir.join(cand_name);
                    if !cand.exists() {
                        dest = cand;
                        break;
                    }
                    n += 1;
                }
            }
            let mut guard = st.lock().unwrap();
            let img = guard
                .image
                .as_mut()
                .ok_or_else(|| "열려 있는 이미지가 없습니다".to_string())?;
            let written = img
                .extract_file(&img_path, &dest)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "추출 완료: {} ({})",
                dest.display(),
                fmt_size(written)
            ))
        })();
        let msg = match res {
            Ok(m) => m,
            Err(e) => format!("추출 실패: {e}"),
        };
        let _ = weak.upgrade_in_event_loop(move |w| w.set_img_browse_status(msg.into()));
    });
}

// ───────────────────── 볼륨 직접 복원 (Windows) ─────────────────────

#[cfg(windows)]
fn show_volume(weak: &slint::Weak<MainWindow>, t: String) {
    let w = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(w) = w.upgrade() {
            w.set_volume_text(t.into());
        }
    });
}

#[cfg(windows)]
fn protected_drive_letters() -> Vec<char> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    store
        .profiles()
        .iter()
        .filter_map(|p| {
            let b = p.repo_dir.as_bytes();
            (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()).then(|| b[0] as char)
        })
        .collect()
}

#[cfg(windows)]
fn protected_repo_paths() -> Vec<PathBuf> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    store
        .profiles()
        .into_iter()
        .filter(|p| !p.repo_dir.is_empty())
        .map(|p| PathBuf::from(p.repo_dir))
        .collect()
}

#[cfg(windows)]
fn volume_check(weak: &slint::Weak<MainWindow>, letter: &str) {
    let letter = letter.trim().to_string();
    let weak = weak.clone();
    std::thread::spawn(move || {
        let (phrase, status) = match letter.chars().next() {
            None => (String::new(), "드라이브 문자를 입력하세요.".to_string()),
            Some(c) => {
                let sys = system_drive_letter();
                let protected = protected_drive_letters();
                match kova_image::volume_restore::check_letter(c, sys, &protected)
                    .and_then(|()| kova_image::volume_restore::volume_info(c))
                {
                    Ok(v) => (
                        format!(
                            "{}: 볼륨 '{}' 의 내용이 전부 덮어써집니다. 계속하려면 아래 칸에 그대로 입력하세요:\n{}",
                            v.letter,
                            v.label,
                            kova_image::volume_restore::confirmation_phrase(&v)
                        ),
                        String::new(),
                    ),
                    Err(e) => (String::new(), format!("대상으로 사용할 수 없음: {e}")),
                }
            }
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_volume_phrase(phrase.into());
                w.set_volume_text(status.into());
            }
        });
    });
}

#[cfg(windows)]
fn path_drive_letter(p: &Path) -> Option<char> {
    let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = real.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let b = s.as_bytes();
    (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
        .then(|| (b[0] as char).to_ascii_uppercase())
}

#[cfg(windows)]
fn restore_volume_job(
    weak: slint::Weak<MainWindow>,
    image: String,
    letter: String,
    typed: String,
    gate: BusyGate,
) {
    if app_locked() {
        show_volume(&weak, LOCKED_MSG.into());
        return;
    }
    let clean_image = image.trim().trim_matches('"').to_string();
    if clean_image.is_empty() {
        show_volume(
            &weak,
            "① 복원할 이미지를 먼저 고르세요 (위 목록에서 누르거나 '찾아보기').".into(),
        );
        return;
    }
    if !Path::new(&clean_image).is_file() {
        show_volume(
            &weak,
            "선택한 이미지 파일을 찾을 수 없습니다. 다시 선택하세요.".into(),
        );
        return;
    }
    if is_encrypted_image_path(Path::new(&clean_image)) {
        show_volume(
            &weak,
            "암호화된 이미지(.qblk.enc) 볼륨 직접 복원은 복구 키가 필요하므로 WinPE 복구 도구를 사용하세요.".into(),
        );
        return;
    }
    let Some(c) = letter.trim().chars().next() else {
        show_volume(&weak, "② 덮어쓸 드라이브를 먼저 고르세요.".into());
        return;
    };
    let Some(guard) = gate.lock() else {
        show_volume(&weak, "이미 볼륨 복원이 진행 중입니다.".into());
        return;
    };
    std::thread::spawn(move || {
        let _guard = guard;
        let protected = protected_drive_letters();
        let mut pre_prot = protected.clone();
        pre_prot.extend(path_drive_letter(Path::new(&clean_image)));
        if let Ok(exe) = std::env::current_exe() {
            pre_prot.extend(path_drive_letter(&exe));
        }
        let precheck =
            kova_image::volume_restore::check_letter(c, system_drive_letter(), &pre_prot)
                .and_then(|()| kova_image::volume_restore::volume_info(c))
                .and_then(|v| kova_image::volume_restore::check_confirmation(&v, &typed));
        if let Err(e) = precheck {
            show_volume(&weak, format!("복원하지 않음: {e}"));
            return;
        }
        show_volume(
            &weak,
            "이미지 검증 중… (검증이 끝나기 전에는 볼륨에 쓰지 않습니다)".into(),
        );
        let cancel = AtomicBool::new(false);
        let last = Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(5));
        let img_path = Path::new(&clean_image);
        let is_chain = kova_image::incremental::chain_path_for(img_path).is_file();
        let r = if is_chain {
            let repo_paths = protected_repo_paths();
            let path_refs: Vec<&Path> = repo_paths.iter().map(PathBuf::as_path).collect();
            let w2 = weak.clone();
            kova_image::volume_restore::restore_chain_to_volume(
                img_path,
                c,
                &typed,
                &path_refs,
                &cancel,
                &|rp| {
                    let mut l = last.lock().unwrap();
                    if l.elapsed() >= std::time::Duration::from_secs(1) {
                        *l = std::time::Instant::now();
                        let gb = rp.stats.raw_bytes as f64 / 1e9;
                        let link = format!("{}/{}", rp.link_index + 1, rp.link_count);
                        let text = match rp.phase {
                            kova_image::volume_restore::RestorePhase::Decrypt => {
                                format!("체인 복호화 중({link})…")
                            }
                            kova_image::volume_restore::RestorePhase::Verify => {
                                format!("체인 검증 중({link})… {gb:.1}GB 확인")
                            }
                            kova_image::volume_restore::RestorePhase::Write => {
                                let pct = (rp.stats.raw_bytes as f64
                                    / rp.stats.total_raw_bytes.max(1) as f64
                                    * 100.0)
                                    .min(100.0);
                                format!("체인 복원 중({link})… {gb:.1}GB 기록 ({pct:.0}%)")
                            }
                        };
                        show_volume(&w2, text);
                    }
                },
            )
        } else {
            let w2 = weak.clone();
            let progress = |s: &kova_image::Stats| {
                let mut l = last.lock().unwrap();
                if l.elapsed() >= std::time::Duration::from_secs(1) {
                    *l = std::time::Instant::now();
                    let gb = s.raw_bytes as f64 / 1e9;
                    let text = if s.total_raw_bytes == 0 {
                        format!(
                            "이미지 검증 중… {gb:.1}GB 확인 (이 단계는 볼륨에 쓰지 않습니다. 끝나면 복원이 시작됩니다)"
                        )
                    } else {
                        let pct =
                            (s.raw_bytes as f64 / s.total_raw_bytes as f64 * 100.0).min(100.0);
                        format!(
                            "복원 중… {gb:.1} / {:.1}GB 기록 ({pct:.0}%)",
                            s.total_raw_bytes as f64 / 1e9
                        )
                    };
                    show_volume(&w2, text);
                }
            };
            kova_image::volume_restore::restore_image_to_volume(
                img_path, c, &typed, &protected, &cancel, &progress,
            )
        };
        let text = match r {
            Ok((_, s)) => format!(
                "복원 완료: {}: ({:.2}GB 기록). 볼륨이 마운트 해제됐으므로 탐색기에서 다시 열어 확인하세요.",
                c.to_ascii_uppercase(),
                s.raw_bytes as f64 / 1e9
            ),
            Err(kova_image::volume_restore::VolumeError::Io(e)) if e.raw_os_error() == Some(5) => {
                "복원하지 않음: 액세스가 거부됐습니다. Kova 앱을 관리자 권한으로 실행해야 합니다."
                    .into()
            }
            Err(e) => format!("복원하지 않음: {e}"),
        };
        show_volume(&weak, text);
    });
}

// ───────────────────── WinPE ISO 제작 & 드라이버 수집 ─────────────────────

fn find_make_pe_script() -> Option<(PathBuf, PathBuf)> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidates = [
        (dir.join("make_pe.ps1"), dir.join("kova-pe.exe")),
        (
            dir.join("installer").join("make_pe.ps1"),
            dir.join("kova-pe.exe"),
        ),
        (
            dir.join("..")
                .join("..")
                .join("installer")
                .join("make_pe.ps1"),
            dir.join("kova-pe.exe"),
        ),
    ];
    candidates
        .into_iter()
        .find(|(script, pe)| script.is_file() && pe.is_file())
}

pub(crate) fn build_pe_ps_args(
    script: &Path,
    out_iso: &Path,
    pe_exe: &Path,
    drivers_dir: &str,
) -> String {
    let q = |s: &str| s.replace('"', "\\\"").replace('\'', "''");
    let mut args = format!(
        "-NoProfile -ExecutionPolicy Bypass -File \"{}\" -Out \"{}\" -Exe \"{}\"",
        q(&script.to_string_lossy()),
        q(&out_iso.to_string_lossy()),
        q(&pe_exe.to_string_lossy()),
    );
    if !drivers_dir.trim().is_empty() {
        args.push_str(&format!(" -DriversDir \"{}\"", q(drivers_dir.trim())));
    }
    args
}

fn run_build_pe_iso(iso_out: &str, drivers_dir: &str) -> String {
    let adk = Path::new(
        r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat",
    );
    if !adk.is_file() {
        return "Windows ADK(및 WinPE 애드온)가 설치되어 있지 않습니다. Microsoft Windows ADK를 먼저 설치하세요.".into();
    }
    let Some((script, pe_exe)) = find_make_pe_script() else {
        return "make_pe.ps1 또는 kova-pe.exe를 찾지 못했습니다. 릴리즈 패키지에 포함돼 있는지 확인하세요.".into();
    };
    let out_iso = if iso_out.is_empty() {
        std::env::var_os("USERPROFILE")
            .map(|u| PathBuf::from(u).join("Desktop"))
            .filter(|d| d.is_dir())
            .unwrap_or_else(std::env::temp_dir)
            .join("Kova2_WinPE_Recovery.iso")
    } else {
        PathBuf::from(iso_out)
    };
    let effective_drivers_dir = if drivers_dir.trim().is_empty() {
        let def = kova_pe::plan::default_driver_export_dir();
        if let Some(valid) = kova_pe::plan::find_collected_drivers(&def) {
            valid.to_string_lossy().to_string()
        } else {
            String::new()
        }
    } else {
        drivers_dir.trim().to_string()
    };
    if !effective_drivers_dir.is_empty() && !Path::new(&effective_drivers_dir).is_dir() {
        return format!("추가 드라이버 폴더를 찾을 수 없습니다: {effective_drivers_dir}");
    }
    let inner_args = build_pe_ps_args(&script, &out_iso, &pe_exe, &effective_drivers_dir);
    let cmd = format!(
        "$ErrorActionPreference = 'Stop'; $p = Start-Process -FilePath 'powershell.exe' -ArgumentList '{inner_args}' -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
    );
    use std::os::windows::process::CommandExt;
    match std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
        .creation_flags(0x0800_0000)
        .output()
    {
        Ok(o) if o.status.success() && out_iso.is_file() => {
            let mb = std::fs::metadata(&out_iso)
                .map(|m| m.len() / (1024 * 1024))
                .unwrap_or(0);
            format!(
                "WinPE 복구 ISO 생성 완료 ({mb}MB): {} — Rufus로 USB에 구워 사용하세요.",
                out_iso.display()
            )
        }
        Ok(o) if !o.status.success() => {
            "관리자 권한 승인이 취소되었거나 제작이 중단되었습니다.".into()
        }
        Ok(_) => "ISO 파일이 생성되지 않았습니다. ADK WinPE 애드온 설치 상태를 확인하세요.".into(),
        Err(e) => format!("제작 실행 실패: {e}"),
    }
}

/// 현재 PC의 서드파티(NVMe, 네트워크) 드라이버를 자동 수집(덤프)한다.
pub(crate) fn run_export_drivers(dest_override: Option<&Path>) -> Result<String, String> {
    let dest = dest_override
        .map(PathBuf::from)
        .unwrap_or_else(kova_pe::plan::default_driver_export_dir);
    kova_pe::plan::export_drivers(&dest).map_err(|e| {
        if e.starts_with("드라이버 수집 실패") {
            e
        } else {
            format!("드라이버 수집 실패: {e}")
        }
    })
}

fn request_volume_capture(weak: &slint::Weak<MainWindow>, drive_raw: &str, incremental: bool) {
    let d = drive_raw.trim().trim_end_matches([':', '\\']).to_string();
    let store = ConfigStore::new(kova_service::default_config_dir());
    let text = match (
        d.len() == 1 && d.as_bytes()[0].is_ascii_alphabetic(),
        store.profiles().first(),
    ) {
        (false, _) => "드라이브 문자 한 글자를 입력하세요 (예: F)".to_string(),
        (_, None) => "프로파일이 없습니다. 홈 화면에서 먼저 백업을 설정하세요".to_string(),
        (true, Some(p)) => {
            let letter = d.to_ascii_uppercase();
            let kind = if incremental {
                format!("image_inc:{letter}")
            } else {
                format!("image:{letter}")
            };
            send(weak.clone(), kind, p.id.clone());
            if incremental {
                format!(
                    "{letter}: 증분 이미지 캡처를 서비스에 요청했습니다. 진행·결과는 상단 실행 상태 표시줄에 표시됩니다"
                )
            } else {
                format!(
                    "{letter}: 이미지 작업을 서비스에 요청했습니다. 진행·결과는 상단 실행 상태 표시줄에 표시됩니다"
                )
            }
        }
    };
    if let Some(w) = weak.upgrade() {
        w.set_image_text(text.into());
    }
}

pub(crate) fn wire(w: &MainWindow) {
    #[cfg(windows)]
    {
        let weak = w.as_weak();
        w.on_volume_check(move |l| volume_check(&weak, l.as_str()));
        let weak = w.as_weak();
        let vol_gate = BusyGate::default();
        w.on_restore_volume(move |img, l, t| {
            restore_volume_job(
                weak.clone(),
                img.to_string(),
                l.to_string(),
                t.to_string(),
                vol_gate.clone(),
            )
        });
    }

    let image_gate = BusyGate::default();
    let weak = w.as_weak();
    let gate_v = image_gate.clone();
    w.on_verify_image(move |p| image_job(weak.clone(), p.to_string(), None, gate_v.clone()));

    let weak = w.as_weak();
    let gate_c = image_gate.clone();
    w.on_capture_image(move |s, o| {
        let (src, mut out) = (s.to_string(), o.to_string());
        if src.trim().is_empty() {
            if let Some(w) = weak.upgrade() {
                w.set_image_text("위 목록에서 변환할 이미지를 먼저 고르세요".into());
            }
            return;
        }
        if out.trim().is_empty() {
            match auto_convert_target(&src) {
                Some(t) => out = t,
                None => {
                    if let Some(w) = weak.upgrade() {
                        w.set_image_text(
                            "프로파일이 없어 저장 위치를 정할 수 없습니다. 홈 화면에서 먼저 백업을 설정하세요"
                                .into(),
                        );
                    }
                    return;
                }
            }
        }
        capture_job(weak.clone(), src, out, gate_c.clone());
    });

    let weak = w.as_weak();
    w.on_scan_convert(move || scan_convert_async(weak.clone()));
    scan_convert_async(w.as_weak());

    let weak = w.as_weak();
    w.on_delete_image(move |p| {
        let res = delete_image_file(p.as_str());
        if let Some(w) = weak.upgrade() {
            match res {
                Ok(()) => {
                    if w.get_img_path() == p {
                        w.set_img_path("".into());
                    }
                    if w.get_vol_img() == p {
                        w.set_vol_img("".into());
                    }
                    w.set_image_text("이미지를 삭제했습니다".into());
                }
                Err(e) => {
                    w.set_image_text(e.into());
                }
            }
        }
    });

    let weak = w.as_weak();
    w.on_capture_volume(move |d| request_volume_capture(&weak, d.as_str(), false));

    let weak = w.as_weak();
    w.on_capture_volume_inc(move |d| request_volume_capture(&weak, d.as_str(), true));

    let weak = w.as_weak();
    let gate_r = image_gate;
    w.on_restore_image(move |p, t| {
        let (p, mut t) = (p.to_string(), t.trim().to_string());
        if t.is_empty() {
            let src = Path::new(&p);
            let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("image");
            let dir = src.parent().unwrap_or(Path::new("."));
            let mut cand = dir.join(format!("{stem}_restored.img"));
            let mut n = 2;
            while cand.exists() {
                cand = dir.join(format!("{stem}_restored_{n}.img"));
                n += 1;
            }
            t = cand.to_string_lossy().to_string();
        }
        image_job(weak.clone(), p, Some(t), gate_r.clone());
    });

    // .qblk NTFS File Browser callbacks
    {
        let img_st: ImgBrowse = Default::default();

        let (weak, s2) = (w.as_weak(), img_st.clone());
        w.on_open_img_browse(move |p| {
            open_img_browse_job(weak.clone(), s2.clone(), p.to_string());
        });

        let (weak, s2) = (w.as_weak(), img_st.clone());
        w.on_img_browse_go(move |d| {
            img_browse_list_dir(weak.clone(), s2.clone(), d.to_string());
        });

        let (weak, s2) = (w.as_weak(), img_st.clone());
        w.on_img_browse_up(move || {
            let parent = img_parent_dir(&s2.lock().unwrap().dir);
            img_browse_list_dir(weak.clone(), s2.clone(), parent);
        });

        let (weak, s2) = (w.as_weak(), img_st.clone());
        w.on_img_browse_search(move |q| {
            img_browse_search_items(weak.clone(), s2.clone(), q.to_string());
        });

        let (weak, s2) = (w.as_weak(), img_st.clone());
        w.on_img_browse_extract(move |path, name, dest_dir| {
            img_browse_extract_job(
                weak.clone(),
                s2.clone(),
                path.to_string(),
                name.to_string(),
                dest_dir.to_string(),
            );
        });

        let (weak, s2) = (w.as_weak(), img_st);
        w.on_img_browse_close(move || {
            let mut s = s2.lock().unwrap();
            s.seq += 1;
            s.image = None;
            s.dir.clear();
            if let Some(w) = weak.upgrade() {
                w.set_img_browse_open(false);
                w.set_img_browse_items(
                    std::rc::Rc::new(slint::VecModel::<ImgBrowseRow>::default()).into(),
                );
                w.set_img_browse_status("".into());
            }
        });
    }

    // WinPE & Driver export
    {
        let weak = w.as_weak();
        w.on_build_pe_iso(move |iso_out, drivers_dir| {
            let iso_out = iso_out.trim().to_string();
            let drivers_dir = drivers_dir.trim().to_string();
            let weak = weak.clone();
            if let Some(w) = weak.upgrade() {
                w.set_pe_text(
                    "WinPE 복구 ISO 제작 준비 중… (관리자 권한 승인이 필요합니다)".into(),
                );
            }
            std::thread::spawn(move || {
                let text = run_build_pe_iso(&iso_out, &drivers_dir);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_pe_text(text.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_export_drivers(move || {
            let weak = weak.clone();
            let start_msg = "현재 PC 드라이버 자동 수집(덤프) 중… (DISM)";
            if let Some(w) = weak.upgrade() {
                w.set_pe_text(start_msg.into());
                w.set_diag_text(start_msg.into());
            }
            std::thread::spawn(move || {
                let res = run_export_drivers(None);
                let def_str = kova_pe::plan::default_driver_export_dir()
                    .to_string_lossy()
                    .to_string();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match res {
                            Ok(text) => {
                                w.set_pe_text(text.clone().into());
                                w.set_diag_text(text.into());
                                w.set_pe_drivers_dir(def_str.into());
                            }
                            Err(text) => {
                                w.set_pe_text(text.clone().into());
                                w.set_diag_text(text.into());
                            }
                        }
                    }
                });
            });
        });
    }
}

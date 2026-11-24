//! 전역 설정, 보안·암호화, 오프사이트(Local/Google Drive/S3), SMB, SMTP, Fleet, 작업 실행 이력, 진단 도구.
use crate::ipc::{ipc_done, ipc_once, send_failure};
use crate::util::{
    alert_rows, app_locked, chrono_fmt, fmt_size, kind_label, lock_status, open_url, profile_name,
    set_unlocked, try_begin, LOCKED_MSG,
};
use crate::{JobHistoryRow, MainWindow, OffsiteRow, SmbCredRow};
use kova_core::config::ConfigStore;
use slint::ComponentHandle;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// 구글 드라이브 로그인·연결 해제가 진행 중이면 true(중복 클릭 방지).
static GDRIVE_BUSY: AtomicBool = AtomicBool::new(false);

pub(crate) fn offsite_rows() -> Vec<OffsiteRow> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    store
        .profiles()
        .into_iter()
        .map(|p| OffsiteRow {
            id: p.id.clone().into(),
            name: p.name.clone().into(),
            dir: p
                .extra
                .get("offsite_dir")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into(),
        })
        .collect()
}

/// 해당 프로파일의 오프사이트 폴더만 바꾼다. 빈 값이면 설정을 지운다.
fn save_offsite(id: &str, dir: &str) -> Result<String, String> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let Some(mut p) = store.get(id) else {
        return Err("없는 프로파일입니다".into());
    };
    let dir = dir.trim();
    if dir.is_empty() {
        p.extra.remove("offsite_dir");
    } else {
        p.extra.insert("offsite_dir".into(), dir.into());
    }
    let name = p.name.clone();
    store
        .upsert(p)
        .map(|()| format!("오프사이트 폴더를 저장했습니다: {name}"))
        .map_err(|e| format!("오프사이트 폴더 저장 실패: {e}"))
}

/// 오프사이트 제공자를 바꾼다(서비스가 gdrive 또는 s3 일 때 클라우드 복제 활성화).
pub(crate) fn set_offsite_provider_in(store: &ConfigStore, p: &str) {
    let mut s = store.settings();
    s.offsite_provider = p.into();
    s.offsite_enabled = matches!(p, "gdrive" | "s3");
    let _ = store.save_settings(&s);
}

fn set_offsite_provider(p: &str) {
    let store = ConfigStore::new(kova_service::default_config_dir());
    set_offsite_provider_in(&store, p);
}

/// 설정 저장·작업 결과 문구와 오류 여부를 화면에 반영한다.
fn set_settings_msg(w: &MainWindow, res: Result<String, String>) {
    match res {
        Ok(m) => {
            w.set_settings_err(false);
            w.set_settings_text(m.into());
        }
        Err(m) => {
            w.set_settings_err(true);
            w.set_settings_text(m.into());
        }
    }
}

/// 화면에서 고친 전역 설정을 저장한다. 최신 파일을 다시 읽어 바꾼 칸만 덮어쓰므로 나머지 값(알 수 없는 키 포함)은 보존된다.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_settings(
    store: &ConfigStore,
    min_free_gb: &str,
    ransomware: bool,
    encrypt: bool,
    use_vss: bool,
    pack_blobs: bool,
    encrypt_manifests: bool,
    preserve_acl: bool,
    incremental_images: bool,
) -> Result<String, String> {
    let gb: u32 = min_free_gb
        .trim()
        .parse()
        .map_err(|_| "최소 여유 공간은 0 이상의 정수(GB)로 입력하세요".to_string())?;
    if gb > 100_000 {
        return Err("최소 여유 공간이 너무 큽니다 (최대 100000GB)".into());
    }
    let mut codes = Vec::new();
    let pending = store.profiles().iter().any(|p| {
        !p.repo_dir.is_empty() && !kova_core::repocrypto::is_enabled(Path::new(&p.repo_dir))
    });
    if encrypt && pending {
        let res = ipc_once(&kova_ipc::Request::EnableEncryption);
        if let Some(why) = send_failure(&res) {
            return Err(format!("저장소 암호화 실패: {why}"));
        }
        codes = res
            .ok()
            .into_iter()
            .flatten()
            .find_map(|e| match e {
                kova_ipc::Event::Encrypted { codes } => {
                    Some(codes.into_iter().map(|c| c.0).collect::<Vec<_>>())
                }
                _ => None,
            })
            .ok_or("저장소 암호화 실패: 서비스가 응답하지 않았습니다(서비스를 최신 버전으로 업데이트하세요)")?;
    }
    let mut s = store.settings();
    s.min_free_disk_gb = gb;
    s.enable_ransomware_protection = ransomware;
    s.encrypt_backups = encrypt;
    s.use_vss = use_vss;
    s.pack_blobs = pack_blobs;
    s.encrypt_manifests = encrypt_manifests;
    s.preserve_acl = preserve_acl;
    s.incremental_images = incremental_images;
    store
        .save_settings(&s)
        .map_err(|e| format!("저장 실패: {e}"))?;
    if codes.is_empty() {
        Ok("저장했습니다".into())
    } else {
        Ok(format!(
            "저장했습니다. '복구 키트 저장' 버튼으로 파일로 보관하세요.\n{}",
            codes.join("\n")
        ))
    }
}

/// 이 PC에 키가 있는 암호화 저장소들의 복구 코드를 서비스에서 받아(관리자 권한 앱만) 복구 키트 파일로 저장한다.
fn export_recovery_kit_to(out_path: &Path) -> Result<String, String> {
    let res = ipc_once(&kova_ipc::Request::ExportRecoveryCodes);
    if let Some(why) = send_failure(&res) {
        return Err(why);
    }
    let entries: Vec<(String, String, String)> = res
        .ok()
        .into_iter()
        .flatten()
        .find_map(|e| match e {
            kova_ipc::Event::RecoveryCodes { entries } => Some(
                entries
                    .into_iter()
                    .map(|x| (x.name, x.repo, x.code.0))
                    .collect(),
            ),
            _ => None,
        })
        .ok_or("서비스가 응답하지 않았습니다(서비스를 최신 버전으로 업데이트하세요)")?;
    kova_core::repocrypto::write_recovery_kit(out_path, &entries)?;
    Ok(format!(
        "복구 키트 저장 완료 (암호화 저장소 {}곳): {}",
        entries.len(),
        out_path.display()
    ))
}

/// 운영 자동화 설정(웹훅·CPU 스레드·오프사이트 대역폭·배터리 일시정지·Fleet 주소)을 검증하고 저장한다.
pub(crate) fn apply_ops_settings(
    store: &ConfigStore,
    webhook: &str,
    max_threads_str: &str,
    bw_limit_str: &str,
    pause_on_battery: bool,
    fleet_endpoint: &str,
) -> Result<String, String> {
    let wh = webhook.trim();
    if !wh.is_empty() {
        kova_core::notify::validate_webhook_url(wh)?;
    }
    let fe = fleet_endpoint.trim();
    if !fe.is_empty() {
        kova_core::notify::validate_webhook_url(fe).map_err(|_| {
            "중앙 관리(Fleet) 주소는 http:// 또는 https:// 로 시작해야 합니다".to_string()
        })?;
    }
    let threads: u32 = max_threads_str
        .trim()
        .parse()
        .map_err(|_| "CPU 스레드 수는 0 이상의 정수로 입력하세요".to_string())?;
    if threads > 64 {
        return Err("CPU 스레드 수는 0~64 범위로 입력하세요".into());
    }
    let bw: u32 = bw_limit_str
        .trim()
        .parse()
        .map_err(|_| "전송 속도(MB/s)는 0 이상의 정수로 입력하세요".to_string())?;
    if bw > 10_000 {
        return Err("전송 속도(MB/s)는 0~10000 범위로 입력하세요".into());
    }
    let mut s = store.settings();
    s.webhook_url = wh.to_string();
    s.max_cpu_threads = threads;
    s.offsite_bw_limit_mbps = bw;
    s.pause_on_battery = pause_on_battery;
    s.fleet_endpoint = fe.to_string();
    store
        .save_settings(&s)
        .map_err(|e| format!("운영 설정 저장 실패: {e}"))?;
    Ok("운영 설정을 저장했습니다".into())
}

/// 중앙 관리 서버(Fleet) 주소만 검증해 저장한다.
pub(crate) fn apply_fleet_endpoint(
    store: &ConfigStore,
    fleet_endpoint: &str,
) -> Result<String, String> {
    let fe = fleet_endpoint.trim();
    if !fe.is_empty() {
        kova_core::notify::validate_webhook_url(fe).map_err(|_| {
            "중앙 관리(Fleet) 주소는 http:// 또는 https:// 로 시작해야 합니다".to_string()
        })?;
    }
    let mut s = store.settings();
    s.fleet_endpoint = fe.to_string();
    store
        .save_settings(&s)
        .map_err(|e| format!("Fleet 주소 저장 실패: {e}"))?;
    if fe.is_empty() {
        Ok("중앙 관리 서버(Fleet) 전송을 비활성화했습니다".into())
    } else {
        Ok("중앙 관리 서버(Fleet) 주소를 저장했습니다".into())
    }
}

/// 안전 점검 설정(복구 훈련 주기·백업 중단 경고 일수)을 검증해 저장한다. 0이면 기능을 끈다.
pub(crate) fn apply_watch_settings(
    store: &ConfigStore,
    drill_days_str: &str,
    stale_days_str: &str,
) -> Result<String, String> {
    let parse = |s: &str, name: &str| -> Result<u32, String> {
        let v: u32 = s
            .trim()
            .parse()
            .map_err(|_| format!("{name}은 0 이상의 정수로 입력하세요"))?;
        if v > 365 {
            return Err(format!("{name}은 0~365 범위로 입력하세요"));
        }
        Ok(v)
    };
    let drill = parse(drill_days_str, "복구 훈련 주기")?;
    let stale = parse(stale_days_str, "백업 중단 경고 일수")?;
    let mut s = store.settings();
    s.auto_drill_days = drill;
    s.stale_warn_days = stale;
    store
        .save_settings(&s)
        .map_err(|e| format!("점검 설정 저장 실패: {e}"))?;
    Ok("점검 설정을 저장했습니다".into())
}

/// 복구 코드로 이 PC의 키 파일을 다시 만든다.
fn restore_keys(code: &str) -> Result<String, String> {
    ipc_done(&kova_ipc::Request::RestoreKey {
        code: kova_ipc::Secret(code.to_string()),
    })
}

/// 암호화 저장소의 복구 훈련은 서비스가 서비스 임시 폴더에서 한다.
fn drill_via_service(p: &kova_core::config::Profile) -> String {
    match ipc_done(&kova_ipc::Request::Drill {
        profile_id: p.id.clone(),
    }) {
        Ok(m) => m,
        Err(e) => format!("{}: 복구 훈련 실패 — {e}", p.name),
    }
}

pub(crate) fn setting_lines() -> Vec<slint::SharedString> {
    let store = ConfigStore::new(kova_service::default_config_dir());
    let s = store.settings();
    let mut v = vec![
        format!(
            "오프사이트: {} ({}) {}",
            if s.offsite_enabled {
                "사용"
            } else {
                "사용 안 함"
            },
            s.offsite_provider,
            s.offsite_remote_path
        ),
        format!(
            "보안: 랜섬웨어 보호 {} · 암호화 {} · 매니페스트 암호화 {} · NTFS ACL 보존 {}",
            if s.enable_ransomware_protection {
                "켜짐"
            } else {
                "꺼짐"
            },
            if s.encrypt_backups {
                "켜짐"
            } else {
                "꺼짐"
            },
            if s.encrypt_manifests {
                "켜짐"
            } else {
                "꺼짐"
            },
            if s.preserve_acl { "켜짐" } else { "꺼짐" }
        ),
        format!(
            "엔진: 최소 여유 {}GB · 증분 디스크 이미지 {} · Fleet {}",
            s.min_free_disk_gb,
            if s.incremental_images {
                "사용"
            } else {
                "기본(전체)"
            },
            if s.fleet_endpoint.is_empty() {
                "미연동"
            } else {
                s.fleet_endpoint.as_str()
            }
        ),
        "프로파일".into(),
    ];
    for p in store.profiles() {
        v.push(format!(
            "· {} — 원본 {}곳 → {} · 보존 {}개/{}일 · 압축 {}",
            p.name,
            p.sources.len(),
            p.repo_dir,
            p.retention_count,
            p.retention_days,
            p.compression_level
        ));
    }
    v.into_iter().map(Into::into).collect()
}

// ───────────────────── S3 / SMB / SMTP / Fleet / JobHistory IPC 헬퍼 ─────────────────────

fn load_s3_status(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let Ok(evs) = ipc_once(&kova_ipc::Request::S3Status) else {
            return;
        };
        let Some((configured, endpoint, region, bucket, prefix)) =
            evs.into_iter().find_map(|e| match e {
                kova_ipc::Event::S3Status {
                    configured,
                    endpoint,
                    region,
                    bucket,
                    prefix,
                } => Some((configured, endpoint, region, bucket, prefix)),
                _ => None,
            })
        else {
            return;
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_s3_configured(configured);
                if configured {
                    w.set_s3_endpoint(endpoint.into());
                    w.set_s3_region(region.into());
                    w.set_s3_bucket(bucket.into());
                    w.set_s3_prefix(prefix.into());
                }
            }
        });
    });
}

fn load_smb_creds(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let Ok(evs) = ipc_once(&kova_ipc::Request::SmbListCreds) else {
            return;
        };
        let Some(creds) = evs.into_iter().find_map(|e| match e {
            kova_ipc::Event::SmbCreds { creds } => Some(creds),
            _ => None,
        }) else {
            return;
        };
        let rows: Vec<SmbCredRow> = creds
            .into_iter()
            .map(|c| SmbCredRow {
                share: c.share.into(),
                username: c.username.into(),
            })
            .collect();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_smb_creds(std::rc::Rc::new(slint::VecModel::from(rows)).into());
            }
        });
    });
}

fn load_smtp_status(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let Ok(evs) = ipc_once(&kova_ipc::Request::SmtpStatus) else {
            return;
        };
        let Some(ev) = evs
            .into_iter()
            .find(|e| matches!(e, kova_ipc::Event::SmtpStatus { .. }))
        else {
            return;
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let (
                Some(w),
                kova_ipc::Event::SmtpStatus {
                    configured,
                    host,
                    port,
                    username,
                    from,
                    to,
                    use_tls,
                },
            ) = (weak.upgrade(), ev)
            {
                w.set_smtp_configured(configured);
                if configured {
                    w.set_smtp_host(host.into());
                    w.set_smtp_port(port.to_string().into());
                    w.set_smtp_user(username.into());
                    w.set_smtp_from(from.into());
                    w.set_smtp_to(to.into());
                    w.set_smtp_tls(use_tls);
                }
            }
        });
    });
}

fn load_fleet_status(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let res = ipc_once(&kova_ipc::Request::FleetStatus);
        if let Some(why) = send_failure(&res) {
            let _ = weak.upgrade_in_event_loop(move |w| {
                w.set_fleet_summary(format!("플릿 상태 조회 실패: {why}").into());
            });
            return;
        }
        let formatted = res.ok().into_iter().flatten().find_map(|e| match e {
            kova_ipc::Event::FleetStatus {
                hostname,
                service_version,
                profiles_total,
                healthy,
                stale,
                last_backup_at,
                unacked_alerts,
                fleet_endpoint,
            } => {
                let last_txt = last_backup_at
                    .map(chrono_fmt)
                    .unwrap_or_else(|| "없음".into());
                let summary = format!(
                    "노드: {hostname} · 서비스 v{service_version} · 프로파일 {profiles_total}개 (정상 {healthy} / 지연 {stale}) · 미확인 알림 {unacked_alerts}건 · 최근 백업: {last_txt}"
                );
                Some((summary, fleet_endpoint))
            }
            _ => None,
        });
        if let Some((summary, fleet_endpoint)) = formatted {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_fleet_summary(summary.into());
                    if w.get_form_fleet_endpoint().is_empty() && !fleet_endpoint.is_empty() {
                        w.set_form_fleet_endpoint(fleet_endpoint.into());
                    }
                }
            });
        }
    });
}

pub(crate) fn load_job_history(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let res = ipc_once(&kova_ipc::Request::JobHistory { limit: 100 });
        if let Some(why) = send_failure(&res) {
            let _ = weak.upgrade_in_event_loop(move |w| {
                w.set_job_history_status(format!("이력 조회 실패: {why}").into());
            });
            return;
        }
        let rows_opt = res.ok().into_iter().flatten().find_map(|e| match e {
            kova_ipc::Event::JobHistory { rows } => Some(rows),
            _ => None,
        });
        match rows_opt {
            Some(raw_rows) => {
                let count = raw_rows.len();
                let ui_rows: Vec<JobHistoryRow> = raw_rows
                    .into_iter()
                    .map(|r| {
                        let ts = if r.finished_at > 0.0 {
                            r.finished_at
                        } else {
                            r.started_at
                        };
                        let dur = (r.finished_at - r.started_at).max(0.0).round() as u64;
                        let when = if dur > 0 {
                            format!("{} ({dur}초)", chrono_fmt(ts))
                        } else {
                            chrono_fmt(ts)
                        };
                        let summary = if r.files > 0 || r.bytes > 0 {
                            format!("파일 {}개 · {}", r.files, fmt_size(r.bytes))
                        } else {
                            "-".into()
                        };
                        JobHistoryRow {
                            when: when.into(),
                            profile: profile_name(&r.profile_id).into(),
                            kind: kind_label(&r.kind).into(),
                            ok: r.ok,
                            summary: summary.into(),
                            message: r.message.into(),
                        }
                    })
                    .collect();
                let status = format!("최근 작업 실행 이력 {count}건");
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_job_history(std::rc::Rc::new(slint::VecModel::from(ui_rows)).into());
                        w.set_job_history_status(status.into());
                    }
                });
            }
            None => {
                let _ = weak.upgrade_in_event_loop(|w| {
                    w.set_job_history_status(
                        "서비스가 이력 응답을 주지 않았습니다(최신 서비스 필요)".into(),
                    );
                });
            }
        }
    });
}

pub(crate) fn wire(w: &MainWindow) {
    // Load persisted settings into UI fields
    {
        let store = ConfigStore::new(kova_service::default_config_dir());
        let s = store.settings();
        w.set_form_min_free(s.min_free_disk_gb.to_string().into());
        w.set_form_ransom(s.enable_ransomware_protection);
        w.set_form_encrypt(s.encrypt_backups);
        w.set_form_vss(s.use_vss);
        w.set_form_pack(s.pack_blobs);
        w.set_form_enc_manifest(s.encrypt_manifests);
        w.set_form_preserve_acl(s.preserve_acl);
        w.set_form_inc_img(s.incremental_images);
        w.set_form_webhook(s.webhook_url.into());
        w.set_form_max_threads(s.max_cpu_threads.to_string().into());
        w.set_form_bw_limit(s.offsite_bw_limit_mbps.to_string().into());
        w.set_form_pause_battery(s.pause_on_battery);
        w.set_form_fleet_endpoint(s.fleet_endpoint.into());
        w.set_form_drill_days(s.auto_drill_days.to_string().into());
        w.set_form_stale_days(s.stale_warn_days.to_string().into());
        w.set_offsite_provider(if s.offsite_provider.is_empty() {
            "local".into()
        } else {
            s.offsite_provider.into()
        });
        w.set_lock_text(lock_status().into());
    }

    // Initial async status loads (GDrive, S3, SMB, SMTP, Fleet, JobHistory)
    {
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let connected = match ipc_once(&kova_ipc::Request::GdriveStatus) {
                Ok(evs) => evs.iter().find_map(|e| match e {
                    kova_ipc::Event::GdriveStatus { connected } => Some(*connected),
                    _ => None,
                }),
                Err(_) => None,
            }
            .unwrap_or_else(|| {
                kova_core::gdrive::is_connected(&kova_service::default_config_dir())
            });
            let _ = weak.upgrade_in_event_loop(move |w| w.set_gdrive_connected(connected));
        });
        load_s3_status(w.as_weak());
        load_smb_creds(w.as_weak());
        load_smtp_status(w.as_weak());
        load_fleet_status(w.as_weak());
        load_job_history(w.as_weak());
    }

    // Job History refresh callback
    {
        let weak = w.as_weak();
        w.on_load_job_history(move || load_job_history(weak.clone()));
    }

    // Offsite local & provider switcher
    {
        let weak = w.as_weak();
        w.on_save_offsite(move |id, dir| {
            let res = if app_locked() {
                Err(LOCKED_MSG.to_string())
            } else {
                save_offsite(&id, &dir)
            };
            if let Some(w) = weak.upgrade() {
                set_settings_msg(&w, res);
            }
        });

        let weak = w.as_weak();
        w.on_select_offsite_provider(move |prov| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    set_settings_msg(&w, Err(LOCKED_MSG.to_string()));
                }
                return;
            }
            let p = prov.to_string();
            set_offsite_provider(&p);
            if let Some(w) = weak.upgrade() {
                w.set_offsite_provider(p.clone().into());
                let label = match p.as_str() {
                    "gdrive" => "Google Drive",
                    "s3" => "S3 호환 스토리지",
                    _ => "로컬 폴더 / NAS",
                };
                set_settings_msg(
                    &w,
                    Ok(format!("오프사이트 제공자를 '{label}'(으)로 전환했습니다")),
                );
            }
        });
    }

    // Google Drive connect / disconnect
    {
        let weak = w.as_weak();
        w.on_connect_gdrive(move || {
            let Some(win) = weak.upgrade() else { return };
            if app_locked() {
                win.set_gdrive_text(LOCKED_MSG.into());
                return;
            }
            if !try_begin(&GDRIVE_BUSY) {
                win.set_gdrive_text(
                    "이미 구글 로그인을 기다리는 중입니다. 브라우저 창을 확인하세요.".into(),
                );
                return;
            }
            let dir = kova_service::default_config_dir();
            let creds = match kova_core::gdrive::load_client(&dir) {
                Ok(c) => c,
                Err(e) => {
                    GDRIVE_BUSY.store(false, Ordering::SeqCst);
                    win.set_gdrive_text(e.into());
                    return;
                }
            };
            win.set_gdrive_text("브라우저에서 구글 로그인을 완료해 주세요(5분 안에).".into());
            let weak = weak.clone();
            std::thread::spawn(move || {
                let cancel = AtomicBool::new(false);
                let r = kova_core::gdrive::login_token(
                    &kova_core::gdrive::Endpoints::default(),
                    &creds,
                    open_url,
                    &cancel,
                    std::time::Duration::from_secs(300),
                )
                .and_then(|token| {
                    ipc_done(&kova_ipc::Request::GdriveStoreToken {
                        token: kova_ipc::Secret(token),
                    })
                    .map(|_| ())
                });
                if r.is_ok() {
                    set_offsite_provider("gdrive");
                }
                GDRIVE_BUSY.store(false, Ordering::SeqCst);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match r {
                            Ok(()) => {
                                w.set_gdrive_connected(true);
                                w.set_offsite_provider("gdrive".into());
                                w.set_gdrive_text(String::new().into());
                            }
                            Err(e) => w.set_gdrive_text(format!("연결 실패: {e}").into()),
                        }
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_disconnect_gdrive(move || {
            let Some(win) = weak.upgrade() else { return };
            if app_locked() {
                win.set_gdrive_text(LOCKED_MSG.into());
                return;
            }
            if !try_begin(&GDRIVE_BUSY) {
                win.set_gdrive_text(
                    "구글 드라이브 작업이 진행 중입니다. 잠시 뒤 다시 누르세요.".into(),
                );
                return;
            }
            win.set_gdrive_text("연결 해제 중…".into());
            let weak = weak.clone();
            std::thread::spawn(move || {
                let r = ipc_done(&kova_ipc::Request::GdriveDisconnect);
                if r.is_ok() {
                    set_offsite_provider("local");
                }
                GDRIVE_BUSY.store(false, Ordering::SeqCst);
                let _ = weak.upgrade_in_event_loop(move |w| match r {
                    Ok(m) => {
                        w.set_gdrive_connected(false);
                        w.set_offsite_provider("local".into());
                        w.set_gdrive_text(m.into());
                    }
                    Err(e) => w.set_gdrive_text(format!("연결 해제 실패: {e}").into()),
                });
            });
        });
    }

    // S3 Config callbacks
    {
        let weak = w.as_weak();
        w.on_s3_save(
            move |endpoint, region, bucket, prefix, access_key, secret_key| {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        w.set_s3_status_text(LOCKED_MSG.into());
                    }
                    return;
                }
                if let Some(w) = weak.upgrade() {
                    w.set_s3_status_text("S3 설정 저장 중…".into());
                }
                let weak = weak.clone();
                let req = kova_ipc::Request::S3SaveConfig {
                    endpoint: endpoint.trim().to_string(),
                    region: region.trim().to_string(),
                    bucket: bucket.trim().to_string(),
                    prefix: prefix.trim().to_string(),
                    access_key: access_key.trim().to_string(),
                    secret_key: kova_ipc::Secret(secret_key.to_string()),
                };
                std::thread::spawn(move || {
                    let res = ipc_done(&req);
                    let ok = res.is_ok();
                    let msg = match res {
                        Ok(m) => m,
                        Err(e) => format!("S3 저장 실패: {e}"),
                    };
                    if ok {
                        load_s3_status(weak.clone());
                    }
                    let _ = weak.upgrade_in_event_loop(move |w| {
                        if ok {
                            w.set_s3_secret_key("".into());
                        }
                        w.set_s3_status_text(msg.into());
                    });
                });
            },
        );

        let weak = w.as_weak();
        w.on_s3_test(move || {
            if let Some(w) = weak.upgrade() {
                w.set_s3_status_text("S3 연결 테스트 중…".into());
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let msg = match ipc_done(&kova_ipc::Request::S3TestConnection) {
                    Ok(m) => m,
                    Err(e) => format!("S3 연결 테스트 실패: {e}"),
                };
                let _ = weak.upgrade_in_event_loop(move |w| w.set_s3_status_text(msg.into()));
            });
        });

        let weak = w.as_weak();
        w.on_s3_delete(move || {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_s3_status_text(LOCKED_MSG.into());
                }
                return;
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let res = ipc_done(&kova_ipc::Request::S3DeleteConfig);
                let ok = res.is_ok();
                let msg = match res {
                    Ok(m) => m,
                    Err(e) => format!("S3 삭제 실패: {e}"),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    if ok {
                        w.set_s3_configured(false);
                        w.set_s3_endpoint("".into());
                        w.set_s3_bucket("".into());
                        w.set_s3_prefix("".into());
                        w.set_s3_access_key("".into());
                        w.set_s3_secret_key("".into());
                    }
                    w.set_s3_status_text(msg.into());
                });
            });
        });
    }

    // SMB / NAS Credential callbacks
    {
        let weak = w.as_weak();
        w.on_smb_save(move |share, username, password| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_smb_status_text(LOCKED_MSG.into());
                }
                return;
            }
            if let Some(w) = weak.upgrade() {
                w.set_smb_status_text("SMB 자격증명 저장 중…".into());
            }
            let weak = weak.clone();
            let req = kova_ipc::Request::SmbSaveCred {
                share: share.trim().to_string(),
                username: username.trim().to_string(),
                password: kova_ipc::Secret(password.to_string()),
            };
            std::thread::spawn(move || {
                let res = ipc_done(&req);
                let ok = res.is_ok();
                let msg = match res {
                    Ok(m) => m,
                    Err(e) => format!("SMB 저장 실패: {e}"),
                };
                if ok {
                    load_smb_creds(weak.clone());
                }
                let _ = weak.upgrade_in_event_loop(move |w| {
                    if ok {
                        w.set_smb_share("".into());
                        w.set_smb_user("".into());
                        w.set_smb_pass("".into());
                    }
                    w.set_smb_status_text(msg.into());
                });
            });
        });

        let weak = w.as_weak();
        w.on_smb_delete(move |share| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_smb_status_text(LOCKED_MSG.into());
                }
                return;
            }
            let weak = weak.clone();
            let share = share.to_string();
            std::thread::spawn(move || {
                let res = ipc_done(&kova_ipc::Request::SmbDeleteCred { share });
                let ok = res.is_ok();
                let msg = match res {
                    Ok(m) => m,
                    Err(e) => format!("SMB 삭제 실패: {e}"),
                };
                if ok {
                    load_smb_creds(weak.clone());
                }
                let _ = weak.upgrade_in_event_loop(move |w| w.set_smb_status_text(msg.into()));
            });
        });
    }

    // SMTP Email callbacks
    {
        let weak = w.as_weak();
        w.on_smtp_save(
            move |host, port_str, username, password, from, to, use_tls| {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        w.set_smtp_status_text(LOCKED_MSG.into());
                    }
                    return;
                }
                let Some(port) = port_str.trim().parse::<u16>().ok().filter(|p| *p > 0) else {
                    if let Some(w) = weak.upgrade() {
                        w.set_smtp_status_text(
                            "SMTP 포트는 1~65535 사이의 숫자여야 합니다 (예: 587 또는 465)".into(),
                        );
                    }
                    return;
                };
                if let Some(w) = weak.upgrade() {
                    w.set_smtp_status_text("SMTP 설정 저장 중…".into());
                }
                let weak = weak.clone();
                let req = kova_ipc::Request::SmtpSaveConfig {
                    host: host.trim().to_string(),
                    port,
                    username: username.trim().to_string(),
                    password: kova_ipc::Secret(password.to_string()),
                    from: from.trim().to_string(),
                    to: to.trim().to_string(),
                    use_tls,
                };
                std::thread::spawn(move || {
                    let res = ipc_done(&req);
                    let ok = res.is_ok();
                    let msg = match res {
                        Ok(m) => m,
                        Err(e) => format!("SMTP 저장 실패: {e}"),
                    };
                    if ok {
                        load_smtp_status(weak.clone());
                    }
                    let _ = weak.upgrade_in_event_loop(move |w| {
                        if ok {
                            w.set_smtp_pass("".into());
                        }
                        w.set_smtp_status_text(msg.into());
                    });
                });
            },
        );

        let weak = w.as_weak();
        w.on_smtp_test(move || {
            if let Some(w) = weak.upgrade() {
                w.set_smtp_status_text("테스트 메일 발송 중…".into());
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let msg = match ipc_done(&kova_ipc::Request::SmtpTest) {
                    Ok(m) => m,
                    Err(e) => format!("테스트 메일 발송 실패: {e}"),
                };
                let _ = weak.upgrade_in_event_loop(move |w| w.set_smtp_status_text(msg.into()));
            });
        });

        let weak = w.as_weak();
        w.on_smtp_delete(move || {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    w.set_smtp_status_text(LOCKED_MSG.into());
                }
                return;
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let res = ipc_done(&kova_ipc::Request::SmtpDeleteConfig);
                let ok = res.is_ok();
                let msg = match res {
                    Ok(m) => m,
                    Err(e) => format!("SMTP 삭제 실패: {e}"),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    if ok {
                        w.set_smtp_configured(false);
                        w.set_smtp_host("".into());
                        w.set_smtp_port("587".into());
                        w.set_smtp_user("".into());
                        w.set_smtp_pass("".into());
                        w.set_smtp_from("".into());
                        w.set_smtp_to("".into());
                        w.set_smtp_tls(true);
                    }
                    w.set_smtp_status_text(msg.into());
                });
            });
        });
    }

    // Core & Security settings save
    {
        let weak = w.as_weak();
        w.on_save_settings(
            move |gb, ransom, enc, vss, pack, enc_manifest, preserve_acl, inc_img| {
                if app_locked() {
                    if let Some(w) = weak.upgrade() {
                        set_settings_msg(&w, Err(LOCKED_MSG.to_string()));
                    }
                    return;
                }
                if let Some(w) = weak.upgrade() {
                    w.set_settings_err(false);
                    w.set_settings_text("설정 저장 중…".into());
                }
                let (gb, weak) = (gb.to_string(), weak.clone());
                std::thread::spawn(move || {
                    let store = ConfigStore::new(kova_service::default_config_dir());
                    let res = apply_settings(
                        &store,
                        &gb,
                        ransom,
                        enc,
                        vss,
                        pack,
                        enc_manifest,
                        preserve_acl,
                        inc_img,
                    );
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = weak.upgrade() {
                            set_settings_msg(&w, res);
                        }
                    });
                });
            },
        );

        let weak = w.as_weak();
        w.on_save_ops_settings(move |wh, th, bw, bat, fleet| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            let res = if app_locked() {
                Err(LOCKED_MSG.to_string())
            } else {
                apply_ops_settings(&store, &wh, &th, &bw, bat, &fleet)
            };
            if let Some(w) = weak.upgrade() {
                set_settings_msg(&w, res);
            }
        });

        let weak = w.as_weak();
        w.on_save_fleet_endpoint(move |fleet| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            let res = if app_locked() {
                Err(LOCKED_MSG.to_string())
            } else {
                apply_fleet_endpoint(&store, &fleet)
            };
            if let Some(w) = weak.upgrade() {
                let msg = match &res {
                    Ok(m) | Err(m) => m.clone(),
                };
                w.set_fleet_status_text(msg.into());
                set_settings_msg(&w, res);
            }
            load_fleet_status(weak.clone());
        });

        let weak = w.as_weak();
        w.on_refresh_fleet_status(move || load_fleet_status(weak.clone()));

        let weak = w.as_weak();
        w.on_save_watch_settings(move |dd, sd| {
            let store = ConfigStore::new(kova_service::default_config_dir());
            let res = if app_locked() {
                Err(LOCKED_MSG.to_string())
            } else {
                apply_watch_settings(&store, &dd, &sd)
            };
            if let Some(w) = weak.upgrade() {
                set_settings_msg(&w, res);
            }
        });

        let weak = w.as_weak();
        w.on_test_webhook(move |wh| {
            let url = wh.to_string();
            let weak = weak.clone();
            if let Some(w) = weak.upgrade() {
                w.set_settings_err(false);
                w.set_settings_text("웹훅 테스트 발송 중…".into());
            }
            std::thread::spawn(move || {
                let res = match kova_core::notify::send_webhook(
                    &url,
                    "info",
                    "테스트 알림",
                    "Kova2 원격 알림이 정상적으로 연결되었습니다.",
                ) {
                    Ok(()) => Ok("웹훅 테스트 발송 성공".to_string()),
                    Err(e) => Err(format!("웹훅 테스트 실패: {e}")),
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        set_settings_msg(&w, res);
                    }
                });
            });
        });
    }

    // Recovery keys, drill, sysinfo, diag, app lock, alert ack
    {
        let weak = w.as_weak();
        w.on_restore_key(move |code| {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    set_settings_msg(&w, Err(LOCKED_MSG.to_string()));
                    w.set_form_recovery("".into());
                }
                return;
            }
            if let Some(w) = weak.upgrade() {
                w.set_settings_err(false);
                w.set_settings_text("복구 키 복원 중…".into());
                w.set_form_recovery("".into());
            }
            let (code, weak) = (code.to_string(), weak.clone());
            std::thread::spawn(move || {
                let res = restore_keys(&code);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        set_settings_msg(&w, res);
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_export_recovery_kit(move || {
            if app_locked() {
                if let Some(w) = weak.upgrade() {
                    set_settings_msg(&w, Err(LOCKED_MSG.to_string()));
                }
                return;
            }
            if let Some(w) = weak.upgrade() {
                w.set_settings_err(false);
                w.set_settings_text("복구 키트 생성 중…".into());
            }
            let weak = weak.clone();
            std::thread::spawn(move || {
                let base = std::env::var_os("USERPROFILE")
                    .map(|u| std::path::PathBuf::from(u).join("Desktop"))
                    .filter(|d| d.is_dir())
                    .unwrap_or_else(std::env::temp_dir);
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let out = base.join(format!("Kova2_Recovery_Kit_{secs}.txt"));
                let res = export_recovery_kit_to(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        set_settings_msg(&w, res);
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_export_sysinfo(move || {
            let weak = weak.clone();
            if let Some(w) = weak.upgrade() {
                w.set_diag_text("설치된 프로그램·드라이버 목록을 모으는 중…".into());
            }
            std::thread::spawn(move || {
                let base = std::env::var_os("USERPROFILE")
                    .map(|u| std::path::PathBuf::from(u).join("Desktop"))
                    .filter(|d| d.is_dir())
                    .unwrap_or_else(std::env::temp_dir);
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let text = match kova_core::sysinfo::export(
                    &base.join(format!("Kova2_시스템정보_{secs}")),
                ) {
                    Ok(m) | Err(m) => m,
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_diag_text(text.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_run_drill(move || {
            let weak = weak.clone();
            if let Some(w) = weak.upgrade() {
                w.set_diag_text(
                    "복구 훈련 중… (최근 스냅샷을 임시 폴더에 복원해 확인합니다)".into(),
                );
            }
            std::thread::spawn(move || {
                let store = ConfigStore::new(kova_service::default_config_dir());
                let scratch = std::env::temp_dir();
                let lines: Vec<String> = store
                    .profiles()
                    .iter()
                    .map(|p| {
                        if kova_core::repocrypto::is_enabled(Path::new(&p.repo_dir)) {
                            drill_via_service(p)
                        } else {
                            kova_core::drill::run(p, &scratch)
                        }
                    })
                    .collect();
                let text = if lines.is_empty() {
                    "프로파일이 없습니다".to_string()
                } else {
                    lines.join("\n")
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_diag_text(text.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_make_diag(move || {
            let weak = weak.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let svc = match rt.block_on(kova_ipc::request(
                    kova_ipc::PIPE_NAME,
                    &kova_ipc::Request::Status,
                )) {
                    Ok(_) => "연결됨",
                    Err(_) => "연결 안 됨",
                };
                let dir = std::env::var_os("USERPROFILE")
                    .map(|u| std::path::PathBuf::from(u).join("Desktop"))
                    .filter(|d| d.is_dir())
                    .unwrap_or_else(std::env::temp_dir);
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let path = dir.join(format!("Kova2_진단_{secs}.zip"));
                let msg = match kova_core::diag::bundle(
                    &kova_service::default_config_dir(),
                    env!("CARGO_PKG_VERSION"),
                    svc,
                    &path,
                ) {
                    Ok(()) => format!("저장했습니다: {}", path.display()),
                    Err(e) => format!("저장 실패: {e}"),
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_diag_text(msg.into());
                    }
                });
            });
        });

        let weak = w.as_weak();
        w.on_unlock_app(move |pw| {
            let ok = kova_core::applock::verify(&kova_service::default_config_dir(), &pw);
            if ok {
                set_unlocked(true);
            }
            if let Some(w) = weak.upgrade() {
                w.set_form_lock_cur("".into());
                w.set_lock_text(
                    if ok {
                        lock_status()
                    } else {
                        "마스터 비밀번호가 맞지 않습니다".to_string()
                    }
                    .into(),
                );
            }
        });

        let weak = w.as_weak();
        w.on_set_master(move |cur, new| {
            let r = kova_core::applock::change(&kova_service::default_config_dir(), &cur, &new);
            let ok = r.is_ok();
            if ok {
                set_unlocked(true);
            }
            if let Some(w) = weak.upgrade() {
                if ok {
                    w.set_form_lock_cur("".into());
                    w.set_form_lock_new("".into());
                }
                let msg = match r {
                    Ok(m) | Err(m) => m,
                };
                w.set_lock_text(msg.into());
            }
        });

        let weak_ack = w.as_weak();
        w.on_ack_alerts(move || {
            if app_locked() {
                if let Some(w) = weak_ack.upgrade() {
                    w.set_pick_error(LOCKED_MSG.into());
                }
                return;
            }
            let _ = kova_core::alerts::AlertLog::new(&kova_service::default_config_dir())
                .acknowledge_all();
            if let Some(w) = weak_ack.upgrade() {
                if w.get_pick_error() == LOCKED_MSG {
                    w.set_pick_error("".into());
                }
                w.set_alert_text("".into());
                let alerts = alert_rows();
                w.set_alerts(std::rc::Rc::new(slint::VecModel::from(alerts)).into());
            }
        });
    }
}

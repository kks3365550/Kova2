//! 상용 수준 통합(E2E) 검증 스위트:
//! 1) 암호화 매니페스트·증분 백업·실행 이력·스냅샷 비교·권한/복구 코드 복원 인가
//! 2) 로컬 모의 S3 서버 기반 암호화 저장소 복제·클라우드 풀·심층 검증·복원·원격 고아 정리
//! 3) 디스크 이미지(.qblk) 증분 체인·레이아웃 사이드카·AES-256-GCM 암호화/복호화·체인 복원
use chrono::Local;
use kova_core::config::{ConfigStore, Profile};
use kova_core::s3::{
    list_objects, prune_s3_orphans, pull_from_s3, replicate_to_s3, test_connection, S3Config,
};
use kova_core::{repocrypto, retention, verify};
use kova_engine::codec::MARKER;
use kova_engine::ops::{run_backup, run_restore, BackupOptions, RestoreOptions};
use kova_image::browse::QblkVolumeReader;
use kova_image::crypto::{decrypt_file, encrypt_file, is_encrypted_image};
use kova_image::incremental::{
    load_block_map, load_chain_meta, restore_chain_to_file, save_block_map, save_chain_meta,
    verify_chain, write_incremental_image, BlockMap, ChainMeta,
};
use kova_image::layout::{
    layout_path_for, load_layout, save_layout, DiskLayout, PartitionInfo, LAYOUT_VERSION,
};
use kova_image::Header;
use kova_ipc::{Caller, ClientToken, Event, Handler, Reply, Request, Secret};
use kova_service::{IpcHandler, Supervisor};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// `KOVA2_KEY_DIR` 환경변수를 변경하는 시험끼리 병렬 충돌하지 않도록 직렬화한다.
static KEY_ENV_LOCK: Mutex<()> = Mutex::new(());

struct KeyDirGuard {
    _lock: MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
}

impl KeyDirGuard {
    fn new() -> Self {
        let lock = KEY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("KOVA2_KEY_DIR", dir.path());
        Self {
            _lock: lock,
            _dir: dir,
        }
    }
}

impl Drop for KeyDirGuard {
    fn drop(&mut self) {
        std::env::remove_var("KOVA2_KEY_DIR");
    }
}

fn wait_idle(sup: &Supervisor) {
    let start = Instant::now();
    while sup.counts() != (0, 0) {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "백그라운드 작업이 제한 시간 내에 끝나지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn once_events(reply: Reply) -> Vec<Event> {
    match reply {
        Reply::Once(evs) => evs,
        Reply::Stream(_) => panic!("Reply::Once 응답을 기대했습니다"),
    }
}

fn first_error(reply: Reply) -> Option<String> {
    match reply {
        Reply::Once(evs) => evs.into_iter().find_map(|e| match e {
            Event::Error { message } => Some(message),
            _ => None,
        }),
        Reply::Stream(_) => None,
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let decoded = bytes
                .get(i + 1..i + 3)
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            if let Some(v) = decoded {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

struct OverrideCaller {
    inner: IpcHandler,
    privileged: Arc<AtomicBool>,
}

impl Handler for OverrideCaller {
    fn handle(&self, req: Request, _caller: Caller) -> Reply {
        self.inner.handle(
            req,
            Caller {
                privileged: self.privileged.load(Ordering::SeqCst),
            },
        )
    }

    fn handle_with_token(
        &self,
        req: Request,
        _caller: Caller,
        token: Option<ClientToken>,
    ) -> Reply {
        self.inner.handle_with_token(
            req,
            Caller {
                privileged: self.privileged.load(Ordering::SeqCst),
            },
            token,
        )
    }
}

/// `HEAD` / `PUT` / `GET` / `DELETE` / `GET ?list-type=2` XML 페이지네이션을 지원하는 로컬 모의 S3 서버.
struct MockS3Server {
    cfg: S3Config,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockS3Server {
    fn start(bucket: &str, prefix: &str, page_size: usize) -> Self {
        let store: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let bucket_prefix = format!("/{}/", bucket.trim_matches('/'));

        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            while !stop_srv.load(Ordering::Relaxed) {
                let Ok((mut sock, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                sock.set_nonblocking(false).unwrap();
                let mut data = Vec::new();
                let mut buf = [0u8; 8192];
                let mut body_start = None;
                let mut content_len = 0usize;
                loop {
                    let n = sock.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&buf[..n]);
                    if body_start.is_none() {
                        let sep = data.windows(4).position(|w| w == b"\r\n\r\n");
                        if let Some(pos) = sep {
                            let hdr = String::from_utf8_lossy(&data[..pos]);
                            content_len = hdr
                                .lines()
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    if k.eq_ignore_ascii_case("content-length") {
                                        v.trim().parse().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            body_start = Some(pos + 4);
                        }
                    }
                    if body_start.is_some_and(|bs| data.len() >= bs + content_len) {
                        break;
                    }
                }
                let bs = body_start.unwrap_or(data.len());
                let hdr = String::from_utf8_lossy(&data[..bs]).to_string();
                let first = hdr.lines().next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("");
                let raw_target = parts.next().unwrap_or("");
                let (uri, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));
                assert!(hdr.contains("AWS4-HMAC-SHA256"), "SigV4 누락: {hdr}");

                match method {
                    "HEAD" => {
                        let exists = store.lock().unwrap().contains_key(uri);
                        let resp = if exists {
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        };
                        let _ = sock.write_all(resp.as_bytes());
                    }
                    "GET" if query.contains("list-type=2") => {
                        let mut qmap = HashMap::new();
                        for kv in query.split('&') {
                            if let Some((k, v)) = kv.split_once('=') {
                                qmap.insert(pct_decode(k), pct_decode(v));
                            }
                        }
                        let qprefix = qmap.get("prefix").cloned().unwrap_or_default();
                        let offset: usize = qmap
                            .get("continuation-token")
                            .and_then(|t| t.parse().ok())
                            .unwrap_or(0);
                        let max_keys: usize = qmap
                            .get("max-keys")
                            .and_then(|t| t.parse().ok())
                            .unwrap_or(page_size);
                        let mut items: Vec<(String, usize)> = store
                            .lock()
                            .unwrap()
                            .iter()
                            .filter_map(|(k, v)| {
                                let key = k.strip_prefix(&bucket_prefix)?;
                                key.starts_with(&qprefix)
                                    .then(|| (key.to_string(), v.len()))
                            })
                            .collect();
                        items.sort_by(|a, b| a.0.cmp(&b.0));
                        let end = (offset + max_keys).min(items.len());
                        let truncated = end < items.len();
                        let mut xml = String::from(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>",
                        );
                        xml.push_str(&format!(
                            "<IsTruncated>{}</IsTruncated>",
                            if truncated { "true" } else { "false" }
                        ));
                        if truncated {
                            xml.push_str(&format!(
                                "<NextContinuationToken>{end}</NextContinuationToken>"
                            ));
                        }
                        for (k, sz) in &items[offset.min(items.len())..end] {
                            xml.push_str(&format!(
                                "<Contents><Key>{k}</Key><Size>{sz}</Size></Contents>"
                            ));
                        }
                        xml.push_str("</ListBucketResult>");
                        let resp_hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            xml.len()
                        );
                        let _ = sock.write_all(resp_hdr.as_bytes());
                        let _ = sock.write_all(xml.as_bytes());
                    }
                    "GET" => {
                        if let Some(body) = store.lock().unwrap().get(uri).cloned() {
                            let resp_hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = sock.write_all(resp_hdr.as_bytes());
                            let _ = sock.write_all(&body);
                        } else {
                            let _ = sock.write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                    }
                    "PUT" => {
                        let end = (bs + content_len).min(data.len());
                        let body = data[bs..end].to_vec();
                        store.lock().unwrap().insert(uri.to_string(), body);
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    "DELETE" => {
                        store.lock().unwrap().remove(uri);
                        let _ = sock.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    _ => {
                        let _ = sock.write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                }
                let _ = sock.flush();
            }
        });

        Self {
            cfg: S3Config {
                endpoint: format!("http://{addr}"),
                region: "ap-northeast-2".into(),
                bucket: bucket.into(),
                prefix: prefix.into(),
                access_key: "E2EACCESSKEY".into(),
                secret_key: "E2ESECRETKEY".into(),
            },
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockS3Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn e2e_encrypted_manifest_incremental_diff_history_and_auth_restore() {
    let _keys = KeyDirGuard::new();
    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    let src_dir = dir.path().join("src");
    let repo_dir = dir.path().join("repo");
    fs::create_dir_all(&src_dir).unwrap();

    fs::write(src_dir.join("keep.txt"), "unchanged commercial payload").unwrap();
    fs::write(src_dir.join("modify_me.txt"), "version one content").unwrap();
    fs::write(
        src_dir.join("delete_me.txt"),
        "to be deleted before backup 2",
    )
    .unwrap();
    fs::write(
        src_dir.join("confidential_payroll_2026.txt"),
        "secret payroll numbers",
    )
    .unwrap();

    let store = ConfigStore::new(&cfg_dir);
    let mut profile = Profile::new("p1", "상용 통합 프로파일");
    profile.sources = vec![src_dir.to_string_lossy().into()];
    profile.repo_dir = repo_dir.to_string_lossy().into();
    profile.auto_backup_enabled = true;
    store.upsert(profile).unwrap();

    let mut st = store.settings();
    st.use_vss = false;
    st.min_free_disk_gb = 0;
    st.enable_ransomware_protection = false;
    store.save_settings(&st).unwrap();

    let sup = Supervisor::new(&cfg_dir, 2);
    let handler = IpcHandler(sup.clone());
    let admin = Caller { privileged: true };
    let user = Caller { privileged: false };

    // 1) 관리자 권한으로 저장소 암호화 활성화 및 복구 코드 획득
    let enc_evs = once_events(handler.handle(Request::EnableEncryption, admin));
    let [Event::Encrypted { codes }] = &enc_evs[..] else {
        panic!("Event::Encrypted 를 기대했습니다: {enc_evs:?}");
    };
    assert_eq!(codes.len(), 1);
    let recovery_code = codes[0].0.rsplit(": ").next().unwrap().to_string();
    assert!(repocrypto::is_enabled(&repo_dir));

    // 2) 매니페스트 암호화 활성화 후 Backup #1 실행(스케줄러 tick 경로)
    st.encrypt_backups = true;
    st.encrypt_manifests = true;
    store.save_settings(&st).unwrap();

    assert_eq!(sup.tick(Local::now()), 1);
    wait_idle(&sup);

    let prof1 = store.get("p1").unwrap();
    assert_eq!(prof1.last_status, "success");
    let sid1 = prof1.last_snapshot_id.expect("Backup #1 스냅샷 ID 누락");

    let manifest1_path = repo_dir.join("snapshots").join(format!("{sid1}.json"));
    let manifest1_bytes = fs::read(&manifest1_path).unwrap();
    assert!(
        manifest1_bytes.starts_with(b"ENC\x01"),
        "ENC\\x01 헤더 누락"
    );
    for secret_name in [
        "keep.txt",
        "modify_me.txt",
        "delete_me.txt",
        "confidential_payroll_2026.txt",
    ] {
        assert!(
            !contains_subslice(&manifest1_bytes, secret_name.as_bytes()),
            "암호화 매니페스트에 평문 파일명이 노출됨: {secret_name}"
        );
    }

    // JobHistoryDb 기록 검증
    let hist1 = once_events(handler.handle(Request::JobHistory { limit: 10 }, user));
    let [Event::JobHistory { rows }] = &hist1[..] else {
        panic!("Event::JobHistory 를 기대했습니다: {hist1:?}");
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].profile_id, "p1");
    assert_eq!(rows[0].kind, "backup");
    assert!(rows[0].ok);
    assert!(rows[0].files >= 4);
    assert!(rows[0].bytes > 0);

    // 3) 파일 추가·수정·삭제 후 Backup #2 실행(IPC RunNow 경로)
    std::thread::sleep(Duration::from_millis(50));
    fs::write(src_dir.join("added_file.txt"), "brand new file in backup 2").unwrap();
    fs::write(
        src_dir.join("modify_me.txt"),
        "version two updated content with longer length",
    )
    .unwrap();
    fs::remove_file(src_dir.join("delete_me.txt")).unwrap();

    let run2 = once_events(handler.handle(
        Request::RunNow {
            profile_id: "p1".into(),
            kind: "backup".into(),
        },
        user,
    ));
    assert!(matches!(&run2[..], [Event::Queued { merged: false, .. }]));
    wait_idle(&sup);

    let prof2 = store.get("p1").unwrap();
    assert_eq!(prof2.last_status, "success");
    let sid2 = prof2.last_snapshot_id.expect("Backup #2 스냅샷 ID 누락");
    assert_ne!(sid1, sid2);

    let manifest2_path = repo_dir.join("snapshots").join(format!("{sid2}.json"));
    let manifest2_bytes = fs::read(&manifest2_path).unwrap();
    assert!(manifest2_bytes.starts_with(b"ENC\x01"));
    assert!(!contains_subslice(&manifest2_bytes, b"added_file.txt"));

    let hist2 = once_events(handler.handle(Request::JobHistory { limit: 10 }, user));
    let [Event::JobHistory { rows: rows2 }] = &hist2[..] else {
        panic!("Event::JobHistory 를 기대했습니다: {hist2:?}");
    };
    assert_eq!(rows2.len(), 2);
    assert!(rows2.iter().all(|r| r.ok && r.kind == "backup"));

    // 4) 스냅샷 DiffSnapshots 비교 (일반 사용자는 거부, 관리자는 정확한 추가/수정/삭제 경로 반환)
    let repo_str = repo_dir.to_string_lossy().to_string();
    let diff_req = Request::DiffSnapshots {
        repo: repo_str.clone(),
        base_id: sid1,
        target_id: sid2.clone(),
        limit: 100,
    };
    assert!(
        first_error(handler.handle(diff_req.clone(), user))
            .is_some_and(|m| m.contains("관리자 권한")),
        "암호화 저장소 DiffSnapshots 는 일반 사용자에게 거부되어야 함"
    );

    let diff_evs = once_events(handler.handle(diff_req, admin));
    let [Event::DiffResult {
        added,
        modified,
        deleted,
        unchanged_count,
    }] = &diff_evs[..]
    else {
        panic!("Event::DiffResult 를 기대했습니다: {diff_evs:?}");
    };
    let added_paths: Vec<&str> = added.iter().map(|e| e.path.as_str()).collect();
    let modified_paths: Vec<&str> = modified.iter().map(|e| e.path.as_str()).collect();
    let deleted_paths: Vec<&str> = deleted.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(added_paths, ["added_file.txt"]);
    assert_eq!(modified_paths, ["modify_me.txt"]);
    assert_eq!(deleted_paths, ["delete_me.txt"]);
    assert_eq!(*unchanged_count, 2);

    // 5) 심층 무결성 검증(deep = true): 문제 0건
    let vrep = verify::verify_repo(&repo_dir, true).unwrap();
    assert!(vrep.ok(), "저장소 검증 실패: {:?}", vrep.problems);
    assert_eq!(vrep.snapshots, 2);

    // 6) 암호화 저장소 Restore 권한 검증:
    //    일반 사용자 + 복구 코드 없음 -> 거부
    //    일반 사용자 + 유효 복구 코드 -> 인가 통과(직접 호출은 토큰 단계 진입, 파이프 가장은 실제 복원 성공)
    let direct_target = dir.path().join("direct_restore");
    let no_code_req = Request::Restore {
        repo: repo_str.clone(),
        session_id: sid2.clone(),
        target: Some(direct_target.to_string_lossy().into()),
        only: None,
        recovery_code: None,
    };
    let refused_msg = first_error(handler.handle_with_token(no_code_req, user, None))
        .expect("복구 코드 없는 일반 사용자 복원은 거부되어야 함");
    assert!(
        refused_msg.contains("관리자 권한 또는 복구 코드가 필요합니다"),
        "{refused_msg}"
    );

    let with_code_req = Request::Restore {
        repo: repo_str.clone(),
        session_id: sid2.clone(),
        target: Some(direct_target.to_string_lossy().into()),
        only: None,
        recovery_code: Some(Secret(recovery_code.clone())),
    };
    let token_check_msg = first_error(handler.handle_with_token(with_code_req, user, None))
        .expect("토큰 없는 직접 호출은 호출자 토큰 확인 단계에서 멈춰야 함");
    assert!(
        !token_check_msg.contains("관리자 권한 또는 복구 코드가 필요합니다")
            && token_check_msg.contains("사용자 권한을 확인하지 못했습니다"),
        "유효 복구 코드는 암호화 인가를 통과해야 함: {token_check_msg}"
    );

    // 실제 네임드 파이프 가장 토큰(stream_as_caller)을 통한 일반 사용자 복구 코드 복원 E2E
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pipe = format!(r"\\.\pipe\kova-e2e-commercial-{}", std::process::id());
    let wrapped: Arc<dyn Handler> = Arc::new(OverrideCaller {
        inner: IpcHandler(sup),
        privileged: Arc::new(AtomicBool::new(false)),
    });
    rt.block_on(async {
        let p_srv = pipe.clone();
        tokio::spawn(async move {
            let _ = kova_ipc::serve(&p_srv, wrapped).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let out_refused = dir.path().join("pipe_restore_refused");
        let mut evs_refused = Vec::new();
        kova_ipc::stream_as_caller(
            &pipe,
            &Request::Restore {
                repo: repo_str.clone(),
                session_id: sid2.clone(),
                target: Some(out_refused.to_string_lossy().into()),
                only: None,
                recovery_code: None,
            },
            |e| {
                evs_refused.push(e);
                true
            },
        )
        .await
        .unwrap();
        match evs_refused.last() {
            Some(Event::Error { message }) => {
                assert!(
                    message.contains("관리자 권한 또는 복구 코드가 필요합니다"),
                    "{message}"
                );
            }
            other => panic!("거부 오류 이벤트를 기대했습니다: {other:?}"),
        }
        assert!(!out_refused.exists());

        let out_ok = dir.path().join("pipe_restore_ok");
        let mut evs_ok = Vec::new();
        kova_ipc::stream_as_caller(
            &pipe,
            &Request::Restore {
                repo: repo_str,
                session_id: sid2,
                target: Some(out_ok.to_string_lossy().into()),
                only: None,
                recovery_code: Some(Secret(recovery_code)),
            },
            |e| {
                evs_ok.push(e);
                true
            },
        )
        .await
        .unwrap();
        match evs_ok.last() {
            Some(Event::Done { message }) => {
                assert!(message.contains("복원 완료"), "{message}");
            }
            other => panic!("복원 완료 이벤트를 기대했습니다: {other:?}"),
        }
        assert_eq!(
            fs::read_to_string(out_ok.join("added_file.txt")).unwrap(),
            "brand new file in backup 2"
        );
        assert_eq!(
            fs::read_to_string(out_ok.join("modify_me.txt")).unwrap(),
            "version two updated content with longer length"
        );
        assert_eq!(
            fs::read_to_string(out_ok.join("keep.txt")).unwrap(),
            "unchanged commercial payload"
        );
        assert!(!out_ok.join("delete_me.txt").exists());
    });
    rt.shutdown_timeout(Duration::from_secs(1));
}

#[test]
fn e2e_s3_cloud_replication_pull_and_prune_roundtrip() {
    let _keys = KeyDirGuard::new();
    repocrypto::install_provider();

    let mock = MockS3Server::start("kova-commercial", "node-a", 3);
    test_connection(&mock.cfg).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let repo_dir = dir.path().join("repo");
    fs::create_dir_all(src_dir.join("nested")).unwrap();

    let alpha_v1 = b"alpha snapshot 1 commercial content".to_vec();
    let binary_payload: Vec<u8> = (0..131_072u32)
        .map(|i| (i.wrapping_mul(1_103_515_245).wrapping_add(12_345) >> 16) as u8)
        .collect();
    fs::write(src_dir.join("alpha.txt"), &alpha_v1).unwrap();
    fs::write(src_dir.join("nested").join("binary.bin"), &binary_payload).unwrap();

    // 암호화 저장소 생성(crypto.json + DPAPI 키)
    repocrypto::enable(&repo_dir)
        .unwrap()
        .expect("암호화 활성화");
    assert!(repo_dir.join(MARKER).is_file());

    let cancel = AtomicBool::new(false);
    let snap1 = "20261124_100000";
    let snap2 = "20261124_110000";
    let snap1_key = format!("snapshots/{snap1}.json");
    let snap2_key = format!("snapshots/{snap2}.json");

    // Snapshot #1 (팩 컨테이너에 암호화 블롭 저장)
    run_backup(
        &BackupOptions {
            sources: vec![src_dir.clone()],
            repo: repo_dir.clone(),
            session_id: Some(snap1.into()),
            zstd_level: 3,
            encrypt_manifest: true,
            ..Default::default()
        },
        &|_| {},
        &cancel,
    )
    .unwrap();

    // Snapshot #2
    let alpha_v2 = b"alpha snapshot 2 updated payload".to_vec();
    let beta_v2 = b"beta file introduced in snapshot 2".to_vec();
    fs::write(src_dir.join("alpha.txt"), &alpha_v2).unwrap();
    fs::write(src_dir.join("beta.txt"), &beta_v2).unwrap();

    run_backup(
        &BackupOptions {
            sources: vec![src_dir],
            repo: repo_dir.clone(),
            session_id: Some(snap2.into()),
            zstd_level: 3,
            encrypt_manifest: true,
            ..Default::default()
        },
        &|_| {},
        &cancel,
    )
    .unwrap();

    // 팩(.pack/.idx)과 crypto.json 이 로컬 저장소에 실제로 생성되었는지 확인
    let pack_file = fs::read_dir(repo_dir.join("packs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "pack"))
        .expect("팩 파일이 생성되어야 함");
    assert_eq!(&fs::read(&pack_file).unwrap()[..4], b"ENC\x01");

    // 1) S3 복제(replicate_to_s3)
    let up = replicate_to_s3(&repo_dir, &mock.cfg, &cancel).unwrap();
    assert_eq!(up.snapshots_uploaded, 2);
    assert!(up.blobs_uploaded >= 1);
    assert!(up.bytes_uploaded > 0);

    let remote_objs = list_objects(&mock.cfg, "").unwrap();
    assert!(remote_objs.iter().any(|(k, _)| k == MARKER));
    assert!(remote_objs.iter().any(|(k, _)| k == &snap1_key));
    assert!(remote_objs.iter().any(|(k, _)| k == &snap2_key));
    assert!(remote_objs
        .iter()
        .any(|(k, _)| k.starts_with("packs/") && k.ends_with(".pack")));
    assert!(remote_objs
        .iter()
        .any(|(k, _)| k.starts_with("packs/") && k.ends_with(".idx")));

    // 재복제는 이미 올라간 스냅샷 2개를 모두 건너뛴다
    let up_again = replicate_to_s3(&repo_dir, &mock.cfg, &cancel).unwrap();
    assert_eq!(
        (up_again.snapshots_uploaded, up_again.snapshots_skipped),
        (0, 2)
    );

    // 2) 빈 디렉터리로 S3 클라우드 풀(pull_from_s3)
    let fresh_dest = dir.path().join("fresh_pulled_repo");
    let progress_ticks = AtomicUsize::new(0);
    let pull = pull_from_s3(&mock.cfg, &fresh_dest, &cancel, &|_, _, _| {
        progress_ticks.fetch_add(1, Ordering::Relaxed);
    })
    .unwrap();
    assert!(pull.crypto_downloaded);
    assert_eq!(pull.snapshots_downloaded, 2);
    assert!(pull.packs_downloaded >= 2);
    assert!(pull.bytes_downloaded > 0);
    assert!(progress_ticks.load(Ordering::Relaxed) >= 4);

    // 3) 내려받은 저장소 심층 검증 + 바이트 단위 복원 검증
    let vrep = verify::verify_repo(&fresh_dest, true).unwrap();
    assert!(vrep.ok(), "풀 저장소 검증 실패: {:?}", vrep.problems);
    assert_eq!(vrep.snapshots, 2);

    let restored_v2 = dir.path().join("restored_v2");
    run_restore(
        &RestoreOptions {
            repo: fresh_dest.clone(),
            session_id: snap2.into(),
            target: Some(restored_v2.clone()),
            only: None,
        },
        &|_| {},
        &cancel,
    )
    .unwrap();
    assert_eq!(fs::read(restored_v2.join("alpha.txt")).unwrap(), alpha_v2);
    assert_eq!(fs::read(restored_v2.join("beta.txt")).unwrap(), beta_v2);
    assert_eq!(
        fs::read(restored_v2.join("nested").join("binary.bin")).unwrap(),
        binary_payload
    );

    let restored_v1 = dir.path().join("restored_v1");
    run_restore(
        &RestoreOptions {
            repo: fresh_dest,
            session_id: snap1.into(),
            target: Some(restored_v1.clone()),
            only: None,
        },
        &|_| {},
        &cancel,
    )
    .unwrap();
    assert_eq!(fs::read(restored_v1.join("alpha.txt")).unwrap(), alpha_v1);
    assert!(!restored_v1.join("beta.txt").exists());

    // 4) 로컬에서 옛 스냅샷 삭제 후 S3 원격 고아 정리(prune_s3_orphans)
    retention::delete_snapshot(&repo_dir, snap1).unwrap();
    let snap1_local = repo_dir.join("snapshots").join(format!("{snap1}.json"));
    assert!(!snap1_local.exists());

    let pruned = prune_s3_orphans(&mock.cfg, &repo_dir, &cancel).unwrap();
    assert!(pruned.deleted_objects >= 1);
    assert!(pruned.freed_bytes > 0);

    let after_prune = list_objects(&mock.cfg, "").unwrap();
    assert!(
        after_prune.iter().any(|(k, _)| k == MARKER),
        "crypto.json 보존 필수"
    );
    assert!(
        after_prune.iter().any(|(k, _)| k == &snap2_key),
        "최신 스냅샷 보존 필수"
    );
    assert!(
        !after_prune.iter().any(|(k, _)| k == &snap1_key),
        "삭제 스냅샷 제거 필수"
    );
}

#[test]
fn e2e_image_incremental_chain_encrypt_decrypt_and_layout_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let cs = 4096usize;
    let total_clusters = 8u64;
    let bitmap = [0xFFu8];
    let mut disk = vec![0u8; cs * total_clusters as usize];
    for i in 0..8usize {
        let fill_byte = (i as u8).wrapping_mul(31).wrapping_add(1);
        disk[i * cs..(i + 1) * cs].fill(fill_byte);
    }

    let cancel = AtomicBool::new(false);
    let base_header = Header {
        version: 1,
        cluster_size: cs as u32,
        total_clusters,
        used_clusters: 0,
        vsn: "ABCD-1234".into(),
        source_label: "OS_VOL".into(),
    };

    // 1) Base .qblk + .qmap.json(블록 단위 2클러스터) + .qlayout.json 저장
    let base_path = dir.path().join("base.qblk");
    let seed_map = BlockMap {
        version: 2,
        cluster_size: cs as u32,
        total_clusters,
        block_clusters: 2,
        hashes: BTreeMap::new(),
    };
    let base_map = {
        let f = File::create(&base_path).unwrap();
        let mut h = base_header.clone();
        let (_st, inc, map, _out) = write_incremental_image(
            &mut Cursor::new(&disk),
            f,
            &mut h,
            &bitmap,
            Some(&seed_map),
            3,
            &cancel,
            &|_| {},
        )
        .unwrap();
        assert_eq!(inc.changed_clusters, 8);
        assert_eq!(inc.skipped_clusters, 0);
        assert_eq!(inc.chunks_written, 4);
        save_block_map(&base_path, &map).unwrap();
        map
    };
    assert_eq!(load_block_map(&base_path).unwrap(), base_map);

    let layout = DiskLayout {
        version: LAYOUT_VERSION,
        disk_number: 0,
        partition_style: "GPT".into(),
        disk_size_bytes: 256_060_514_304,
        captured_drive: 'C',
        partitions: vec![
            PartitionInfo {
                number: 1,
                offset_bytes: 1_048_576,
                size_bytes: 104_857_600,
                style: "GPT".into(),
                kind: "EFI".into(),
                drive_letter: None,
                label: "SYSTEM".into(),
                file_system: "FAT32".into(),
            },
            PartitionInfo {
                number: 2,
                offset_bytes: 105_906_176,
                size_bytes: 16_777_216,
                style: "GPT".into(),
                kind: "MSR".into(),
                drive_letter: None,
                label: String::new(),
                file_system: String::new(),
            },
            PartitionInfo {
                number: 3,
                offset_bytes: 122_683_392,
                size_bytes: 255_000_000_000,
                style: "GPT".into(),
                kind: "Basic".into(),
                drive_letter: Some('C'),
                label: "Windows".into(),
                file_system: "NTFS".into(),
            },
            PartitionInfo {
                number: 4,
                offset_bytes: 255_122_683_392,
                size_bytes: 937_000_000,
                style: "GPT".into(),
                kind: "Recovery".into(),
                drive_letter: None,
                label: "복구".into(),
                file_system: "NTFS".into(),
            },
        ],
    };
    save_layout(&base_path, &layout).unwrap();
    assert!(layout_path_for(&base_path).is_file());
    assert_eq!(load_layout(&base_path).unwrap(), Some(layout));

    // 2) 클러스터 2..4(2클러스터) 수정 후 Incremental .qblk + .qchain.json + 갱신된 .qmap.json 생성
    disk[2 * cs..3 * cs].fill(0xAA);
    disk[3 * cs..4 * cs].fill(0xBB);

    let inc_path = dir.path().join("inc1.qblk");
    let inc_map = {
        let f = File::create(&inc_path).unwrap();
        let mut h = base_header;
        let (_st, inc, map, _out) = write_incremental_image(
            &mut Cursor::new(&disk),
            f,
            &mut h,
            &bitmap,
            Some(&base_map),
            3,
            &cancel,
            &|_| {},
        )
        .unwrap();
        assert_eq!(inc.changed_clusters, 2);
        assert_eq!(inc.skipped_clusters, 6);
        assert_eq!(inc.chunks_written, 1);
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
        map
    };
    assert_eq!(load_block_map(&inc_path).unwrap(), inc_map);
    let chain_meta = load_chain_meta(&inc_path).unwrap().unwrap();
    assert_eq!(chain_meta.parent, "base.qblk");

    // 3) 2-링크 체인 무결성 검증
    let chain_res = verify_chain(&inc_path, &cancel, &|_| {}).unwrap();
    assert_eq!(chain_res.len(), 2);
    assert_eq!(chain_res[0].0, base_path);
    assert_eq!(chain_res[1].0, inc_path);

    // 4) Base .qblk AES-256-GCM 암호화 -> 감지 -> 복호화 바이트 동일성 검증
    let enc_path = dir.path().join("base.qblk.enc");
    let dec_path = dir.path().join("base_decrypted.qblk");
    let bad_dec_path = dir.path().join("base_wrong_key.qblk");
    let key = [0x5Au8; 32];
    let wrong_key = [0xA5u8; 32];

    assert!(!is_encrypted_image(&base_path));
    encrypt_file(&base_path, &enc_path, &key, &cancel).unwrap();
    assert!(is_encrypted_image(&enc_path));

    decrypt_file(&enc_path, &dec_path, &key, &cancel).unwrap();
    assert_eq!(fs::read(&dec_path).unwrap(), fs::read(&base_path).unwrap());

    assert!(decrypt_file(&enc_path, &bad_dec_path, &wrong_key, &cancel).is_err());
    assert!(!bad_dec_path.exists());

    // 5) 2-링크 증분 체인 복원 및 희소 볼륨 리더 일치 검증
    let restored_img = dir.path().join("restored_disk.img");
    let (restored_hdr, restored_stats) =
        restore_chain_to_file(&inc_path, &restored_img, &cancel, &|_| {}).unwrap();
    assert_eq!(restored_hdr.total_clusters, total_clusters);
    assert_eq!(restored_stats.clusters, 10);
    assert_eq!(fs::read(&restored_img).unwrap(), disk);

    let mut vol_reader = QblkVolumeReader::open(&inc_path).unwrap();
    assert_eq!(vol_reader.volume_len(), total_clusters * cs as u64);
    let mut streamed = Vec::new();
    vol_reader.read_to_end(&mut streamed).unwrap();
    assert_eq!(streamed, disk);
}

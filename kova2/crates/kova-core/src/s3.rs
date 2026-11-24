//! S3 호환(AWS S3 / Cloudflare R2 / Backblaze B2 / MinIO) 클라우드 오프사이트 백엔드.
//! 추가 외부 SDK 없이 표준 AWS Signature Version 4(HMAC-SHA256)와 `ureq`로 구현한다.
use chrono::Utc;
use kova_engine::storage::{CasStorage, SnapshotManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

const S3_TIMEOUT: Duration = Duration::from_secs(30);
const S3_STREAM_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const CONFIG_FILE: &str = "s3_config.bin";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3Config {
    /// 예: "https://s3.ap-northeast-2.amazonaws.com" 또는 "https://<acct>.r2.cloudflarestorage.com"
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
}

/// 로그·오류에 `{:?}` 로 찍혀도 비밀 키가 드러나지 않게 가린다.
impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .field(
                "secret_key",
                &if self.secret_key.is_empty() {
                    ""
                } else {
                    "***"
                },
            )
            .finish()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct S3ReplicaReport {
    pub snapshots_uploaded: usize,
    pub snapshots_skipped: usize,
    pub blobs_uploaded: usize,
    pub blobs_skipped: usize,
    pub bytes_uploaded: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct S3PullReport {
    pub crypto_downloaded: bool,
    pub snapshots_downloaded: usize,
    pub packs_downloaded: usize,
    pub blobs_downloaded: usize,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct S3PruneReport {
    pub deleted_objects: usize,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3StatusSummary {
    pub configured: bool,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key: String,
}

pub fn save_config(cfg_dir: &Path, cfg: &S3Config) -> Result<(), String> {
    host_from_endpoint(&cfg.endpoint)?;
    if cfg.region.trim().is_empty() {
        return Err("S3 리전(region)이 비어 있습니다".into());
    }
    if cfg.bucket.trim().is_empty() {
        return Err("S3 버킷(bucket)이 비어 있습니다".into());
    }
    if cfg.access_key.trim().is_empty() || cfg.secret_key.is_empty() {
        return Err("S3 액세스 키와 비밀 키를 모두 입력하세요".into());
    }
    fs::create_dir_all(cfg_dir).map_err(|e| format!("설정 폴더 생성 실패: {e}"))?;
    let json = serde_json::to_vec(cfg).map_err(|e| format!("S3 설정 직렬화 실패: {e}"))?;
    let enc = crate::repocrypto::dpapi_protect(&json)?;
    crate::secrets::write_private(&cfg_dir.join(CONFIG_FILE), &enc)
        .map_err(|e| format!("S3 설정 저장 실패: {e}"))
}

pub fn load_config(cfg_dir: &Path) -> Result<Option<S3Config>, String> {
    let path = cfg_dir.join(CONFIG_FILE);
    let enc = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("S3 설정 읽기 실패: {e}")),
    };
    let raw = crate::repocrypto::dpapi_unprotect(&enc)?;
    let cfg: S3Config =
        serde_json::from_slice(&raw).map_err(|e| format!("S3 설정 형식 오류: {e}"))?;
    Ok(Some(cfg))
}

pub fn delete_config(cfg_dir: &Path) -> Result<(), String> {
    let path = cfg_dir.join(CONFIG_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("S3 설정 삭제 실패: {e}")),
    }
}

pub fn status(cfg_dir: &Path) -> S3StatusSummary {
    match load_config(cfg_dir) {
        Ok(Some(c)) => S3StatusSummary {
            configured: true,
            endpoint: c.endpoint,
            region: c.region,
            bucket: c.bucket,
            prefix: c.prefix,
            access_key: c.access_key,
        },
        _ => S3StatusSummary::default(),
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

fn host_from_endpoint(endpoint: &str) -> Result<String, String> {
    let rest = endpoint
        .trim()
        .strip_prefix("https://")
        .or_else(|| endpoint.trim().strip_prefix("http://"))
        .ok_or("S3 endpoint는 http:// 또는 https:// 로 시작해야 합니다")?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() {
        return Err("S3 endpoint 호스트가 비어 있습니다".into());
    }
    Ok(host.to_string())
}

fn encode_uri_segment(seg: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(seg.len());
    for b in seg.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn object_uri(bucket: &str, key: &str) -> String {
    let bucket_enc = encode_uri_segment(bucket.trim_matches('/'));
    let key_trimmed = key.trim_start_matches('/');
    if key_trimmed.is_empty() {
        return format!("/{bucket_enc}/");
    }
    let key_enc = key_trimmed
        .split('/')
        .map(encode_uri_segment)
        .collect::<Vec<_>>()
        .join("/");
    format!("/{bucket_enc}/{key_enc}")
}

/// AWS Signature Version 4 인증 헤더(`Authorization`, `x-amz-date`, `x-amz-content-sha256`, `Host`)를 생성한다.
#[allow(clippy::too_many_arguments)]
pub fn sign_v4(
    method: &str,
    host: &str,
    canonical_uri: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    payload: &[u8],
    amz_date: &str,
) -> (String, String, String) {
    sign_v4_with_query(
        method,
        host,
        canonical_uri,
        "",
        region,
        access_key,
        secret_key,
        payload,
        amz_date,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_v4_with_query(
    method: &str,
    host: &str,
    canonical_uri: &str,
    canonical_query: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
    payload: &[u8],
    amz_date: &str,
) -> (String, String, String) {
    let date_stamp = if amz_date.is_ascii() && amz_date.len() >= 8 {
        &amz_date[..8]
    } else {
        ""
    };
    let payload_hash = sha256_hex(payload);
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    (authorization, amz_date.to_string(), payload_hash)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(S3_TIMEOUT)
        .timeout_read(S3_TIMEOUT)
        .timeout_write(S3_TIMEOUT)
        .build()
}

fn streaming_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(S3_TIMEOUT)
        .timeout_read(S3_STREAM_TIMEOUT)
        .timeout_write(S3_STREAM_TIMEOUT)
        .build()
}

fn canonical_query_string(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (encode_uri_segment(k), encode_uri_segment(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn xml_tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml_unescape(&xml[start..start + end]))
}

fn xml_blocks<'a>(mut xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    while let Some(s) = xml.find(&open) {
        let after = &xml[s + open.len()..];
        let Some(e) = after.find(&close) else {
            break;
        };
        out.push(&after[..e]);
        xml = &after[e + close.len()..];
    }
    out
}

fn strip_cfg_prefix(cfg: &S3Config, full: &str) -> String {
    let p = cfg.prefix.trim_matches('/');
    if p.is_empty() {
        full.trim_start_matches('/').to_string()
    } else {
        let with_slash = format!("{p}/");
        full.strip_prefix(&with_slash)
            .unwrap_or(full)
            .trim_start_matches('/')
            .to_string()
    }
}

type ListObjectsPage = (Vec<(String, u64)>, Option<String>);

fn list_objects_page(
    cfg: &S3Config,
    subprefix: &str,
    max_keys: Option<u32>,
    continuation_token: Option<&str>,
) -> Result<ListObjectsPage, String> {
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, "");
    let prefix = if subprefix.is_empty() {
        let p = cfg.prefix.trim_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("{p}/")
        }
    } else {
        full_key(cfg, subprefix)
    };
    let max_str = max_keys.map(|m| m.to_string());
    let mut params: Vec<(&str, &str)> = vec![("list-type", "2")];
    if !prefix.is_empty() {
        params.push(("prefix", &prefix));
    }
    if let Some(ref m) = max_str {
        params.push(("max-keys", m));
    }
    if let Some(tok) = continuation_token {
        params.push(("continuation-token", tok));
    }
    let qs = canonical_query_string(&params);
    let url = format!("{}{}?{qs}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4_with_query(
        "GET",
        &host,
        &uri,
        &qs,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        b"",
        &amz_date,
    );
    let resp = agent()
        .get(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .call()
        .map_err(|e| format!("S3 ListObjectsV2 실패: {e}"))?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!("S3 ListObjectsV2 오류: HTTP {}", resp.status()));
    }
    let body = resp
        .into_string()
        .map_err(|e| format!("S3 ListObjectsV2 응답 읽기 실패: {e}"))?;
    let mut items = Vec::new();
    for block in xml_blocks(&body, "Contents") {
        let Some(key) = xml_tag_value(block, "Key") else {
            continue;
        };
        let size = xml_tag_value(block, "Size")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let rel = strip_cfg_prefix(cfg, &key);
        if !rel.is_empty() {
            items.push((rel, size));
        }
    }
    let truncated =
        xml_tag_value(&body, "IsTruncated").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    let next = if truncated {
        xml_tag_value(&body, "NextContinuationToken").filter(|t| !t.is_empty())
    } else {
        None
    };
    Ok((items, next))
}

/// S3 버킷에서 `subprefix` 아래의 객체 목록(`(상대 키, 크기)`)을 페이지네이션으로 전부 가져온다.
pub fn list_objects(cfg: &S3Config, subprefix: &str) -> Result<Vec<(String, u64)>, String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..10_000 {
        let (items, next) = list_objects_page(cfg, subprefix, None, token.as_deref())?;
        out.extend(items);
        match next {
            Some(t) if token.as_deref() != Some(t.as_str()) => token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

/// S3 객체를 삭제한다(404 도 이미 없는 것으로 간주해 성공).
pub fn delete_object(cfg: &S3Config, key: &str) -> Result<(), String> {
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, &full_key(cfg, key));
    let url = format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4(
        "DELETE",
        &host,
        &uri,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        b"",
        &amz_date,
    );
    match agent()
        .delete(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .call()
    {
        Ok(r) if (200..300).contains(&r.status()) => Ok(()),
        Ok(r) => Err(format!("S3 DELETE 오류({key}): HTTP {}", r.status())),
        Err(ureq::Error::Status(404, _)) => Ok(()),
        Err(e) => Err(format!("S3 DELETE 실패({key}): {e}")),
    }
}

/// S3 자격 증명·버킷 접근 가능 여부를 `ListObjectsV2(max-keys=1)` 로 점검한다.
pub fn test_connection(cfg: &S3Config) -> Result<(), String> {
    list_objects_page(cfg, "", Some(1), None)?;
    Ok(())
}

fn full_key(cfg: &S3Config, rel: &str) -> String {
    let p = cfg.prefix.trim_matches('/');
    let r = rel.trim_start_matches('/');
    if p.is_empty() {
        r.to_string()
    } else {
        format!("{p}/{r}")
    }
}

pub fn head_object(cfg: &S3Config, rel_key: &str) -> Result<bool, String> {
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, &full_key(cfg, rel_key));
    let url = format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4(
        "HEAD",
        &host,
        &uri,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        b"",
        &amz_date,
    );
    match agent()
        .head(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .call()
    {
        Ok(r) => Ok((200..300).contains(&r.status())),
        Err(ureq::Error::Status(404, _)) => Ok(false),
        Err(e) => Err(format!("S3 HEAD 실패({rel_key}): {e}")),
    }
}

pub fn put_object(cfg: &S3Config, rel_key: &str, data: &[u8]) -> Result<(), String> {
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, &full_key(cfg, rel_key));
    let url = format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4(
        "PUT",
        &host,
        &uri,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        data,
        &amz_date,
    );
    let resp = agent()
        .put(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(data)
        .map_err(|e| format!("S3 PUT 실패({rel_key}): {e}"))?;
    if (200..300).contains(&resp.status()) {
        Ok(())
    } else {
        Err(format!("S3 PUT 오류({rel_key}): HTTP {}", resp.status()))
    }
}

fn get_object(cfg: &S3Config, rel_key: &str) -> Result<Option<Vec<u8>>, String> {
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, &full_key(cfg, rel_key));
    let url = format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4(
        "GET",
        &host,
        &uri,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        b"",
        &amz_date,
    );
    match agent()
        .get(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .call()
    {
        Ok(r) if (200..300).contains(&r.status()) => {
            let mut buf = Vec::new();
            r.into_reader()
                .take(1024 * 1024)
                .read_to_end(&mut buf)
                .map_err(|e| format!("S3 GET 본문 읽기 실패({rel_key}): {e}"))?;
            Ok(Some(buf))
        }
        Ok(r) => Err(format!("S3 GET 오류({rel_key}): HTTP {}", r.status())),
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("S3 GET 실패({rel_key}): {e}")),
    }
}

/// 저장소의 스냅샷과 블롭(팩 포함)을 S3 호환 버킷으로 증분 복제한다.
/// 블롭을 먼저 올리고 매니페스트를 마지막에 올려 불완전 스냅샷이 보이지 않게 한다.
pub fn replicate_to_s3(
    repo: &Path,
    cfg: &S3Config,
    cancel: &AtomicBool,
) -> Result<S3ReplicaReport, String> {
    let mut rep = S3ReplicaReport::default();
    let snaps = repo.join("snapshots");
    if !snaps.is_dir() {
        return Ok(rep);
    }
    let mut manifests: Vec<PathBuf> = fs::read_dir(&snaps)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    manifests.sort();
    // 암호화 표식(crypto.json)을 스냅샷보다 먼저 올린다. 없으면 S3 복제본만으로는 복호화할 수 없다.
    let marker_path = repo.join(kova_engine::codec::MARKER);
    if marker_path.is_file() {
        let local_bytes = fs::read(&marker_path).map_err(|e| e.to_string())?;
        if head_object(cfg, kova_engine::codec::MARKER)? {
            match get_object(cfg, kova_engine::codec::MARKER)? {
                Some(remote_bytes) if remote_bytes == local_bytes => {}
                Some(_) => {
                    return Err(
                        "S3 버킷의 암호화 표식이 이 저장소와 다릅니다(다른 저장소의 복제본)".into(),
                    );
                }
                None => {
                    put_object(cfg, kova_engine::codec::MARKER, &local_bytes)?;
                    rep.bytes_uploaded += local_bytes.len() as u64;
                }
            }
        } else {
            put_object(cfg, kova_engine::codec::MARKER, &local_bytes)?;
            rep.bytes_uploaded += local_bytes.len() as u64;
        }
    }
    let packs = kova_engine::pack::load_index(repo);
    let mut done_packs = HashSet::new();
    let mut cas: Option<CasStorage> = None;

    for mp in manifests {
        if cancel.load(Ordering::Relaxed) {
            return Err("취소됨".into());
        }
        let name = mp.file_name().unwrap().to_string_lossy().to_string();
        let snap_key = format!("snapshots/{name}");
        if head_object(cfg, &snap_key)? {
            rep.snapshots_skipped += 1;
            continue;
        }
        let manifest_bytes = fs::read(&mp).map_err(|e| e.to_string())?;
        let plain_bytes = if kova_engine::storage::is_encrypted_manifest_bytes(&manifest_bytes) {
            let sid = mp
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let store = match cas.as_ref() {
                Some(c) => c,
                None => {
                    let c = CasStorage::new(repo).map_err(|e| format!("{}: {e}", mp.display()))?;
                    cas.insert(c)
                }
            };
            store
                .read_manifest_bytes(&mp, &sid)
                .map_err(|e| format!("{}: {e}", mp.display()))?
        } else {
            manifest_bytes.clone()
        };
        let m: SnapshotManifest =
            serde_json::from_slice(&plain_bytes).map_err(|e| format!("{}: {e}", mp.display()))?;

        let mut hashes = Vec::new();
        for fe in m.files() {
            hashes.extend(fe.chunks.into_iter().map(|c| c.hash));
            if let Some(b) = fe.blob_id {
                hashes.push(b);
            }
            if let Some(s) = fe.sha256 {
                hashes.push(s);
            }
        }
        hashes.retain(|h| !h.is_empty());
        if let Some(bad) = hashes.iter().find(|h| !crate::offsite::valid_hash(h)) {
            return Err(format!("{name}: 잘못된 해시 {bad:?}"));
        }

        let mut seen = HashSet::new();
        for h in hashes {
            if !seen.insert(h.clone()) {
                continue;
            }
            if cancel.load(Ordering::Relaxed) {
                return Err("취소됨".into());
            }
            let prefix = &h[0..2];
            let local_blob = repo.join("blobs").join(prefix).join(format!("{h}.blob"));
            if local_blob.is_file() {
                let key = format!("blobs/{prefix}/{h}.blob");
                if head_object(cfg, &key)? {
                    rep.blobs_skipped += 1;
                } else {
                    let data = fs::read(&local_blob).map_err(|e| e.to_string())?;
                    put_object(cfg, &key, &data)?;
                    rep.bytes_uploaded += data.len() as u64;
                    rep.blobs_uploaded += 1;
                }
            } else if let Some(entry) = packs.get(&h) {
                if done_packs.insert(entry.pack.clone()) {
                    use kova_engine::pack::{idx_file, pack_file};
                    let pk_key = format!("packs/{}.pack", entry.pack);
                    let ix_key = format!("packs/{}.idx", entry.pack);
                    if head_object(cfg, &ix_key)? && head_object(cfg, &pk_key)? {
                        rep.blobs_skipped += 1;
                    } else {
                        let pk_data =
                            fs::read(pack_file(repo, &entry.pack)).map_err(|e| e.to_string())?;
                        let ix_data =
                            fs::read(idx_file(repo, &entry.pack)).map_err(|e| e.to_string())?;
                        put_object(cfg, &pk_key, &pk_data)?;
                        put_object(cfg, &ix_key, &ix_data)?;
                        rep.bytes_uploaded += (pk_data.len() + ix_data.len()) as u64;
                        rep.blobs_uploaded += 1;
                    }
                }
            } else {
                return Err(format!("원본에 블롭이 없음: {h}"));
            }
        }
        put_object(cfg, &snap_key, &manifest_bytes)?;
        rep.bytes_uploaded += manifest_bytes.len() as u64;
        rep.snapshots_uploaded += 1;
    }
    Ok(rep)
}

fn is_safe_segment(seg: &str) -> bool {
    !seg.is_empty() && seg != "." && seg != ".." && !seg.contains(['/', '\\', ':', '\0'])
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PullKind {
    Crypto = 0,
    PackData = 1,
    PackIdx = 2,
    Blob = 3,
    Snapshot = 4,
}

fn classify_s3_key(key: &str) -> Result<Option<(PullKind, PathBuf)>, String> {
    if key == kova_engine::codec::MARKER {
        return Ok(Some((
            PullKind::Crypto,
            PathBuf::from(kova_engine::codec::MARKER),
        )));
    }
    if key.contains(['\\', ':', '\0']) || key.starts_with('/') || key.ends_with('/') {
        return Err(format!("안전하지 않은 S3 키: {key}"));
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts.iter().any(|s| !is_safe_segment(s)) {
        return Err(format!("안전하지 않은 S3 키: {key}"));
    }
    match parts.as_slice() {
        ["packs", file] if file.ends_with(".pack") && file.len() > 5 => Ok(Some((
            PullKind::PackData,
            PathBuf::from("packs").join(file),
        ))),
        ["packs", file] if file.ends_with(".idx") && file.len() > 4 => {
            Ok(Some((PullKind::PackIdx, PathBuf::from("packs").join(file))))
        }
        ["blobs", prefix, file]
            if prefix.len() == 2
                && prefix.bytes().all(|b| b.is_ascii_hexdigit())
                && file.ends_with(".blob") =>
        {
            let stem = &file[..file.len() - 5];
            if !crate::offsite::valid_hash(stem) || !stem[..2].eq_ignore_ascii_case(prefix) {
                return Err(format!("안전하지 않은 S3 블롭 키: {key}"));
            }
            Ok(Some((
                PullKind::Blob,
                PathBuf::from("blobs").join(prefix).join(file),
            )))
        }
        ["snapshots", file] if file.ends_with(".json") && file.len() > 5 => Ok(Some((
            PullKind::Snapshot,
            PathBuf::from("snapshots").join(file),
        ))),
        ["packs", ..] | ["blobs", ..] | ["snapshots", ..] => {
            Err(format!("안전하지 않은 S3 키 구조: {key}"))
        }
        _ => Ok(None),
    }
}

fn download_object_atomic(
    cfg: &S3Config,
    rel_key: &str,
    dest: &Path,
    cancel: &AtomicBool,
) -> Result<u64, String> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let host = host_from_endpoint(&cfg.endpoint)?;
    let uri = object_uri(&cfg.bucket, &full_key(cfg, rel_key));
    let url = format!("{}{}", cfg.endpoint.trim_end_matches('/'), uri);
    let amz_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (auth, date, hash) = sign_v4(
        "GET",
        &host,
        &uri,
        &cfg.region,
        &cfg.access_key,
        &cfg.secret_key,
        b"",
        &amz_date,
    );
    let resp = streaming_agent()
        .get(&url)
        .set("Host", &host)
        .set("x-amz-date", &date)
        .set("x-amz-content-sha256", &hash)
        .set("Authorization", &auth)
        .call()
        .map_err(|e| format!("S3 다운로드 실패({rel_key}): {e}"))?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!(
            "S3 다운로드 오류({rel_key}): HTTP {}",
            resp.status()
        ));
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(kova_engine::longpath::to_extended(parent))
            .map_err(|e| format!("폴더 생성 실패: {e}"))?;
    }
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "obj".into());
    let tmp = dest.with_file_name(format!(
        "{name}.{}.{}.tmp",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let ext_tmp = kova_engine::longpath::to_extended(&tmp);
    let ext_dest = kova_engine::longpath::to_extended(dest);
    let write_res = (|| -> Result<u64, String> {
        let mut reader = resp.into_reader();
        let mut file =
            fs::File::create(&ext_tmp).map_err(|e| format!("임시 파일 생성 실패: {e}"))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("취소됨".into());
            }
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("S3 스트림 읽기 실패({rel_key}): {e}"))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .map_err(|e| format!("디스크 쓰기 실패({rel_key}): {e}"))?;
            total += n as u64;
        }
        file.flush().map_err(|e| format!("플러시 실패: {e}"))?;
        file.sync_all().map_err(|e| format!("동기화 실패: {e}"))?;
        drop(file);
        if let Err(e) = fs::rename(&ext_tmp, &ext_dest) {
            if ext_dest.exists() {
                let _ = crate::worm::remove_protected(dest);
                fs::rename(&ext_tmp, &ext_dest)
                    .map_err(|e2| format!("파일 교체 실패({rel_key}): {e2}"))?;
            } else {
                return Err(format!("파일 교체 실패({rel_key}): {e}"));
            }
        }
        Ok(total)
    })();
    write_res.inspect_err(|_| {
        let _ = fs::remove_file(&ext_tmp);
    })
}

/// S3 버킷에서 백업 저장소(`crypto.json`, `packs/*`, `blobs/*/*`, `snapshots/*`)를 로컬 폴더로 내려받는다.
/// 이미 같은 크기로 존재하는 파일은 건너뛰고, 모든 파일은 `.tmp` → `sync_all` → `rename` 으로 원자 저장한다.
pub fn pull_from_s3(
    cfg: &S3Config,
    dest_repo: &Path,
    cancel: &AtomicBool,
    progress: &dyn Fn(u64, u64, &str),
) -> Result<S3PullReport, String> {
    let objects = list_objects(cfg, "")?;
    let mut plan: Vec<(PullKind, String, PathBuf, u64)> = Vec::new();
    for (key, size) in objects {
        if let Some((kind, rel_path)) = classify_s3_key(&key)? {
            plan.push((kind, key, rel_path, size));
        }
    }
    // crypto.json → packs(.pack → .idx) → blobs → snapshots 순으로 내려받아 반쪽 스냅샷을 막는다
    plan.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let total_bytes: u64 = plan.iter().map(|(_, _, _, sz)| *sz).sum();
    let mut done_bytes = 0u64;
    let mut rep = S3PullReport::default();

    for (kind, key, rel_path, expected_size) in plan {
        if cancel.load(Ordering::Relaxed) {
            return Err("취소됨".into());
        }
        let dest = dest_repo.join(&rel_path);
        let ext_dest = kova_engine::longpath::to_extended(&dest);
        if fs::metadata(&ext_dest).is_ok_and(|m| m.is_file() && m.len() == expected_size) {
            done_bytes = done_bytes.saturating_add(expected_size);
            progress(done_bytes, total_bytes, &key);
            continue;
        }
        let n = download_object_atomic(cfg, &key, &dest, cancel)?;
        rep.bytes_downloaded += n;
        match kind {
            PullKind::Crypto => rep.crypto_downloaded = true,
            PullKind::PackData | PullKind::PackIdx => rep.packs_downloaded += 1,
            PullKind::Blob => rep.blobs_downloaded += 1,
            PullKind::Snapshot => rep.snapshots_downloaded += 1,
        }
        done_bytes = done_bytes.saturating_add(n);
        progress(done_bytes, total_bytes, &key);
    }
    Ok(rep)
}

/// 로컬 저장소에 더 이상 없는 원격 S3 스냅샷·팩·블롭을 정리한다.
/// 로컬 스냅샷이 0개이면 실수로 클라우드 전체가 지워지지 않도록 거부한다(fail-closed).
pub fn prune_s3_orphans(
    cfg: &S3Config,
    local_repo: &Path,
    cancel: &AtomicBool,
) -> Result<S3PruneReport, String> {
    let mut local_snaps = HashSet::new();
    if let Ok(rd) = fs::read_dir(local_repo.join("snapshots")) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() && p.extension().is_some_and(|x| x == "json") {
                local_snaps.insert(format!("snapshots/{}", e.file_name().to_string_lossy()));
            }
        }
    }
    if local_snaps.is_empty() {
        return Err("로컬 저장소에 스냅샷이 없어 S3 원격 정리를 거부합니다".into());
    }

    let mut local_packs = HashSet::new();
    for id in kova_engine::pack::pack_ids(local_repo) {
        local_packs.insert(format!("packs/{id}.pack"));
        local_packs.insert(format!("packs/{id}.idx"));
    }

    let mut local_blobs = HashSet::new();
    if let Ok(dirs) = fs::read_dir(local_repo.join("blobs")) {
        for d in dirs.flatten() {
            let dp = d.path();
            if !dp.is_dir() {
                continue;
            }
            let prefix = d.file_name().to_string_lossy().to_string();
            if let Ok(files) = fs::read_dir(&dp) {
                for f in files.flatten() {
                    let fp = f.path();
                    if fp.is_file() && fp.extension().is_some_and(|x| x == "blob") {
                        local_blobs.insert(format!(
                            "blobs/{prefix}/{}",
                            f.file_name().to_string_lossy()
                        ));
                    }
                }
            }
        }
    }

    let remote = list_objects(cfg, "")?;
    let mut to_delete: Vec<(u8, String, u64)> = Vec::new();
    for (key, size) in remote {
        if key == kova_engine::codec::MARKER {
            continue;
        }
        if key.starts_with("snapshots/") && key.ends_with(".json") && !local_snaps.contains(&key) {
            to_delete.push((0, key, size));
        } else if key.starts_with("packs/") && key.ends_with(".idx") && !local_packs.contains(&key)
        {
            to_delete.push((1, key, size));
        } else if key.starts_with("packs/") && key.ends_with(".pack") && !local_packs.contains(&key)
        {
            to_delete.push((2, key, size));
        } else if key.starts_with("blobs/") && key.ends_with(".blob") && !local_blobs.contains(&key)
        {
            to_delete.push((3, key, size));
        }
    }
    // 스냅샷 → 팩 색인 → 팩 본문 → 낱개 블롭 순으로 삭제한다
    to_delete.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut rep = S3PruneReport::default();
    for (_, key, size) in to_delete {
        if cancel.load(Ordering::Relaxed) {
            return Err("취소됨".into());
        }
        delete_object(cfg, &key)?;
        rep.deleted_objects += 1;
        rep.freed_bytes += size;
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn sigv4_signature_is_deterministic_and_well_formed() {
        let (auth, date, hash) = sign_v4(
            "PUT",
            "s3.us-east-1.amazonaws.com",
            "/mybucket/test.txt",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            b"hello",
            "20261119T120000Z",
        );
        assert_eq!(date, "20261119T120000Z");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261119/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        ));
        assert_eq!(auth.split("Signature=").nth(1).unwrap().len(), 64);
    }

    #[test]
    fn replicate_to_mock_s3_uploads_then_skips() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("doc.txt"), "s3 offsite test content").unwrap();
        let repo = d.path().join("repo");
        kova_engine::ops::run_backup(
            &kova_engine::ops::BackupOptions {
                sources: vec![src],
                repo: repo.clone(),
                session_id: None,
                zstd_level: 3,
                exclude: vec![],
                profile_id: None,
                scan_from: None,
                ..Default::default()
            },
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();

        let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let store_srv = store.clone();
        let srv = std::thread::spawn(move || {
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
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            let hdr = String::from_utf8_lossy(&data[..pos]);
                            content_len = hdr
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
                            body_start = Some(pos + 4);
                        }
                    }
                    if let Some(bs) = body_start {
                        if data.len() >= bs + content_len {
                            break;
                        }
                    }
                }
                let bs = body_start.unwrap_or(data.len());
                let hdr = String::from_utf8_lossy(&data[..bs]).to_string();
                let first = hdr.lines().next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("");
                let uri = parts.next().unwrap_or("").to_string();
                assert!(hdr.contains("AWS4-HMAC-SHA256"));
                match method {
                    "HEAD" => {
                        let exists = store_srv.lock().unwrap().contains_key(&uri);
                        let resp = if exists {
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        };
                        let _ = sock.write_all(resp.as_bytes());
                    }
                    "GET" => {
                        if let Some(body) = store_srv.lock().unwrap().get(&uri).cloned() {
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
                        let body = data[bs..bs + content_len].to_vec();
                        store_srv.lock().unwrap().insert(uri, body);
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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

        let cfg = S3Config {
            endpoint: format!("http://{addr}"),
            region: "ap-northeast-2".into(),
            bucket: "kova-bucket".into(),
            prefix: "pc1".into(),
            access_key: "TESTKEY".into(),
            secret_key: "TESTSECRET".into(),
        };
        // Debug 출력에 비밀 키가 드러나지 않는다
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("TESTSECRET") && dbg.contains("TESTKEY"),
            "{dbg}"
        );
        let no = AtomicBool::new(false);
        let r1 = replicate_to_s3(&repo, &cfg, &no).unwrap();
        assert_eq!(r1.snapshots_uploaded, 1);
        assert!(r1.blobs_uploaded >= 1);
        assert!(r1.bytes_uploaded > 0);

        let r2 = replicate_to_s3(&repo, &cfg, &no).unwrap();
        assert_eq!((r2.snapshots_uploaded, r2.snapshots_skipped), (0, 1));

        stop.store(true, Ordering::Relaxed);
        srv.join().unwrap();
    }

    #[test]
    fn object_uri_percent_encodes_segments_and_sign_v4_handles_short_date() {
        assert_eq!(
            object_uri("my-bucket", "한글 폴더/a b/c~d_e-f.json"),
            "/my-bucket/%ED%95%9C%EA%B8%80%20%ED%8F%B4%EB%8D%94/a%20b/c~d_e-f.json"
        );
        assert_eq!(
            object_uri("버킷 이름", "prefix/sub/file+1.txt"),
            "/%EB%B2%84%ED%82%B7%20%EC%9D%B4%EB%A6%84/prefix/sub/file%2B1.txt"
        );
        // 짧거나 비-ASCII amz_date 에서도 패닉하지 않아야 한다
        let (auth1, _, _) = sign_v4("GET", "h", "/b/k", "r", "ak", "sk", b"", "2026");
        assert!(auth1.starts_with("AWS4-HMAC-SHA256 "));
        let (auth2, _, _) = sign_v4("GET", "h", "/b/k", "r", "ak", "sk", b"", "한글날짜입니다");
        assert!(auth2.starts_with("AWS4-HMAC-SHA256 "));
    }

    #[test]
    fn replicate_to_s3_uploads_crypto_marker_and_rejects_conflict() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("doc.txt"), "s3 encrypted marker test").unwrap();
        let repo = d.path().join("repo");
        kova_engine::ops::run_backup(
            &kova_engine::ops::BackupOptions {
                sources: vec![src],
                repo: repo.clone(),
                session_id: Some("20261124_100000".into()),
                zstd_level: 3,
                exclude: vec![],
                profile_id: None,
                scan_from: None,
                ..Default::default()
            },
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let marker = br#"{"version":1,"repo_id":"repo1111","key_check":"aaaa"}"#;
        fs::write(repo.join(kova_engine::codec::MARKER), marker).unwrap();

        let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
        let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let store_srv = store.clone();
        let order_srv = order.clone();
        let srv = std::thread::spawn(move || {
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
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            let hdr = String::from_utf8_lossy(&data[..pos]);
                            content_len = hdr
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
                            body_start = Some(pos + 4);
                        }
                    }
                    if let Some(bs) = body_start {
                        if data.len() >= bs + content_len {
                            break;
                        }
                    }
                }
                let bs = body_start.unwrap_or(data.len());
                let hdr = String::from_utf8_lossy(&data[..bs]).to_string();
                let first = hdr.lines().next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("");
                let uri = parts.next().unwrap_or("").to_string();
                match method {
                    "HEAD" => {
                        let exists = store_srv.lock().unwrap().contains_key(&uri);
                        let resp = if exists {
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        };
                        let _ = sock.write_all(resp.as_bytes());
                    }
                    "GET" => {
                        if let Some(body) = store_srv.lock().unwrap().get(&uri).cloned() {
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
                        let body = data[bs..bs + content_len].to_vec();
                        store_srv.lock().unwrap().insert(uri.clone(), body);
                        order_srv.lock().unwrap().push(uri);
                        let _ = sock.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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

        let cfg = S3Config {
            endpoint: format!("http://{addr}"),
            region: "ap-northeast-2".into(),
            bucket: "kova-bucket".into(),
            prefix: "pc1".into(),
            access_key: "TESTKEY".into(),
            secret_key: "TESTSECRET".into(),
        };
        let no = AtomicBool::new(false);
        let r1 = replicate_to_s3(&repo, &cfg, &no).unwrap();
        assert_eq!(r1.snapshots_uploaded, 1);

        let marker_uri = format!("/kova-bucket/pc1/{}", kova_engine::codec::MARKER);
        let snap_uri = "/kova-bucket/pc1/snapshots/20261124_100000.json".to_string();
        {
            let st = store.lock().unwrap();
            assert_eq!(st.get(&marker_uri).map(Vec::as_slice), Some(&marker[..]));
            let ord = order.lock().unwrap();
            let mk_pos = ord.iter().position(|u| u == &marker_uri).unwrap();
            let sn_pos = ord.iter().position(|u| u == &snap_uri).unwrap();
            assert!(
                mk_pos < sn_pos,
                "crypto.json 은 스냅샷보다 먼저 올라가야 함"
            );
        }

        // 같은 내용의 crypto.json 으로 재실행하면 통과
        let r2 = replicate_to_s3(&repo, &cfg, &no).unwrap();
        assert_eq!((r2.snapshots_uploaded, r2.snapshots_skipped), (0, 1));

        // 같은 길이의 다른 crypto.json 은 충돌로 거부
        let conflict = br#"{"version":1,"repo_id":"repo2222","key_check":"bbbb"}"#;
        assert_eq!(conflict.len(), marker.len());
        fs::write(repo.join(kova_engine::codec::MARKER), conflict).unwrap();
        let err = replicate_to_s3(&repo, &cfg, &no).unwrap_err();
        assert!(err.contains("암호화 표식"), "{err}");

        // 잘못된 해시가 들어 있는 매니페스트는 패닉 없이 오류 반환
        fs::write(repo.join(kova_engine::codec::MARKER), marker).unwrap();
        fs::write(
            repo.join("snapshots").join("20261124_110000.json"),
            r#"{"id":"20261124_110000","files":[{"path":"a","size":1,"chunks":[{"hash":"../bad","offset":0,"length":1,"compressed_length":1}]}]}"#,
        )
        .unwrap();
        let err2 = replicate_to_s3(&repo, &cfg, &no).unwrap_err();
        assert!(err2.contains("잘못된 해시"), "{err2}");

        stop.store(true, Ordering::Relaxed);
        srv.join().unwrap();
    }

    /// HEAD / GET / ListObjectsV2(페이지네이션 포함) / PUT / DELETE 를 모두 지원하는 모의 S3 서버.
    struct MockS3 {
        cfg: S3Config,
        store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl MockS3 {
        fn start(bucket: &str, prefix: &str, page_size: usize) -> Self {
            let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_srv = stop.clone();
            let store_srv = store.clone();
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
                            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                                let hdr = String::from_utf8_lossy(&data[..pos]);
                                content_len = hdr
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
                                body_start = Some(pos + 4);
                            }
                        }
                        if let Some(bs) = body_start {
                            if data.len() >= bs + content_len {
                                break;
                            }
                        }
                    }
                    let bs = body_start.unwrap_or(data.len());
                    let hdr = String::from_utf8_lossy(&data[..bs]).to_string();
                    let first = hdr.lines().next().unwrap_or("");
                    let mut parts = first.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let raw_target = parts.next().unwrap_or("");
                    let (uri, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));
                    assert!(hdr.contains("AWS4-HMAC-SHA256"));
                    match method {
                        "HEAD" => {
                            let exists = store_srv.lock().unwrap().contains_key(uri);
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
                                    qmap.insert(
                                        crate::gdrive::pct_decode(k),
                                        crate::gdrive::pct_decode(v),
                                    );
                                }
                            }
                            let qprefix = qmap.get("prefix").cloned().unwrap_or_default();
                            let offset: usize = qmap
                                .get("continuation-token")
                                .and_then(|t| t.parse().ok())
                                .unwrap_or(0);
                            let max_k: usize = qmap
                                .get("max-keys")
                                .and_then(|t| t.parse().ok())
                                .unwrap_or(page_size);
                            let mut all: Vec<(String, usize)> = store_srv
                                .lock()
                                .unwrap()
                                .iter()
                                .filter_map(|(k, v)| {
                                    let key = k.strip_prefix(&bucket_prefix)?;
                                    key.starts_with(&qprefix)
                                        .then(|| (key.to_string(), v.len()))
                                })
                                .collect();
                            all.sort_by(|a, b| a.0.cmp(&b.0));
                            let end = (offset + max_k).min(all.len());
                            let truncated = end < all.len();
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
                            for (k, sz) in &all[offset.min(all.len())..end] {
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
                            if let Some(body) = store_srv.lock().unwrap().get(uri).cloned() {
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
                            let body = data[bs..bs + content_len].to_vec();
                            store_srv.lock().unwrap().insert(uri.to_string(), body);
                            let _ = sock.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                        "DELETE" => {
                            store_srv.lock().unwrap().remove(uri);
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
                    access_key: "AKTEST".into(),
                    secret_key: "SKTEST".into(),
                },
                store,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for MockS3 {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    #[test]
    fn s3_pack_replication_pull_roundtrip_and_prune_orphans() {
        let srv = MockS3::start("kova-bucket", "host1", 2);
        test_connection(&srv.cfg).unwrap();

        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let payload = "S3 pack + pull + prune end-to-end payload ".repeat(50);
        fs::write(src.join("report.txt"), &payload).unwrap();
        let repo = d.path().join("repo");
        kova_engine::ops::run_backup(
            &kova_engine::ops::BackupOptions {
                sources: vec![src.clone()],
                repo: repo.clone(),
                session_id: Some("20261124_120000".into()),
                zstd_level: 3,
                exclude: vec![],
                profile_id: None,
                scan_from: None,
                ..Default::default()
            },
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();

        // 1) 팩 복제 확인 (.pack + .idx 모두 S3 에 올라가야 한다)
        let no = AtomicBool::new(false);
        let up = replicate_to_s3(&repo, &srv.cfg, &no).unwrap();
        assert_eq!(up.snapshots_uploaded, 1);
        assert!(up.blobs_uploaded >= 1);
        let listed = list_objects(&srv.cfg, "").unwrap();
        assert!(listed
            .iter()
            .any(|(k, _)| k.starts_with("packs/") && k.ends_with(".pack")));
        assert!(listed
            .iter()
            .any(|(k, _)| k.starts_with("packs/") && k.ends_with(".idx")));
        assert!(listed
            .iter()
            .any(|(k, _)| k == "snapshots/20261124_120000.json"));

        // 2) 클라우드 풀(pull_from_s3) → 빈 폴더로 내려받아 검증·복원
        let pulled_repo = d.path().join("pulled_repo");
        let progress_calls = std::sync::atomic::AtomicUsize::new(0);
        let pull1 = pull_from_s3(&srv.cfg, &pulled_repo, &no, &|_, _, _| {
            progress_calls.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();
        assert_eq!(pull1.snapshots_downloaded, 1);
        assert!(pull1.packs_downloaded >= 2);
        assert!(pull1.bytes_downloaded > 0);
        assert!(progress_calls.load(Ordering::Relaxed) >= 3);
        assert!(crate::verify::verify_repo(&pulled_repo, true).unwrap().ok());

        let restored = d.path().join("restored");
        kova_engine::ops::run_restore(
            &kova_engine::ops::RestoreOptions {
                repo: pulled_repo.clone(),
                session_id: "20261124_120000".into(),
                target: Some(restored.clone()),
                only: None,
            },
            &|_| {},
            &no,
        )
        .unwrap();
        let found = restored.join("src").join("report.txt");
        let restored_text = if found.is_file() {
            fs::read_to_string(found).unwrap()
        } else {
            fs::read_to_string(restored.join("report.txt")).unwrap()
        };
        assert_eq!(restored_text, payload);

        // 같은 크기로 이미 있으면 두 번째 pull 은 모두 건너뛴다
        let pull2 = pull_from_s3(&srv.cfg, &pulled_repo, &no, &|_, _, _| {}).unwrap();
        assert_eq!(pull2.snapshots_downloaded, 0);
        assert_eq!(pull2.packs_downloaded, 0);
        assert_eq!(pull2.bytes_downloaded, 0);

        // 3) 원격 고아 정리(prune_s3_orphans): 빈 로컬 저장소는 거부
        let empty_repo = d.path().join("empty_repo");
        fs::create_dir_all(empty_repo.join("snapshots")).unwrap();
        assert!(prune_s3_orphans(&srv.cfg, &empty_repo, &no).is_err());

        // 원격에만 있는 고아 스냅샷·팩·블롭 + 보호 대상 crypto.json 심기
        put_object(&srv.cfg, kova_engine::codec::MARKER, b"{\"version\":1}").unwrap();
        put_object(&srv.cfg, "snapshots/old_orphan.json", b"{}").unwrap();
        put_object(&srv.cfg, "packs/porphan.pack", b"packdata").unwrap();
        put_object(&srv.cfg, "packs/porphan.idx", b"idx").unwrap();
        let orphan_blob = format!("blobs/aa/{}.blob", "aa".repeat(32));
        put_object(&srv.cfg, &orphan_blob, b"blobdata").unwrap();

        let pruned = prune_s3_orphans(&srv.cfg, &repo, &no).unwrap();
        assert_eq!(pruned.deleted_objects, 4);
        assert_eq!(pruned.freed_bytes, 2 + 8 + 3 + 8);

        let after = list_objects(&srv.cfg, "").unwrap();
        assert!(after.iter().any(|(k, _)| k == kova_engine::codec::MARKER));
        assert!(after
            .iter()
            .any(|(k, _)| k == "snapshots/20261124_120000.json"));
        assert!(!after.iter().any(|(k, _)| k == "snapshots/old_orphan.json"));
        assert!(!after.iter().any(|(k, _)| k == "packs/porphan.pack"));
        assert!(!after.iter().any(|(k, _)| *k == orphan_blob));

        // 4) 경로 탈출 키 거부 확인
        srv.store.lock().unwrap().insert(
            "/kova-bucket/host1/snapshots/../../evil.json".into(),
            b"x".to_vec(),
        );
        assert!(pull_from_s3(&srv.cfg, &pulled_repo, &no, &|_, _, _| {}).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn s3_config_dpapi_roundtrip_and_status() {
        let d = tempfile::tempdir().unwrap();
        assert!(!status(d.path()).configured);
        assert!(load_config(d.path()).unwrap().is_none());

        let cfg = S3Config {
            endpoint: "https://s3.ap-northeast-2.amazonaws.com".into(),
            region: "ap-northeast-2".into(),
            bucket: "my-backup-bucket".into(),
            prefix: "office-pc1".into(),
            access_key: "AKIA123456".into(),
            secret_key: "VerySecretS3KeyValue!".into(),
        };
        save_config(d.path(), &cfg).unwrap();
        let raw = fs::read(d.path().join(CONFIG_FILE)).unwrap();
        assert!(!raw.windows(10).any(|w| w == b"VerySecret"));

        let loaded = load_config(d.path()).unwrap().unwrap();
        assert_eq!(loaded, cfg);

        let st = status(d.path());
        assert!(st.configured);
        assert_eq!(st.bucket, "my-backup-bucket");
        assert_eq!(st.access_key, "AKIA123456");

        delete_config(d.path()).unwrap();
        assert!(!status(d.path()).configured);
    }
}

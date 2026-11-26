//! 저장소 검증: 매니페스트가 가리키는 모든 청크가 존재하고(빠른 검사),
//! 필요하면 압축을 풀어 BLAKE3 해시와 길이가 일치하는지(전체 검사) 확인한다.
use kova_engine::{
    hasher,
    storage::{valid_session_id, CasStorage, SnapshotManifest},
};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum Problem {
    MissingBlob {
        snapshot: String,
        path: String,
        hash: String,
    },
    CorruptBlob {
        hash: String,
        reason: String,
    },
    BadManifest {
        file: String,
        reason: String,
    },
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub snapshots: usize,
    pub files: usize,
    pub unique_chunks: usize,
    pub problems: Vec<Problem>,
    /// 문제가 있는 스냅샷(매니페스트 파일 이름) -> 문제 수. 손상 청크는 그 청크를 쓰는 모든 스냅샷에 센다.
    pub snapshot_errors: BTreeMap<String, i64>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// deep=false: 청크 파일 존재만 확인. deep=true: 전부 읽어 압축 해제 + 해시 + 길이 확인.
pub fn verify_repo(repo: &Path, deep: bool) -> io::Result<VerifyReport> {
    let mut paths = Vec::new();
    for e in fs::read_dir(repo.join("snapshots"))? {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "json") {
            paths.push(p);
        }
    }
    verify_manifests(repo, paths, deep)
}

/// 스냅샷 하나만 검증한다. 보고되는 문제는 모두 그 스냅샷의 것이다(손상 청크 포함).
pub fn verify_snapshot(repo: &Path, session_id: &str, deep: bool) -> io::Result<VerifyReport> {
    if !valid_session_id(session_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "스냅샷 번호가 올바르지 않습니다",
        ));
    }
    let path = repo.join("snapshots").join(format!("{session_id}.json"));
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("스냅샷을 찾을 수 없습니다: {session_id}"),
        ));
    }
    verify_manifests(repo, vec![path], deep)
}

fn verify_manifests(repo: &Path, paths: Vec<PathBuf>, deep: bool) -> io::Result<VerifyReport> {
    let cas = CasStorage::new(repo)?;
    let mut rep = VerifyReport::default();
    // 해시 -> (기대 길이(0 이면 미상), 구형 blob_id/sha256 여부). 같은 청크는 한 번만 검사한다.
    let mut unique: BTreeMap<String, (usize, bool)> = BTreeMap::new();
    for p in &paths {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let sid_stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let manifest = match read_manifest(&cas, p, &sid_stem) {
            Ok(m) => m,
            Err(reason) => {
                *rep.snapshot_errors.entry(sid_stem).or_default() += 1;
                rep.problems
                    .push(Problem::BadManifest { file: name, reason });
                continue;
            }
        };
        rep.snapshots += 1;
        let sid = manifest.session_id();
        for fe in manifest.files() {
            rep.files += 1;
            // 청크 정보가 없는 구형 항목은 blob_id/sha256 이 가리키는 블롭(파일 전체)을 검사한다
            if fe.chunks.is_empty() && !fe.is_dir {
                if let Some(id) = fe.blob_id.clone().or(fe.sha256.clone()) {
                    let found = [fe.blob_id.as_ref(), fe.sha256.as_ref()]
                        .into_iter()
                        .flatten()
                        .find(|h| cas.has_blob(h))
                        .cloned();
                    match found {
                        Some(h) => {
                            unique.entry(h).or_insert((fe.size as usize, true));
                        }
                        None => {
                            *rep.snapshot_errors.entry(sid_stem.clone()).or_default() += 1;
                            rep.problems.push(Problem::MissingBlob {
                                snapshot: sid.clone(),
                                path: fe.path.clone(),
                                hash: id,
                            });
                        }
                    }
                }
            }
            for c in fe.chunks {
                if !cas.has_blob(&c.hash) {
                    *rep.snapshot_errors.entry(sid_stem.clone()).or_default() += 1;
                    rep.problems.push(Problem::MissingBlob {
                        snapshot: sid.clone(),
                        path: fe.path.clone(),
                        hash: c.hash.clone(),
                    });
                }
                unique.entry(c.hash).or_insert((c.length, false));
            }
        }
    }
    rep.unique_chunks = unique.len();
    if deep {
        let bad: Vec<Problem> = unique
            .par_iter()
            .filter_map(|(hash, (len, legacy))| {
                let comp = match cas.read_blob(hash) {
                    Ok(c) => c,
                    // 있다고 나오는데 읽지 못하면(팩 읽기 IO 오류·잘린 팩 등) 손상으로 보고한다
                    Err(e) if cas.has_blob(hash) => {
                        return Some(Problem::CorruptBlob {
                            hash: hash.clone(),
                            reason: format!("읽기 실패: {}", e),
                        })
                    }
                    Err(_) => return None, // 없는 청크는 위에서 이미 MissingBlob 으로 보고됨
                };
                let raw = match cas.decode_blob(&comp, hash) {
                    Ok(r) => r,
                    Err(e) => {
                        return Some(Problem::CorruptBlob {
                            hash: hash.clone(),
                            reason: format!("압축 해제 실패: {}", e),
                        })
                    }
                };
                if *len != 0 && raw.len() != *len {
                    return Some(Problem::CorruptBlob {
                        hash: hash.clone(),
                        reason: format!("길이 불일치: {} != {}", raw.len(), len),
                    });
                }
                // 구형 blob_id/sha256 은 해시 종류가 BLAKE3 또는 SHA-256 일 수 있다
                let sha_ok = || {
                    use sha2::Digest;
                    sha2::Sha256::digest(&raw)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                        .eq_ignore_ascii_case(hash)
                };
                if !hasher::hash_bytes(&raw).eq_ignore_ascii_case(hash) && !(*legacy && sha_ok()) {
                    return Some(Problem::CorruptBlob {
                        hash: hash.clone(),
                        reason: "해시 불일치".into(),
                    });
                }
                None
            })
            .collect();
        let corrupt: HashSet<&str> = bad
            .iter()
            .filter_map(|p| match p {
                Problem::CorruptBlob { hash, .. } => Some(hash.as_str()),
                _ => None,
            })
            .collect();
        if !corrupt.is_empty() {
            mark_users(&cas, &paths, &corrupt, &mut rep.snapshot_errors);
        }
        rep.problems.extend(bad);
    }
    Ok(rep)
}

fn read_manifest(cas: &CasStorage, path: &Path, stem: &str) -> Result<SnapshotManifest, String> {
    cas.read_manifest_bytes(path, stem)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
}

/// 손상 청크를 쓰는 스냅샷을 찾아 문제 수를 더한다. 손상이 있을 때만 매니페스트를 다시 읽으므로
/// 정상 저장소에서는 "청크 -> 스냅샷" 목록을 메모리에 쌓지 않는다.
fn mark_users(
    cas: &CasStorage,
    paths: &[PathBuf],
    corrupt: &HashSet<&str>,
    errors: &mut BTreeMap<String, i64>,
) {
    for p in paths {
        let Some(stem) = p.file_stem().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        // 못 읽는 매니페스트는 첫 번째 순회에서 이미 BadManifest 로 셌다
        let Ok(manifest) = read_manifest(cas, p, &stem) else {
            continue;
        };
        let mut used: HashSet<String> = HashSet::new();
        for fe in manifest.files() {
            if fe.chunks.is_empty() && !fe.is_dir {
                // 첫 번째 순회와 같이 실제로 있는 구형 블롭 하나만 본다
                let found = [fe.blob_id.as_ref(), fe.sha256.as_ref()]
                    .into_iter()
                    .flatten()
                    .find(|h| cas.has_blob(h));
                used.extend(found.filter(|h| corrupt.contains(h.as_str())).cloned());
            }
            used.extend(
                fe.chunks
                    .into_iter()
                    .map(|c| c.hash)
                    .filter(|h| corrupt.contains(h.as_str())),
            );
        }
        if !used.is_empty() {
            *errors.entry(stem).or_default() += used.len() as i64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kova_engine::compressor;

    /// 청크 하나짜리 저장소를 엔진 라이브러리로 직접 만든다.
    fn make_repo(data: &[u8]) -> (tempfile::TempDir, String) {
        let d = tempfile::tempdir().unwrap();
        let cas = CasStorage::new(d.path()).unwrap();
        let hash = hasher::hash_bytes(data);
        cas.save_blob(&hash, &compressor::compress(data, 3).unwrap())
            .unwrap();
        fs::write(
            d.path().join("snapshots").join("s1.json"),
            format!(
                r#"{{"id":"s1","files":[{{"path":"a.txt","size":{},"chunks":[{{"hash":"{}","length":{}}}]}}]}}"#,
                data.len(),
                hash,
                data.len()
            ),
        )
        .unwrap();
        (d, hash)
    }

    #[test]
    fn healthy_repo_passes_deep_verify() {
        let (d, _) = make_repo(b"kova verify test data");
        let r = verify_repo(d.path(), true).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!((r.snapshots, r.files, r.unique_chunks), (1, 1, 1));
    }

    #[test]
    fn single_snapshot_verify_checks_only_that_snapshot() {
        let (d, _) = make_repo(b"good data");
        // s2 는 없는 청크를 가리킨다
        fs::write(
            d.path().join("snapshots").join("s2.json"),
            r#"{"id":"s2","files":[{"path":"b.txt","size":1,"chunks":[{"hash":"00ff","length":1}]}]}"#,
        )
        .unwrap();
        let good = verify_snapshot(d.path(), "s1", true).unwrap();
        assert!(good.ok(), "{:?}", good.problems);
        assert_eq!(good.snapshots, 1);
        assert!(!verify_snapshot(d.path(), "s2", true).unwrap().ok());
        assert_eq!(
            verify_snapshot(d.path(), "../s1", true).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            verify_snapshot(d.path(), "none", true).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn corrupt_blob_is_charged_to_every_snapshot_that_uses_it() {
        let (d, hash) = make_repo(b"original content");
        let snap = |id: &str, h: &str| {
            fs::write(
                d.path().join("snapshots").join(format!("{id}.json")),
                format!(
                    r#"{{"id":"{id}","files":[{{"path":"a","size":16,"chunks":[{{"hash":"{h}","length":16}}]}},{{"path":"copy","size":16,"chunks":[{{"hash":"{h}","length":16}}]}}]}}"#
                ),
            )
            .unwrap();
        };
        // s2 는 같은 청크를 두 파일에서 쓰고, ok 는 멀쩡한 청크만 쓴다
        snap("s2", &hash);
        let other = b"another content!";
        let other_hash = hasher::hash_bytes(other);
        CasStorage::new(d.path())
            .unwrap()
            .save_blob(&other_hash, &compressor::compress(other, 3).unwrap())
            .unwrap();
        snap("ok", &other_hash);
        fs::write(
            d.path()
                .join("blobs")
                .join(&hash[..2])
                .join(format!("{}.blob", hash)),
            b"not zstd",
        )
        .unwrap();
        let r = verify_repo(d.path(), true).unwrap();
        assert_eq!(
            r.snapshot_errors,
            BTreeMap::from([("s1".to_string(), 1), ("s2".to_string(), 1)]),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn missing_blob_is_reported() {
        let (d, hash) = make_repo(b"data");
        fs::remove_file(
            d.path()
                .join("blobs")
                .join(&hash[..2])
                .join(format!("{}.blob", hash)),
        )
        .unwrap();
        let r = verify_repo(d.path(), false).unwrap();
        assert!(matches!(r.problems[0], Problem::MissingBlob { .. }));
    }

    #[test]
    fn corrupt_blob_is_caught_only_by_deep_verify() {
        let (d, hash) = make_repo(b"original content");
        // 정상 압축본이지만 내용이 다른 데이터로 바꿔치기 (해시 불일치)
        let evil = compressor::compress(b"tampered content", 3).unwrap();
        fs::write(
            d.path()
                .join("blobs")
                .join(&hash[..2])
                .join(format!("{}.blob", hash)),
            evil,
        )
        .unwrap();
        assert!(verify_repo(d.path(), false).unwrap().ok());
        let r = verify_repo(d.path(), true).unwrap();
        assert!(
            matches!(r.problems[0], Problem::CorruptBlob { .. }),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn garbage_blob_is_caught() {
        let (d, hash) = make_repo(b"original content");
        fs::write(
            d.path()
                .join("blobs")
                .join(&hash[..2])
                .join(format!("{}.blob", hash)),
            b"not zstd",
        )
        .unwrap();
        let r = verify_repo(d.path(), true).unwrap();
        assert!(matches!(r.problems[0], Problem::CorruptBlob { .. }));
    }

    /// 청크 정보 없는 구형 항목은 blob_id/sha256 블롭을 검사한다(없으면 MissingBlob, SHA-256 해시도 인정).
    #[test]
    fn legacy_blob_id_and_sha256_entries_are_checked() {
        use sha2::Digest;
        let d = tempfile::tempdir().unwrap();
        let cas = CasStorage::new(d.path()).unwrap();
        let data = b"legacy whole-file blob";
        let sha: String = sha2::Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        cas.save_blob(&sha, &compressor::compress(data, 3).unwrap())
            .unwrap();
        let missing = "e".repeat(64);
        fs::write(
            d.path().join("snapshots").join("old.json"),
            format!(
                r#"{{"id":"old","files":[{{"path":"a","size":{},"sha256":"{sha}"}},{{"path":"b","size":5,"blob_id":"{missing}"}}]}}"#,
                data.len()
            ),
        )
        .unwrap();
        let r = verify_repo(d.path(), true).unwrap();
        assert_eq!(r.problems.len(), 1, "{:?}", r.problems);
        assert!(
            matches!(&r.problems[0], Problem::MissingBlob { hash, .. } if *hash == missing),
            "{:?}",
            r.problems
        );
    }

    /// 있다고 나오는 블롭을 읽지 못하면(IO 오류) 깊은 검사에서 손상으로 보고한다.
    #[test]
    fn unreadable_blob_is_reported_as_corrupt() {
        let (d, hash) = make_repo(b"data");
        let p = d
            .path()
            .join("blobs")
            .join(&hash[..2])
            .join(format!("{}.blob", hash));
        fs::remove_file(&p).unwrap();
        fs::create_dir_all(&p).unwrap(); // 파일 자리에 폴더 → 열기 실패
        let r = verify_repo(d.path(), true).unwrap();
        assert!(
            r.problems.iter().any(
                |x| matches!(x, Problem::CorruptBlob { reason, .. } if reason.contains("읽기 실패"))
            ),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn broken_manifest_is_reported() {
        let (d, _) = make_repo(b"data");
        fs::write(d.path().join("snapshots").join("bad.json"), "{{{").unwrap();
        let r = verify_repo(d.path(), false).unwrap();
        assert!(r
            .problems
            .iter()
            .any(|p| matches!(p, Problem::BadManifest { .. })));
    }
}

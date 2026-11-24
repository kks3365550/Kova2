//! `.qblk` 블록 단위 증분 이미지 & 체인 복원.
//! - 커널 드라이버 없이 사이드카 블록 해시 맵(`.qmap.json`)과 체인 메타(`.qchain.json`)로 증분 캡처·복원을 구현한다.
//! - 개별 증분 파일도 표준 `QBLKSTRM` v1 포맷을 유지하므로 기존 검증기와 100% 호환된다.
use crate::bitmap::{allocated_runs, RunParams};
use crate::qblk::{restore_to, verify, Header, QblkError, Stats, Writer};
use crate::restore::{check_target, RestoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const DEFAULT_BLOCK_CLUSTERS: u64 = 256; // 4KiB 클러스터 기준 1MiB 단위
pub const MAX_CHAIN_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockEntry {
    pub count: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockMap {
    pub version: u32,
    pub cluster_size: u32,
    pub total_clusters: u64,
    pub block_clusters: u64,
    /// 블록 시작 LCN -> (클러스터 수, SHA-256 해시)
    pub hashes: BTreeMap<u64, BlockEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainMeta {
    pub version: u32,
    /// 같은 폴더 내 부모 `.qblk` 파일명
    pub parent: String,
    pub changed_clusters: u64,
    pub skipped_clusters: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IncrementalStats {
    pub changed_clusters: u64,
    pub skipped_clusters: u64,
    pub chunks_written: u64,
}

pub fn map_path_for(image: &Path) -> PathBuf {
    PathBuf::from(format!("{}.qmap.json", image.display()))
}

pub fn chain_path_for(image: &Path) -> PathBuf {
    PathBuf::from(format!("{}.qchain.json", image.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), QblkError> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = PathBuf::from(format!(
        "{}.{}.{}.tmp",
        path.display(),
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| -> std::io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(QblkError::from)
}

pub fn save_block_map(image: &Path, map: &BlockMap) -> Result<(), QblkError> {
    let json = serde_json::to_string_pretty(map)
        .map_err(|e| QblkError::Io(std::io::Error::other(e.to_string())))?;
    write_atomic(&map_path_for(image), json.as_bytes())
}

pub fn load_block_map(image: &Path) -> Result<BlockMap, QblkError> {
    let raw = fs::read_to_string(map_path_for(image))?;
    serde_json::from_str(&raw).map_err(|e| QblkError::Io(std::io::Error::other(e.to_string())))
}

pub fn save_chain_meta(image: &Path, meta: &ChainMeta) -> Result<(), QblkError> {
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| QblkError::Io(std::io::Error::other(e.to_string())))?;
    write_atomic(&chain_path_for(image), json.as_bytes())
}

pub fn load_chain_meta(image: &Path) -> Result<Option<ChainMeta>, QblkError> {
    let p = chain_path_for(image);
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(p)?;
    let meta = serde_json::from_str(&raw)
        .map_err(|e| QblkError::Io(std::io::Error::other(e.to_string())))?;
    Ok(Some(meta))
}

/// `base_map`이 None이면 전체 풀 이미지를 쓰고 블록 해시 맵을 만든다.
/// `base_map`이 Some이면 해시가 달라진 블록만 `.qblk`에 기록(증분)하고 갱신된 블록 맵을 돌려준다.
#[allow(clippy::too_many_arguments)]
pub fn write_incremental_image<R: Read + Seek, W: Write + Seek>(
    src: &mut R,
    out: W,
    header: &mut Header,
    bitmap: &[u8],
    base_map: Option<&BlockMap>,
    level: i32,
    cancel: &AtomicBool,
    progress: &dyn Fn(&Stats),
) -> Result<(Stats, IncrementalStats, BlockMap, W), QblkError> {
    let cs = header.cluster_size as u64;
    let total = header.total_clusters;
    if cs == 0 || !header.cluster_size.is_power_of_two() || cs > crate::qblk::MAX_CHUNK_BYTES {
        return Err(QblkError::BadHeaderField("cluster_size"));
    }
    let block_clusters = base_map
        .map(|m| m.block_clusters)
        .unwrap_or(DEFAULT_BLOCK_CLUSTERS)
        .max(1);
    let max_chunk_bytes = block_clusters
        .checked_mul(cs)
        .filter(|&n| n <= crate::qblk::MAX_CHUNK_BYTES)
        .ok_or(QblkError::BadHeaderField("block_clusters"))?;

    // 블록 단위로 분할된 할당 런 목록
    let runs = allocated_runs(
        bitmap,
        RunParams {
            cluster_size: cs,
            max_chunk_bytes,
            max_coalesce_gap_bytes: 0,
            ..RunParams::default()
        },
    );

    let mut w = Writer::new(BufWriter::new(out), header, level)?;
    let mut st = Stats {
        total_raw_bytes: runs
            .iter()
            .filter(|(lcn, _)| *lcn < total)
            .map(|(lcn, count)| (*count).min(total - *lcn) * cs)
            .sum(),
        ..Stats::default()
    };
    let mut inc = IncrementalStats::default();
    let mut new_hashes = BTreeMap::new();
    let mut buf = Vec::new();

    for (lcn, count) in runs {
        if cancel.load(Ordering::Relaxed) {
            return Err(QblkError::Cancelled);
        }
        if lcn >= total {
            continue;
        }
        let count = count.min(total - lcn);
        let byte_off = lcn
            .checked_mul(cs)
            .ok_or(QblkError::BadHeaderField("lcn overflow"))?;
        let byte_len = count
            .checked_mul(cs)
            .ok_or(QblkError::BadHeaderField("chunk length"))?;
        buf.resize(byte_len as usize, 0);
        src.seek(SeekFrom::Start(byte_off))?;
        src.read_exact(&mut buf)?;
        let hash = format!("{:x}", Sha256::digest(&buf));

        let unchanged = base_map
            .and_then(|m| {
                if m.version == 2
                    && m.cluster_size == header.cluster_size
                    && m.total_clusters == total
                {
                    m.hashes.get(&lcn)
                } else {
                    None
                }
            })
            .is_some_and(|prev| prev.count == count && prev.hash == hash);

        new_hashes.insert(lcn, BlockEntry { count, hash });

        if unchanged {
            inc.skipped_clusters += count;
        } else {
            w.write_chunk(lcn, &buf)?;
            inc.changed_clusters += count;
            inc.chunks_written += 1;
            st.chunks += 1;
            st.clusters += count;
            st.raw_bytes += byte_len;
        }
        progress(&st);
    }

    header.used_clusters = w.clusters_written();
    let bw = w.finish()?;
    let mut f = bw.into_inner().map_err(|e| e.into_error())?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&header.to_bytes())?;
    f.flush()?;

    let new_map = BlockMap {
        version: 2,
        cluster_size: header.cluster_size,
        total_clusters: total,
        block_clusters,
        hashes: new_hashes,
    };
    Ok((st, inc, new_map, f))
}

/// `.qchain.json`을 거슬러 올라가 `[base.qblk, inc1.qblk, ..., target.qblk]` 복원 순서를 반환한다.
pub fn resolve_chain(image: &Path) -> Result<Vec<PathBuf>, QblkError> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut cur = image.to_path_buf();
    loop {
        if chain.len() >= MAX_CHAIN_DEPTH {
            return Err(QblkError::Io(std::io::Error::other(
                "증분 체인 깊이가 상한(64)을 초과했습니다",
            )));
        }
        if !cur.is_file() {
            return Err(QblkError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("체인 이미지 파일이 없습니다: {}", cur.display()),
            )));
        }
        let canon = fs::canonicalize(&cur).unwrap_or_else(|_| cur.clone());
        if !visited.insert(canon) {
            return Err(QblkError::Io(std::io::Error::other(
                "증분 체인에 순환 참조가 있습니다",
            )));
        }
        chain.push(cur.clone());
        let Some(meta) = load_chain_meta(&cur)? else {
            break;
        };
        let comps: Vec<Component<'_>> = Path::new(&meta.parent).components().collect();
        if meta.parent.is_empty()
            || meta.parent.contains(['/', '\\', ':'])
            || !matches!(comps.as_slice(), [Component::Normal(_)])
        {
            return Err(QblkError::Io(std::io::Error::other(format!(
                "잘못된 부모 이미지 이름: {}",
                meta.parent
            ))));
        }
        let parent_dir = cur.parent().unwrap_or_else(|| Path::new("."));
        cur = parent_dir.join(meta.parent);
    }
    chain.reverse();
    Ok(chain)
}

/// 체인의 모든 `.qblk` 파일이 손상되지 않았는지 순서대로 검증한다.
pub fn verify_chain(
    image: &Path,
    cancel: &AtomicBool,
    progress: &dyn Fn(&Stats),
) -> Result<Vec<(PathBuf, Header, Stats)>, QblkError> {
    let chain = resolve_chain(image)?;
    let mut results = Vec::with_capacity(chain.len());
    for p in chain {
        let src = BufReader::with_capacity(8 << 20, File::open(&p)?);
        let (h, s) = verify(src, cancel, progress)?;
        results.push((p, h, s));
    }
    Ok(results)
}

/// 풀+증분 체인을 `base`부터 최신까지 순서대로 새 파일(`target`)에 복원한다.
pub fn restore_chain_to_file(
    image: &Path,
    target: &Path,
    cancel: &AtomicBool,
    progress: &dyn Fn(&Stats),
) -> Result<(Header, Stats), RestoreError> {
    check_target(target)?;
    let chain = resolve_chain(image)?;
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let res = (|| -> Result<(Header, Stats), RestoreError> {
        crate::restore::mark_sparse(&f);
        let mut out = BufWriter::with_capacity(8 << 20, f);
        let mut first_geom: Option<(u32, u64)> = None;
        let mut last_header = None;
        let mut total_stats = Stats::default();
        for p in &chain {
            let src = BufReader::with_capacity(8 << 20, File::open(p)?);
            let (h, s) = restore_to(src, &mut out, cancel, progress)?;
            if let Some((cs, tc)) = first_geom {
                if h.cluster_size != cs || h.total_clusters != tc {
                    return Err(QblkError::BadHeaderField("chain geometry mismatch").into());
                }
            } else {
                first_geom = Some((h.cluster_size, h.total_clusters));
            }
            total_stats.chunks += s.chunks;
            total_stats.clusters += s.clusters;
            total_stats.raw_bytes += s.raw_bytes;
            total_stats.compressed_bytes += s.compressed_bytes;
            last_header = Some(h);
        }
        out.flush()?;
        let h = last_header.ok_or(QblkError::BadHeaderField("empty chain"))?;
        let mut full = h
            .total_clusters
            .checked_mul(h.cluster_size as u64)
            .ok_or(QblkError::BadHeaderField("volume size overflow"))?;
        let f = out.into_inner().map_err(|e| e.into_error())?;
        if let Some(n) = crate::restore::ntfs_volume_len(target) {
            full = full.max(n);
        }
        if f.metadata()?.len() < full {
            f.set_len(full)?;
        }
        f.sync_all()?;
        Ok((h, total_stats))
    })();
    if res.is_err() {
        let _ = fs::remove_file(target);
    }
    res
}

/// `images_dir` 안에서 `<DRIVE>_*.qblk` 패턴에 맞는 가장 최신 이미지를 찾는다.
/// 유효한 `.qmap.json`(v2)이 존재하고 현재 체인 길이가 `max_chain_depth` 미만인 후보만 반환한다.
pub fn find_latest_base_image(
    images_dir: &Path,
    drive: char,
    max_chain_depth: usize,
) -> Option<PathBuf> {
    if !drive.is_ascii_alphabetic() || max_chain_depth == 0 {
        return None;
    }
    let prefix = format!("{}_", drive.to_ascii_uppercase());
    let entries = fs::read_dir(images_dir).ok()?;
    let mut candidates: Vec<(std::time::SystemTime, String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_qblk = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("qblk"));
        if !is_qblk {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let prefix_ok = name
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|b| b.eq_ignore_ascii_case(prefix.as_bytes()));
        if !prefix_ok {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        candidates.push((modified, name.to_string(), path));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, _, path) in candidates {
        let map_ok = load_block_map(&path)
            .is_ok_and(|m| m.version == 2 && m.cluster_size > 0 && m.total_clusters > 0);
        if !map_ok {
            continue;
        }
        let chain_ok = resolve_chain(&path).is_ok_and(|chain| chain.len() < max_chain_depth);
        if chain_ok {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn incremental_chain_captures_only_changed_blocks_and_restores_exact_bytes() {
        let d = tempfile::tempdir().unwrap();
        let cs = 4096usize;
        let total_clusters = 8u64;
        // 클러스터 0..8 모두 할당됨
        let bitmap = [0xFFu8];
        let mut disk = vec![0u8; cs * total_clusters as usize];
        for i in 0..8 {
            disk[i * cs..(i + 1) * cs].fill((i as u8) + 1);
        }
        let no = AtomicBool::new(false);

        // 1) Base 풀 이미지 (블록 단위 = 2클러스터씩)
        let base_path = d.path().join("base.qblk");
        let mut h1 = Header {
            version: 1,
            cluster_size: cs as u32,
            total_clusters,
            used_clusters: 0,
            vsn: "AABB-CCDD".into(),
            source_label: "DATA".into(),
        };
        {
            let f = File::create(&base_path).unwrap();
            let (_, inc1, mut map1, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h1,
                &bitmap,
                None,
                3,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc1.changed_clusters, 8);
            assert_eq!(inc1.skipped_clusters, 0);
            map1.block_clusters = 2;
            save_block_map(&base_path, &map1).unwrap();
        }

        // 2) 블록 단위(2클러스터)로 다시 base를 생성해 정확한 증분 비교 테스트
        let base2_path = d.path().join("base2.qblk");
        let base2_map = {
            let f = File::create(&base2_path).unwrap();
            let dummy = BlockMap {
                version: 2,
                cluster_size: cs as u32,
                total_clusters,
                block_clusters: 2,
                hashes: BTreeMap::new(),
            };
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h1.clone(),
                &bitmap,
                Some(&dummy),
                3,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 8);
            save_block_map(&base2_path, &map).unwrap();
            map
        };

        // 3) 클러스터 4..6 (1개 블록=2클러스터)만 수정 후 1차 증분
        disk[4 * cs..6 * cs].fill(0xEE);
        let inc1_path = d.path().join("inc1.qblk");
        let inc1_map = {
            let f = File::create(&inc1_path).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h1.clone(),
                &bitmap,
                Some(&base2_map),
                3,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 2);
            assert_eq!(inc.skipped_clusters, 6);
            save_block_map(&inc1_path, &map).unwrap();
            save_chain_meta(
                &inc1_path,
                &ChainMeta {
                    version: 1,
                    parent: "base2.qblk".into(),
                    changed_clusters: inc.changed_clusters,
                    skipped_clusters: inc.skipped_clusters,
                },
            )
            .unwrap();
            map
        };

        // 4) 클러스터 0..2 수정 후 2차 증분
        disk[0..2 * cs].fill(0xAA);
        let inc2_path = d.path().join("inc2.qblk");
        {
            let f = File::create(&inc2_path).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h1.clone(),
                &bitmap,
                Some(&inc1_map),
                3,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 2);
            assert_eq!(inc.skipped_clusters, 6);
            save_block_map(&inc2_path, &map).unwrap();
            save_chain_meta(
                &inc2_path,
                &ChainMeta {
                    version: 1,
                    parent: "inc1.qblk".into(),
                    changed_clusters: inc.changed_clusters,
                    skipped_clusters: inc.skipped_clusters,
                },
            )
            .unwrap();
        }

        // 체인 검증 & 복원 → 최신 disk 바이트와 100% 일치
        let verified = verify_chain(&inc2_path, &no, &|_| {}).unwrap();
        assert_eq!(verified.len(), 3);
        let out_raw = d.path().join("restored.img");
        restore_chain_to_file(&inc2_path, &out_raw, &no, &|_| {}).unwrap();
        assert_eq!(fs::read(&out_raw).unwrap(), disk);
    }

    #[test]
    fn resolve_chain_rejects_missing_parent_and_cycles() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a.qblk");
        let b = d.path().join("b.qblk");
        fs::write(&a, b"x").unwrap();
        fs::write(&b, b"y").unwrap();
        // 누락 부모
        save_chain_meta(
            &a,
            &ChainMeta {
                version: 1,
                parent: "missing.qblk".into(),
                changed_clusters: 0,
                skipped_clusters: 0,
            },
        )
        .unwrap();
        assert!(resolve_chain(&a).is_err());

        // 순환 참조 a -> b -> a
        save_chain_meta(
            &a,
            &ChainMeta {
                version: 1,
                parent: "b.qblk".into(),
                changed_clusters: 0,
                skipped_clusters: 0,
            },
        )
        .unwrap();
        save_chain_meta(
            &b,
            &ChainMeta {
                version: 1,
                parent: "a.qblk".into(),
                changed_clusters: 0,
                skipped_clusters: 0,
            },
        )
        .unwrap();
        assert!(resolve_chain(&a).is_err());
    }

    #[test]
    fn expanded_run_at_same_lcn_is_not_skipped() {
        let d = tempfile::tempdir().unwrap();
        let cs = 4096usize;
        let total_clusters = 8u64;
        let mut disk = vec![0u8; cs * total_clusters as usize];
        disk[0..cs].fill(0x11);
        disk[cs..2 * cs].fill(0x22);
        let no = AtomicBool::new(false);
        let h = Header {
            version: 1,
            cluster_size: cs as u32,
            total_clusters,
            used_clusters: 0,
            vsn: "AABB-CCDD".into(),
            source_label: "DATA".into(),
        };

        // 1) Base: LCN 0에 1클러스터만 할당 (bitmap = 0b0000_0001)
        let base_path = d.path().join("base.qblk");
        let base_map = {
            let f = File::create(&base_path).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h.clone(),
                &[0b0000_0001],
                None,
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 1);
            assert_eq!(map.version, 2);
            assert_eq!(map.hashes.get(&0).map(|e| e.count), Some(1));
            map
        };

        // 2) 해시가 우연히 같더라도 count가 다르면 절대로 건너뛰지 않아야 한다
        let expanded_hash = format!("{:x}", Sha256::digest(&disk[0..2 * cs]));
        let mut collided_map = base_map.clone();
        collided_map.hashes.insert(
            0,
            BlockEntry {
                count: 1,
                hash: expanded_hash,
            },
        );
        let inc_path = d.path().join("inc.qblk");
        {
            let f = File::create(&inc_path).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&disk),
                f,
                &mut h.clone(),
                &[0b0000_0011],
                Some(&collided_map),
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 2);
            assert_eq!(inc.skipped_clusters, 0);
            assert_eq!(map.hashes.get(&0).map(|e| e.count), Some(2));
        }

        // 3) 실제 확장 런 복원 검증
        save_chain_meta(
            &inc_path,
            &ChainMeta {
                version: 1,
                parent: "base.qblk".into(),
                changed_clusters: 2,
                skipped_clusters: 0,
            },
        )
        .unwrap();
        let out_raw = d.path().join("expanded.img");
        restore_chain_to_file(&inc_path, &out_raw, &no, &|_| {}).unwrap();
        assert_eq!(fs::read(&out_raw).unwrap(), disk);
    }

    #[test]
    fn resolve_chain_rejects_drive_relative_and_ads_parent() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a.qblk");
        fs::write(&a, b"x").unwrap();
        for bad in [
            "C:evil.qblk",
            "foo.qblk:stream",
            "../evil.qblk",
            "sub/b.qblk",
            ".",
        ] {
            save_chain_meta(
                &a,
                &ChainMeta {
                    version: 1,
                    parent: bad.into(),
                    changed_clusters: 0,
                    skipped_clusters: 0,
                },
            )
            .unwrap();
            assert!(resolve_chain(&a).is_err(), "should reject parent {bad:?}");
        }
    }

    #[test]
    fn restore_chain_rejects_mismatched_header_geometry() {
        let d = tempfile::tempdir().unwrap();
        let no = AtomicBool::new(false);
        let base_path = d.path().join("base.qblk");
        let inc_path = d.path().join("inc.qblk");

        let mut h1 = Header {
            version: 1,
            cluster_size: 4096,
            total_clusters: 8,
            used_clusters: 0,
            vsn: "1111".into(),
            source_label: "A".into(),
        };
        write_incremental_image(
            &mut Cursor::new(vec![1u8; 4096 * 8]),
            File::create(&base_path).unwrap(),
            &mut h1,
            &[0x01],
            None,
            1,
            &no,
            &|_| {},
        )
        .unwrap();

        let mut h2 = Header {
            version: 1,
            cluster_size: 4096,
            total_clusters: 16, // total_clusters 불일치
            used_clusters: 0,
            vsn: "1111".into(),
            source_label: "A".into(),
        };
        write_incremental_image(
            &mut Cursor::new(vec![2u8; 4096 * 16]),
            File::create(&inc_path).unwrap(),
            &mut h2,
            &[0x01],
            None,
            1,
            &no,
            &|_| {},
        )
        .unwrap();
        save_chain_meta(
            &inc_path,
            &ChainMeta {
                version: 1,
                parent: "base.qblk".into(),
                changed_clusters: 1,
                skipped_clusters: 0,
            },
        )
        .unwrap();

        let target = d.path().join("mismatch.img");
        assert!(restore_chain_to_file(&inc_path, &target, &no, &|_| {}).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn find_latest_base_image_filters_drive_map_and_chain_depth() {
        let d = tempfile::tempdir().unwrap();
        let make_map = || BlockMap {
            version: 2,
            cluster_size: 4096,
            total_clusters: 8,
            block_clusters: 256,
            hashes: BTreeMap::new(),
        };
        // 다른 드라이브(D_)와 한국어 파일명, 맵 없는 C_ 이미지는 무시되어야 한다
        fs::write(d.path().join("D_20261124_01.qblk"), b"x").unwrap();
        save_block_map(&d.path().join("D_20261124_01.qblk"), &make_map()).unwrap();
        fs::write(d.path().join("한글.qblk"), b"x").unwrap();
        let c_nomap = d.path().join("C_20261124_99.qblk");
        fs::write(&c_nomap, b"x").unwrap();

        // 유효한 base(깊이 1)와 inc(깊이 2)
        let c_base = d.path().join("C_20261124_01.qblk");
        fs::write(&c_base, b"x").unwrap();
        save_block_map(&c_base, &make_map()).unwrap();

        let c_inc = d.path().join("C_20261124_02.qblk");
        fs::write(&c_inc, b"x").unwrap();
        save_block_map(&c_inc, &make_map()).unwrap();
        save_chain_meta(
            &c_inc,
            &ChainMeta {
                version: 1,
                parent: "C_20261124_01.qblk".into(),
                changed_clusters: 1,
                skipped_clusters: 7,
            },
        )
        .unwrap();

        // max_chain_depth = 14 → 최신 c_inc(깊이 2) 선택
        assert_eq!(
            find_latest_base_image(d.path(), 'c', 14),
            Some(c_inc.clone())
        );
        // max_chain_depth = 2 → c_inc(깊이 2)은 제외되고 c_base(깊이 1) 선택
        assert_eq!(find_latest_base_image(d.path(), 'C', 2), Some(c_base));
        // max_chain_depth = 1 → 모두 깊이 >= 1 이므로 None
        assert_eq!(find_latest_base_image(d.path(), 'C', 1), None);
    }
}

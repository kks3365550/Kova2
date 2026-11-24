//! 순수 Rust 읽기 전용 NTFS 파일 브라우저 & 추출기(`.qblk` 및 증분 `.qblk` 체인 직접 탐색).
//! VHD 마운트나 WinFsp/Dokan 드라이버 없이 `.qblk` 이미지 안에서 디렉터리 조회·검색·개별 파일 추출을 수행한다.
use crate::qblk::{Header, QblkError, CHUNK_HEADER_SIZE, HEADER_SIZE, MAX_CHUNK_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CHUNK_CACHE_CAP: usize = 4;
const MAX_MFT_RECORDS: u64 = 2_000_000;
const MAX_DATA_RUNS: usize = 1_000_000;
const MAX_PATH_DEPTH: usize = 128;
const NTFS_FIXUP_STRIDE: usize = 512;
const MFT_ROOT_ID: u64 = 5;

const ATTR_STANDARD_INFO: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

const MFT_FLAG_IN_USE: u16 = 0x0001;
const MFT_FLAG_DIRECTORY: u16 = 0x0002;

const DATA_FLAG_COMPRESSED: u16 = 0x0001;
const DATA_FLAG_ENCRYPTED: u16 = 0x4000;

const FILETIME_UNIX_EPOCH_SECS: u64 = 11_644_473_600;

#[derive(Debug, Clone, Copy)]
struct ChunkSpan {
    start_lcn: u64,
    count: u64,
    /// 원본 청크의 시작 LCN(압축 해제된 청크 버퍼 내 오프셋 계산용)
    chunk_base_lcn: u64,
    link_idx: usize,
    /// 압축 페이로드의 파일 내 시작 오프셋(24바이트 청크 헤더 직후)
    data_offset: u64,
    comp_len: u32,
    uncomp_len: u32,
    crc: u32,
}

struct CacheEntry {
    key: (usize, u64),
    raw: Vec<u8>,
}

/// `.qblk` 단일 이미지 또는 증분 체인 위에서 논리 볼륨 바이트(`0..total_clusters * cluster_size`)를
/// 임의 접근(`Read + Seek`)하는 희소 볼륨 리더. 미할당 클러스터는 0으로 읽는다.
pub struct QblkVolumeReader {
    header: Header,
    volume_len: u64,
    files: Vec<File>,
    spans: Vec<ChunkSpan>,
    cache: Vec<CacheEntry>,
    pos: u64,
}

fn insert_span(map: &mut BTreeMap<u64, ChunkSpan>, span: ChunkSpan) {
    let new_start = span.start_lcn;
    let new_end = span.start_lcn.saturating_add(span.count);

    // 1) new_start 이전에 시작해 new_start를 넘어 겹치는 기존 구간 분할
    let prev_overlap = map.range(..new_start).next_back().and_then(|(&k, s)| {
        let prev_end = s.start_lcn.saturating_add(s.count);
        (prev_end > new_start).then_some((k, *s, prev_end))
    });
    if let Some((k, prev, prev_end)) = prev_overlap {
        if let Some(entry) = map.get_mut(&k) {
            entry.count = new_start - prev.start_lcn;
        }
        if prev_end > new_end {
            let mut right = prev;
            right.start_lcn = new_end;
            right.count = prev_end - new_end;
            map.insert(new_end, right);
        }
    }

    // 2) new_start..new_end 구간 안에 시작점이 들어오는 기존 구간 정리
    let covered_keys: Vec<u64> = map.range(new_start..new_end).map(|(&k, _)| k).collect();
    for k in covered_keys {
        if let Some(old) = map.remove(&k) {
            let old_end = old.start_lcn.saturating_add(old.count);
            if old_end > new_end {
                let mut right = old;
                right.start_lcn = new_end;
                right.count = old_end - new_end;
                map.insert(new_end, right);
            }
        }
    }

    // 3) 새 구간 삽입
    map.insert(new_start, span);
}

impl QblkVolumeReader {
    /// 단일 `.qblk` 또는 `.qchain.json`이 연결된 증분 체인을 열어 희소 LCN 인덱스를 구축한다.
    pub fn open(image: &Path) -> Result<Self, QblkError> {
        let chain = crate::incremental::resolve_chain(image)?;
        if chain.is_empty() {
            return Err(QblkError::BadHeaderField("empty chain"));
        }
        let mut files = Vec::with_capacity(chain.len());
        let mut span_map: BTreeMap<u64, ChunkSpan> = BTreeMap::new();
        let mut final_header: Option<Header> = None;

        for (link_idx, link_path) in chain.iter().enumerate() {
            let mut f = File::open(link_path)?;
            let file_len = f.metadata()?.len();
            if file_len < HEADER_SIZE as u64 {
                return Err(QblkError::TruncatedChunkHeader {
                    offset: 0,
                    got: file_len as usize,
                });
            }
            let mut hb = [0u8; HEADER_SIZE];
            f.read_exact(&mut hb)?;
            let h = Header::parse(&hb)?;
            if let Some(ref prev) = final_header {
                if h.cluster_size != prev.cluster_size || h.total_clusters != prev.total_clusters {
                    return Err(QblkError::BadHeaderField("chain geometry mismatch"));
                }
            }
            let cs = h.cluster_size as u64;
            let mut pos = HEADER_SIZE as u64;
            let mut ch = [0u8; CHUNK_HEADER_SIZE];
            while pos < file_len {
                let rem = file_len - pos;
                if rem < CHUNK_HEADER_SIZE as u64 {
                    return Err(QblkError::TruncatedChunkHeader {
                        offset: pos,
                        got: rem as usize,
                    });
                }
                f.read_exact(&mut ch)?;
                let lcn = u64::from_le_bytes(ch[0..8].try_into().unwrap());
                let cluster_count = u32::from_le_bytes(ch[8..12].try_into().unwrap());
                let uncomp = u32::from_le_bytes(ch[12..16].try_into().unwrap());
                let comp = u32::from_le_bytes(ch[16..20].try_into().unwrap());
                let crc = u32::from_le_bytes(ch[20..24].try_into().unwrap());
                if uncomp as u64 > MAX_CHUNK_BYTES || comp as u64 > MAX_CHUNK_BYTES + 1024 * 1024 {
                    return Err(QblkError::ChunkTooLarge {
                        offset: pos,
                        size: uncomp.max(comp) as u64,
                    });
                }
                if uncomp != 0 && cluster_count as u64 * cs != uncomp as u64 {
                    return Err(QblkError::ChunkSizeMismatch {
                        offset: pos,
                        cluster_count,
                        uncompressed: uncomp,
                        cluster_size: h.cluster_size,
                    });
                }
                if uncomp != 0
                    && lcn
                        .checked_add(cluster_count as u64)
                        .is_none_or(|e| e > h.total_clusters)
                {
                    return Err(QblkError::OutOfRange {
                        lcn,
                        cluster_count,
                        total_clusters: h.total_clusters,
                    });
                }
                let data_offset = pos + CHUNK_HEADER_SIZE as u64;
                let next_pos = data_offset
                    .checked_add(comp as u64)
                    .filter(|&e| e <= file_len)
                    .ok_or_else(|| QblkError::TruncatedChunkData {
                        offset: pos,
                        want: comp as u64,
                        got: file_len.saturating_sub(data_offset),
                    })?;
                if uncomp != 0 && cluster_count > 0 {
                    insert_span(
                        &mut span_map,
                        ChunkSpan {
                            start_lcn: lcn,
                            count: cluster_count as u64,
                            chunk_base_lcn: lcn,
                            link_idx,
                            data_offset,
                            comp_len: comp,
                            uncomp_len: uncomp,
                            crc,
                        },
                    );
                }
                f.seek(SeekFrom::Start(next_pos))?;
                pos = next_pos;
            }
            files.push(f);
            final_header = Some(h);
        }

        let header = final_header.ok_or(QblkError::BadHeaderField("empty chain"))?;
        let volume_len = header
            .total_clusters
            .checked_mul(header.cluster_size as u64)
            .ok_or(QblkError::BadHeaderField("volume size overflow"))?;
        let spans: Vec<ChunkSpan> = span_map.into_values().collect();
        Ok(Self {
            header,
            volume_len,
            files,
            spans,
            cache: Vec::with_capacity(CHUNK_CACHE_CAP),
            pos: 0,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn volume_len(&self) -> u64 {
        self.volume_len
    }

    pub fn cluster_size(&self) -> u32 {
        self.header.cluster_size
    }

    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), QblkError> {
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(buf)?;
        Ok(())
    }

    fn load_chunk(&mut self, span: ChunkSpan) -> io::Result<&[u8]> {
        let key = (span.link_idx, span.data_offset);
        if let Some(pos) = self.cache.iter().position(|e| e.key == key) {
            if pos + 1 < self.cache.len() {
                let item = self.cache.remove(pos);
                self.cache.push(item);
            }
            return Ok(&self.cache.last().unwrap().raw);
        }
        let f = &mut self.files[span.link_idx];
        f.seek(SeekFrom::Start(span.data_offset))?;
        let mut comp = vec![0u8; span.comp_len as usize];
        f.read_exact(&mut comp)?;
        let raw = zstd::bulk::decompress(&comp, span.uncomp_len as usize).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("청크 압축 해제 실패(오프셋 {}): {e}", span.data_offset),
            )
        })?;
        if raw.len() != span.uncomp_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "압축 해제 길이 불일치({} != {})",
                    raw.len(),
                    span.uncomp_len
                ),
            ));
        }
        if crc32fast::hash(&raw) != span.crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("청크 CRC32 불일치(LCN {})", span.chunk_base_lcn),
            ));
        }
        if self.cache.len() >= CHUNK_CACHE_CAP {
            self.cache.remove(0);
        }
        self.cache.push(CacheEntry { key, raw });
        Ok(&self.cache.last().unwrap().raw)
    }
}

impl Seek for QblkVolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
            SeekFrom::End(d) => self.volume_len as i128 + d as i128,
        };
        if next < 0 || next > u64::MAX as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "볼륨 탐색 위치가 범위를 벗어남",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

impl Read for QblkVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.volume_len {
            return Ok(0);
        }
        let cs = self.header.cluster_size as u64;
        let remaining = self.volume_len - self.pos;
        let to_read = buf.len().min(remaining as usize);
        let lcn = self.pos / cs;
        let in_cluster = (self.pos % cs) as usize;

        let idx = self.spans.partition_point(|s| s.start_lcn <= lcn);
        if idx > 0 {
            let span = self.spans[idx - 1];
            let span_end_lcn = span.start_lcn.saturating_add(span.count);
            if lcn < span_end_lcn {
                let span_end_byte = span_end_lcn.saturating_mul(cs).min(self.volume_len);
                let avail = (span_end_byte - self.pos) as usize;
                let take = to_read.min(avail);
                let chunk_off = ((lcn - span.chunk_base_lcn) * cs) as usize + in_cluster;
                let raw = self.load_chunk(span)?;
                if chunk_off + take > raw.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "청크 데이터 경계 초과",
                    ));
                }
                buf[..take].copy_from_slice(&raw[chunk_off..chunk_off + take]);
                self.pos += take as u64;
                return Ok(take);
            }
        }

        // 미할당 클러스터 구간 → 0 바이트 반환
        let next_span_byte = self
            .spans
            .get(idx)
            .map_or(self.volume_len, |s| s.start_lcn.saturating_mul(cs))
            .min(self.volume_len);
        let avail = (next_span_byte - self.pos) as usize;
        let take = to_read.min(avail);
        buf[..take].fill(0);
        self.pos += take as u64;
        Ok(take)
    }
}

/// `.qblk` 이미지 안의 NTFS 파일/폴더 항목.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageFileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mft_id: u64,
    /// `$STANDARD_INFORMATION` 수정 시각(Unix 초, 없으면 None)
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone)]
struct NtfsBoot {
    cluster_size: u64,
    mft_cluster: u64,
    mft_record_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataRun {
    /// `None`이면 NTFS 희소(0) 런
    lcn: Option<u64>,
    cluster_count: u64,
}

#[derive(Debug, Clone)]
enum DataSource {
    Empty,
    Resident(Vec<u8>),
    NonResident {
        runs: Vec<DataRun>,
        real_size: u64,
        init_size: u64,
        flags: u16,
    },
}

struct RawMftEntry {
    mft_id: u64,
    parent_id: u64,
    name: String,
    is_dir: bool,
    mtime: Option<i64>,
    data: DataSource,
}

fn bad_ntfs(msg: impl Into<String>) -> QblkError {
    QblkError::Io(io::Error::new(io::ErrorKind::InvalidData, msg.into()))
}

fn parse_boot_sector(b: &[u8; 512]) -> Result<NtfsBoot, QblkError> {
    if &b[3..11] != b"NTFS    " {
        return Err(bad_ntfs("NTFS 부트 섹터가 아닙니다(OEM 불일치)"));
    }
    let bytes_per_sector = u16::from_le_bytes([b[11], b[12]]) as u64;
    if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        return Err(bad_ntfs("NTFS bytes_per_sector 값이 올바르지 않음"));
    }
    let spc_raw = b[13];
    let sectors_per_cluster = if spc_raw == 0 {
        return Err(bad_ntfs("NTFS sectors_per_cluster가 0임"));
    } else if spc_raw <= 128 {
        if !spc_raw.is_power_of_two() {
            return Err(bad_ntfs("NTFS sectors_per_cluster가 2의 거듭제곱이 아님"));
        }
        spc_raw as u64
    } else {
        let shift = 256u32 - spc_raw as u32;
        if shift > 20 {
            return Err(bad_ntfs("NTFS sectors_per_cluster 범위 초과"));
        }
        1u64 << shift
    };
    let cluster_size = bytes_per_sector
        .checked_mul(sectors_per_cluster)
        .filter(|&cs| (512..=2 * 1024 * 1024).contains(&cs))
        .ok_or_else(|| bad_ntfs("NTFS cluster_size 범위 오류"))?;
    let mft_cluster = u64::from_le_bytes(b[48..56].try_into().unwrap());
    let raw_rec = b[64] as i8;
    let mft_record_size_u64 = if raw_rec > 0 {
        (raw_rec as u64)
            .checked_mul(cluster_size)
            .ok_or_else(|| bad_ntfs("MFT 레코드 크기 오버플로"))?
    } else if raw_rec < 0 {
        let shift = -(raw_rec as i32) as u32;
        if shift > 16 {
            return Err(bad_ntfs("MFT 레코드 크기 범위 초과"));
        }
        1u64 << shift
    } else {
        return Err(bad_ntfs("MFT 레코드 크기가 0임"));
    };
    if !(512..=65536).contains(&mft_record_size_u64)
        || !mft_record_size_u64.is_power_of_two()
        || !mft_record_size_u64.is_multiple_of(NTFS_FIXUP_STRIDE as u64)
    {
        return Err(bad_ntfs("MFT 레코드 크기가 올바르지 않음"));
    }
    Ok(NtfsBoot {
        cluster_size,
        mft_cluster,
        mft_record_size: mft_record_size_u64 as usize,
    })
}

/// NTFS 멀티섹터 업데이트 시퀀스(USA/USN) 픽스업을 복원한다. 손상된 레코드는 false.
fn apply_fixup(rec: &mut [u8]) -> bool {
    if rec.len() < 48 || &rec[0..4] != b"FILE" {
        return false;
    }
    let usa_offset = u16::from_le_bytes([rec[4], rec[5]]) as usize;
    let usa_count = u16::from_le_bytes([rec[6], rec[7]]) as usize;
    if usa_count == 0 {
        return true;
    }
    let Some(usa_bytes) = usa_count.checked_mul(2) else {
        return false;
    };
    let Some(usa_end) = usa_offset.checked_add(usa_bytes) else {
        return false;
    };
    if usa_end > rec.len() {
        return false;
    }
    let usn = u16::from_le_bytes([rec[usa_offset], rec[usa_offset + 1]]);
    for i in 1..usa_count {
        let Some(sector_end) = i.checked_mul(NTFS_FIXUP_STRIDE) else {
            return false;
        };
        if sector_end > rec.len() {
            return false;
        }
        let actual = u16::from_le_bytes([rec[sector_end - 2], rec[sector_end - 1]]);
        if actual != usn {
            return false;
        }
        let saved = usa_offset + i * 2;
        rec[sector_end - 2] = rec[saved];
        rec[sector_end - 1] = rec[saved + 1];
    }
    true
}

/// NTFS 비거주 속성의 데이터 런(mapping pairs)을 파싱한다.
fn parse_data_runs(data: &[u8]) -> Result<Vec<DataRun>, QblkError> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut prev_lcn = 0i64;

    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        if header == 0 {
            break;
        }
        if runs.len() >= MAX_DATA_RUNS {
            return Err(bad_ntfs("데이터 런 개수 상한 초과"));
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
            return Err(bad_ntfs("잘못된 데이터 런 헤더"));
        }
        let Some(need) = pos
            .checked_add(len_bytes)
            .and_then(|p| p.checked_add(off_bytes))
        else {
            return Err(bad_ntfs("데이터 런 오프셋 오버플로"));
        };
        if need > data.len() {
            return Err(bad_ntfs("데이터 런이 중간에 잘림"));
        }
        let mut cluster_count = 0u64;
        for (i, &b) in data[pos..pos + len_bytes].iter().enumerate() {
            cluster_count |= (b as u64) << (i * 8);
        }
        pos += len_bytes;
        if cluster_count == 0 {
            return Err(bad_ntfs("클러스터 길이가 0인 데이터 런"));
        }
        let lcn = if off_bytes == 0 {
            None
        } else {
            let mut raw = 0u64;
            for (i, &b) in data[pos..pos + off_bytes].iter().enumerate() {
                raw |= (b as u64) << (i * 8);
            }
            pos += off_bytes;
            let delta = if off_bytes < 8 {
                let sign_bit = 1u64 << (off_bytes * 8 - 1);
                if (raw & sign_bit) != 0 {
                    let mask = !0u64 << (off_bytes * 8);
                    (raw | mask) as i64
                } else {
                    raw as i64
                }
            } else {
                raw as i64
            };
            let next_lcn = prev_lcn
                .checked_add(delta)
                .filter(|&v| v >= 0)
                .ok_or_else(|| bad_ntfs("데이터 런 LCN 계산 오류"))?;
            prev_lcn = next_lcn;
            Some(next_lcn as u64)
        };
        runs.push(DataRun { lcn, cluster_count });
    }
    Ok(runs)
}

fn filetime_to_unix_secs(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    let secs = ft / 10_000_000;
    let unix = secs.checked_sub(FILETIME_UNIX_EPOCH_SECS)?;
    i64::try_from(unix).ok()
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    String::from_utf16_lossy(&units)
}

fn namespace_rank(ns: u8) -> u8 {
    match ns {
        1 | 3 => 3, // Win32 / Win32+DOS
        0 => 2,     // POSIX
        2 => 1,     // DOS 8.3
        _ => 0,
    }
}

fn parse_mft_record(mft_id: u64, rec: &mut [u8]) -> Option<RawMftEntry> {
    if !apply_fixup(rec) {
        return None;
    }
    let attrs_offset = u16::from_le_bytes([rec[20], rec[21]]) as usize;
    let flags = u16::from_le_bytes([rec[22], rec[23]]);
    if (flags & MFT_FLAG_IN_USE) == 0 {
        return None;
    }
    let used_size = u32::from_le_bytes(rec[24..28].try_into().ok()?) as usize;
    let base_record = u64::from_le_bytes(rec[32..40].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
    if base_record != 0 {
        return None;
    }
    let limit = used_size.min(rec.len());
    if attrs_offset < 40 || attrs_offset >= limit {
        return None;
    }

    let mut mtime: Option<i64> = None;
    let mut best_name: Option<(u8, u64, String)> = None;
    let mut data = DataSource::Empty;

    let mut off = attrs_offset;
    while off + 8 <= limit {
        let attr_type = u32::from_le_bytes(rec[off..off + 4].try_into().ok()?);
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = u32::from_le_bytes(rec[off + 4..off + 8].try_into().ok()?) as usize;
        if attr_len < 16 || off.checked_add(attr_len).is_none_or(|e| e > limit) {
            break;
        }
        let attr = &rec[off..off + attr_len];
        let non_resident = attr[8] != 0;
        let name_len = attr[9] as usize;
        let attr_flags = u16::from_le_bytes([attr[12], attr[13]]);

        match attr_type {
            ATTR_STANDARD_INFO if !non_resident && attr.len() >= 24 => {
                let val_len = u32::from_le_bytes(attr[16..20].try_into().ok()?) as usize;
                let val_off = u16::from_le_bytes([attr[20], attr[21]]) as usize;
                if val_off
                    .checked_add(val_len)
                    .is_some_and(|e| e <= attr.len())
                    && val_len >= 16
                {
                    let ft = u64::from_le_bytes(attr[val_off + 8..val_off + 16].try_into().ok()?);
                    mtime = filetime_to_unix_secs(ft);
                }
            }
            ATTR_FILE_NAME if !non_resident && attr.len() >= 24 => {
                let val_len = u32::from_le_bytes(attr[16..20].try_into().ok()?) as usize;
                let val_off = u16::from_le_bytes([attr[20], attr[21]]) as usize;
                if val_off
                    .checked_add(val_len)
                    .is_some_and(|e| e <= attr.len())
                    && val_len >= 66
                {
                    let val = &attr[val_off..val_off + val_len];
                    let parent_id =
                        u64::from_le_bytes(val[0..8].try_into().ok()?) & 0x0000_FFFF_FFFF_FFFF;
                    let fn_len = val[64] as usize;
                    let ns = val[65];
                    let end = 66usize.saturating_add(fn_len.saturating_mul(2));
                    if end <= val.len() {
                        let rank = namespace_rank(ns);
                        let should_replace = best_name
                            .as_ref()
                            .is_none_or(|(prev_rank, _, _)| rank > *prev_rank);
                        if should_replace {
                            best_name = Some((rank, parent_id, decode_utf16le(&val[66..end])));
                        }
                    }
                }
            }
            ATTR_DATA if name_len == 0 => {
                if !non_resident && attr.len() >= 24 {
                    let val_len = u32::from_le_bytes(attr[16..20].try_into().ok()?) as usize;
                    let val_off = u16::from_le_bytes([attr[20], attr[21]]) as usize;
                    if val_off
                        .checked_add(val_len)
                        .is_some_and(|e| e <= attr.len())
                    {
                        data = DataSource::Resident(attr[val_off..val_off + val_len].to_vec());
                    }
                } else if non_resident && attr.len() >= 64 {
                    let start_vcn = u64::from_le_bytes(attr[16..24].try_into().ok()?);
                    if start_vcn == 0 {
                        let run_off = u16::from_le_bytes([attr[32], attr[33]]) as usize;
                        let real_size = u64::from_le_bytes(attr[48..56].try_into().ok()?);
                        let init_size = u64::from_le_bytes(attr[56..64].try_into().ok()?);
                        if run_off <= attr.len() {
                            if let Ok(runs) = parse_data_runs(&attr[run_off..]) {
                                data = DataSource::NonResident {
                                    runs,
                                    real_size,
                                    init_size,
                                    flags: attr_flags,
                                };
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        off += attr_len;
    }

    let (_, parent_id, name) = best_name?;
    Some(RawMftEntry {
        mft_id,
        parent_id,
        name,
        is_dir: (flags & MFT_FLAG_DIRECTORY) != 0,
        mtime,
        data,
    })
}

fn normalize_query_path(raw: &str) -> String {
    let parts: Vec<&str> = raw
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn write_zeros<W: Write>(w: &mut W, mut count: u64) -> io::Result<()> {
    static ZEROS: [u8; 64 * 1024] = [0u8; 64 * 1024];
    while count > 0 {
        let take = count.min(ZEROS.len() as u64) as usize;
        w.write_all(&ZEROS[..take])?;
        count -= take as u64;
    }
    Ok(())
}

/// `.qblk` 이미지(단일 또는 증분 체인)를 읽기 전용 NTFS 볼륨으로 열어 탐색·추출한다.
pub struct NtfsImage {
    reader: QblkVolumeReader,
    cluster_size: u64,
    children: HashMap<String, Vec<ImageFileEntry>>,
    by_path: HashMap<String, usize>,
    by_path_lower: HashMap<String, usize>,
    entries: Vec<ImageFileEntry>,
    data_sources: Vec<DataSource>,
}

impl NtfsImage {
    /// `.qblk` 이미지(또는 증분 체인 끝 파일)를 열어 NTFS `$MFT` 인덱스를 메모리에 구성한다.
    pub fn open(image: &Path) -> Result<Self, QblkError> {
        let mut reader = QblkVolumeReader::open(image)?;
        if reader.volume_len() < 512 {
            return Err(bad_ntfs("볼륨 크기가 512바이트 미만임"));
        }
        let mut boot_buf = [0u8; 512];
        reader.read_at(0, &mut boot_buf)?;
        let boot = parse_boot_sector(&boot_buf)?;

        // MFT 레코드 0 ($MFT) 읽기
        let mft0_off = boot
            .mft_cluster
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| bad_ntfs("$MFT 시작 오프셋 오버플로"))?;
        let mut rec0 = vec![0u8; boot.mft_record_size];
        reader.read_at(mft0_off, &mut rec0)?;
        let mft0 = parse_mft_record(0, &mut rec0)
            .ok_or_else(|| bad_ntfs("$MFT 레코드 0을 해석할 수 없음"))?;

        let raw_entries = match mft0.data {
            DataSource::NonResident {
                runs, real_size, ..
            } => scan_mft_non_resident(&mut reader, &boot, &runs, real_size)?,
            DataSource::Resident(mut buf) => {
                let mut map = HashMap::new();
                let rec_size = boot.mft_record_size;
                for (id, slice) in buf
                    .chunks_exact_mut(rec_size)
                    .take(MAX_MFT_RECORDS as usize)
                    .enumerate()
                {
                    if let Some(e) = parse_mft_record(id as u64, slice) {
                        map.insert(id as u64, e);
                    }
                }
                map
            }
            DataSource::Empty => return Err(bad_ntfs("$MFT에 $DATA 속성이 없음")),
        };

        let (children, by_path, by_path_lower, entries, data_sources) =
            build_directory_index(raw_entries);
        Ok(Self {
            reader,
            cluster_size: boot.cluster_size,
            children,
            by_path,
            by_path_lower,
            entries,
            data_sources,
        })
    }

    /// 지정 디렉터리의 직계 항목을 돌려준다(`""` 또는 `"/"` = 루트). 폴더 우선, 이름순 정렬.
    pub fn list_dir(&self, dir_path: &str) -> Vec<ImageFileEntry> {
        let norm = normalize_query_path(dir_path);
        if let Some(list) = self.children.get(&norm) {
            return list.clone();
        }
        if !norm.is_empty() {
            if let Some(&idx) = self.by_path_lower.get(&norm.to_lowercase()) {
                let entry = &self.entries[idx];
                if entry.is_dir {
                    if let Some(list) = self.children.get(&entry.path) {
                        return list.clone();
                    }
                }
            }
        }
        Vec::new()
    }

    /// 전체 파일·폴더에서 대소문자 구분 없이 부분 일치 검색을 수행한다.
    pub fn search(&self, query: &str, limit: usize) -> Vec<ImageFileEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let match_path = query.contains('/') || query.contains('\\');
        let q_lower = query.replace('\\', "/").to_lowercase();
        let mut hits: Vec<ImageFileEntry> = self
            .entries
            .iter()
            .filter(|e| {
                if q_lower.is_empty() {
                    true
                } else if match_path {
                    e.path.to_lowercase().contains(&q_lower)
                } else {
                    e.name.to_lowercase().contains(&q_lower)
                }
            })
            .cloned()
            .collect();
        hits.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
                .then_with(|| a.path.cmp(&b.path))
        });
        hits.truncate(limit);
        hits
    }

    /// 이미지 내 파일을 `dest`로 원자적(`.tmp` → `sync_all` → `rename`) 추출하고 기록한 정확한 바이트 수를 돌려준다.
    pub fn extract_file(&mut self, path: &str, dest: &Path) -> Result<u64, QblkError> {
        let norm = normalize_query_path(path);
        let idx = self
            .by_path
            .get(&norm)
            .or_else(|| self.by_path_lower.get(&norm.to_lowercase()))
            .copied()
            .ok_or_else(|| {
                QblkError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("이미지에서 파일을 찾을 수 없음: {path}"),
                ))
            })?;
        if self.entries[idx].is_dir {
            return Err(QblkError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("디렉터리는 파일로 추출할 수 없음: {path}"),
            )));
        }

        static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = PathBuf::from(format!(
            "{}.{}.{}.tmp",
            dest.display(),
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let data = &self.data_sources[idx];
        let reader = &mut self.reader;
        let cluster_size = self.cluster_size;

        let res = (|| -> Result<u64, QblkError> {
            let file = File::create(&tmp)?;
            let mut out = BufWriter::with_capacity(256 * 1024, file);
            let total_written = match data {
                DataSource::Empty => 0,
                DataSource::Resident(bytes) => {
                    out.write_all(bytes)?;
                    bytes.len() as u64
                }
                DataSource::NonResident {
                    runs,
                    real_size,
                    init_size,
                    flags,
                } => {
                    if (*flags & DATA_FLAG_ENCRYPTED) != 0 {
                        return Err(QblkError::Io(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "NTFS EFS 암호화 파일은 직접 추출을 지원하지 않습니다",
                        )));
                    }
                    if (*flags & DATA_FLAG_COMPRESSED) != 0 {
                        return Err(QblkError::Io(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "NTFS 압축 속성 파일은 직접 추출을 지원하지 않습니다",
                        )));
                    }
                    let valid_limit = (*init_size).min(*real_size);
                    let mut written = 0u64;
                    let mut io_buf = vec![0u8; 256 * 1024];
                    for run in runs {
                        if written >= *real_size {
                            break;
                        }
                        let run_bytes = run
                            .cluster_count
                            .checked_mul(cluster_size)
                            .ok_or_else(|| bad_ntfs("데이터 런 크기 오버플로"))?;
                        let need = run_bytes.min(*real_size - written);
                        match run.lcn {
                            None => {
                                write_zeros(&mut out, need)?;
                                written += need;
                            }
                            Some(start_lcn) => {
                                let base_off = start_lcn
                                    .checked_mul(cluster_size)
                                    .ok_or_else(|| bad_ntfs("데이터 런 LCN 오버플로"))?;
                                let mut run_pos = 0u64;
                                while run_pos < need {
                                    if written >= valid_limit {
                                        let rem_zero = need - run_pos;
                                        write_zeros(&mut out, rem_zero)?;
                                        written += rem_zero;
                                        break;
                                    }
                                    let can_read = (need - run_pos)
                                        .min(valid_limit - written)
                                        .min(io_buf.len() as u64)
                                        as usize;
                                    reader.read_at(base_off + run_pos, &mut io_buf[..can_read])?;
                                    out.write_all(&io_buf[..can_read])?;
                                    run_pos += can_read as u64;
                                    written += can_read as u64;
                                }
                            }
                        }
                    }
                    if written < *real_size {
                        write_zeros(&mut out, *real_size - written)?;
                    }
                    *real_size
                }
            };
            out.flush()?;
            let f = out.into_inner().map_err(|e| e.into_error())?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, dest)?;
            Ok(total_written)
        })();

        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }
}

fn scan_mft_non_resident(
    reader: &mut QblkVolumeReader,
    boot: &NtfsBoot,
    runs: &[DataRun],
    real_size: u64,
) -> Result<HashMap<u64, RawMftEntry>, QblkError> {
    let rec_size = boot.mft_record_size;
    let total_records = (real_size / rec_size as u64).min(MAX_MFT_RECORDS);
    let mut entries = HashMap::new();
    let mut mft_id = 0u64;
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];

    for run in runs {
        if mft_id >= total_records {
            break;
        }
        let run_bytes = run
            .cluster_count
            .checked_mul(boot.cluster_size)
            .ok_or_else(|| bad_ntfs("$MFT 런 크기 오버플로"))?;
        match run.lcn {
            None => {
                // 희소 $MFT 구간: 레코드 경계만 진행
                let total_skip = carry.len() as u64 + run_bytes;
                let skipped_recs = total_skip / rec_size as u64;
                let rem = (total_skip % rec_size as u64) as usize;
                mft_id = mft_id.saturating_add(skipped_recs).min(total_records);
                carry.clear();
                carry.resize(rem, 0);
            }
            Some(start_lcn) => {
                let base_off = start_lcn
                    .checked_mul(boot.cluster_size)
                    .ok_or_else(|| bad_ntfs("$MFT LCN 오버플로"))?;
                let mut run_pos = 0u64;
                while run_pos < run_bytes && mft_id < total_records {
                    let rem_target_bytes = (total_records - mft_id)
                        .saturating_mul(rec_size as u64)
                        .saturating_sub(carry.len() as u64);
                    if rem_target_bytes == 0 {
                        break;
                    }
                    let take = (run_bytes - run_pos)
                        .min(buf.len() as u64)
                        .min(rem_target_bytes) as usize;
                    reader.read_at(base_off + run_pos, &mut buf[..take])?;
                    run_pos += take as u64;

                    let mut offset = 0usize;
                    if !carry.is_empty() {
                        let need = rec_size - carry.len();
                        if take < need {
                            carry.extend_from_slice(&buf[..take]);
                            continue;
                        }
                        carry.extend_from_slice(&buf[..need]);
                        offset = need;
                        if let Some(entry) = parse_mft_record(mft_id, &mut carry) {
                            entries.insert(mft_id, entry);
                        }
                        mft_id += 1;
                        carry.clear();
                    }

                    while offset + rec_size <= take && mft_id < total_records {
                        if let Some(entry) =
                            parse_mft_record(mft_id, &mut buf[offset..offset + rec_size])
                        {
                            entries.insert(mft_id, entry);
                        }
                        mft_id += 1;
                        offset += rec_size;
                    }
                    if offset < take && mft_id < total_records {
                        carry.extend_from_slice(&buf[offset..take]);
                    }
                }
            }
        }
    }
    Ok(entries)
}

type IndexResult = (
    HashMap<String, Vec<ImageFileEntry>>,
    HashMap<String, usize>,
    HashMap<String, usize>,
    Vec<ImageFileEntry>,
    Vec<DataSource>,
);

fn build_directory_index(mut raw_entries: HashMap<u64, RawMftEntry>) -> IndexResult {
    // 부모 ID·이름 맵만 분리해 경로를 계산한다.
    let parent_meta: HashMap<u64, (u64, String)> = raw_entries
        .iter()
        .map(|(&id, e)| (id, (e.parent_id, e.name.clone())))
        .collect();

    let mut children: HashMap<String, Vec<ImageFileEntry>> = HashMap::new();
    let mut by_path: HashMap<String, usize> = HashMap::new();
    let mut by_path_lower: HashMap<String, usize> = HashMap::new();
    let mut entries: Vec<ImageFileEntry> = Vec::new();
    let mut data_sources: Vec<DataSource> = Vec::new();

    let mut ids: Vec<u64> = raw_entries.keys().copied().collect();
    ids.sort_unstable();

    for id in ids {
        let Some(raw) = raw_entries.remove(&id) else {
            continue;
        };
        if id == MFT_ROOT_ID || (id < 16 && raw.name.starts_with('$')) {
            continue;
        }
        // 부모 체인을 거슬러 올라가 루트(MFT 5) 도달 여부 확인
        let mut parent_parts: Vec<String> = Vec::new();
        let mut cur = raw.parent_id;
        let mut reached_root = false;
        for _ in 0..MAX_PATH_DEPTH {
            if cur == MFT_ROOT_ID {
                reached_root = true;
                break;
            }
            let Some((next_parent, name)) = parent_meta.get(&cur) else {
                break;
            };
            if *next_parent == cur {
                break;
            }
            parent_parts.push(name.clone());
            cur = *next_parent;
        }
        if !reached_root {
            continue;
        }
        parent_parts.reverse();
        let parent_path = if parent_parts.is_empty() {
            String::new()
        } else {
            format!("/{}", parent_parts.join("/"))
        };
        let full_path = if parent_path.is_empty() {
            format!("/{}", raw.name)
        } else {
            format!("{parent_path}/{}", raw.name)
        };
        let size = if raw.is_dir {
            0
        } else {
            match &raw.data {
                DataSource::Empty => 0,
                DataSource::Resident(v) => v.len() as u64,
                DataSource::NonResident { real_size, .. } => *real_size,
            }
        };
        let entry = ImageFileEntry {
            name: raw.name,
            path: full_path.clone(),
            is_dir: raw.is_dir,
            size,
            mft_id: raw.mft_id,
            mtime: raw.mtime,
        };
        let idx = entries.len();
        by_path.insert(full_path.clone(), idx);
        by_path_lower.insert(full_path.to_lowercase(), idx);
        children.entry(parent_path).or_default().push(entry.clone());
        entries.push(entry);
        data_sources.push(raw.data);
    }

    for list in children.values_mut() {
        list.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
    }

    (children, by_path, by_path_lower, entries, data_sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::capture_file;
    use crate::incremental::{
        save_block_map, save_chain_meta, write_incremental_image, BlockMap, ChainMeta,
    };
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;

    fn encode_runlist(runs: &[(Option<u64>, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev_lcn = 0i64;
        for &(lcn_opt, count) in runs {
            let count_bytes = minimal_unsigned_le(count);
            match lcn_opt {
                None => {
                    out.push(count_bytes.len() as u8);
                    out.extend_from_slice(&count_bytes);
                }
                Some(lcn) => {
                    let delta = lcn as i64 - prev_lcn;
                    prev_lcn = lcn as i64;
                    let off_bytes = minimal_signed_le(delta);
                    out.push(((off_bytes.len() as u8) << 4) | (count_bytes.len() as u8));
                    out.extend_from_slice(&count_bytes);
                    out.extend_from_slice(&off_bytes);
                }
            }
        }
        out.push(0);
        out
    }

    fn minimal_unsigned_le(v: u64) -> Vec<u8> {
        let raw = v.to_le_bytes();
        let mut len = 8;
        while len > 1 && raw[len - 1] == 0 {
            len -= 1;
        }
        raw[..len].to_vec()
    }

    fn minimal_signed_le(v: i64) -> Vec<u8> {
        let raw = v.to_le_bytes();
        let mut len = 8;
        while len > 1 {
            let top = raw[len - 1];
            let next_sign = (raw[len - 2] & 0x80) != 0;
            if (top == 0x00 && !next_sign) || (top == 0xFF && next_sign) {
                len -= 1;
            } else {
                break;
            }
        }
        raw[..len].to_vec()
    }

    fn build_resident_attr(attr_type: u32, payload: &[u8]) -> Vec<u8> {
        let val_off = 24usize;
        let total = (val_off + payload.len()).next_multiple_of(8);
        let mut b = vec![0u8; total];
        b[0..4].copy_from_slice(&attr_type.to_le_bytes());
        b[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        b[8] = 0; // resident
        b[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        b[20..22].copy_from_slice(&(val_off as u16).to_le_bytes());
        b[val_off..val_off + payload.len()].copy_from_slice(payload);
        b
    }

    fn build_non_resident_data(runs: &[(Option<u64>, u64)], real_size: u64, cs: u64) -> Vec<u8> {
        let runlist = encode_runlist(runs);
        let run_off = 64usize;
        let total = (run_off + runlist.len()).next_multiple_of(8);
        let total_clusters: u64 = runs.iter().map(|(_, c)| *c).sum();
        let alloc_size = total_clusters * cs;
        let mut b = vec![0u8; total];
        b[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        b[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        b[8] = 1; // non-resident
        b[16..24].copy_from_slice(&0u64.to_le_bytes()); // start_vcn
        b[24..32].copy_from_slice(&(total_clusters.saturating_sub(1)).to_le_bytes()); // last_vcn
        b[32..34].copy_from_slice(&(run_off as u16).to_le_bytes());
        b[40..48].copy_from_slice(&alloc_size.to_le_bytes());
        b[48..56].copy_from_slice(&real_size.to_le_bytes());
        b[56..64].copy_from_slice(&real_size.to_le_bytes()); // init_size
        b[run_off..run_off + runlist.len()].copy_from_slice(&runlist);
        b
    }

    fn build_std_info(unix_secs: u64) -> Vec<u8> {
        let ft = (unix_secs + FILETIME_UNIX_EPOCH_SECS) * 10_000_000;
        let mut p = vec![0u8; 48];
        p[0..8].copy_from_slice(&ft.to_le_bytes()); // ctime
        p[8..16].copy_from_slice(&ft.to_le_bytes()); // mtime
        build_resident_attr(ATTR_STANDARD_INFO, &p)
    }

    fn build_file_name(parent_id: u64, name: &str, namespace: u8) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut p = vec![0u8; 66 + utf16.len() * 2];
        // 상위 16비트는 sequence number(예: 1), 하위 48비트가 parent MFT ID
        let parent_ref = parent_id | (1u64 << 48);
        p[0..8].copy_from_slice(&parent_ref.to_le_bytes());
        p[64] = utf16.len() as u8;
        p[65] = namespace;
        for (i, &u) in utf16.iter().enumerate() {
            p[66 + i * 2..66 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        build_resident_attr(ATTR_FILE_NAME, &p)
    }

    fn build_mft_record(flags: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 48u16;
        let usa_count = 3u16; // USN + 2개 512바이트 섹터
        rec[4..6].copy_from_slice(&usa_offset.to_le_bytes());
        rec[6..8].copy_from_slice(&usa_count.to_le_bytes());
        let attrs_offset = 56usize;
        rec[20..22].copy_from_slice(&(attrs_offset as u16).to_le_bytes());
        rec[22..24].copy_from_slice(&flags.to_le_bytes());

        let mut pos = attrs_offset;
        for a in attrs {
            assert!(pos + a.len() + 4 <= 1024);
            rec[pos..pos + a.len()].copy_from_slice(a);
            pos += a.len();
        }
        rec[pos..pos + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        pos += 4;
        rec[24..28].copy_from_slice(&(pos as u32).to_le_bytes());
        rec[28..32].copy_from_slice(&1024u32.to_le_bytes());

        // NTFS 멀티섹터 픽스업(USA/USN) 적용: 각 512B 끝 2바이트를 USA에 백업하고 USN으로 치환
        let usn = 0x1357u16;
        rec[48..50].copy_from_slice(&usn.to_le_bytes());
        let s1 = [rec[510], rec[511]];
        let s2 = [rec[1022], rec[1023]];
        rec[50..52].copy_from_slice(&s1);
        rec[52..54].copy_from_slice(&s2);
        rec[510..512].copy_from_slice(&usn.to_le_bytes());
        rec[1022..1024].copy_from_slice(&usn.to_le_bytes());
        rec
    }

    /// 부트 섹터 + 단편화된 $MFT + 루트 + 서브폴더 + 거주 파일(512B 경계 교차) + 비거주 멀티클러스터(음수 델타+희소 런) 파일로 구성된 합성 NTFS 볼륨 생성.
    fn build_synthetic_ntfs_volume() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let cs = 4096usize;
        let total_clusters = 64usize;
        let mut vol = vec![0u8; cs * total_clusters];

        // 1) 부트 섹터 (LCN 0)
        vol[3..11].copy_from_slice(b"NTFS    ");
        vol[11..13].copy_from_slice(&512u16.to_le_bytes());
        vol[13] = 8; // 8 * 512 = 4096
        vol[40..48].copy_from_slice(&((total_clusters * 8 - 1) as u64).to_le_bytes());
        vol[48..56].copy_from_slice(&4u64.to_le_bytes()); // mft_cluster = 4
        vol[64] = (-10i8) as u8; // 2^10 = 1024 bytes per MFT record

        // 2) $MFT 배치: LCN 4..6 (레코드 0..8) + LCN 12..15 (레코드 8..20) → 총 20개 레코드, 단편화됨
        let mft_runs = [(Some(4u64), 2u64), (Some(12u64), 3u64)];
        let write_rec = |vol: &mut [u8], id: usize, rec: &[u8]| {
            let off = if id < 8 {
                4 * cs + id * 1024
            } else {
                12 * cs + (id - 8) * 1024
            };
            vol[off..off + 1024].copy_from_slice(rec);
        };

        // Record 0: $MFT
        let rec0 = build_mft_record(
            MFT_FLAG_IN_USE,
            &[
                build_file_name(5, "$MFT", 3),
                build_non_resident_data(&mft_runs, 20 * 1024, cs as u64),
            ],
        );
        write_rec(&mut vol, 0, &rec0);

        // Record 5: 루트 디렉터리 "."
        let rec5 = build_mft_record(
            MFT_FLAG_IN_USE | MFT_FLAG_DIRECTORY,
            &[build_file_name(5, ".", 3)],
        );
        write_rec(&mut vol, 5, &rec5);

        // Record 16: 서브폴더 "/docs"
        let rec16 = build_mft_record(
            MFT_FLAG_IN_USE | MFT_FLAG_DIRECTORY,
            &[build_std_info(1_700_000_000), build_file_name(5, "docs", 1)],
        );
        write_rec(&mut vol, 16, &rec16);

        // Record 17: 거주 파일 "/docs/hello.txt" — DOS 8.3 + Win32 이름 공존, 512B 픽스업 경계를 가로지르는 480바이트 데이터
        let hello_bytes: Vec<u8> = (0..480u32).map(|i| b'A' + (i % 26) as u8).collect();
        let rec17 = build_mft_record(
            MFT_FLAG_IN_USE,
            &[
                build_std_info(1_700_000_123),
                build_file_name(16, "HELLO~1.TXT", 2), // DOS 이름
                build_file_name(16, "hello.txt", 1),   // Win32 이름(우선 선택되어야 함)
                build_resident_attr(ATTR_DATA, &hello_bytes),
            ],
        );
        write_rec(&mut vol, 17, &rec17);

        // Record 18: 비거주 멀티클러스터 파일 "/docs/big.bin"
        // LCN 30 (2클러스터) + LCN 25 (1클러스터, 음수 델타 -5) + 희소 1클러스터(0) + LCN 35 (1클러스터 중 123B 유효)
        let big_real_size = 4 * cs + 123;
        let mut expected_big = vec![0u8; big_real_size];
        for (i, b) in expected_big[..2 * cs].iter_mut().enumerate() {
            *b = ((i * 7 + 3) % 251) as u8;
        }
        for (i, b) in expected_big[2 * cs..3 * cs].iter_mut().enumerate() {
            *b = ((i * 13 + 9) % 241) as u8;
        }
        // expected_big[3 * cs..4 * cs] 는 희소 런 → 0 유지
        for (i, b) in expected_big[4 * cs..big_real_size].iter_mut().enumerate() {
            *b = ((i * 5 + 1) % 239) as u8;
        }
        vol[30 * cs..32 * cs].copy_from_slice(&expected_big[..2 * cs]);
        vol[25 * cs..26 * cs].copy_from_slice(&expected_big[2 * cs..3 * cs]);
        vol[35 * cs..35 * cs + 123].copy_from_slice(&expected_big[4 * cs..big_real_size]);
        let big_runs = [
            (Some(30u64), 2u64),
            (Some(25u64), 1u64),
            (None, 1u64),
            (Some(35u64), 1u64),
        ];
        let rec18 = build_mft_record(
            MFT_FLAG_IN_USE,
            &[
                build_std_info(1_700_000_456),
                build_file_name(16, "big.bin", 1),
                build_non_resident_data(&big_runs, big_real_size as u64, cs as u64),
            ],
        );
        write_rec(&mut vol, 18, &rec18);

        // Record 19: 루트 파일 "/readme.txt"
        let rec19 = build_mft_record(
            MFT_FLAG_IN_USE,
            &[
                build_std_info(1_700_000_789),
                build_file_name(5, "readme.txt", 1),
                build_resident_attr(ATTR_DATA, b"Kova NTFS root readme"),
            ],
        );
        write_rec(&mut vol, 19, &rec19);

        (vol, hello_bytes, expected_big)
    }

    #[test]
    fn ntfs_browse_search_and_extract_over_single_and_incremental_qblk() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vol, hello_bytes, mut expected_big) = build_synthetic_ntfs_volume();
        let raw_path = dir.path().join("vol.img");
        fs::write(&raw_path, &vol).unwrap();

        let qblk_path = dir.path().join("base.qblk");
        let no = AtomicBool::new(false);
        capture_file(&raw_path, &qblk_path, 4096, 1, "TEST", &no, &|_| {}).unwrap();

        // 1) 단일 .qblk 열기 & 디렉터리 목록 확인
        let mut img = NtfsImage::open(&qblk_path).unwrap();
        let root = img.list_dir("");
        assert_eq!(root, img.list_dir("/"));
        assert_eq!(root.len(), 2);
        assert_eq!(root[0].name, "docs");
        assert!(root[0].is_dir);
        assert_eq!(root[0].path, "/docs");
        assert_eq!(root[1].name, "readme.txt");
        assert!(!root[1].is_dir);
        assert_eq!(root[1].size, 21);

        let docs = img.list_dir("/docs");
        assert_eq!(docs, img.list_dir("docs"));
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].name, "big.bin");
        assert_eq!(docs[0].size, expected_big.len() as u64);
        assert_eq!(docs[1].name, "hello.txt");
        assert_eq!(docs[1].size, hello_bytes.len() as u64);
        assert_eq!(docs[1].mtime, Some(1_700_000_123));

        // 2) 대소문자 무시 검색
        let found = img.search("HELLO", 10);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "/docs/hello.txt");
        let limited = img.search("t", 1);
        assert_eq!(limited.len(), 1);

        // 3) 거주 파일(512B 픽스업 경계 교차) 및 비거주 멀티클러스터(음수 델타+희소 런) 추출 바이트 일치 검증
        let out_hello = dir.path().join("out_hello.txt");
        let n1 = img.extract_file("/docs/hello.txt", &out_hello).unwrap();
        assert_eq!(n1, hello_bytes.len() as u64);
        assert_eq!(fs::read(&out_hello).unwrap(), hello_bytes);

        let out_big = dir.path().join("out_big.bin");
        let n2 = img.extract_file("\\docs\\big.bin", &out_big).unwrap();
        assert_eq!(n2, expected_big.len() as u64);
        assert_eq!(fs::read(&out_big).unwrap(), expected_big);

        let out_readme = dir.path().join("out_readme.txt");
        img.extract_file("readme.txt", &out_readme).unwrap();
        assert_eq!(fs::read(&out_readme).unwrap(), b"Kova NTFS root readme");

        // 4) 증분 체인 위에서의 파일 추출 검증(LCN 25만 증분으로 덮어쓰기)
        let cs = 4096usize;
        let bitmap = vec![0xFFu8; 8]; // 64클러스터 전체
        let base2 = dir.path().join("chain_base.qblk");
        let h_tmpl = Header {
            version: crate::qblk::VERSION,
            cluster_size: cs as u32,
            total_clusters: 64,
            used_clusters: 0,
            vsn: "ABCD-EF01".into(),
            source_label: "C:".into(),
        };
        let base_map = {
            let f = File::create(&base2).unwrap();
            let seed = BlockMap {
                version: 2,
                cluster_size: cs as u32,
                total_clusters: 64,
                block_clusters: 1,
                hashes: BTreeMap::new(),
            };
            let (_, _, map, _) = write_incremental_image(
                &mut Cursor::new(&vol),
                f,
                &mut h_tmpl.clone(),
                &bitmap,
                Some(&seed),
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            save_block_map(&base2, &map).unwrap();
            map
        };

        // LCN 25 (big.bin의 3번째 클러스터) 내용 변경
        let patched_cluster = vec![0x9Au8; cs];
        vol[25 * cs..26 * cs].copy_from_slice(&patched_cluster);
        expected_big[2 * cs..3 * cs].copy_from_slice(&patched_cluster);

        let inc1 = dir.path().join("chain_inc1.qblk");
        {
            let f = File::create(&inc1).unwrap();
            let (_, inc, map, _) = write_incremental_image(
                &mut Cursor::new(&vol),
                f,
                &mut h_tmpl.clone(),
                &bitmap,
                Some(&base_map),
                1,
                &no,
                &|_| {},
            )
            .unwrap();
            assert_eq!(inc.changed_clusters, 1);
            save_block_map(&inc1, &map).unwrap();
            save_chain_meta(
                &inc1,
                &ChainMeta {
                    version: 1,
                    parent: "chain_base.qblk".into(),
                    changed_clusters: inc.changed_clusters,
                    skipped_clusters: inc.skipped_clusters,
                },
            )
            .unwrap();
        }

        let mut chain_img = NtfsImage::open(&inc1).unwrap();
        let out_big_inc = dir.path().join("out_big_inc.bin");
        let n3 = chain_img
            .extract_file("/docs/big.bin", &out_big_inc)
            .unwrap();
        assert_eq!(n3, expected_big.len() as u64);
        assert_eq!(fs::read(&out_big_inc).unwrap(), expected_big);
    }
}

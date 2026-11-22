//! 시험용: write_image_bench <원본파일> <출력.qblk> [레벨]
//! 원본 파일 전체를 할당 클러스터로 보고 write_image 로 이미지를 만들어 속도와 크기를 잰다(디스크 성능 시험용).
use kova_image::{volume::write_image, Header};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: write_image_bench <src> <out.qblk> [level]");
        std::process::exit(2);
    }
    let level: i32 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut src = std::fs::File::open(&a[0]).expect("open src");
    let len = src.metadata().unwrap().len();
    let total = len / 4096;
    let mut bitmap = vec![0xFFu8; (total as usize).div_ceil(8)];
    let rem = (total % 8) as u8;
    if rem != 0 {
        *bitmap.last_mut().unwrap() = (1u8 << rem) - 1;
    }
    let mut h = Header {
        version: kova_image::qblk::VERSION,
        cluster_size: 4096,
        total_clusters: total,
        used_clusters: 0,
        vsn: "BENCH".into(),
        source_label: "bench".into(),
    };
    let out = std::fs::File::create(&a[1]).expect("create out");
    let t = Instant::now();
    let (st, f) = write_image(
        &mut src,
        out,
        &mut h,
        &bitmap,
        level,
        &AtomicBool::new(false),
        &|_| {},
    )
    .expect("write_image");
    f.sync_all().unwrap();
    let s = t.elapsed().as_secs_f64();
    let osz = std::fs::metadata(&a[1]).unwrap().len();
    println!(
        "level={level} raw={:.2}GB out={:.2}GB {:.1}s {:.0}MB/s chunks={}",
        st.raw_bytes as f64 / 1e9,
        osz as f64 / 1e9,
        s,
        st.raw_bytes as f64 / 1e6 / s,
        st.chunks
    );
}

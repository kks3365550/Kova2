//! 오류 문구에 "그래서 무엇을 하면 되는지"를 한 줄 덧붙인다. 원문은 그대로 두고 끝에 안내만 붙인다.

const HINTS: &[(&[&str], &str)] = &[
    (
        &["다른 작업이 저장소를 사용 중", "저장소 잠금"],
        "다른 백업이 진행 중입니다. 잠시 후 자동으로 다시 시도합니다.",
    ),
    (
        &["원본 경로를 찾을 수 없음", "지정된 경로를 찾을 수 없습니다", "os error 3"],
        "백업할 폴더나 드라이브가 연결돼 있는지 확인하세요 (외장 디스크·네트워크 드라이브 포함).",
    ),
    (
        &["No space left", "디스크 공간", "os error 112", "공간이 부족"],
        "저장 공간이 부족합니다. 저장소 드라이브의 용량을 비우거나 보관 개수를 줄이세요.",
    ),
    (
        &["Access is denied", "액세스가 거부", "os error 5", "권한"],
        "접근 권한이 없습니다. 해당 폴더가 다른 프로그램에서 잠겨 있지 않은지, 읽기 전용이 아닌지 확인하세요.",
    ),
    (
        &["os error 53", "os error 1326", "네트워크 경로", "network"],
        "네트워크 경로에 연결하지 못했습니다. 공유 폴더 주소와 PC 전원, 로그인 정보를 확인하세요.",
    ),
];

/// 알려진 오류면 `원문 → 조치: 안내`, 아니면 원문 그대로.
pub fn with_hint(msg: &str) -> String {
    for (keys, hint) in HINTS {
        if keys.iter().any(|k| msg.contains(k)) && !msg.contains("→ 조치:") {
            return format!("{msg} → 조치: {hint}");
        }
    }
    msg.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_hint_once_and_keeps_unknown_messages() {
        let m = with_hint("원본 경로를 찾을 수 없음: D:/data");
        assert!(m.starts_with("원본 경로를 찾을 수 없음") && m.contains("→ 조치:"));
        assert_eq!(with_hint(&m), m);
        assert_eq!(with_hint("알 수 없는 문제"), "알 수 없는 문제");
    }
}

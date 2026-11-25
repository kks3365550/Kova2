//! 암호로 보호한 키 파일(.kovakey). 복구 코드(평문 16진수)를 종이·메모에 두는 대신,
//! 암호(scrypt) + AES-256-GCM 으로 감싼 파일 하나로 다른 PC에 키를 옮기거나 에스크로 보관한다.
//! 파일에는 저장소 경로·프로파일 이름과 복구 코드가 들어 있으나, 암호 없이는 읽을 수 없다.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};

const MAGIC: &str = "kova2-keybundle";
const AAD: &[u8] = b"kova2-keybundle-v1";
// scrypt: N=2^15, r=8, p=1 (약 0.1초, 무차별 대입 비용을 높임)
const KDF_N: u32 = 1 << 15;
const MIN_PASS_CHARS: usize = 8;

#[derive(Serialize, Deserialize)]
struct Envelope {
    magic: String,
    version: u32,
    n: u32,
    r: u32,
    p: u32,
    salt: String,
    nonce: String,
    ct: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub name: String,
    pub repo: String,
    pub code: String,
}

fn cipher(pass: &str, salt: &[u8], n: u32, r: u32, p: u32) -> Result<Aes256Gcm, String> {
    // 파일이 요구하는 비용 매개변수에 상한을 둔다(악성 파일로 메모리·시간을 소진시키지 못하게)
    if n > (1 << 20) || r > 16 || p > 4 {
        return Err("키 파일의 암호 설정이 올바르지 않습니다".into());
    }
    let key = crate::crypto::derive_key(pass, salt, n, r, p).map_err(|e| e.to_string())?;
    Ok(Aes256Gcm::new_from_slice(&key).expect("32바이트 키"))
}

/// 항목들을 암호로 감싼 키 파일 내용(JSON 텍스트)으로 만든다.
pub fn seal(entries: &[KeyEntry], pass: &str) -> Result<String, String> {
    if pass.chars().count() < MIN_PASS_CHARS {
        return Err(format!("암호는 {MIN_PASS_CHARS}자 이상이어야 합니다"));
    }
    if entries.is_empty() {
        return Err("내보낼 암호화 저장소 키가 없습니다".into());
    }
    let salt = crate::crypto::random_bytes::<16>();
    let nonce = crate::crypto::random_bytes::<12>();
    let c = cipher(pass, &salt, KDF_N, 8, 1)?;
    let plain = serde_json::to_vec(entries).map_err(|e| e.to_string())?;
    let ct = c
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: AAD,
            },
        )
        .map_err(|_| "암호화 실패".to_string())?;
    let env = Envelope {
        magic: MAGIC.into(),
        version: 1,
        n: KDF_N,
        r: 8,
        p: 1,
        salt: crate::crypto::hex(&salt),
        nonce: crate::crypto::hex(&nonce),
        ct: crate::crypto::hex(&ct),
    };
    serde_json::to_string_pretty(&env).map_err(|e| e.to_string())
}

/// 키 파일 내용을 암호로 풀어 항목을 돌려준다. 암호가 틀리거나 파일이 변조되면 같은 오류를 낸다.
pub fn open(text: &str, pass: &str) -> Result<Vec<KeyEntry>, String> {
    let env: Envelope = serde_json::from_str(text).map_err(|_| "키 파일 형식이 아닙니다")?;
    if env.magic != MAGIC || env.version != 1 {
        return Err("지원하지 않는 키 파일입니다".into());
    }
    let bad = || "키 파일을 열 수 없습니다(암호가 틀렸거나 파일이 손상됨)".to_string();
    let salt = crate::crypto::unhex(&env.salt).ok_or_else(bad)?;
    let nonce = crate::crypto::unhex(&env.nonce).ok_or_else(bad)?;
    let ct = crate::crypto::unhex(&env.ct).ok_or_else(bad)?;
    if nonce.len() != 12 {
        return Err(bad());
    }
    let c = cipher(pass, &salt, env.n, env.r, env.p)?;
    let plain = c
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: AAD })
        .map_err(|_| bad())?;
    serde_json::from_slice(&plain).map_err(|_| bad())
}

/// 키 파일을 열어 이 PC의 암호화 저장소 키를 복원한다. 복원한 저장소 수를 돌려준다.
pub fn import(
    store: &crate::config::ConfigStore,
    text: &str,
    pass: &str,
) -> Result<String, String> {
    let entries = open(text, pass)?;
    let (mut ok, mut missing) = (0usize, 0usize);
    for e in &entries {
        if crate::repocrypto::restore_keys_at(store, &e.code, Some(&e.repo)).is_ok() {
            ok += 1;
        } else {
            missing += 1;
        }
    }
    if ok == 0 {
        return Err(
            "맞는 암호화 저장소를 찾지 못했습니다. 저장소 드라이브가 연결돼 있는지 보세요".into(),
        );
    }
    Ok(format!(
        "키를 복원했습니다 (키 {ok}개{})",
        if missing > 0 {
            format!(", 저장소를 못 찾은 키 {missing}개")
        } else {
            String::new()
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e() -> Vec<KeyEntry> {
        vec![KeyEntry {
            name: "회계".into(),
            repo: "D:/repo".into(),
            code: "0123abcd".repeat(8),
        }]
    }

    #[test]
    fn roundtrip_and_wrong_password_and_tamper() {
        let t = seal(&e(), "correct horse 1").unwrap();
        assert!(!t.contains("0123abcd"), "평문 코드가 새면 안 된다");
        assert_eq!(open(&t, "correct horse 1").unwrap(), e());
        assert!(open(&t, "wrong password 1").is_err());
        // 암호문 한 글자 변조 → 인증 실패
        let mut v: serde_json::Value = serde_json::from_str(&t).unwrap();
        let ct = v["ct"].as_str().unwrap().to_string();
        let flipped = format!(
            "{}{}",
            if ct.starts_with('0') { "1" } else { "0" },
            &ct[1..]
        );
        v["ct"] = flipped.into();
        assert!(open(&v.to_string(), "correct horse 1").is_err());
        // 같은 입력도 소금·논스가 달라 결과가 다르다
        assert_ne!(t, seal(&e(), "correct horse 1").unwrap());
    }

    #[test]
    fn rejects_short_password_empty_and_hostile_params() {
        assert!(seal(&e(), "short").is_err());
        assert!(seal(&[], "long enough pw").is_err());
        let t = seal(&e(), "long enough pw").unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&t).unwrap();
        v["n"] = (1u64 << 30).into();
        assert!(open(&v.to_string(), "long enough pw").is_err());
        assert!(open("not json", "long enough pw").is_err());
    }
}

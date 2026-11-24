//! 제외 필터 (core/filter.py 이식). 패턴은 소문자 비교, 구조는 파이썬과 동일하다.
use std::collections::HashSet;

pub const DEFAULT_EXCLUDE_PATTERNS: &[&str] = &[
    "$RECYCLE.BIN",
    "$Recycle.Bin",
    "System Volume Information",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "DumpStack.log.tmp",
    "Thumbs.db",
    "desktop.ini",
    "*.etl",
    "LiveKernelReports",
    "WindowsApps",
    "Temporary Internet Files",
    "UsrClass.dat*",
    "WebCacheLock.dat",
    "WindowsImageBackup",
    "MyBackup_Repository",
    "backup_repository",
    "emergency_restore",
    "*.blob",
    "*.tmp",
    "*.temp",
    "*.lock",
    "lockfile",
    "*~*",
    "~$*",
    "*.crdownload",
    "*.part",
    "*.swp",
    "*.swo",
    "*.dmp",
    "*.mdmp",
    "*.hdmp",
    "CrashDumps",
    "*Crashpad*",
    "*CrashReporting*",
    "*crash_reports*",
    "SoftwareDistribution",
    "DeliveryOptimization",
    "INetCache",
    "*thumbcache*.db",
    "Cache",
    "Caches",
    "*GPUCache*",
    "*Code Cache*",
    "*ShaderCache*",
    "*DawnCache*",
    "*D3DSCache*",
    "*GrShaderCache*",
    "*DirectXShaderCache*",
    "*CacheStorage*",
    "*Service Worker*",
    "*blob_storage*",
    "*SquirrelTemp*",
    "pip/cache",
    "npm-cache",
    "yarn-cache",
    "Package Cache",
    ".gradle/caches",
    ".m2/repository",
    ".nuget/packages",
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".git",
    "node_modules",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".turbo",
    ".parcel-cache",
    "*.iso",
    "*.vhdx",
    "*.vmdk",
    "*.vdi",
    "*.qcow2",
    "*userdata*.img",
    "*system*.img",
];

/// 이 이름의 디렉터리는 (기본 규칙과 별개로) 항상 휘발성 캐시로 본다.
const VOLATILE_DIRS: &[&str] = &[
    "cache",
    "caches",
    "gpucache",
    "shadercache",
    "code cache",
    "temp",
    "tmp",
    "crashpad",
    "crashreporting",
    "logs",
    "log",
];

/// 파이썬 fnmatch 호환 글롭(`*`, `?`, `[seq]`, `[!seq]`). 입력은 이미 소문자.
/// 반복적 투포인터 구현으로 최악의 와일드카드 조합에서도 O(n * m) 안에 끝난다.
pub fn fnmatch(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            star_pi = Some(pi);
            star_ti = ti;
            continue;
        }
        if pi < p.len() {
            if let Some(next_pi) = match_one(t[ti], &p, pi) {
                ti += 1;
                pi = next_pi;
                continue;
            }
        }
        if let Some(sp) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = sp;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn match_one(ch: char, p: &[char], pi: usize) -> Option<usize> {
    match p[pi] {
        '?' => Some(pi + 1),
        '[' => {
            if let Some(rel_end) = p[pi..].iter().skip(2).position(|&c| c == ']') {
                let end = pi + 2 + rel_end;
                let (neg, set) = if p[pi + 1] == '!' {
                    (true, &p[pi + 2..end])
                } else {
                    (false, &p[pi + 1..end])
                };
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        if set[i] <= ch && ch <= set[i + 2] {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if set[i] == ch {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                (hit != neg).then_some(end + 1)
            } else {
                (ch == '[').then_some(pi + 1)
            }
        }
        c => (ch == c).then_some(pi + 1),
    }
}

fn norm(p: &str) -> String {
    p.replace('\\', "/").to_lowercase()
}

pub struct PathFilter {
    exact: HashSet<String>,
    exts: HashSet<String>,
    substrs: Vec<String>,
    complex: Vec<String>,
    protected: Vec<String>,
}

impl PathFilter {
    pub fn new(exclude: &[String], use_defaults: bool, protected_prefixes: &[String]) -> Self {
        let mut raw: Vec<String> = if use_defaults {
            DEFAULT_EXCLUDE_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            vec![]
        };
        for p in exclude {
            let p = p.trim();
            if !p.is_empty() && !raw.iter().any(|r| r == p) {
                raw.push(p.to_string());
            }
        }
        let mut protected = vec![];
        if let Ok(v) = std::env::var("LOCALAPPDATA") {
            protected.push(norm(&format!("{v}/hermes")));
        }
        if let Ok(v) = std::env::var("APPDATA") {
            protected.push(norm(&format!("{v}/uv")));
        }
        for p in protected_prefixes {
            let n = norm(p);
            if !protected.contains(&n) {
                protected.push(n);
            }
        }
        let (mut exact, mut exts, mut substrs, mut complex) =
            (HashSet::new(), HashSet::new(), vec![], vec![]);
        for pat in raw {
            let p = pat.trim().to_lowercase();
            if p.is_empty() || p.starts_with('#') {
                continue;
            }
            let has_wild = |s: &str| s.contains(['*', '?', '[']);
            if p.starts_with("*.") && !has_wild(&p[2..]) && !p[2..].contains('.') {
                exts.insert(p[1..].to_string());
            } else if p.starts_with('*')
                && p.ends_with('*')
                && p.len() > 2
                && !has_wild(&p[1..p.len() - 1])
            {
                substrs.push(p[1..p.len() - 1].to_string());
            } else if has_wild(&p) {
                complex.push(p);
            } else {
                exact.insert(p);
            }
        }
        Self {
            exact,
            exts,
            substrs,
            complex,
            protected,
        }
    }

    fn protected_match(&self, np: &str) -> Option<&str> {
        self.protected.iter().map(String::as_str).find(|p| {
            let p = p.trim_end_matches('/');
            !p.is_empty()
                && (np == p || np.strip_prefix(p).is_some_and(|rest| rest.starts_with('/')))
        })
    }

    fn matches_common(&self, name: &str) -> bool {
        self.exact.contains(name)
            || self.substrs.iter().any(|s| name.contains(s.as_str()))
            || self.complex.iter().any(|c| fnmatch(name, c))
    }

    fn ext_of(name: &str) -> Option<&str> {
        name.rfind('.').map(|i| &name[i..])
    }

    pub fn is_dir_excluded(&self, dirname: &str, full_path: Option<&str>) -> bool {
        let dn = dirname.to_lowercase();
        if let Some(fp) = full_path {
            let nf = norm(fp);
            if self.protected_match(&nf).is_some() {
                // 보호 구역 안에서는 순수 휘발성 캐시만 제외 (venv, node_modules 등은 통과)
                return VOLATILE_DIRS.contains(&dn.as_str()) || dn == "__pycache__";
            }
            for cp in &self.complex {
                if fnmatch(&nf, cp) || fnmatch(&nf, &format!("*{cp}*")) {
                    return true;
                }
            }
        }
        if VOLATILE_DIRS.contains(&dn.as_str()) || dn == "deliveryoptimization" {
            return true;
        }
        self.matches_common(&dn)
    }

    pub fn is_file_excluded(&self, filename: &str) -> bool {
        let fn_ = filename.to_lowercase();
        let ext_hit = Self::ext_of(&fn_).is_some_and(|e| self.exts.contains(e));
        // .py 는 'cache' 같은 부분 문자열 규칙에 걸리지 않게 보호 (예: linecache.py)
        if fn_.ends_with(".py") {
            return ext_hit || self.exact.contains(&fn_);
        }
        ext_hit || self.matches_common(&fn_)
    }

    pub fn is_excluded(&self, path: &str, is_dir: bool) -> bool {
        let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
        if is_dir {
            if self.is_dir_excluded(base, Some(path)) {
                return true;
            }
        } else if self.is_file_excluded(base) {
            return true;
        }
        let np = norm(path);
        if let Some(pref) = self.protected_match(&np) {
            let rel = np
                .strip_prefix(pref.trim_end_matches('/'))
                .unwrap_or("")
                .trim_start_matches('/');
            let dirs = if is_dir {
                rel
            } else {
                rel.rsplit_once('/').map_or("", |(parent, _)| parent)
            };
            return dirs
                .split('/')
                .filter(|part| !part.is_empty())
                .any(|part| VOLATILE_DIRS.contains(&part) || part == "__pycache__");
        }
        if np.split('/').any(|part| self.exact.contains(part)) {
            return true;
        }
        self.complex.iter().any(|cp| {
            fnmatch(&np, cp)
                || fnmatch(&np, &format!("*/{cp}/*"))
                || fnmatch(&np, &format!("*/{cp}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f() -> PathFilter {
        PathFilter::new(&[], true, &[])
    }

    #[test]
    fn fnmatch_basics() {
        assert!(fnmatch("usrclass.dat.log1", "usrclass.dat*"));
        assert!(fnmatch("a/b/c", "*/b/*"));
        assert!(fnmatch("file1.txt", "file[0-9].txt") && !fnmatch("filex.txt", "file[0-9].txt"));
        assert!(fnmatch("filex.txt", "file[!0-9].txt") && fnmatch("ab", "a?"));
    }

    #[test]
    fn files_and_dirs() {
        let f = f();
        assert!(f.is_file_excluded("a.TMP") && f.is_file_excluded("pagefile.sys"));
        assert!(f.is_file_excluded("~$문서.docx") && f.is_file_excluded("x.vhdx"));
        assert!(!f.is_file_excluded("보고서.xlsx"));
        assert!(f.is_dir_excluded("node_modules", None) && f.is_dir_excluded("GPUCache", None));
        assert!(!f.is_dir_excluded("src", None));
    }

    #[test]
    fn python_sources_survive_substring_rules() {
        let f = f();
        assert!(!f.is_file_excluded("linecache.py"));
        assert!(f.is_file_excluded("mod.pyc"));
    }

    #[test]
    fn ancestor_and_user_patterns() {
        let f = PathFilter::new(&["내부자료".to_string()], true, &[]);
        assert!(f.is_excluded(r"C:\data\node_modules\x\y.js", false));
        assert!(f.is_excluded(r"C:\data\내부자료\a.txt", false));
        assert!(!f.is_excluded(r"C:\data\문서\a.txt", false));
    }

    #[test]
    fn protected_prefix_keeps_venv_but_drops_cache() {
        let f = PathFilter::new(&[], true, &[r"C:\ai\runtime".to_string()]);
        assert!(!f.is_dir_excluded("node_modules", Some(r"C:\ai\runtime\node_modules")));
        assert!(f.is_dir_excluded("cache", Some(r"C:\ai\runtime\cache")));
        // is_excluded 도 보호 구역을 존중해야 한다
        assert!(!f.is_excluded(r"C:\ai\runtime\node_modules", true));
        assert!(!f.is_excluded(r"C:\ai\runtime\node_modules\pkg\index.js", false));
        assert!(!f.is_excluded(r"C:\ai\runtime\venv\lib\site.py", false));
        assert!(f.is_excluded(r"C:\ai\runtime\cache", true));
        assert!(f.is_excluded(r"C:\ai\runtime\cache\item.dat", false));
        assert!(f.is_excluded(r"C:\ai\runtime\venv\__pycache__\a.dat", false));
        // 보호 구역 바깥의 비슷한 접두어 경로는 보호하지 않는다
        assert!(f.is_excluded(r"C:\ai\runtime2\node_modules\a.js", false));
    }

    #[test]
    fn compound_extension_and_wildcard_extension_patterns_match() {
        let f = PathFilter::new(&["*.tar.gz".to_string(), "*.log*".to_string()], false, &[]);
        assert!(f.is_file_excluded("backup.tar.gz"));
        assert!(!f.is_file_excluded("backup.gz"));
        assert!(f.is_file_excluded("app.log"));
        assert!(f.is_file_excluded("app.log.1"));
        assert!(!f.is_file_excluded("app.txt"));
    }

    #[test]
    fn fnmatch_handles_pathological_wildcards_quickly() {
        let text = "a".repeat(80);
        let pat = format!("{}b", "*a".repeat(20));
        assert!(!fnmatch(&text, &pat));
        assert!(fnmatch(&format!("{text}b"), &pat));
        assert!(fnmatch("axbxb", "a**b"));
        assert!(fnmatch("a", "a***"));
        assert!(fnmatch("", "***"));
    }
}

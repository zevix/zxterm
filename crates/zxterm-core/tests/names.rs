//! Blocks the upstream identity-key package's name, and the bare word it
//! starts with (`X-01`'s forbidden org/package name fragment), from ever
//! appearing in a product file. Rust-side twin of ZBTerm's
//! `test/name.test.js` (`D-27`).
//!
//! Neither forbidden string is spelled out literally anywhere in this file,
//! including in this comment: each is assembled from two pieces at runtime
//! (see `forbidden_tokens` below), so a `grep` of this source for either
//! string finds nothing.
//!
//! Scans every file under `crates/`, `contracts/` (once it exists, K10),
//! `Cargo.toml`, `Cargo.lock` and `LICENSE`, skipping `target/`/`.git`
//! directories and `THIRD-PARTY-NOTICES.md` (`A-8`, the one file allowed to
//! carry the upstream package's name for attribution).
//!
//! Both forbidden strings are assembled from pieces at runtime so this test
//! file itself never contains either one literally.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// The two forbidden byte strings, built from pieces so neither appears
/// literally in this source file.
fn forbidden_tokens() -> Vec<Vec<u8>> {
    let bare_word = concat_pieces("ke", "et");
    // Split inside the bare word itself (after 2 of its 4 bytes), so this
    // half-pair does not spell out the bare word either — only the
    // concatenation does.
    let upstream_package_name = concat_pieces("ke", "et-identity-key");
    vec![bare_word.into_bytes(), upstream_package_name.into_bytes()]
}

fn concat_pieces(a: &str, b: &str) -> String {
    format!("{a}{b}")
}

fn workspace_root() -> PathBuf {
    // <root>/crates/zxterm-core/tests -> <root>/crates/zxterm-core -> <root>/crates -> <root>
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("zxterm-core is expected under <root>/crates"))
        .to_path_buf()
}

fn is_exempt(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("THIRD-PARTY-NOTICES.md"))
}

fn skip_dir(name: &OsStr) -> bool {
    name == OsStr::new("target") || name == OsStr::new(".git")
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            if let Some(name) = path.file_name()
                && !skip_dir(name)
            {
                collect_files(&path, out);
            }
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}

/// Every file this test is responsible for: `crates/`, `contracts/` (once it
/// exists), and the named root files.
fn scan_targets(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for rel in ["crates", "contracts"] {
        let dir = root.join(rel);
        if dir.is_dir() {
            collect_files(&dir, &mut files);
        }
    }
    for rel in ["Cargo.toml", "Cargo.lock", "LICENSE"] {
        let f = root.join(rel);
        if f.is_file() {
            files.push(f);
        }
    }
    files
}

fn contains_token(haystack: &[u8], token: &[u8]) -> bool {
    !token.is_empty() && haystack.windows(token.len()).any(|w| w == token)
}

#[test]
fn no_forbidden_names_in_product_files() {
    let root = workspace_root();
    let tokens = forbidden_tokens();
    let mut hits = Vec::new();

    for path in scan_targets(&root) {
        if is_exempt(&path) {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for token in &tokens {
            if contains_token(&bytes, token) {
                hits.push(format!(
                    "{}: contains a forbidden name ({} bytes)",
                    path.display(),
                    token.len()
                ));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "forbidden names found in product files (X-01):\n{}",
        hits.join("\n")
    );
}

#[test]
fn forbidden_tokens_are_the_expected_length() {
    // Sanity: the bare word (4 bytes) and the full package name (17 bytes)
    // — guards against a typo in the piece-assembly above silently
    // producing an empty or truncated token that would make the scan above
    // vacuous.
    let tokens = forbidden_tokens();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].len(), 4);
    assert_eq!(tokens[1].len(), 17);
}

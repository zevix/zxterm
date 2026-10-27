//! `~/.ssh/config` parsing and default key-file discovery, ported from
//! ZBTerm `electron/ssh-keys.js` (`identityFilesForHost`/`resolveIncludes`/
//! `hostPatternMatches`/`listDefaultKeyFiles`), byte-for-byte.
//!
//! `SSH_CONFIG_HOST` and `DEFAULT_KEY_EXCLUDES` are ssh-keys.js's own
//! application-level defaults, not part of any wire/signature/derivation
//! format, so they live here rather than in `zxterm_core::wire`.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// `SSH_CONFIG_HOST` (ssh-keys.js).
pub const SSH_CONFIG_HOST: &str = "github.com";

/// `Include` is resolved exactly one level deep; an `Include` inside an
/// included file is ignored (`INCLUDE_DEPTH` in ssh-keys.js).
const INCLUDE_DEPTH: i32 = 1;

/// A directive read from a `~/.ssh/config`-family file: lowercased keyword,
/// trimmed value.
type Directive = (String, String);

/// `expandPath` (ssh-keys.js): strips surrounding quotes, expands `%d` to
/// `home`, `~`/`~/...`, and resolves a bare relative name against
/// `home/.ssh`.
pub(crate) fn expand_path(value: &str, home: &Path) -> PathBuf {
    let mut out = value.trim().to_string();
    if out.starts_with('"') && out.ends_with('"') && out.len() > 1 {
        out = out[1..out.len() - 1].to_string();
    }
    let home_str = home.to_string_lossy().into_owned();
    out = out.replace("%d", &home_str);
    if out == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = out.strip_prefix("~/") {
        return home.join(rest);
    }
    let candidate = Path::new(&out);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        home.join(".ssh").join(&out)
    }
}

/// `parseConfigLine` (ssh-keys.js): `/^([A-Za-z0-9_-]+)\s*(?:=|\s)\s*(.*)$/`
/// against the line with only its leading whitespace stripped, ported as a
/// direct character walk rather than a regex (this crate has no `regex`
/// dependency).
fn parse_config_line(line: &str) -> Option<Directive> {
    let stripped = line.trim_start();
    if stripped.is_empty() || stripped.starts_with('#') {
        return None;
    }
    let chars: Vec<char> = stripped.chars().collect();
    let mut i = 0;
    while i < chars.len()
        && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '-')
    {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let keyword: String = chars[..i].iter().collect::<String>().to_ascii_lowercase();

    let mut j = i;
    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }
    let had_ws_run = j > i;
    let sep_at_j_is_eq = j < chars.len() && chars[j] == '=';
    if !had_ws_run && !sep_at_j_is_eq {
        return None;
    }
    let mut k = j;
    if sep_at_j_is_eq {
        k += 1;
    }
    while k < chars.len() && chars[k].is_whitespace() {
        k += 1;
    }
    let value: String = chars[k..].iter().collect::<String>().trim().to_string();
    if value.is_empty() {
        return None;
    }
    Some((keyword, value))
}

/// `splitArgs` (ssh-keys.js): `/"([^"]*)"|(\S+)/g` — a quoted run (content
/// only, sans quotes) or a run of non-whitespace, ported as a direct
/// character walk.
fn split_args(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        if chars[i] == '"'
            && let Some(rel_close) = chars[i + 1..].iter().position(|&c| c == '"')
        {
            let close = i + 1 + rel_close;
            out.push(chars[i + 1..close].iter().collect());
            i = close + 1;
            continue;
        }
        // A `"` with no later closing quote: the `"([^"]*)"` alternative
        // fails, so the regex falls through to `(\S+)` starting at the
        // quote itself.
        let start = i;
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        out.push(chars[start..i].iter().collect());
    }
    out
}

/// A simple `*`/`?` glob matcher (OpenSSH host-pattern semantics): `*`
/// matches any run, `?` matches exactly one character, everything else is
/// literal. This crate has no `regex` dependency, so this replaces the JS
/// twin's escape-then-regex approach with an equivalent direct matcher.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some('*') => {
            for i in 0..=text.len() {
                if glob_match(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        Some('?') => !text.is_empty() && glob_match(&pattern[1..], &text[1..]),
        Some(c) => !text.is_empty() && text[0] == *c && glob_match(&pattern[1..], &text[1..]),
    }
}

fn glob_match_str(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match(&p, &t)
}

/// `hostPatternMatches` (ssh-keys.js): `!`-negated patterns veto immediately
/// (short-circuiting the whole match); a positive match just records
/// `matched = true` and keeps evaluating (a later negation can still veto).
pub(crate) fn host_pattern_matches(patterns: &[String], host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        let (negated, body) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern.as_str()),
        };
        if !glob_match_str(body, host) {
            continue;
        }
        if negated {
            return false;
        }
        matched = true;
    }
    matched
}

/// `path.resolve` equivalent: makes `p` absolute against the current
/// directory if it is not already, then lexically collapses `.`/`..`
/// components (no symlink resolution, no filesystem access — `path.resolve`
/// does not require the path to exist).
fn lexical_resolve(p: &Path) -> PathBuf {
    let base = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(p)
    };
    let mut out: Vec<Component> = Vec::new();
    for component in base.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    let mut result = PathBuf::new();
    for c in out {
        result.push(c.as_os_str());
    }
    result
}

/// `resolveIncludes` (ssh-keys.js): a literal path is used as-is; a
/// glob-bearing basename is matched against its directory's entries, sorted.
fn resolve_includes(value: &str, home: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for arg in split_args(value) {
        let target = expand_path(&arg, home);
        let dir = target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        let base = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !base.contains('*') && !base.contains('?') {
            files.push(target);
            continue;
        }
        let mut entries: Vec<String> = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => continue,
        };
        entries.sort();
        for entry in entries {
            if glob_match_str(&base, &entry) {
                files.push(dir.join(&entry));
            }
        }
    }
    files
}

/// `flattenConfig` (ssh-keys.js): the flat directive list of `file` with
/// `Include`s spliced in at the position they appear, up to `depth` levels.
fn flatten_config(
    file: &Path,
    home: &Path,
    depth: i32,
    seen: &mut HashSet<PathBuf>,
) -> Vec<Directive> {
    let resolved = lexical_resolve(file);
    if seen.contains(&resolved) {
        return Vec::new();
    }
    seen.insert(resolved.clone());
    let text = match fs::read_to_string(&resolved) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let Some((keyword, value)) = parse_config_line(line) else {
            continue;
        };
        if keyword == "include" {
            if depth <= 0 {
                continue;
            }
            for included in resolve_includes(&value, home) {
                out.extend(flatten_config(&included, home, depth - 1, seen));
            }
            continue;
        }
        out.push((keyword, value));
    }
    out
}

/// `identityFilesForHost` (ssh-keys.js): the first `Host` block whose
/// patterns match `host` and that carries at least one `IdentityFile` wins;
/// a `Match` line ends the current block without ever being evaluated.
pub fn identity_files_for_host(
    home: &Path,
    host: &str,
    config_path: Option<&Path>,
) -> Vec<PathBuf> {
    let file: PathBuf = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".ssh").join("config"));
    let mut seen = HashSet::new();
    let directives = flatten_config(&file, home, INCLUDE_DEPTH, &mut seen);

    struct Block {
        patterns: Vec<String>,
        identity_files: Vec<PathBuf>,
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut current: Option<usize> = None;

    for (keyword, value) in directives {
        match keyword.as_str() {
            "host" => {
                blocks.push(Block {
                    patterns: split_args(&value),
                    identity_files: Vec::new(),
                });
                current = Some(blocks.len() - 1);
            }
            "match" => current = None,
            "identityfile" => {
                if let Some(idx) = current {
                    for arg in split_args(&value) {
                        blocks[idx].identity_files.push(expand_path(&arg, home));
                    }
                }
            }
            _ => {}
        }
    }

    for block in &blocks {
        if !host_pattern_matches(&block.patterns, host) {
            continue;
        }
        if block.identity_files.is_empty() {
            continue;
        }
        return block.identity_files.clone();
    }
    Vec::new()
}

fn is_default_key_exclude(name: &str) -> bool {
    // `DEFAULT_KEY_EXCLUDES = /^(config|authorized_keys|known_hosts.*)$/`
    // (ssh-keys.js). Ported faithfully even though it can never match here:
    // every `name` reaching this check already starts with `id_` (the
    // caller's own filter), so none of these three alternatives can ever be
    // equal to it.
    name == "config" || name == "authorized_keys" || name.starts_with("known_hosts")
}

/// `listDefaultKeyFiles` (ssh-keys.js): every `id_*` basename under
/// `home/.ssh`, deduplicating a lone `.pub` to its private-key path, sorted.
pub(crate) fn list_default_key_files(home: &Path) -> Vec<PathBuf> {
    let dir = home.join(".ssh");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut names: BTreeSet<String> = BTreeSet::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let entry_name = entry.file_name().to_string_lossy().into_owned();
        if !entry_name.starts_with("id_") {
            continue;
        }
        let name = entry_name
            .strip_suffix(".pub")
            .map(str::to_string)
            .unwrap_or(entry_name);
        if name.is_empty() || is_default_key_exclude(&name) {
            continue;
        }
        names.insert(name);
    }
    names.into_iter().map(|n| dir.join(n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_line_handles_equals_and_whitespace_separators() {
        assert_eq!(
            parse_config_line("Host github.com"),
            Some(("host".to_string(), "github.com".to_string()))
        );
        assert_eq!(
            parse_config_line("  IdentityFile = ~/.ssh/id_ed25519  "),
            Some(("identityfile".to_string(), "~/.ssh/id_ed25519".to_string()))
        );
        assert_eq!(parse_config_line("# a comment"), None);
        assert_eq!(parse_config_line(""), None);
        assert_eq!(parse_config_line("Host"), None);
        assert_eq!(parse_config_line("Host   "), None);
    }

    #[test]
    fn split_args_handles_quotes_and_unclosed_quotes() {
        assert_eq!(
            split_args(r#"conf.d/*.conf "with space" plain"#),
            vec!["conf.d/*.conf", "with space", "plain"]
        );
        assert_eq!(split_args(r#""unclosed"#), vec![r#""unclosed"#]);
    }

    #[test]
    fn host_pattern_matches_wildcards_and_negation() {
        assert!(host_pattern_matches(&["*".to_string()], "github.com"));
        assert!(host_pattern_matches(
            &["github.*".to_string()],
            "github.com"
        ));
        assert!(!host_pattern_matches(
            &["*".to_string(), "!github.com".to_string()],
            "github.com"
        ));
    }

    #[test]
    fn expand_path_handles_tilde_and_percent_d() {
        let home = Path::new("/home/z");
        assert_eq!(expand_path("~", home), home);
        assert_eq!(
            expand_path("~/.ssh/id_ed25519", home),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(
            expand_path("%d/.ssh/id_ed25519", home),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(
            expand_path("id_ed25519", home),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(expand_path("/abs/path", home), PathBuf::from("/abs/path"));
    }
}

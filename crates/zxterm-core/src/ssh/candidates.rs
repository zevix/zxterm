//! SSH-key candidate enumeration, ported from ZBTerm `electron/ssh-keys.js`
//! (`listCandidates`/`inspectKey`/`signability`/`sortRank`).
//!
//! Never panics on a single bad key: a parse failure is reported as one
//! `Candidate` with `signable: false` and a `reason`, exactly as the JS twin
//! never throws from `listCandidates`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::agent::{AgentIdentity, agent_identities};
use super::codec::base64_encode;
use super::config::{
    SSH_CONFIG_HOST, expand_path, identity_files_for_host, list_default_key_files,
};
use super::key::{
    DescribedFile, describe_file, fingerprint, key_type_of, unsupported_key_type_reason,
};
use crate::error::{Code, Error};

/// `candidate.source` (ssh-keys.js): `"ssh-config" | "default" | "agent" |
/// "manual"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    SshConfig,
    Default,
    Agent,
    Manual,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::SshConfig => "ssh-config",
            Source::Default => "default",
            Source::Agent => "agent",
            Source::Manual => "manual",
        }
    }
}

/// `listCandidates`/`inspectKey`'s per-key return shape (ssh-keys.js).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: Option<PathBuf>,
    pub source: Source,
    pub key_type: Option<String>,
    pub fingerprint: Option<String>,
    pub comment: String,
    pub public_key_blob_base64: Option<String>,
    pub encrypted: bool,
    pub signable: bool,
    pub reason: Option<String>,
}

struct Verdict {
    signable: bool,
    reason: Option<String>,
}

/// `signability` (ssh-keys.js), byte-for-byte, including its exact reason
/// text.
fn signability(
    key_type: Option<&str>,
    encrypted: bool,
    has_private: bool,
    error: Option<&str>,
    in_agent: bool,
    path: Option<&Path>,
) -> Verdict {
    let Some(key_type) = key_type else {
        return Verdict {
            signable: false,
            reason: Some(error.unwrap_or("Key could not be parsed").to_string()),
        };
    };
    if key_type != crate::wire::KEY_TYPE && key_type != crate::wire::RSA_KEY_TYPE {
        return Verdict {
            signable: false,
            reason: Some(unsupported_key_type_reason(key_type)),
        };
    }
    if in_agent {
        return Verdict {
            signable: true,
            reason: None,
        };
    }
    if encrypted {
        let hint = match path {
            Some(p) => format!("ssh-add {}", p.display()),
            None => "ssh-add".to_string(),
        };
        return Verdict {
            signable: false,
            reason: Some(format!(
                "Key is passphrase-protected - add it to ssh-agent ({hint}) to sign with it"
            )),
        };
    }
    if !has_private {
        let reason = match error {
            Some(e) => format!("{e} - add the key to ssh-agent to sign with it"),
            None => "Private key file is not available - add the key to ssh-agent to sign with it"
                .to_string(),
        };
        return Verdict {
            signable: false,
            reason: Some(reason),
        };
    }
    Verdict {
        signable: true,
        reason: None,
    }
}

/// `sortRank` (ssh-keys.js): `ssh-config` first, then `default` with
/// `id_ed25519` ahead of every other default basename, then everything else
/// (agent-only); ties break by original discovery order (a stable sort).
fn sort_rank(source: Source, path: Option<&Path>) -> u8 {
    match source {
        Source::SshConfig => 0,
        Source::Default => {
            let basename = path
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if basename == "id_ed25519" { 1 } else { 2 }
        }
        Source::Agent | Source::Manual => 3,
    }
}

fn candidate_from_file(
    file: &Path,
    source: Source,
    info: &DescribedFile,
    in_agent: bool,
    agent_comment: Option<&str>,
) -> Candidate {
    let blob_b64 = info.public_key_blob.as_ref().map(|b| base64_encode(b));
    let verdict = signability(
        info.key_type.as_deref(),
        info.encrypted,
        info.has_private,
        info.error.as_deref(),
        in_agent,
        Some(file),
    );
    let comment = if !info.comment.is_empty() {
        info.comment.clone()
    } else if in_agent {
        agent_comment.unwrap_or_default().to_string()
    } else {
        String::new()
    };
    Candidate {
        path: Some(file.to_path_buf()),
        source,
        key_type: info.key_type.clone(),
        fingerprint: info.public_key_blob.as_ref().map(|b| fingerprint(b)),
        comment,
        public_key_blob_base64: blob_b64,
        encrypted: info.encrypted,
        signable: verdict.signable,
        reason: verdict.reason,
    }
}

/// `listCandidates` (ssh-keys.js). Enumerates every SSH key this user could
/// plausibly have: config-directed or default files, deduplicated against
/// ssh-agent's own identities, sorted by `sortRank`.
pub fn list_candidates(home: &Path, env: &HashMap<String, String>) -> Vec<Candidate> {
    let config_files = identity_files_for_host(home, SSH_CONFIG_HOST, None);
    let source = if config_files.is_empty() {
        Source::Default
    } else {
        Source::SshConfig
    };
    let files: Vec<PathBuf> = if config_files.is_empty() {
        list_default_key_files(home)
    } else {
        config_files
    };

    let agent_keys = agent_identities(env);
    let mut agent_by_blob: HashMap<String, &AgentIdentity> = HashMap::new();
    for key in &agent_keys {
        agent_by_blob.insert(base64_encode(&key.public_key_blob), key);
    }

    let mut candidates = Vec::new();
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    let mut used_agent_blobs: HashSet<String> = HashSet::new();

    for file in &files {
        if !seen_files.insert(file.clone()) {
            continue;
        }
        let info = describe_file(file);
        let blob_b64 = info.public_key_blob.as_ref().map(|b| base64_encode(b));
        let agent_hit = blob_b64
            .as_deref()
            .and_then(|b| agent_by_blob.get(b).copied());
        if let Some(b) = &blob_b64
            && agent_hit.is_some()
        {
            used_agent_blobs.insert(b.clone());
        }
        candidates.push(candidate_from_file(
            file,
            source,
            &info,
            agent_hit.is_some(),
            agent_hit.map(|k| k.comment.as_str()),
        ));
    }

    for key in &agent_keys {
        let blob_b64 = base64_encode(&key.public_key_blob);
        if used_agent_blobs.contains(&blob_b64) {
            continue;
        }
        used_agent_blobs.insert(blob_b64.clone());
        let Ok(key_type) = key_type_of(&key.public_key_blob) else {
            continue;
        };
        let verdict = signability(Some(&key_type), false, false, None, true, None);
        candidates.push(Candidate {
            path: None,
            source: Source::Agent,
            key_type: Some(key_type),
            fingerprint: Some(fingerprint(&key.public_key_blob)),
            comment: key.comment.clone(),
            public_key_blob_base64: Some(blob_b64),
            encrypted: false,
            signable: verdict.signable,
            reason: verdict.reason,
        });
    }

    let mut indexed: Vec<(usize, Candidate)> = candidates.into_iter().enumerate().collect();
    indexed.sort_by(|a, b| {
        let ra = sort_rank(a.1.source, a.1.path.as_deref());
        let rb = sort_rank(b.1.source, b.1.path.as_deref());
        ra.cmp(&rb).then(a.0.cmp(&b.0))
    });
    indexed.into_iter().map(|(_, c)| c).collect()
}

/// `inspectKey` (ssh-keys.js): describes exactly one key path,
/// `source: "manual"`. Errors when the path holds no key at all.
pub fn inspect_key(
    key_path: &str,
    home: &Path,
    env: &HashMap<String, String>,
) -> Result<Candidate, Error> {
    let raw = key_path.trim();
    if raw.is_empty() {
        return Err(Error::new(Code::EAuth, "A key file path is required"));
    }
    let mut file = expand_path(raw, home);
    if let Some(stripped) = file.to_string_lossy().strip_suffix(".pub") {
        file = PathBuf::from(stripped.to_string());
    }
    let info = describe_file(&file);
    let Some(public_key_blob) = &info.public_key_blob else {
        let message = info
            .error
            .clone()
            .unwrap_or_else(|| format!("No SSH key could be read from {}", file.display()));
        return Err(Error::new(Code::EAuth, message));
    };
    let blob_b64 = base64_encode(public_key_blob);
    let agent_keys = agent_identities(env);
    let in_agent = agent_keys
        .iter()
        .any(|k| base64_encode(&k.public_key_blob) == blob_b64);
    let verdict = signability(
        info.key_type.as_deref(),
        info.encrypted,
        info.has_private,
        info.error.as_deref(),
        in_agent,
        Some(file.as_path()),
    );
    Ok(Candidate {
        path: Some(file),
        source: Source::Manual,
        key_type: info.key_type.clone(),
        fingerprint: Some(fingerprint(public_key_blob)),
        comment: info.comment.clone(),
        public_key_blob_base64: Some(blob_b64),
        encrypted: info.encrypted,
        signable: verdict.signable,
        reason: verdict.reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_rank_orders_config_then_default_ed25519_then_default_other_then_agent() {
        assert_eq!(sort_rank(Source::SshConfig, None), 0);
        assert_eq!(
            sort_rank(Source::Default, Some(Path::new("/h/.ssh/id_ed25519"))),
            1
        );
        assert_eq!(
            sort_rank(Source::Default, Some(Path::new("/h/.ssh/id_rsa"))),
            2
        );
        assert_eq!(sort_rank(Source::Agent, None), 3);
        assert_eq!(sort_rank(Source::Manual, None), 3);
    }

    #[test]
    fn signability_reports_the_unsupported_key_type_reason_verbatim() {
        let verdict = signability(Some("ecdsa-sha2-nistp256"), false, true, None, false, None);
        assert!(!verdict.signable);
        assert_eq!(
            verdict.reason.unwrap(),
            "ZBTerm can only sign with ssh-ed25519 or ssh-rsa keys (this key is ecdsa-sha2-nistp256)"
        );
    }

    #[test]
    fn inspect_key_requires_a_path() {
        let home = std::env::temp_dir();
        let env = HashMap::new();
        let err = inspect_key("", &home, &env).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(err.message, "A key file path is required");
    }

    #[test]
    fn list_candidates_on_an_empty_home_is_empty() {
        let dir = std::env::temp_dir().join(format!("zx-cand-empty-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".ssh")).unwrap();
        let env = HashMap::new();
        let candidates = list_candidates(&dir, &env);
        assert!(candidates.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

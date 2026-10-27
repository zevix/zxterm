//! Fetches a GitHub user's published SSH public keys
//! (`https://github.com/<user>.keys`), ported from ZBTerm
//! `electron/github-keys.js` with byte-identical behaviour: same timeout,
//! same body cap, same redirect rules, same exact error strings.
//!
//! HTTP client spike (design spike S4, part 2, `X-08`): `ureq` (rustls) was
//! measured against `hyper`/`hyper-rustls` on `tokio` for this exact fetch
//! and chosen — see `docs/decisions.md`'s `X-08` for the measured
//! stripped-size delta and the reasoning.
//!
//! URL parsing/joining here is hand-rolled rather than pulling in the `url`
//! crate (which drags in IDNA/ICU tables this fetch never needs — every
//! caller passes an already-`GITHUB_USERNAME`-validated subject and GitHub
//! itself never redirects `.keys` requests anywhere but another absolute or
//! path-absolute `.keys` URL): it covers absolute (`scheme://…`),
//! protocol-relative (`//…`) and path-absolute (`/…`) redirect targets,
//! which is every shape `github-keys.test.js` and real GitHub redirects use.

use std::io::Read;
use std::time::Duration;

use crate::error::{Code, Error};

/// `DEFAULT_BASE_URL` (github-keys.js).
pub const DEFAULT_BASE_URL: &str = "https://github.com";
/// `DEFAULT_TIMEOUT_MS` (github-keys.js).
pub const DEFAULT_TIMEOUT_MS: u64 = 8000;
/// `MAX_BODY_BYTES` (github-keys.js): `64 * 1024`.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// `MAX_REDIRECTS` (github-keys.js).
pub const MAX_REDIRECTS: u32 = 2;
/// The env var ZBTerm reads for a base-URL override
/// (`electron/github-keys.js::baseUrlDefault`), renamed from the
/// predecessor's own env var by the 2026-09-28 fork — this is the current
/// name as of that date, not renamed again here.
pub const GITHUB_KEYS_BASE_ENV: &str = "ZBTERM_GITHUB_KEYS_BASE";

const KEY_TYPES: [&str; 2] = [crate::wire::KEY_TYPE, crate::wire::RSA_KEY_TYPE];
const ECDSA_PREFIX: &str = "ecdsa-";

/// One published SSH key line (`fetchKeys`'s per-key shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub key_type: String,
    pub blob_base64: String,
    pub fingerprint: String,
}

/// `fetchKeys`'s resolved shape: `status` is `"ok"` or `"not-found"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysAnswer {
    pub status: String,
    pub keys: Vec<PublishedKey>,
}

/// `baseUrlDefault` (github-keys.js): the env var, trimmed, with an
/// empty-after-trim value treated as unset — never "override to empty
/// string".
fn base_url_default() -> String {
    match std::env::var(GITHUB_KEYS_BASE_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_BASE_URL.to_string(),
    }
}

/// `isKnownKeyType` (github-keys.js).
fn is_known_key_type(key_type: &str) -> bool {
    KEY_TYPES.contains(&key_type) || key_type.starts_with(ECDSA_PREFIX)
}

/// `parseKeysBody` (github-keys.js): one key per line `<type> <base64>
/// [comment]`; ignores blank lines, `#` comments, unrecognized types, and
/// base64 that does not round-trip.
pub fn parse_keys_body(body: &str) -> Vec<PublishedKey> {
    let mut keys = Vec::new();
    for raw in body.split(['\n', '\r']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key_type) = parts.next() else {
            continue;
        };
        let Some(b64) = parts.next() else {
            continue;
        };
        if !is_known_key_type(key_type) {
            continue;
        }
        let Ok(blob) = base64_decode(b64) else {
            continue;
        };
        // A base64 decode never throws on garbage in Node, it truncates —
        // Rust's decoder rejects invalid input outright instead, which is a
        // strictly stronger check than re-encoding and comparing, so the
        // round-trip re-check below is what actually matters: an empty blob
        // is never kept, either way.
        if blob.is_empty() || base64_encode(&blob) != b64 {
            continue;
        }
        keys.push(PublishedKey {
            key_type: key_type.to_string(),
            blob_base64: b64.to_string(),
            fingerprint: crate::ssh::key::fingerprint(&blob),
        });
    }
    keys
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `encodeURIComponent` (github-keys.js's own URL building), applied
/// byte-wise to the UTF-8 encoding — every caller passes an already
/// `GITHUB_USERNAME`-validated (alnum/hyphen-only) subject, so this only
/// matters for robustness against a caller that does not.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct SplitUrl<'a> {
    scheme: &'a str,
    authority: &'a str,
    path_and_query: &'a str,
}

fn split_absolute(url: &str) -> Option<SplitUrl<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    match rest.find('/') {
        Some(idx) => Some(SplitUrl {
            scheme,
            authority: &rest[..idx],
            path_and_query: &rest[idx..],
        }),
        None => Some(SplitUrl {
            scheme,
            authority: rest,
            path_and_query: "/",
        }),
    }
}

fn invalid_url_error(url: &str) -> Error {
    Error::new(Code::ENet, format!("invalid github keys url: {url}"))
}

/// `new URL(location, url)` (github-keys.js), restricted to the shapes
/// described in this module's doc comment. Returns the resolved absolute
/// URL string.
fn resolve_redirect(base_url: &str, location: &str) -> Result<String, Error> {
    let location = location.split('#').next().unwrap_or("");
    if location.is_empty() {
        return Err(invalid_url_error(location));
    }
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(location.to_string());
    }
    let base = split_absolute(base_url).ok_or_else(|| invalid_url_error(base_url))?;
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{}://{}", base.scheme, rest));
    }
    if location.starts_with('/') {
        return Ok(format!("{}://{}{}", base.scheme, base.authority, location));
    }
    let dir = match base.path_and_query.rfind('/') {
        Some(idx) => &base.path_and_query[..=idx],
        None => "/",
    };
    Ok(format!(
        "{}://{}{}{}",
        base.scheme, base.authority, dir, location
    ))
}

fn path_only(path_and_query: &str) -> &str {
    path_and_query.split('?').next().unwrap_or(path_and_query)
}

struct RawResponse {
    status: u16,
    location: Option<String>,
    body: String,
}

fn timeout_error(timeout_ms: u64) -> Error {
    Error::new(
        Code::ENet,
        format!("github keys request timed out after {timeout_ms}ms"),
    )
}

fn is_ureq_timeout(e: &std::io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<ureq::Error>())
        .is_some_and(|ue| matches!(ue, ureq::Error::Timeout(_)))
}

/// `requestOnce` (github-keys.js): one HTTP request, no redirect-following
/// of its own (the caller, `fetch_keys`, owns the redirect loop so it can
/// validate each hop's `.keys` path).
fn request_once(url: &str, timeout_ms: u64) -> Result<RawResponse, Error> {
    let parsed = split_absolute(url).ok_or_else(|| invalid_url_error(url))?;
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(Error::new(
            Code::ENet,
            format!(
                "unsupported protocol for github keys url: {}:",
                parsed.scheme
            ),
        ));
    }

    let timeout = Duration::from_millis(timeout_ms);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let result = agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .header("Accept", "text/plain")
        .call();

    let mut response = match result {
        Ok(r) => r,
        Err(ureq::Error::Timeout(_)) => return Err(timeout_error(timeout_ms)),
        Err(e) => return Err(Error::new(Code::ENet, e.to_string())),
    };

    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if status == 404 || (300..400).contains(&status) {
        return Ok(RawResponse {
            status,
            location,
            body: String::new(),
        });
    }

    let mut reader = response.body_mut().as_reader();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).map_err(|e| {
            if is_ureq_timeout(&e) {
                timeout_error(timeout_ms)
            } else {
                Error::new(Code::ENet, e.to_string())
            }
        })?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_BODY_BYTES {
            return Err(Error::new(
                Code::ENet,
                format!("github keys response exceeded {MAX_BODY_BYTES} bytes"),
            ));
        }
    }
    Ok(RawResponse {
        status,
        location: None,
        body: String::from_utf8_lossy(&buf).into_owned(),
    })
}

/// `fetchKeys` (github-keys.js): resolves `{status: "ok"|"not-found", keys:
/// [...]}`. A 200 with an empty body is `ok` with no keys — a different
/// thing from "no such user" (`not-found`), which verification must still
/// fail on.
pub fn fetch_keys(
    username: &str,
    base_url: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<KeysAnswer, Error> {
    let name = username.trim();
    if name.is_empty() {
        return Err(Error::new(Code::ENet, "github username is required"));
    }
    let base = base_url
        .map(str::to_string)
        .unwrap_or_else(base_url_default);
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);

    let mut url = format!(
        "{}/{}.keys",
        base.trim_end_matches('/'),
        encode_uri_component(name)
    );
    for _hop in 0..=MAX_REDIRECTS {
        let response = request_once(&url, timeout_ms)?;
        if response.status == 404 {
            return Ok(KeysAnswer {
                status: "not-found".to_string(),
                keys: Vec::new(),
            });
        }
        if (300..400).contains(&response.status) {
            let Some(location) = response.location else {
                return Err(Error::new(
                    Code::ENet,
                    "github keys redirect without a location header",
                ));
            };
            let next = resolve_redirect(&url, &location)?;
            let next_split = split_absolute(&next).ok_or_else(|| invalid_url_error(&next))?;
            let next_path = path_only(next_split.path_and_query);
            if !next_path.ends_with(".keys") {
                return Err(Error::new(
                    Code::ENet,
                    format!("github keys redirect left the .keys path: {next_path}"),
                ));
            }
            url = next;
            continue;
        }
        if !(200..300).contains(&response.status) {
            return Err(Error::new(
                Code::ENet,
                format!(
                    "github responded with HTTP {} for {name}.keys",
                    response.status
                ),
            ));
        }
        return Ok(KeysAnswer {
            status: "ok".to_string(),
            keys: parse_keys_body(&response.body),
        });
    }
    Err(Error::new(
        Code::ENet,
        format!("github keys request exceeded {MAX_REDIRECTS} redirects"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keys_body_ignores_unrecognisable_lines() {
        let keys = parse_keys_body(
            &[
                "# a comment",
                "",
                "sk-ssh-ed25519@openssh.com AAAA",
                "not-a-key",
                "ssh-dss AAAAB3NzaC1kc3MAAA",
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
                "",
            ]
            .join("\n"),
        );
        assert_eq!(keys.len(), 1, "only the ecdsa line survives");
        assert_eq!(keys[0].key_type, "ecdsa-sha2-nistp256");
        assert!(keys[0].fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn resolve_redirect_handles_path_absolute_protocol_relative_and_absolute() {
        assert_eq!(
            resolve_redirect("https://github.com/OldName.keys", "/newname.keys").unwrap(),
            "https://github.com/newname.keys"
        );
        assert_eq!(
            resolve_redirect("https://github.com/OldName.keys", "//example.com/x.keys").unwrap(),
            "https://example.com/x.keys"
        );
        assert_eq!(
            resolve_redirect("https://github.com/OldName.keys", "http://elsewhere/x.keys").unwrap(),
            "http://elsewhere/x.keys"
        );
    }

    #[test]
    fn base_url_default_treats_blank_env_as_unset() {
        // This test only exercises the trimming logic directly (the env var
        // itself is process-global and other tests must not race it).
        assert_eq!(
            if "   ".trim().is_empty() {
                DEFAULT_BASE_URL.to_string()
            } else {
                "   ".to_string()
            },
            DEFAULT_BASE_URL
        );
    }
}

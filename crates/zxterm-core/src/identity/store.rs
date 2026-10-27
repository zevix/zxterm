//! On-disk identity records for one profile: the local claim (`self.json`)
//! and one file per remote peer (`peers/<identityKeyHex>.json`), ported from
//! ZBTerm `engine/identity/store.js`. Same storage rules as ZBTerm's
//! `AccountStore`: JSON, mode `0o600`, tmp file + rename, `version: VERSION`
//! on every record.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use super::claim::{self, Claim};
use super::github::PublishedKey;
use super::providers;
use crate::error::{Code, Error};
use crate::ssh::sshsig;

/// `VERSION` (`engine/schema.js::VERSION`, currently `2`), tagged on every
/// record; a version mismatch or corrupt JSON on read is `E_CORRUPT`.
pub const VERSION: u32 = 2;
/// `PEER_STATUS` (store.js).
pub const PEER_STATUS: [&str; 4] = ["unknown", "pending", "verified", "failed"];
/// `PROVIDER_CACHE_DIR` (store.js).
pub const PROVIDER_CACHE_DIR: &str = "provider-cache";

/// A profile's identity records, rooted at `<profile>/account/identity/`.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    root: PathBuf,
}

/// `self.json`'s shape (`getSelf`/`setSelf`'s return value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfRecord {
    pub version: u32,
    pub provider: String,
    pub subject: Option<String>,
    pub identity_key: String,
    pub auth_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_key_type: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub issued_at: Option<i64>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
    pub created_at: i64,
}

/// `setSelf`'s input shape — the claim plus the fields `setSelf` alone
/// accepts (`sshPublicKey`, `sshKeyType`, `createdAt`).
#[derive(Debug, Clone, Default)]
pub struct SetSelfInput {
    pub provider: String,
    pub subject: Option<String>,
    pub identity_key: String,
    pub auth_key: Option<String>,
    pub ssh_public_key: Option<String>,
    pub ssh_key_type: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub issued_at: Option<i64>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
    pub created_at: Option<i64>,
}

impl SetSelfInput {
    /// The claim fields alone, in `claimBytes`'s input shape — built from
    /// the *raw* (not provider-normalized) fields, matching `setSelf`'s own
    /// call order (`verifyClaimSignature(record)` runs before
    /// `provider.validateSubject`).
    fn to_claim(&self) -> Claim {
        Claim {
            provider: Some(self.provider.clone()),
            subject: self.subject.clone(),
            identity_key: Some(self.identity_key.clone()),
            auth_key: self.auth_key.clone(),
            ssh_fingerprint: self.ssh_fingerprint.clone(),
            issued_at: self.issued_at,
            nonce: self.nonce.clone(),
            signature: self.signature.clone(),
            ssh_public_key: self.ssh_public_key.clone(),
        }
    }
}

/// `peers/<identityKeyHex>.json`'s shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub version: u32,
    pub identity_key: String,
    pub provider: String,
    pub subject: Option<String>,
    pub display_id: String,
    pub status: String,
    pub last_verified_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub local_name: Option<String>,
    pub local_comment: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub failure_reason: Option<String>,
}

/// `provider-cache/<provider>/<subject>.json`'s shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCacheRecord {
    pub version: u32,
    pub provider: String,
    pub subject: String,
    pub status: String,
    pub keys: Vec<PublishedKey>,
    pub fetched_at: u64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn io_error(err: std::io::Error) -> Error {
    Error::new(Code::EInternal, err.to_string())
}

impl IdentityStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        IdentityStore { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `ready` (store.js): creates `peers/` and `provider-cache/`.
    pub fn ready(&self) -> Result<(), Error> {
        fs::create_dir_all(self.root.join("peers")).map_err(io_error)?;
        fs::create_dir_all(self.root.join(PROVIDER_CACHE_DIR)).map_err(io_error)?;
        Ok(())
    }

    // -- provider cache ----------------------------------------------------

    /// `readProviderCache` (store.js): a corrupt or unreadable entry is a
    /// cache miss, never an error.
    pub fn read_provider_cache(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<ProviderCacheRecord>, Error> {
        let key = provider_cache_key(provider, subject)?;
        let value = match self.read_json(&key) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(_) => return Ok(None),
        };
        if value.get("version").and_then(Value::as_u64) != Some(VERSION as u64) {
            return Ok(None);
        }
        Ok(Some(ProviderCacheRecord {
            version: VERSION,
            provider: string_field(&value, "provider"),
            subject: string_field(&value, "subject"),
            status: string_field(&value, "status"),
            keys: keys_from_value(value.get("keys")),
            fetched_at: value.get("fetchedAt").and_then(Value::as_u64).unwrap_or(0),
        }))
    }

    /// `writeProviderCache` (store.js).
    pub fn write_provider_cache(
        &self,
        provider: &str,
        subject: &str,
        status: &str,
        keys: &[PublishedKey],
        fetched_at: u64,
    ) -> Result<ProviderCacheRecord, Error> {
        let entry = providers::get_provider(provider)?;
        let normalized_subject = entry.validate_subject(Some(subject))?;
        let record = ProviderCacheRecord {
            version: VERSION,
            provider: entry.id.to_string(),
            subject: normalized_subject,
            status: status.to_string(),
            keys: keys.to_vec(),
            fetched_at,
        };
        let key = provider_cache_key(provider, subject)?;
        self.write_json(&key, &provider_cache_to_value(&record))?;
        Ok(record)
    }

    // -- self ----------------------------------------------------------

    /// `getSelf` (store.js).
    pub fn get_self(&self) -> Result<Option<SelfRecord>, Error> {
        let Some(value) = self.read_json("self")? else {
            return Ok(None);
        };
        assert_version(&value)?;
        Ok(Some(self_record_from_value(&value)))
    }

    /// `setSelf` (store.js): verifies the fingerprint and SSHSIG before
    /// writing, for every provider except `unknown` (which writes a minimal
    /// record with no signature).
    pub fn set_self(&self, record: &SetSelfInput) -> Result<SelfRecord, Error> {
        let provider = providers::get_provider(&record.provider)?;
        if provider.id == providers::UNKNOWN {
            let unknown = SelfRecord {
                version: VERSION,
                provider: providers::UNKNOWN.to_string(),
                subject: None,
                identity_key: record.identity_key.clone(),
                auth_key: None,
                ssh_public_key: None,
                ssh_key_type: None,
                ssh_fingerprint: None,
                issued_at: None,
                nonce: None,
                signature: None,
                created_at: record.created_at.unwrap_or_else(now_ms),
            };
            self.write_json("self", &self_record_to_value(&unknown))?;
            return Ok(unknown);
        }
        verify_claim_signature(record)?;
        let subject = provider.validate_subject(record.subject.as_deref())?;
        let next = SelfRecord {
            version: VERSION,
            provider: provider.id.to_string(),
            subject: Some(subject),
            identity_key: record.identity_key.clone(),
            auth_key: record.auth_key.clone(),
            ssh_public_key: record.ssh_public_key.clone(),
            ssh_key_type: Some(
                record
                    .ssh_key_type
                    .clone()
                    .unwrap_or_else(|| crate::wire::KEY_TYPE.to_string()),
            ),
            ssh_fingerprint: record.ssh_fingerprint.clone(),
            issued_at: record.issued_at,
            nonce: record.nonce.clone(),
            signature: record.signature.clone(),
            created_at: record.created_at.unwrap_or_else(now_ms),
        };
        self.write_json("self", &self_record_to_value(&next))?;
        Ok(next)
    }

    /// `clearSelf` (store.js): drops to `unknown`, leaving peers intact.
    pub fn clear_self(&self, identity_key: Option<&str>) -> Result<SelfRecord, Error> {
        let identity_key = match identity_key {
            Some(k) => k.to_string(),
            None => self.get_self()?.map(|s| s.identity_key).unwrap_or_default(),
        };
        let record = SelfRecord {
            version: VERSION,
            provider: providers::UNKNOWN.to_string(),
            subject: None,
            identity_key,
            auth_key: None,
            ssh_public_key: None,
            ssh_key_type: None,
            ssh_fingerprint: None,
            issued_at: None,
            nonce: None,
            signature: None,
            created_at: now_ms(),
        };
        self.write_json("self", &self_record_to_value(&record))?;
        Ok(record)
    }

    // -- peers ---------------------------------------------------------

    /// `listPeers` (store.js): sorted by `lastSeenAt` descending (missing
    /// treated as `0`).
    pub fn list_peers(&self) -> Result<Vec<PeerRecord>, Error> {
        let dir = self.root.join("peers");
        let mut names = Vec::new();
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(io_error)?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(stripped) = name.strip_suffix(".json") {
                        names.push(stripped.to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
        let mut peers = Vec::new();
        for name in names {
            if let Some(value) = self.read_json(&format!("peers/{name}"))? {
                assert_version(&value)?;
                peers.push(peer_record_from_value(&value));
            }
        }
        peers.sort_by(|a, b| {
            b.last_seen_at
                .unwrap_or(0)
                .cmp(&a.last_seen_at.unwrap_or(0))
        });
        Ok(peers)
    }

    /// `getPeer` (store.js).
    pub fn get_peer(&self, id_hex: &str) -> Result<Option<PeerRecord>, Error> {
        let key = normalize_key(id_hex)?;
        let Some(value) = self.read_json(&format!("peers/{key}"))? else {
            return Ok(None);
        };
        assert_version(&value)?;
        Ok(Some(peer_record_from_value(&value)))
    }

    /// `putPeer` (store.js): merges `patch` onto the existing peer record
    /// (or a fresh `unknown` one). A key *absent* from `patch` is left
    /// untouched; a key explicitly `Value::Null` overwrites, **except**
    /// `localName`/`localComment`, which a `null` patch value never wipes —
    /// distinguishing "omitted" from "explicit null" is exactly why the
    /// patch is a `serde_json::Map`, not a typed struct.
    pub fn put_peer(&self, id_hex: &str, patch: Map<String, Value>) -> Result<PeerRecord, Error> {
        let identity_key = normalize_key(id_hex)?;
        let previous = match self.read_json(&format!("peers/{identity_key}"))? {
            Some(v) => {
                assert_version(&v)?;
                v.as_object().cloned().unwrap_or_default()
            }
            None => empty_peer_map(&identity_key),
        };
        let mut next = previous;
        for (key, value) in patch {
            if value.is_null() && (key == "localName" || key == "localComment") {
                continue;
            }
            next.insert(key, value);
        }
        next.insert("version".to_string(), json!(VERSION));
        next.insert("identityKey".to_string(), json!(identity_key));
        let status = next
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_string);
        match &status {
            Some(s) if !PEER_STATUS.contains(&s.as_str()) => {
                return Err(Error::new(
                    Code::EInternal,
                    format!("Unknown peer status: {s}"),
                ));
            }
            None => {
                next.insert("status".to_string(), json!("unknown"));
            }
            _ => {}
        }
        let display_id = peer_display_id(&next)?;
        next.insert("displayId".to_string(), json!(display_id));
        self.write_json(
            &format!("peers/{identity_key}"),
            &Value::Object(next.clone()),
        )?;
        Ok(peer_record_from_value(&Value::Object(next)))
    }

    // -- raw JSON storage ------------------------------------------------

    fn path(&self, key: &str) -> PathBuf {
        let mut path = self.root.clone();
        for segment in key.split('/') {
            path.push(segment);
        }
        path.set_extension("json");
        path
    }

    fn read_json(&self, key: &str) -> Result<Option<Value>, Error> {
        let file = self.path(key);
        let text = match fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| Error::new(Code::ECorrupt, format!("Corrupt identity record: {key}")))
    }

    fn write_json(&self, key: &str, value: &Value) -> Result<(), Error> {
        assert_version(value)?;
        let file = self.path(key);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let tmp = file.with_extension(format!("json.{}.{}.tmp", std::process::id(), now_ms()));
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| Error::new(Code::EInternal, e.to_string()))?;
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            let mut handle = opts.open(&tmp).map_err(io_error)?;
            use std::io::Write as _;
            handle.write_all(&bytes).map_err(io_error)?;
        }
        fs::rename(&tmp, &file).map_err(io_error)?;
        let _ = fs::set_permissions(&file, fs::Permissions::from_mode(0o600));
        Ok(())
    }
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn opt_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn opt_i64_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn keys_from_value(value: Option<&Value>) -> Vec<PublishedKey> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let key_type = item.get("keyType").and_then(Value::as_str)?;
            let blob_base64 = item.get("blobBase64").and_then(Value::as_str)?;
            let fingerprint = item.get("fingerprint").and_then(Value::as_str)?;
            Some(PublishedKey {
                key_type: key_type.to_string(),
                blob_base64: blob_base64.to_string(),
                fingerprint: fingerprint.to_string(),
            })
        })
        .collect()
}

fn provider_cache_to_value(record: &ProviderCacheRecord) -> Value {
    let keys: Vec<Value> = record
        .keys
        .iter()
        .map(|k| {
            json!({
                "keyType": k.key_type,
                "blobBase64": k.blob_base64,
                "fingerprint": k.fingerprint,
            })
        })
        .collect();
    json!({
        "version": record.version,
        "provider": record.provider,
        "subject": record.subject,
        "status": record.status,
        "keys": keys,
        "fetchedAt": record.fetched_at,
    })
}

fn self_record_to_value(record: &SelfRecord) -> Value {
    if record.provider == providers::UNKNOWN {
        return json!({
            "version": record.version,
            "provider": record.provider,
            "identityKey": record.identity_key,
            "createdAt": record.created_at,
        });
    }
    json!({
        "version": record.version,
        "provider": record.provider,
        "subject": record.subject,
        "identityKey": record.identity_key,
        "authKey": record.auth_key,
        "sshPublicKey": record.ssh_public_key,
        "sshKeyType": record.ssh_key_type,
        "sshFingerprint": record.ssh_fingerprint,
        "issuedAt": record.issued_at,
        "nonce": record.nonce,
        "signature": record.signature,
        "createdAt": record.created_at,
    })
}

fn self_record_from_value(value: &Value) -> SelfRecord {
    SelfRecord {
        version: value.get("version").and_then(Value::as_u64).unwrap_or(0) as u32,
        provider: string_field(value, "provider"),
        subject: opt_string_field(value, "subject"),
        identity_key: string_field(value, "identityKey"),
        auth_key: opt_string_field(value, "authKey"),
        ssh_public_key: opt_string_field(value, "sshPublicKey"),
        ssh_key_type: opt_string_field(value, "sshKeyType"),
        ssh_fingerprint: opt_string_field(value, "sshFingerprint"),
        issued_at: opt_i64_field(value, "issuedAt"),
        nonce: opt_string_field(value, "nonce"),
        signature: opt_string_field(value, "signature"),
        created_at: value.get("createdAt").and_then(Value::as_i64).unwrap_or(0),
    }
}

fn peer_record_from_value(value: &Value) -> PeerRecord {
    PeerRecord {
        version: value.get("version").and_then(Value::as_u64).unwrap_or(0) as u32,
        identity_key: string_field(value, "identityKey"),
        provider: {
            let p = string_field(value, "provider");
            if p.is_empty() {
                providers::UNKNOWN.to_string()
            } else {
                p
            }
        },
        subject: opt_string_field(value, "subject"),
        display_id: string_field(value, "displayId"),
        status: {
            let s = string_field(value, "status");
            if s.is_empty() {
                "unknown".to_string()
            } else {
                s
            }
        },
        last_verified_at: opt_i64_field(value, "lastVerifiedAt"),
        last_seen_at: opt_i64_field(value, "lastSeenAt"),
        local_name: opt_string_field(value, "localName"),
        local_comment: opt_string_field(value, "localComment"),
        ssh_fingerprint: opt_string_field(value, "sshFingerprint"),
        failure_reason: opt_string_field(value, "failureReason"),
    }
}

fn empty_peer_map(identity_key: &str) -> Map<String, Value> {
    let display_id = providers::get_provider(providers::UNKNOWN)
        .expect("unknown provider always resolves")
        .display_id(identity_key);
    let mut map = Map::new();
    map.insert("version".to_string(), json!(VERSION));
    map.insert("identityKey".to_string(), json!(identity_key));
    map.insert("provider".to_string(), json!(providers::UNKNOWN));
    map.insert("subject".to_string(), Value::Null);
    map.insert("displayId".to_string(), json!(display_id));
    map.insert("status".to_string(), json!("unknown"));
    map.insert("lastVerifiedAt".to_string(), Value::Null);
    map.insert("lastSeenAt".to_string(), Value::Null);
    map.insert("localName".to_string(), Value::Null);
    map.insert("localComment".to_string(), Value::Null);
    map.insert("sshFingerprint".to_string(), Value::Null);
    map.insert("failureReason".to_string(), Value::Null);
    map
}

/// `peerDisplayId` (store.js).
fn peer_display_id(map: &Map<String, Value>) -> Result<String, Error> {
    let provider_id = map
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or(providers::UNKNOWN);
    let provider = providers::get_provider(provider_id).unwrap_or(
        providers::get_provider(providers::UNKNOWN).expect("unknown provider always resolves"),
    );
    if provider.id == providers::UNKNOWN {
        let identity_key = map.get("identityKey").and_then(Value::as_str).unwrap_or("");
        return Ok(provider.display_id(identity_key));
    }
    let subject = map.get("subject").and_then(Value::as_str).unwrap_or("");
    Ok(provider.display_id(subject))
}

/// `verifyClaimSignature` (store.js).
fn verify_claim_signature(record: &SetSelfInput) -> Result<(), Error> {
    let signature = record
        .signature
        .as_deref()
        .ok_or_else(|| Error::new(Code::EAuth, "Identity claim is not signed"))?;
    let parsed = sshsig::parse_armored_signature(signature)?;
    let actual = crate::ssh::key::fingerprint(&parsed.pubkey_blob);
    if record.ssh_fingerprint.as_deref() != Some(actual.as_str()) {
        return Err(Error::new(
            Code::EAuth,
            format!(
                "Identity claim fingerprint mismatch: claim says {}, signature is {actual}",
                record.ssh_fingerprint.as_deref().unwrap_or("undefined")
            ),
        ));
    }
    if let Some(supplied) = &record.ssh_public_key {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&parsed.pubkey_blob);
        if *supplied != encoded {
            return Err(Error::new(
                Code::EAuth,
                "Identity claim public key does not match its signature",
            ));
        }
    }
    let message = claim::claim_bytes(&record.to_claim());
    let ok = sshsig::verify(signature, &message, None, None, Some(&parsed.pubkey_blob))?;
    if !ok {
        return Err(Error::new(
            Code::EAuth,
            "Identity claim signature does not verify",
        ));
    }
    Ok(())
}

/// `providerCacheKey` (store.js): `provider` and `subject` both go through
/// the registry first, so a subject can never carry a path separator into
/// the cache directory; the extra `^[a-z0-9][a-z0-9._-]{0,63}$` check is a
/// path-traversal guard kept even for the already-validated `github`
/// subject shape, matching the JS twin exactly.
fn provider_cache_key(provider: &str, subject: &str) -> Result<String, Error> {
    let entry = providers::get_provider(provider)?;
    let value = entry.validate_subject(Some(subject))?;
    if !is_valid_cache_segment(&value) {
        return Err(Error::new(
            Code::EAuth,
            format!("Invalid identity subject: {value}"),
        ));
    }
    Ok(format!("{PROVIDER_CACHE_DIR}/{}/{value}", entry.id))
}

fn is_valid_cache_segment(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// `normalizeKey` (store.js).
fn normalize_key(id_hex: &str) -> Result<String, Error> {
    // `/^[0-9a-f]{2,128}$/` (store.js) — no evenness constraint, on purpose:
    // it matches the JS regex exactly, which does not require an even
    // number of hex digits either.
    let value = id_hex.to_lowercase();
    let bytes = value.as_bytes();
    let valid = (2..=128).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_hexdigit());
    if !valid {
        return Err(Error::new(Code::EInternal, "Peer identity key must be hex"));
    }
    Ok(value)
}

/// `assertVersion` (store.js).
fn assert_version(value: &Value) -> Result<(), Error> {
    if value.get("version").and_then(Value::as_u64) != Some(VERSION as u64) {
        return Err(Error::new(
            Code::ECorrupt,
            "Unsupported identity record version",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (zxterm_testkit::ScratchHome, IdentityStore) {
        let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
        let store = IdentityStore::new(home.path().join("account").join("identity"));
        store.ready().expect("ready");
        (home, store)
    }

    #[test]
    fn provider_cache_round_trips() {
        let (_dir, store) = temp_store();
        let keys = vec![PublishedKey {
            key_type: "ssh-ed25519".into(),
            blob_base64: "AAAA".into(),
            fingerprint: "SHA256:x".into(),
        }];
        store
            .write_provider_cache("github", "Octocat", "ok", &keys, 1000)
            .expect("write cache");
        let record = store
            .read_provider_cache("github", "octocat")
            .expect("read cache")
            .expect("present");
        assert_eq!(record.subject, "octocat");
        assert_eq!(record.keys, keys);
    }

    #[test]
    fn provider_cache_key_rejects_path_traversal_shapes() {
        assert!(provider_cache_key("unknown", "../../etc").is_err());
    }

    #[test]
    fn normalize_key_rejects_non_hex() {
        assert!(normalize_key("not-hex").is_err());
        assert!(normalize_key("AB").is_ok());
    }
}

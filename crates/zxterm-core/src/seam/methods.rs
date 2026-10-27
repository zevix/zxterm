//! The seam's method dispatcher (K7 Step 3): `core.version`, `core.health`,
//! and every `identity.*` method over K2-K4's already-landed
//! `crate::ssh`/`crate::identity` APIs. This is glue code, not new logic —
//! each method unwraps `Request.args` (JSON text), calls the corresponding
//! library function, and wraps the result or error into the `Reply` the
//! caller sends.
//!
//! Method names are chosen to match ZBTerm's existing method strings where
//! one already exists (`engine/index.js`, verified 2026-09-29:
//! `identity.self`, `identity.beginClaim`, `identity.setSelf`,
//! `identity.clear`, `identity.peers`, `identity.annotatePeer`,
//! `identity.lookup`, `identity.inspectInvite`; the SSH-key methods carry
//! the same `identity.sshCandidates`/`identity.sshInspect`/`identity.sshSign`
//! names this project's own K9 mapping notes) so K9's routing step needs no
//! translation table. `identity.verifyClaim` (the live-challenge, layer-2
//! path) has no ZBTerm precedent — no seam existed before this phase — so
//! this phase names it.
//!
//! Every field name on the wire is `camelCase`, matching ZBTerm's own JSON
//! shapes exactly (so a caller that already knows ZBTerm's IPC payloads
//! recognises these at a glance).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crypto_secretbox::aead::OsRng;
use crypto_secretbox::aead::rand_core::RngCore;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;

use crate::error::{Code, Error};
use crate::identity::claim::{Challenge, Claim, claim_bytes};
use crate::identity::resolver::{IdentityResolver, Resolve, ResolverOptions};
use crate::identity::store::{IdentityStore, PeerRecord, SelfRecord, SetSelfInput};
use crate::identity::verify::{self, InspectClaimOpts, VerifyPeerIdentityOpts};
use crate::identity::{UNKNOWN, get_provider};
use crate::ssh::codec::{base64_decode_lenient, base64_encode};
use crate::ssh::sshsig::Via;
use crate::ssh::{Candidate, Source, inspect_key, list_candidates};

use super::protocol::{Frame, WireError};

/// Per-connection state a method may need beyond its own arguments: right
/// now, only the outbound frame channel `test.flood`/`test.echo` use to
/// stream `Output`/`Reply` frames (`#[cfg(feature = "seam-test")]`).
/// Present unconditionally so `server.rs` never has to `#[cfg]` its own
/// construction of it.
pub struct ConnCtx {
    pub outbound: mpsc::Sender<Frame>,
    /// K10: non-droppable frames in order with this connection's replies
    /// (the `freenet.*` events and `Chan` frames).
    pub events: mpsc::Sender<Frame>,
    /// Whether this connection already receives the Freenet backend's
    /// events.
    pub freenet_listening: std::sync::atomic::AtomicBool,
    /// K13: whether this connection already receives the session service's
    /// `share.*` events.
    pub share_listening: std::sync::atomic::AtomicBool,
    /// Turns `true` once the client has gone (its socket reached EOF), so
    /// a forwarding task ends with the connection.
    pub gone: tokio::sync::watch::Receiver<bool>,
}

impl ConnCtx {
    /// A context whose frames go to `outbound` (droppable) and `events`
    /// (never dropped).
    pub fn new(
        outbound: mpsc::Sender<Frame>,
        events: mpsc::Sender<Frame>,
        gone: tokio::sync::watch::Receiver<bool>,
    ) -> ConnCtx {
        ConnCtx {
            outbound,
            events,
            freenet_listening: std::sync::atomic::AtomicBool::new(false),
            share_listening: std::sync::atomic::AtomicBool::new(false),
            gone,
        }
    }
}

/// Work a method leaves for after its `Reply` is queued (K10: releasing a
/// held channel, so the reply naming it precedes its first bytes).
pub type After = Box<dyn FnOnce() + Send>;

/// Owns the one profile this sidecar process serves. Cheap to clone the
/// `Arc` around; every method call re-opens whatever files it needs (no
/// long-lived file handles beyond the profile lock itself, held in
/// `server.rs`).
///
/// K9: the identity store and the key resolver are now held for the
/// process's lifetime, one of each per profile, so concurrent
/// `identity.lookup`/`identity.verifyClaim` calls for the same subject
/// share one provider request (`resolver.js`'s in-flight dedupe) instead of
/// each call building its own resolver.
pub struct Dispatcher {
    profile: PathBuf,
    start: Instant,
    store: IdentityStore,
    resolver: Arc<IdentityResolver>,
    /// K10: the sidecar's one Freenet transport service.
    freenet: super::freenet_methods::FreenetSeam,
    /// K13: the session protocol on that transport (`share.*`).
    share: super::share_methods::ShareSeam,
    /// K15: C3 history (`history.*`), sharing its sources with `share`.
    history: super::history_methods::HistorySeam,
}

impl Dispatcher {
    pub fn new(profile: PathBuf) -> Self {
        let store = IdentityStore::new(profile.join("identity"));
        let resolver = Arc::new(IdentityResolver::new(ResolverOptions {
            store: Some(store.clone()),
            ..Default::default()
        }));
        let registry = crate::history::serve::HistoryRegistry::new();
        Dispatcher {
            profile,
            start: Instant::now(),
            share: super::share_methods::ShareSeam::new(
                store.clone(),
                resolver.clone(),
                registry.clone(),
            ),
            history: super::history_methods::HistorySeam::new(registry),
            store,
            resolver,
            freenet: super::freenet_methods::FreenetSeam::default(),
        }
    }

    /// Like [`Self::dispatch`], with the work to run once the reply is
    /// queued.
    pub async fn dispatch_full(
        &self,
        method: &str,
        args_json: &str,
        ctx: &ConnCtx,
    ) -> (Result<String, Error>, Option<After>) {
        if method.starts_with("freenet.") {
            let args = match parse_args(args_json) {
                Ok(a) => a,
                Err(e) => return (Err(e), None),
            };
            return match self.freenet.dispatch(method, args, ctx).await {
                Ok((value, after)) => (
                    serde_json::to_string(&value).map_err(|e| {
                        Error::new(Code::EInternal, format!("failed to encode reply: {e}"))
                    }),
                    after,
                ),
                Err(e) => (Err(e), None),
            };
        }
        if method.starts_with("share.") {
            let args = match parse_args(args_json) {
                Ok(a) => a,
                Err(e) => return (Err(e), None),
            };
            let res = self
                .share
                .dispatch(method, args, ctx, &self.freenet)
                .await
                .and_then(|value| {
                    serde_json::to_string(&value).map_err(|e| {
                        Error::new(Code::EInternal, format!("failed to encode reply: {e}"))
                    })
                });
            return (res, None);
        }
        if method.starts_with("history.") {
            let args = match parse_args(args_json) {
                Ok(a) => a,
                Err(e) => return (Err(e), None),
            };
            let res = self
                .history
                .dispatch(method, args, &self.freenet)
                .await
                .and_then(|value| {
                    serde_json::to_string(&value).map_err(|e| {
                        Error::new(Code::EInternal, format!("failed to encode reply: {e}"))
                    })
                });
            return (res, None);
        }
        (self.dispatch(method, args_json, ctx).await, None)
    }

    /// A `Chan` frame from a client (K10).
    pub async fn chan_frame(&self, chan: u64, bytes: &[u8], ctx: &ConnCtx) {
        self.freenet.chan_frame(chan, bytes, ctx).await;
    }

    /// Dispatches one method call, returning the JSON-encoded result text
    /// on success. Blocking (file/agent/network) work runs on
    /// `spawn_blocking` so one slow `identity.*` call never stalls this
    /// connection's other in-flight requests or the writer task.
    pub async fn dispatch(
        &self,
        method: &str,
        args_json: &str,
        ctx: &ConnCtx,
    ) -> Result<String, Error> {
        let value = self.dispatch_value(method, args_json, ctx).await?;
        serde_json::to_string(&value)
            .map_err(|e| Error::new(Code::EInternal, format!("failed to encode reply: {e}")))
    }

    async fn dispatch_value(
        &self,
        method: &str,
        args_json: &str,
        ctx: &ConnCtx,
    ) -> Result<Value, Error> {
        match method {
            "core.version" => Ok(core_version()),
            "core.health" => Ok(self.core_health()),
            #[cfg(feature = "seam-test")]
            "test.echo" => {
                let args = parse_args(args_json)?;
                super::test_methods::echo(args)
            }
            #[cfg(feature = "seam-test")]
            "test.flood" => {
                let args = parse_args(args_json)?;
                super::test_methods::flood(args, ctx).await
            }
            other if other.starts_with("identity.") => {
                let _ = ctx;
                let _ = &self.profile;
                let store = self.store.clone();
                let resolver = self.resolver.clone();
                let method = other.to_string();
                let args_json = args_json.to_string();
                tokio::task::spawn_blocking(move || {
                    let _ = store.ready();
                    dispatch_identity(&method, &args_json, &store, &resolver)
                })
                .await
                .map_err(|e| Error::new(Code::EInternal, format!("dispatch task panicked: {e}")))?
            }
            other if other.starts_with("idkey.") => {
                let method = other.to_string();
                let args_json = args_json.to_string();
                tokio::task::spawn_blocking(move || {
                    super::idkey_methods::dispatch_idkey(&method, &args_json)
                })
                .await
                .map_err(|e| Error::new(Code::EInternal, format!("dispatch task panicked: {e}")))?
            }
            other => Err(Error::new(
                Code::EBackendUnsupported,
                format!("no such seam method: {other}"),
            )),
        }
    }

    fn core_health(&self) -> Value {
        json!({
            "status": "ok",
            "pid": std::process::id(),
            "uptimeMs": self.start.elapsed().as_millis() as u64,
        })
    }
}

/// Converts a library [`Error`] into the wire's `{code, message}` shape,
/// folding `details` into `message` (the wire has no separate field for it).
pub fn to_wire_error(e: Error) -> WireError {
    let message = match e.details {
        Some(details) => format!("{}: {details}", e.message),
        None => e.message,
    };
    WireError {
        code: e.code.as_str().to_string(),
        message,
    }
}

pub(super) fn parse_args(args_json: &str) -> Result<Value, Error> {
    if args_json.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str(args_json)
        .map_err(|e| Error::new(Code::EInternal, format!("invalid JSON args: {e}")))
}

fn core_version() -> Value {
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": format!("{build}+{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    })
}

// ---------------------------------------------------------------------
// identity.* — runs on a blocking thread (see `Dispatcher::dispatch_value`)
// ---------------------------------------------------------------------

fn dispatch_identity(
    method: &str,
    args_json: &str,
    store: &IdentityStore,
    resolver: &IdentityResolver,
) -> Result<Value, Error> {
    let args = parse_args(args_json)?;
    match method {
        "identity.get" => identity_get(&args, store),
        "identity.claimBytes" => identity_claim_bytes(&args),
        "identity.challengeBytes" => identity_challenge_bytes(&args),
        "identity.signChallenge" => identity_sign_challenge(&args),
        "identity.verifyChallenge" => identity_verify_challenge(&args),
        "identity.fingerprint" => identity_fingerprint(&args),
        "identity.parseSignature" => identity_parse_signature(&args),
        "identity.verifySshSignature" => identity_verify_ssh_signature(&args),
        "identity.signedDataBlob" => identity_signed_data_blob(&args),
        "identity.armorSignature" => identity_armor_signature(&args),
        "identity.sshParsePrivateKey" => identity_ssh_parse_private_key(&args),
        "identity.fetchKeys" => identity_fetch_keys(&args),
        "identity.parseKeysBody" => Ok(identity_parse_keys_body(&args)),
        "identity.getPeer" => identity_get_peer(&args, store),
        "identity.encodePublicKey" => identity_encode_public_key(&args),
        "identity.putPeer" => identity_put_peer(&args, store),
        "identity.resolve" => identity_resolve(&args, resolver),
        "identity.sshCandidates" => identity_ssh_candidates(&args),
        "identity.sshInspect" => identity_ssh_inspect(&args),
        "identity.sshSign" => identity_ssh_sign(&args),
        "identity.beginClaim" => identity_begin_claim(&args),
        "identity.setSelf" => identity_set_self(&args, store),
        "identity.self" => identity_self(store),
        "identity.clear" => identity_clear(&args, store),
        "identity.peers" => identity_peers(store),
        "identity.annotatePeer" => identity_annotate_peer(&args, store),
        "identity.lookup" => identity_lookup(&args, resolver),
        "identity.inspectInvite" => identity_inspect_invite(&args, resolver),
        "identity.verifyClaim" => identity_verify_claim(&args, store, resolver),
        other => Err(Error::new(
            Code::EBackendUnsupported,
            format!("no such seam method: {other}"),
        )),
    }
}

fn required_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(Code::EInternal, format!("{key} is required")))
}

fn opt_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn opt_string(v: &Value, key: &str) -> Option<String> {
    opt_str(v, key).map(str::to_string)
}

/// The `env` argument as a map. K9: an *absent* `env` means "this
/// sidecar's own environment" (the one it inherited from the host that
/// spawned it), exactly as `ssh-keys.js::listCandidates({})` fell back to
/// `process.env`; an explicit `env` object (tests, a scratch home) is used
/// as given and never merged with the process's own.
fn env_map(v: &Value, key: &str) -> HashMap<String, String> {
    match v.get(key).and_then(Value::as_object) {
        Some(m) => m
            .iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        None => std::env::vars().collect(),
    }
}

/// The `home` argument. K9: absent means this sidecar's own `HOME`
/// (`USERPROFILE` on Windows), as `ssh-keys.js` fell back to
/// `os.homedir()`.
fn home_arg(v: &Value) -> Result<PathBuf, Error> {
    if let Some(home) = opt_str(v, "home") {
        return Ok(PathBuf::from(home));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| {
            Error::new(
                Code::EInternal,
                "home is required (no HOME in the environment)",
            )
        })
}

fn source_str(s: Source) -> &'static str {
    s.as_str()
}

fn candidate_json(c: &Candidate) -> Value {
    json!({
        "path": c.path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "source": source_str(c.source),
        "keyType": c.key_type,
        "fingerprint": c.fingerprint,
        "comment": c.comment,
        "publicKeyBlobBase64": c.public_key_blob_base64,
        "encrypted": c.encrypted,
        "signable": c.signable,
        "reason": c.reason,
    })
}

fn identity_ssh_candidates(args: &Value) -> Result<Value, Error> {
    let home = home_arg(args)?;
    let env = env_map(args, "env");
    let candidates = list_candidates(&home, &env);
    Ok(json!({
        "candidates": candidates.iter().map(candidate_json).collect::<Vec<_>>(),
    }))
}

fn identity_ssh_inspect(args: &Value) -> Result<Value, Error> {
    let key_path = required_str(args, "keyPath")?;
    let home = home_arg(args)?;
    let env = env_map(args, "env");
    let candidate = inspect_key(key_path, &home, &env)?;
    Ok(candidate_json(&candidate))
}

fn identity_ssh_sign(args: &Value) -> Result<Value, Error> {
    let message_base64 = required_str(args, "messageBase64")?;
    let key_path = opt_str(args, "keyPath").map(Path::new);
    let public_key_blob_base64 = opt_str(args, "publicKeyBlobBase64");
    let env = env_map(args, "env");
    let result = crate::ssh::sshsig::sign(message_base64, key_path, public_key_blob_base64, &env)?;
    Ok(json!({
        "signature": result.signature,
        "publicKeyBlobBase64": result.public_key_blob_base64,
        "fingerprint": result.fingerprint,
        "via": match result.via {
            Via::File => "file",
            Via::Agent => "agent",
        },
    }))
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(super) fn claim_json(c: &Claim) -> Value {
    json!({
        "provider": c.provider,
        "subject": c.subject,
        "identityKey": c.identity_key,
        "authKey": c.auth_key,
        "sshPublicKey": c.ssh_public_key,
        "sshFingerprint": c.ssh_fingerprint,
        "issuedAt": c.issued_at,
        "nonce": c.nonce,
        "signature": c.signature,
    })
}

pub(super) fn claim_from_json(v: &Value) -> Claim {
    Claim {
        provider: opt_string(v, "provider"),
        subject: opt_string(v, "subject"),
        identity_key: opt_string(v, "identityKey"),
        auth_key: opt_string(v, "authKey"),
        ssh_fingerprint: opt_string(v, "sshFingerprint"),
        issued_at: v.get("issuedAt").and_then(Value::as_i64),
        nonce: opt_string(v, "nonce"),
        signature: opt_string(v, "signature"),
        ssh_public_key: opt_string(v, "sshPublicKey"),
    }
}

fn challenge_from_json(v: &Value) -> Challenge {
    Challenge {
        session_id: opt_string(v, "sessionId"),
        challenge_id: opt_string(v, "challengeId"),
        nonce: opt_string(v, "nonce"),
        verifier_dht_key: opt_string(v, "verifierDhtKey"),
        prover_dht_key: opt_string(v, "proverDhtKey"),
        role: opt_string(v, "role"),
    }
}

/// `identity.beginClaim` (ZBTerm `engine/index.js::beginIdentityClaim`).
/// This seam has no "local device" concept of its own (K2-K4 land no such
/// module; ZBTerm's own `identityKey`/`authKey` come from account wiring
/// K9 owns) — the caller supplies them explicitly, everything else mints
/// exactly as ZBTerm's own method does.
fn identity_begin_claim(args: &Value) -> Result<Value, Error> {
    let provider = get_provider(required_str(args, "provider")?)?;
    if provider.id == UNKNOWN {
        return Err(Error::new(
            Code::EAuth,
            "The unknown provider cannot be claimed",
        ));
    }
    let subject = provider.validate_subject(opt_str(args, "subject"))?;
    let identity_key = required_str(args, "identityKeyHex")?.to_string();
    let auth_key = required_str(args, "authKeyHex")?.to_string();
    let ssh_public_key = opt_string(args, "sshPublicKeyBase64");
    let ssh_fingerprint = match &ssh_public_key {
        Some(b64) => Some(crate::ssh::key::fingerprint(&base64_decode_lenient(b64))),
        None => opt_string(args, "sshFingerprint"),
    };
    let claim = Claim {
        provider: Some(provider.id.to_string()),
        subject: Some(subject),
        identity_key: Some(identity_key),
        auth_key: Some(auth_key),
        ssh_fingerprint,
        issued_at: Some(now_ms()),
        nonce: Some(random_hex(16)),
        signature: None,
        ssh_public_key,
    };
    let bytes = claim_bytes(&claim);
    Ok(json!({
        "claim": claim_json(&claim),
        "bytesBase64": base64_encode(&bytes),
    }))
}

fn self_record_json(record: &SelfRecord) -> Value {
    json!({
        "configured": record.provider != UNKNOWN,
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

fn identity_set_self(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let record = args
        .get("record")
        .ok_or_else(|| Error::new(Code::EAuth, "An identity claim is required"))?;
    let input = SetSelfInput {
        provider: required_str(record, "provider")?.to_string(),
        subject: opt_string(record, "subject"),
        identity_key: required_str(record, "identityKeyHex")?.to_string(),
        auth_key: opt_string(record, "authKeyHex"),
        ssh_public_key: opt_string(record, "sshPublicKeyBase64"),
        ssh_key_type: opt_string(record, "sshKeyType"),
        ssh_fingerprint: opt_string(record, "sshFingerprint"),
        issued_at: record.get("issuedAt").and_then(Value::as_i64),
        nonce: opt_string(record, "nonce"),
        signature: opt_string(record, "signature"),
        created_at: record.get("createdAt").and_then(Value::as_i64),
    };
    let saved = store.set_self(&input)?;
    Ok(self_record_json(&saved))
}

fn identity_self(store: &IdentityStore) -> Result<Value, Error> {
    match store.get_self()? {
        Some(record) => Ok(self_record_json(&record)),
        None => Ok(json!({ "configured": false })),
    }
}

fn identity_clear(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let identity_key = opt_str(args, "identityKeyHex");
    let record = store.clear_self(identity_key)?;
    Ok(self_record_json(&record))
}

fn peer_record_json(p: &PeerRecord) -> Value {
    json!({
        "version": p.version,
        "identityKey": p.identity_key,
        "provider": p.provider,
        "subject": p.subject,
        "displayId": p.display_id,
        "status": p.status,
        "lastVerifiedAt": p.last_verified_at,
        "lastSeenAt": p.last_seen_at,
        "localName": p.local_name,
        "localComment": p.local_comment,
        "sshFingerprint": p.ssh_fingerprint,
        "failureReason": p.failure_reason,
    })
}

fn identity_peers(store: &IdentityStore) -> Result<Value, Error> {
    let peers = store.list_peers()?;
    Ok(json!({
        "peers": peers.iter().map(peer_record_json).collect::<Vec<_>>(),
    }))
}

fn identity_annotate_peer(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let identity_key = required_str(args, "identityKeyHex")?;
    let args_obj = args.as_object().cloned().unwrap_or_default();
    let mut patch = Map::new();
    if let Some(v) = args_obj.get("name") {
        patch.insert("localName".to_string(), v.clone());
    }
    if let Some(v) = args_obj.get("comment") {
        patch.insert("localComment".to_string(), v.clone());
    }
    let record = store.put_peer(identity_key, patch)?;
    Ok(peer_record_json(&record))
}

fn source_wire(source: crate::identity::resolver::Source) -> &'static str {
    match source {
        crate::identity::resolver::Source::Cache => "cache",
        crate::identity::resolver::Source::CacheStale => "cache-stale",
        crate::identity::resolver::Source::Remote => "remote",
    }
}

fn identity_lookup(args: &Value, resolver: &IdentityResolver) -> Result<Value, Error> {
    let provider = get_provider(required_str(args, "provider")?)?;
    let subject = provider.validate_subject(opt_str(args, "subject"))?;
    let refresh = args
        .get("refresh")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let answer = resolver.resolve_with_refresh(provider.id, &subject, refresh)?;
    Ok(json!({
        "provider": provider.id,
        "subject": subject,
        "status": answer.status,
        "fetchedAt": answer.fetched_at,
        "source": source_wire(answer.source),
        "keys": answer.keys.iter().map(|k| json!({
            "keyType": k.key_type,
            "fingerprint": k.fingerprint,
        })).collect::<Vec<_>>(),
    }))
}

fn outcome_json(o: &verify::Outcome, claimed: bool) -> Value {
    let status = match o.status {
        verify::Status::Verified => "verified",
        verify::Status::Unknown => "unknown",
        verify::Status::Failed => "failed",
    };
    json!({
        "status": status,
        "displayId": o.display_id,
        "provider": o.provider,
        "subject": o.subject,
        "sshFingerprint": o.ssh_fingerprint,
        "reason": o.reason,
        "claimed": claimed,
    })
}

fn identity_inspect_invite(args: &Value, resolver: &IdentityResolver) -> Result<Value, Error> {
    let claim_value = args.get("claim").filter(|v| !v.is_null());
    let claim = claim_value.map(claim_from_json);
    let resolve_ref: Option<&dyn Resolve> = Some(resolver);
    let outcome = verify::inspect_claim(&InspectClaimOpts {
        claim: claim.as_ref(),
        identity_key: None,
        resolver: resolve_ref,
    });
    Ok(outcome_json(&outcome, claim.is_some()))
}

fn identity_verify_claim(
    args: &Value,
    store: &IdentityStore,
    resolver: &IdentityResolver,
) -> Result<Value, Error> {
    let claim_value = args.get("claim").filter(|v| !v.is_null());
    let claim = claim_value.map(claim_from_json);
    let challenge_value = args.get("challenge").filter(|v| !v.is_null());
    let challenge = challenge_value.map(challenge_from_json);
    let identity_key = opt_string(args, "identityKeyHex");
    let auth_key = opt_string(args, "authKeyHex");
    let signature = opt_string(args, "signatureHex");
    let resolve_ref: Option<&dyn Resolve> = Some(resolver);
    let outcome = verify::verify_peer_identity(
        &VerifyPeerIdentityOpts {
            claim: claim.as_ref(),
            identity_key: identity_key.as_deref(),
            auth_key: auth_key.as_deref(),
            challenge: challenge.as_ref(),
            signature: signature.as_deref(),
            resolver: resolve_ref,
        },
        Some(store),
    );
    Ok(outcome_json(&outcome, claim.is_some()))
}

// ---------------------------------------------------------------------
// K9: the methods ZBTerm's call-throughs need beyond K7's twelve.
// ---------------------------------------------------------------------

fn hex_arg(args: &Value, key: &str) -> Result<Vec<u8>, Error> {
    let text = required_str(args, key)?;
    hex::decode(text).map_err(|_| Error::new(Code::EAuth, format!("{key} is not valid hex")))
}

fn base64_arg(args: &Value, key: &str) -> Result<Vec<u8>, Error> {
    Ok(base64_decode_lenient(required_str(args, key)?))
}

/// `identity.get` (ZBTerm `engine/index.js`, the `identity.get` branch):
/// the device's own keys (which the caller owns: they live in ZBTerm's
/// account records) plus the provider and display id of the stored self
/// claim, falling back to `unknown` and the identity key's own display id.
fn identity_get(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let identity_key = required_str(args, "identityKeyHex")?;
    let self_record = store.get_self().ok().flatten();
    let (provider, display_id) = match self_record {
        Some(record) if record.provider != UNKNOWN => {
            let provider = get_provider(&record.provider)?;
            let subject = record.subject.clone().unwrap_or_default();
            (provider.id.to_string(), provider.display_id(&subject))
        }
        _ => (
            UNKNOWN.to_string(),
            get_provider(UNKNOWN)?.display_id(identity_key),
        ),
    };
    Ok(json!({
        "deviceKey": opt_str(args, "deviceKeyHex"),
        "dhtKey": opt_str(args, "dhtKeyHex"),
        "identityKey": identity_key,
        "deviceName": opt_str(args, "deviceName"),
        "deviceStatus": opt_str(args, "deviceStatus").unwrap_or("active"),
        "provider": provider,
        "displayId": display_id,
    }))
}

/// `identity.claimBytes` (`claim.js::claimBytes`).
fn identity_claim_bytes(args: &Value) -> Result<Value, Error> {
    let claim = claim_from_json(args.get("claim").unwrap_or(&Value::Null));
    Ok(json!({ "bytesBase64": base64_encode(&claim_bytes(&claim)) }))
}

/// `identity.challengeBytes` (`claim.js::challengeBytes`).
fn identity_challenge_bytes(args: &Value) -> Result<Value, Error> {
    let challenge = challenge_from_json(args.get("challenge").unwrap_or(&Value::Null));
    Ok(json!({
        "bytesBase64": base64_encode(&crate::identity::claim::challenge_bytes(&challenge)),
    }))
}

/// `identity.signChallenge` (`claim.js::signChallenge`): the prover half of
/// the live identity challenge, signed with the device's ed25519 auth key.
fn identity_sign_challenge(args: &Value) -> Result<Value, Error> {
    let secret_key = hex_arg(args, "authSecretKeyHex")?;
    let challenge = challenge_from_json(args.get("challenge").unwrap_or(&Value::Null));
    let signature = crate::identity::claim::sign_challenge(&secret_key, &challenge)?;
    Ok(json!({ "signatureHex": hex::encode(signature) }))
}

/// `identity.verifyChallenge` (`claim.js::verifyChallenge`).
fn identity_verify_challenge(args: &Value) -> Result<Value, Error> {
    let challenge = challenge_from_json(args.get("challenge").unwrap_or(&Value::Null));
    let public_key = hex::decode(opt_str(args, "authKeyHex").unwrap_or("")).unwrap_or_default();
    let signature = hex::decode(opt_str(args, "signatureHex").unwrap_or("")).unwrap_or_default();
    Ok(json!({
        "valid": crate::identity::claim::verify_challenge(&public_key, &challenge, &signature),
    }))
}

/// `identity.fingerprint` (`claim.js::fingerprint`): `SHA256:<base64>` of
/// an SSH wire-format public-key blob.
fn identity_fingerprint(args: &Value) -> Result<Value, Error> {
    let blob = base64_arg(args, "blobBase64")?;
    Ok(json!({ "fingerprint": crate::ssh::key::fingerprint(&blob) }))
}

/// `identity.parseSignature` (`claim.js::parseArmoredSignature`).
fn identity_parse_signature(args: &Value) -> Result<Value, Error> {
    let parsed = crate::ssh::sshsig::parse_armored_signature(required_str(args, "armored")?)?;
    Ok(json!({
        "pubkeyBlobBase64": base64_encode(&parsed.pubkey_blob),
        "namespace": parsed.namespace,
        "hashAlg": parsed.hash_alg,
        "sigType": parsed.sig_type,
        "rawSigBase64": base64_encode(&parsed.raw_sig),
    }))
}

/// `identity.verifySshSignature` (`claim.js::verifySshSignature`): `valid`
/// is `false` for every refusal `claim.js` answered `false` to; the two it
/// threw for (an unsupported key type, a signature-algorithm mismatch) are
/// errors here too.
fn identity_verify_ssh_signature(args: &Value) -> Result<Value, Error> {
    let armored = required_str(args, "armored")?;
    let message = base64_arg(args, "messageBase64")?;
    let expected = opt_str(args, "expectedPublicKeyBlobBase64").map(base64_decode_lenient);
    let valid = crate::ssh::sshsig::verify(
        armored,
        &message,
        opt_str(args, "namespace"),
        opt_str(args, "hashAlg"),
        expected.as_deref(),
    )?;
    Ok(json!({ "valid": valid }))
}

/// `identity.signedDataBlob` (`claim.js::signedDataBlob`): the SSHSIG
/// "signed data" an SSH key actually signs.
fn identity_signed_data_blob(args: &Value) -> Result<Value, Error> {
    let message = base64_arg(args, "messageBase64")?;
    let blob = crate::ssh::sshsig::signed_data_blob(
        opt_str(args, "namespace").unwrap_or(crate::wire::NAMESPACE),
        opt_str(args, "hashAlg").unwrap_or(crate::wire::HASH_ALG),
        &message,
    );
    Ok(json!({ "bytesBase64": base64_encode(&blob) }))
}

/// `identity.armorSignature` (`claim.js::buildArmoredSignature`).
fn identity_armor_signature(args: &Value) -> Result<Value, Error> {
    let blob = base64_arg(args, "publicKeyBlobBase64")?;
    let raw = base64_arg(args, "rawSigBase64")?;
    let armored = crate::ssh::sshsig::build_armored_signature(
        &blob,
        &raw,
        opt_str(args, "namespace").unwrap_or(crate::wire::NAMESPACE),
        opt_str(args, "hashAlg").unwrap_or(crate::wire::HASH_ALG),
    )?;
    Ok(json!({ "armored": armored }))
}

/// `identity.sshParsePrivateKey` (`ssh-keys.js::parseOpenSshPrivateKey`):
/// what a key file is, never its secret (`hasSecretKey` says whether one
/// was readable).
fn identity_ssh_parse_private_key(args: &Value) -> Result<Value, Error> {
    let parsed = crate::ssh::key::parse_openssh_private_key(required_str(args, "text")?)?;
    Ok(json!({
        "keyType": parsed.key_type,
        "publicKeyBlobBase64": base64_encode(&parsed.public_key_blob),
        "encrypted": parsed.encrypted,
        "comment": parsed.comment,
        "hasSecretKey": parsed.secret_key.is_some() || parsed.rsa.is_some(),
    }))
}

fn published_keys_json(keys: &[crate::identity::github::PublishedKey]) -> Vec<Value> {
    keys.iter()
        .map(|k| {
            json!({
                "keyType": k.key_type,
                "blobBase64": k.blob_base64,
                "fingerprint": k.fingerprint,
            })
        })
        .collect()
}

/// `identity.fetchKeys` (`github-keys.js::fetchKeys`): one provider fetch,
/// no cache. `baseUrl`/`timeoutMs` default as the JS twin's did (the
/// `ZBTERM_GITHUB_KEYS_BASE` environment variable, then github.com; 8 s).
fn identity_fetch_keys(args: &Value) -> Result<Value, Error> {
    let answer = crate::identity::github::fetch_keys(
        required_str(args, "subject")?,
        opt_str(args, "baseUrl"),
        args.get("timeoutMs").and_then(Value::as_u64),
    )?;
    Ok(json!({ "status": answer.status, "keys": published_keys_json(&answer.keys) }))
}

/// `identity.parseKeysBody` (`github-keys.js::parseKeysBody`).
fn identity_parse_keys_body(args: &Value) -> Value {
    let body = opt_str(args, "body").unwrap_or("");
    json!({ "keys": published_keys_json(&crate::identity::github::parse_keys_body(body)) })
}

/// `identity.getPeer` (`store.js::getPeer`): `null` when never seen.
fn identity_get_peer(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let identity_key = required_str(args, "identityKeyHex")?;
    Ok(match store.get_peer(identity_key)? {
        Some(p) => peer_record_json(&p),
        None => Value::Null,
    })
}

/// `identity.putPeer` (`store.js::putPeer`): merges `patch` (an omitted
/// field keeps its value, an explicit `null` clears it).
fn identity_put_peer(args: &Value, store: &IdentityStore) -> Result<Value, Error> {
    let identity_key = required_str(args, "identityKeyHex")?;
    let patch = args
        .get("patch")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    Ok(peer_record_json(&store.put_peer(identity_key, patch)?))
}

/// `identity.encodePublicKey` (`claim.js::encodeEd25519PublicKey` with
/// `ed25519PublicKeyHex`, `claim.js::encodeRsaPublicKey` with `eHex`/`nHex`):
/// the SSH wire-format public-key blob.
fn identity_encode_public_key(args: &Value) -> Result<Value, Error> {
    let blob = if args.get("ed25519PublicKeyHex").is_some() {
        crate::identity::claim::encode_ed25519_public_key(&hex_arg(args, "ed25519PublicKeyHex")?)?
    } else {
        let (Some(_), Some(_)) = (opt_str(args, "eHex"), opt_str(args, "nHex")) else {
            return Err(Error::new(Code::EAuth, "RSA public key needs both e and n"));
        };
        crate::identity::claim::encode_rsa_public_key(
            &hex_arg(args, "eHex")?,
            &hex_arg(args, "nHex")?,
        )
    };
    Ok(json!({ "blobBase64": base64_encode(&blob) }))
}

/// `identity.resolve` (`resolver.js::IdentityResolver#resolve`): the
/// resolver's own answer, published keys in full (`identity.lookup` is the
/// UI-facing variant that strips the key blobs).
fn identity_resolve(args: &Value, resolver: &IdentityResolver) -> Result<Value, Error> {
    let provider = get_provider(required_str(args, "provider")?)?;
    let subject = provider.validate_subject(opt_str(args, "subject"))?;
    let refresh = args
        .get("refresh")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let answer = resolver.resolve_with_refresh(provider.id, &subject, refresh)?;
    Ok(json!({
        "status": answer.status,
        "keys": published_keys_json(&answer.keys),
        "fetchedAt": answer.fetched_at,
        "source": source_wire(answer.source),
    }))
}

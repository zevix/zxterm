//! Verifies one peer's presented identity claim during a join handshake,
//! ported from ZBTerm `engine/identity/verify.js`. Two layers, both
//! required: (1) the SSH-signed claim binds `provider+subject ->
//! identityKey -> authKey`, and the provider must actually publish the SSH
//! key that signed it; (2) the live challenge signed by that `authKey`
//! binds the claim to the peer on this connection.
//!
//! The handshake wiring itself (`engine/share-manager.js`'s
//! `_issueIdentityChallenge`/`_answerIdentityChallenge`/
//! `_verifyViewerIdentity`/`_verifyHostIdentity`) is not ported here — K9
//! routes ZBTerm's calls into `verify_peer_identity`/`inspect_claim` over
//! the seam.

use serde_json::{Map, Value, json};

use super::claim::{self, Challenge, Claim};
use super::providers::{self, Provider};
use super::resolver::Resolve;
use super::store::IdentityStore;
use crate::ssh::sshsig;

/// `IDENTITY_TIMEOUT_MS` (verify.js) — how long a caller should wait for the
/// other side to answer its challenge before treating it as a refusal.
/// Nothing in this module enforces it: the wait itself belongs to the
/// connection-handling code that calls `verify_peer_identity` (K9's seam
/// wiring), not to this pure evaluation.
pub const IDENTITY_TIMEOUT_MS: u64 = 15000;
/// `RESOLVER_UNREACHABLE` (verify.js): the one non-refusing failure reason —
/// the provider could not be asked, so the claim downgrades to `Unknown`
/// rather than `Failed`.
pub const RESOLVER_UNREACHABLE: &str = "resolver-unreachable";

/// An evaluated claim's outcome (`verifyPeerIdentity`/`inspectClaim`'s
/// return shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Verified,
    Unknown,
    Failed,
}

/// `verifyPeerIdentity`/`inspectClaim`'s resolved shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub display_id: String,
    pub provider: String,
    pub subject: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub reason: Option<String>,
}

/// `verifyPeerIdentity`'s options.
#[derive(Default)]
pub struct VerifyPeerIdentityOpts<'a> {
    pub claim: Option<&'a Claim>,
    pub identity_key: Option<&'a str>,
    pub auth_key: Option<&'a str>,
    pub challenge: Option<&'a Challenge>,
    /// The live challenge signature, hex-encoded (matching every other
    /// identity field's own encoding).
    pub signature: Option<&'a str>,
    pub resolver: Option<&'a dyn Resolve>,
}

/// `inspectClaim`'s options: layer 1 only (no connection, so no
/// `authKey`/`challenge`/`signature`), and never persisted.
#[derive(Default)]
pub struct InspectClaimOpts<'a> {
    pub claim: Option<&'a Claim>,
    pub identity_key: Option<&'a str>,
    pub resolver: Option<&'a dyn Resolve>,
}

/// `verifyPeerIdentity` (verify.js): evaluates, then persists the outcome to
/// `store` (a write failure is swallowed — bookkeeping never refuses a
/// connection).
pub fn verify_peer_identity(
    opts: &VerifyPeerIdentityOpts<'_>,
    store: Option<&IdentityStore>,
) -> Outcome {
    let identity_key = opts.identity_key.unwrap_or("").to_string();
    let outcome = evaluate(opts, &identity_key);
    persist(store, &identity_key, &outcome);
    outcome
}

/// `inspectClaim` (verify.js): layer 1 alone, never persisted. A pass here
/// means "this claim is genuine", never "the party in front of me holds
/// it" — used to inspect an identity carried inside an invite link, where
/// there is no connection to challenge yet.
pub fn inspect_claim(opts: &InspectClaimOpts<'_>) -> Outcome {
    let identity_key = opts
        .identity_key
        .map(str::to_string)
        .or_else(|| opts.claim.and_then(|c| c.identity_key.clone()))
        .unwrap_or_default();
    match claim_shape(opts.claim, &identity_key) {
        ClaimShape::Outcome(o) => o,
        ClaimShape::Shaped { provider, subject } => {
            let claim = opts.claim.expect("Shaped implies a claim");
            match claim_proof(claim, &provider, &subject, &identity_key, opts.resolver) {
                ClaimProof::Outcome(o) => o,
                ClaimProof::Proof { ssh_fingerprint } => Outcome {
                    status: Status::Verified,
                    display_id: provider.display_id(&subject),
                    provider: provider.id.to_string(),
                    subject: Some(subject),
                    ssh_fingerprint: Some(ssh_fingerprint),
                    reason: None,
                },
            }
        }
    }
}

enum ClaimShape {
    Outcome(Outcome),
    Shaped { provider: Provider, subject: String },
}

/// Does the claim even name a provider and a subject, and is it signed at
/// all? (`claimShape`, verify.js — inlined here as a helper, not exported.)
fn claim_shape(claim: Option<&Claim>, identity_key: &str) -> ClaimShape {
    let Some(claim) = claim else {
        return ClaimShape::Outcome(unknown(identity_key, None));
    };
    let provider = match providers::get_provider(claim.provider.as_deref().unwrap_or("undefined")) {
        Ok(p) => p,
        Err(_) => {
            return ClaimShape::Outcome(failed(
                identity_key,
                Some(claim),
                format!(
                    "unknown identity provider: {}",
                    claim.provider.as_deref().unwrap_or("undefined")
                ),
            ));
        }
    };
    if provider.id == providers::UNKNOWN {
        return ClaimShape::Outcome(unknown(identity_key, None));
    }
    let subject = match provider.validate_subject(claim.subject.as_deref()) {
        Ok(s) => s,
        Err(_) => {
            return ClaimShape::Outcome(failed(
                identity_key,
                Some(claim),
                format!(
                    "identity claim carries an invalid {} username: {}",
                    provider.label,
                    claim.subject.as_deref().unwrap_or("undefined")
                ),
            ));
        }
    };
    if claim.signature.is_none() {
        return ClaimShape::Outcome(failed(
            identity_key,
            Some(claim),
            "identity claim is not signed".to_string(),
        ));
    }
    ClaimShape::Shaped { provider, subject }
}

enum ClaimProof {
    Outcome(Outcome),
    Proof { ssh_fingerprint: String },
}

/// The SSHSIG over the canonical claim bytes, plus "does the provider
/// actually publish this key" (`claimProof`, verify.js).
fn claim_proof(
    claim: &Claim,
    provider: &Provider,
    subject: &str,
    identity_key: &str,
    resolver: Option<&dyn Resolve>,
) -> ClaimProof {
    let signature = claim
        .signature
        .as_deref()
        .expect("claim_shape only shapes a signed claim");

    let parsed = match sshsig::parse_armored_signature(signature) {
        Ok(p) => p,
        Err(e) => {
            return ClaimProof::Outcome(failed(
                identity_key,
                Some(claim),
                format!("identity claim signature is unusable: {}", e.message),
            ));
        }
    };
    let blob = match &claim.ssh_public_key {
        Some(b64) => crate::ssh::codec::base64_decode_lenient(b64),
        None => parsed.pubkey_blob.clone(),
    };
    if blob != parsed.pubkey_blob {
        return ClaimProof::Outcome(failed(
            identity_key,
            Some(claim),
            "identity claim public key does not match its signature".to_string(),
        ));
    }
    let ssh_fingerprint = crate::ssh::key::fingerprint(&blob);
    if let Some(claimed) = &claim.ssh_fingerprint
        && claimed.as_str() != ssh_fingerprint
    {
        return ClaimProof::Outcome(failed(
            identity_key,
            Some(claim),
            "identity claim fingerprint does not match its signature".to_string(),
        ));
    }
    let message = claim::claim_bytes(claim);
    match sshsig::verify(signature, &message, None, None, Some(&blob)) {
        Ok(true) => {}
        Ok(false) => {
            return ClaimProof::Outcome(failed(
                identity_key,
                Some(claim),
                "identity claim signature does not verify".to_string(),
            ));
        }
        Err(e) => {
            return ClaimProof::Outcome(failed(
                identity_key,
                Some(claim),
                format!("identity claim signature is unusable: {}", e.message),
            ));
        }
    }

    if provider.needs_resolver {
        let Some(resolver) = resolver else {
            return ClaimProof::Outcome(unknown(identity_key, Some(RESOLVER_UNREACHABLE)));
        };
        match resolver.resolve(provider.id, subject) {
            Err(_) => {
                return ClaimProof::Outcome(unknown(identity_key, Some(RESOLVER_UNREACHABLE)));
            }
            Ok(answer) => {
                if answer.status != "ok" || answer.keys.is_empty() {
                    return ClaimProof::Outcome(failed(
                        identity_key,
                        Some(claim),
                        format!(
                            "{} publishes no SSH keys, so this identity claim cannot be checked",
                            provider.display_id(subject)
                        ),
                    ));
                }
                if !answer.keys.iter().any(|k| k.fingerprint == ssh_fingerprint) {
                    return ClaimProof::Outcome(failed(
                        identity_key,
                        Some(claim),
                        format!(
                            "SSH key {ssh_fingerprint} is not published by {}",
                            provider.display_id(subject)
                        ),
                    ));
                }
            }
        }
    }

    ClaimProof::Proof { ssh_fingerprint }
}

/// The full evaluation (`evaluate`, verify.js): `claim_shape` plus the
/// connection-bound pre-checks, plus the live challenge — everything
/// `inspect_claim` does *not* do.
fn evaluate(opts: &VerifyPeerIdentityOpts<'_>, identity_key: &str) -> Outcome {
    let (provider, subject) = match claim_shape(opts.claim, identity_key) {
        ClaimShape::Outcome(o) => return o,
        ClaimShape::Shaped { provider, subject } => (provider, subject),
    };
    let claim = opts.claim.expect("Shaped implies a claim");

    // A challenge that was never answered is a refusal — it must not fall
    // through to the resolver, or a resolver hiccup would downgrade a
    // silent prover to `unknown`.
    if opts.challenge.is_none() || opts.signature.is_none() {
        return failed(
            identity_key,
            Some(claim),
            "peer did not answer the identity challenge".to_string(),
        );
    }

    let auth_key = opts.auth_key.unwrap_or("");
    if auth_key.is_empty() || claim.auth_key.as_deref().unwrap_or("") != auth_key {
        return failed(
            identity_key,
            Some(claim),
            "identity claim is not bound to the device auth key used on this connection"
                .to_string(),
        );
    }
    if !identity_key.is_empty() && claim.identity_key.as_deref().unwrap_or("") != identity_key {
        return failed(
            identity_key,
            Some(claim),
            "identity claim is not bound to this peer identity key".to_string(),
        );
    }

    let ssh_fingerprint = match claim_proof(claim, &provider, &subject, identity_key, opts.resolver)
    {
        ClaimProof::Outcome(o) => return o,
        ClaimProof::Proof { ssh_fingerprint } => ssh_fingerprint,
    };

    let challenge = opts.challenge.expect("checked above");
    let auth_key_bytes = hex::decode(auth_key).unwrap_or_default();
    let signature_bytes = hex::decode(opts.signature.expect("checked above")).unwrap_or_default();
    if !claim::verify_challenge(&auth_key_bytes, challenge, &signature_bytes) {
        return failed(
            identity_key,
            Some(claim),
            "identity challenge signature does not verify".to_string(),
        );
    }

    Outcome {
        status: Status::Verified,
        display_id: provider.display_id(&subject),
        provider: provider.id.to_string(),
        subject: Some(subject),
        ssh_fingerprint: Some(ssh_fingerprint),
        reason: None,
    }
}

fn unknown(identity_key: &str, reason: Option<&str>) -> Outcome {
    let provider = providers::get_provider(providers::UNKNOWN).expect("unknown always resolves");
    Outcome {
        status: Status::Unknown,
        display_id: provider.display_id(identity_key),
        provider: providers::UNKNOWN.to_string(),
        subject: None,
        ssh_fingerprint: None,
        reason: reason.map(str::to_string),
    }
}

/// A failed claim keeps its *claimed* provider/subject in the result, but
/// never gets that provider's `display_id` — an unverified peer always
/// renders as `UNKNOWN`.
fn failed(identity_key: &str, claim: Option<&Claim>, reason: String) -> Outcome {
    let provider = providers::get_provider(providers::UNKNOWN).expect("unknown always resolves");
    Outcome {
        status: Status::Failed,
        display_id: provider.display_id(identity_key),
        provider: claim
            .and_then(|c| c.provider.clone())
            .unwrap_or_else(|| providers::UNKNOWN.to_string()),
        subject: claim.and_then(|c| c.subject.clone()),
        ssh_fingerprint: claim.and_then(|c| c.ssh_fingerprint.clone()),
        reason: Some(reason),
    }
}

fn status_str(status: Status) -> &'static str {
    match status {
        Status::Verified => "verified",
        Status::Unknown => "unknown",
        Status::Failed => "failed",
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Only a verified outcome writes a real provider/subject: a failed or
/// unknown peer must not leave a record that renders as `alice@github`.
/// `put_peer` merges, so `localName`/`localComment` survive.
fn persist(store: Option<&IdentityStore>, identity_key: &str, outcome: &Outcome) {
    let Some(store) = store else { return };
    if !is_valid_identity_key(identity_key) {
        return;
    }
    let now = now_ms();
    let verified = outcome.status == Status::Verified;
    let mut patch = Map::new();
    patch.insert(
        "provider".to_string(),
        json!(if verified {
            outcome.provider.clone()
        } else {
            providers::UNKNOWN.to_string()
        }),
    );
    patch.insert(
        "subject".to_string(),
        if verified {
            json!(outcome.subject)
        } else {
            Value::Null
        },
    );
    patch.insert("status".to_string(), json!(status_str(outcome.status)));
    patch.insert("sshFingerprint".to_string(), json!(outcome.ssh_fingerprint));
    patch.insert("failureReason".to_string(), json!(outcome.reason));
    patch.insert("lastSeenAt".to_string(), json!(now));
    if verified {
        patch.insert("lastVerifiedAt".to_string(), json!(now));
    }
    // A write failure is bookkeeping for the UI: it must never turn into a
    // refused connection.
    let _ = store.put_peer(identity_key, patch);
}

/// `/^[0-9a-f]{2,128}$/` (verify.js's own `persist` guard).
fn is_valid_identity_key(s: &str) -> bool {
    let bytes = s.as_bytes();
    (2..=128).contains(&bytes.len()) && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

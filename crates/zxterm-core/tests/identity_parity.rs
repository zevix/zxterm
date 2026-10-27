//! Cross-language parity gates for `zxterm_core::identity` (K3, spike S4
//! part 2), against the real ZBTerm `engine/identity/{claim,verify,store}.js`
//! and `electron/github-keys.js` (via `zxterm_testkit::js` and
//! `crates/zxterm-testkit/js/identity_parity.js`) and the testkit's loopback
//! `.keys` server (`zxterm_testkit::KeysServer`, `A-9`).
//!
//! Every test skips with a printed reason when the ZBTerm tree
//! (`ZX_ZBTERM`) or `node` is unavailable.

use std::sync::Arc;

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey};
use serde_json::{Value, json};

use zxterm_core::identity::claim::{self, Challenge, Claim};
use zxterm_core::identity::resolver::{FetchAnswer, IdentityResolver, ResolverOptions};
use zxterm_core::identity::store::{IdentityStore, SetSelfInput};
use zxterm_core::identity::verify::{self, InspectClaimOpts, VerifyPeerIdentityOpts};
use zxterm_core::ssh::sshsig::{build_armored_signature, signed_data_blob};
use zxterm_core::wire;
use zxterm_testkit::KeysServer;

/// The JS reference is ZBTerm's last pure-JS revision
/// (`zxterm_testkit::js::reference_root`): from K9 on, the live tree's
/// identity code is a call-through to this core.
fn require_zbterm_tree() -> Option<String> {
    zxterm_testkit::js::reference_root().err()
}

fn require_node() -> Option<String> {
    zxterm_testkit::require_tool("node")
}

macro_rules! skip_unless_ready {
    ($name:expr) => {
        if let Some(reason) = require_node() {
            println!("SKIP {}: {reason}", $name);
            return;
        }
        if let Some(reason) = require_zbterm_tree() {
            println!("SKIP {}: {reason}", $name);
            return;
        }
    };
}

fn run_bridge(cmd: &str, args: &Value) -> Value {
    let args_json = args.to_string();
    let output = zxterm_testkit::js::run_reference("identity_parity.js", &[cmd, &args_json], None)
        .expect("spawn node bridge");
    assert!(
        output.status.success(),
        "bridge exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "bridge produced non-JSON stdout ({e}): {stdout:?}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn fixture_claim() -> Claim {
    Claim {
        provider: Some("github".into()),
        subject: Some("octocat".into()),
        identity_key: Some("a".repeat(64)),
        auth_key: Some("b".repeat(64)),
        ssh_fingerprint: Some("SHA256:placeholder".into()),
        issued_at: Some(1_750_000_000_000),
        nonce: Some("c".repeat(32)),
        signature: None,
        ssh_public_key: None,
    }
}

fn fixture_challenge() -> Challenge {
    Challenge {
        session_id: Some("sess-1".into()),
        challenge_id: Some("0".repeat(32)),
        nonce: Some("1".repeat(64)),
        verifier_dht_key: Some("2".repeat(64)),
        prover_dht_key: Some("3".repeat(64)),
        role: Some("viewer".into()),
    }
}

fn claim_to_json(c: &Claim) -> Value {
    json!({
        "provider": c.provider,
        "subject": c.subject,
        "identityKey": c.identity_key,
        "authKey": c.auth_key,
        "sshFingerprint": c.ssh_fingerprint,
        "issuedAt": c.issued_at,
        "nonce": c.nonce,
    })
}

fn challenge_to_json(c: &Challenge) -> Value {
    json!({
        "sessionId": c.session_id,
        "challengeId": c.challenge_id,
        "nonce": c.nonce,
        "verifierDhtKey": c.verifier_dht_key,
        "proverDhtKey": c.prover_dht_key,
        "role": c.role,
    })
}

// ---------------------------------------------------------------------------
// Claim bytes / challenge bytes are byte-equal to the JS twin.
// ---------------------------------------------------------------------------

#[test]
fn claim_bytes_match_claim_js() {
    skip_unless_ready!("claim_bytes_match_claim_js");
    let claim = fixture_claim();
    let rust_bytes = claim::claim_bytes(&claim);
    let js_result = run_bridge("claim-bytes", &claim_to_json(&claim));
    let js_bytes_b64 = js_result["bytesBase64"].as_str().expect("bytesBase64");
    assert_eq!(base64_of(&rust_bytes), js_bytes_b64);
}

#[test]
fn challenge_bytes_match_claim_js() {
    skip_unless_ready!("challenge_bytes_match_claim_js");
    let challenge = fixture_challenge();
    let rust_bytes = claim::challenge_bytes(&challenge);
    let js_result = run_bridge("challenge-bytes", &challenge_to_json(&challenge));
    let js_bytes_b64 = js_result["bytesBase64"].as_str().expect("bytesBase64");
    assert_eq!(base64_of(&rust_bytes), js_bytes_b64);
}

// ---------------------------------------------------------------------------
// A claim minted by the Rust port verifies in verify.js::verifyPeerIdentity
// against the testkit's loopback `.keys` server.
// ---------------------------------------------------------------------------

#[test]
fn rust_minted_claim_verifies_in_js() {
    skip_unless_ready!("rust_minted_claim_verifies_in_js");

    let ssh_signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let ssh_public = ssh_signing_key.verifying_key().to_bytes();
    let pubkey_blob = claim::encode_ed25519_public_key(&ssh_public).unwrap();
    let ssh_fingerprint = zxterm_core::ssh::key::fingerprint(&pubkey_blob);

    let auth_signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let auth_public = auth_signing_key.verifying_key().to_bytes();
    let mut auth_secret = [0u8; 64];
    auth_secret[..32].copy_from_slice(&[12u8; 32]);
    auth_secret[32..].copy_from_slice(&auth_public);

    let claim = Claim {
        provider: Some("github".into()),
        subject: Some("octocat".into()),
        identity_key: Some("a".repeat(64)),
        auth_key: Some(hex::encode(auth_public)),
        ssh_fingerprint: Some(ssh_fingerprint),
        issued_at: Some(1_750_000_000_000),
        nonce: Some("c".repeat(32)),
        signature: None,
        ssh_public_key: Some(base64_of(&pubkey_blob)),
    };
    let message = claim::claim_bytes(&claim);
    let blob = signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &message);
    let raw_sig: Signature = ssh_signing_key.sign(&blob);
    let armored = build_armored_signature(
        &pubkey_blob,
        &raw_sig.to_bytes(),
        wire::NAMESPACE,
        wire::HASH_ALG,
    )
    .unwrap();
    let claim = Claim {
        signature: Some(armored),
        ..claim
    };

    let ssh_public_key_line = format!("ssh-ed25519 {}\n", base64_of(&pubkey_blob));
    let server = KeysServer::start(Arc::new(move |user| {
        if user == "octocat" {
            Some(ssh_public_key_line.clone())
        } else {
            None
        }
    }))
    .expect("start keys server");

    let challenge = fixture_challenge();
    let challenge_sig = claim::sign_challenge(&auth_secret, &challenge).unwrap();

    let mut claim_json = claim_to_json(&claim);
    claim_json["signature"] = json!(claim.signature);
    claim_json["sshPublicKey"] = json!(claim.ssh_public_key);

    let outcome = run_bridge(
        "verify-peer-identity",
        &json!({
            "claim": claim_json,
            "identityKey": claim.identity_key,
            "authKey": claim.auth_key,
            "challenge": challenge_to_json(&challenge),
            "signatureHex": hex::encode(challenge_sig),
            "baseUrl": server.base_url(),
        }),
    );
    assert_eq!(outcome["status"], json!("verified"), "{outcome}");
    assert_eq!(outcome["displayId"], json!("octocat@github"));
}

// ---------------------------------------------------------------------------
// A claim minted by claim.js/github-keys.js verifies in the Rust
// verify::verify_peer_identity against the same loopback server.
// ---------------------------------------------------------------------------

#[test]
fn js_minted_claim_verifies_in_rust() {
    skip_unless_ready!("js_minted_claim_verifies_in_rust");

    let minted = run_bridge(
        "mint-claim",
        &json!({"provider": "github", "subject": "octocat", "identityKey": "a".repeat(64)}),
    );
    let ssh_public_key_line = minted["sshPublicKeyLine"].as_str().unwrap().to_string();
    let server = KeysServer::start(Arc::new(move |user| {
        if user == "octocat" {
            Some(format!("{ssh_public_key_line}\n"))
        } else {
            None
        }
    }))
    .expect("start keys server");

    let claim_json = &minted["claim"];
    let claim = Claim {
        provider: claim_json["provider"].as_str().map(str::to_string),
        subject: claim_json["subject"].as_str().map(str::to_string),
        identity_key: claim_json["identityKey"].as_str().map(str::to_string),
        auth_key: claim_json["authKey"].as_str().map(str::to_string),
        ssh_fingerprint: claim_json["sshFingerprint"].as_str().map(str::to_string),
        issued_at: claim_json["issuedAt"].as_i64(),
        nonce: claim_json["nonce"].as_str().map(str::to_string),
        signature: claim_json["signature"].as_str().map(str::to_string),
        ssh_public_key: claim_json["sshPublicKey"].as_str().map(str::to_string),
    };

    let auth_secret_hex = minted["authSecretKeyHex"].as_str().unwrap();
    let auth_secret = hex::decode(auth_secret_hex).unwrap();
    let auth_key_hex = claim.auth_key.clone().unwrap();
    let challenge = fixture_challenge();
    let signature = claim::sign_challenge(&auth_secret, &challenge).unwrap();

    let base_url = server.base_url();
    let resolver = IdentityResolver::new(ResolverOptions {
        fetch: Some(Box::new(move |_provider, subject| {
            let answer = zxterm_core::identity::github::fetch_keys(subject, Some(&base_url), None)?;
            Ok(FetchAnswer {
                status: answer.status,
                keys: answer.keys,
            })
        })),
        ..Default::default()
    });

    let identity_key = claim.identity_key.clone().unwrap();
    let signature_hex = hex::encode(signature);
    let opts = VerifyPeerIdentityOpts {
        claim: Some(&claim),
        identity_key: Some(&identity_key),
        auth_key: Some(&auth_key_hex),
        challenge: Some(&challenge),
        signature: Some(&signature_hex),
        resolver: Some(&resolver),
    };
    let outcome = verify::verify_peer_identity(&opts, None);
    assert_eq!(
        outcome.status,
        verify::Status::Verified,
        "{:?}",
        outcome.reason
    );
    assert_eq!(outcome.display_id, "octocat@github");

    // `inspect_claim` (layer 1 only) also passes on the same claim.
    let inspect_opts = InspectClaimOpts {
        claim: Some(&claim),
        identity_key: Some(&identity_key),
        resolver: Some(&resolver),
    };
    let inspected = verify::inspect_claim(&inspect_opts);
    assert_eq!(inspected.status, verify::Status::Verified);
}

// ---------------------------------------------------------------------------
// A `self.json`/`peers/<hex>.json` file written by `store.js` is read
// correctly by the Rust `store` module, and the reverse.
// ---------------------------------------------------------------------------

#[test]
fn self_json_written_by_rust_is_read_by_js() {
    skip_unless_ready!("self_json_written_by_rust_is_read_by_js");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path().join("account").join("identity");
    let store = IdentityStore::new(&dir);
    store.ready().unwrap();

    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    let pubkey_blob = claim::encode_ed25519_public_key(&public).unwrap();
    let mut input = SetSelfInput {
        provider: "github".into(),
        subject: Some("octocat".into()),
        identity_key: "a".repeat(64),
        auth_key: Some("b".repeat(64)),
        ssh_public_key: Some(base64_of(&pubkey_blob)),
        ssh_key_type: Some(wire::KEY_TYPE.to_string()),
        ssh_fingerprint: Some(zxterm_core::ssh::key::fingerprint(&pubkey_blob)),
        issued_at: Some(1_750_000_000_000),
        nonce: Some("c".repeat(32)),
        signature: None,
        created_at: None,
    };
    let unsigned = Claim {
        provider: Some(input.provider.clone()),
        subject: input.subject.clone(),
        identity_key: Some(input.identity_key.clone()),
        auth_key: input.auth_key.clone(),
        ssh_fingerprint: input.ssh_fingerprint.clone(),
        issued_at: input.issued_at,
        nonce: input.nonce.clone(),
        signature: None,
        ssh_public_key: input.ssh_public_key.clone(),
    };
    let message = claim::claim_bytes(&unsigned);
    let blob = signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &message);
    let raw_sig: Signature = signing_key.sign(&blob);
    input.signature = Some(
        build_armored_signature(
            &pubkey_blob,
            &raw_sig.to_bytes(),
            wire::NAMESPACE,
            wire::HASH_ALG,
        )
        .unwrap(),
    );

    let written = store.set_self(&input).expect("rust set_self");
    let js_read = run_bridge("read-self", &json!({"dir": dir.to_string_lossy()}));
    assert_eq!(js_read["provider"], json!("github"));
    assert_eq!(js_read["subject"], json!("octocat"));
    assert_eq!(js_read["identityKey"], json!(written.identity_key));
    assert_eq!(js_read["sshFingerprint"], json!(written.ssh_fingerprint));
    assert_eq!(js_read["version"], json!(2));
}

#[test]
fn self_json_written_by_js_is_read_by_rust() {
    skip_unless_ready!("self_json_written_by_js_is_read_by_rust");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path().join("account").join("identity");

    let minted = run_bridge(
        "mint-claim",
        &json!({"provider": "github", "subject": "octocat"}),
    );
    let mut record = minted["claim"].clone();
    record["createdAt"] = json!(1_750_000_000_000i64);

    let written = run_bridge(
        "write-self",
        &json!({"dir": dir.to_string_lossy(), "record": record}),
    );
    assert_eq!(written["provider"], json!("github"));

    let store = IdentityStore::new(&dir);
    let read = store.get_self().expect("rust get_self").expect("present");
    assert_eq!(read.provider, "github");
    assert_eq!(read.subject.as_deref(), Some("octocat"));
    assert_eq!(read.version, 2);
    assert_eq!(read.signature.as_deref(), record["signature"].as_str());
}

#[test]
fn peer_file_written_by_rust_is_read_by_js() {
    skip_unless_ready!("peer_file_written_by_rust_is_read_by_js");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path().join("account").join("identity");
    let store = IdentityStore::new(&dir);
    store.ready().unwrap();
    let id_hex = "ab".repeat(32);

    let mut patch = serde_json::Map::new();
    patch.insert("provider".into(), json!("github"));
    patch.insert("subject".into(), json!("octocat"));
    patch.insert("status".into(), json!("verified"));
    store.put_peer(&id_hex, patch).expect("rust put_peer");

    let js_read = run_bridge(
        "read-peer",
        &json!({"dir": dir.to_string_lossy(), "idHex": id_hex}),
    );
    assert_eq!(js_read["provider"], json!("github"));
    assert_eq!(js_read["displayId"], json!("octocat@github"));
    assert_eq!(js_read["status"], json!("verified"));
}

#[test]
fn peer_file_written_by_js_is_read_by_rust() {
    skip_unless_ready!("peer_file_written_by_js_is_read_by_rust");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path().join("account").join("identity");
    let id_hex = "cd".repeat(32);

    let written = run_bridge(
        "write-peer",
        &json!({
            "dir": dir.to_string_lossy(),
            "idHex": id_hex,
            "patch": {"provider": "github", "subject": "octocat", "status": "verified"}
        }),
    );
    assert_eq!(written["displayId"], json!("octocat@github"));

    let store = IdentityStore::new(&dir);
    let read = store
        .get_peer(&id_hex)
        .expect("rust get_peer")
        .expect("present");
    assert_eq!(read.provider, "github");
    assert_eq!(read.subject.as_deref(), Some("octocat"));
    assert_eq!(read.display_id, "octocat@github");
    assert_eq!(read.status, "verified");
}

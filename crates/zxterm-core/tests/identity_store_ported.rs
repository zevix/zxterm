//! Ports the in-scope cases of ZBTerm `test/identity-store.test.js` (7
//! `test(` cases, recounted 2026-09-29) to `zxterm_core::identity::store`.
//!
//! Cases 6 and 7 of that file ("engine ready installs a device auth keypair
//! and never rotates it", "engine identity methods mint, install, annotate
//! and clear identities") exercise `SessionEngine`/`PtyHost`'s
//! account/device wiring and the `identity.*` invoke methods — ZBTerm
//! infrastructure this phase does not port (K9 routes ZBTerm's calls into
//! this module over the seam; see this crate's `identity` module doc
//! comment). They are not, in substance, tests of `engine/identity/
//! store.js` — they are co-located in the same JS file. Cases 1-5, which
//! exercise `IdentityStore`/`providers` directly, are ported below.

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey};

use zxterm_core::identity::claim::{claim_bytes, encode_ed25519_public_key};
use zxterm_core::identity::providers::{GITHUB, UNKNOWN, get_provider};
use zxterm_core::identity::store::{IdentityStore, SetSelfInput};
use zxterm_core::ssh::key::fingerprint;
use zxterm_core::ssh::sshsig::{build_armored_signature, signed_data_blob};
use zxterm_core::wire;

fn fresh_store() -> (zxterm_testkit::ScratchHome, IdentityStore) {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let store = IdentityStore::new(home.path().join("account").join("identity"));
    store.ready().expect("ready");
    (home, store)
}

struct Ed25519Key {
    secret: [u8; 32],
    pubkey_blob: Vec<u8>,
}

fn ed25519() -> Ed25519Key {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    Ed25519Key {
        secret: [5u8; 32],
        pubkey_blob: encode_ed25519_public_key(&public).unwrap(),
    }
}

fn sign_claim(key: &Ed25519Key, input: &SetSelfInput) -> String {
    let claim = zxterm_core::identity::claim::Claim {
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
    let message = claim_bytes(&claim);
    let signing_key = SigningKey::from_bytes(&key.secret);
    let blob = signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &message);
    let raw_sig: Signature = signing_key.sign(&blob);
    build_armored_signature(
        &key.pubkey_blob,
        &raw_sig.to_bytes(),
        wire::NAMESPACE,
        wire::HASH_ALG,
    )
    .unwrap()
}

fn signed_self_input(key: &Ed25519Key) -> SetSelfInput {
    let mut input = SetSelfInput {
        provider: GITHUB.to_string(),
        subject: Some("octocat".to_string()),
        identity_key: "a".repeat(64),
        auth_key: Some("b".repeat(64)),
        ssh_public_key: Some(base64_of(&key.pubkey_blob)),
        ssh_key_type: Some(wire::KEY_TYPE.to_string()),
        ssh_fingerprint: Some(fingerprint(&key.pubkey_blob)),
        issued_at: Some(1_750_000_000_000),
        nonce: Some("c".repeat(32)),
        signature: None,
        created_at: None,
    };
    input.signature = Some(sign_claim(key, &input));
    input
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn identity_store_round_trips_a_signed_self_claim() {
    let (_home, store) = fresh_store();
    let key = ed25519();
    let input = signed_self_input(&key);

    let written = store.set_self(&input).expect("set self");
    let read = store.get_self().expect("get self").expect("present");

    assert_eq!(written.provider, "github");
    assert_eq!(read, written);
    assert_eq!(read.subject.as_deref(), Some("octocat"));
    assert_eq!(read.version, 2);
    assert_eq!(
        get_provider(&read.provider)
            .unwrap()
            .display_id(read.subject.as_deref().unwrap()),
        "octocat@github"
    );
    assert_eq!(mode(&store.root().join("self.json")), 0o600);
}

#[test]
fn identity_store_rejects_a_claim_whose_signature_does_not_match_its_bytes() {
    let (_home, store) = fresh_store();
    let key = ed25519();
    let input = signed_self_input(&key);

    let mut wrong_subject = input.clone();
    wrong_subject.subject = Some("someone-else".to_string());
    let err = store.set_self(&wrong_subject).unwrap_err();
    assert!(
        err.message.contains("signature does not verify"),
        "{}",
        err.message
    );

    let mut no_sig = input.clone();
    no_sig.signature = None;
    let err = store.set_self(&no_sig).unwrap_err();
    assert!(err.message.contains("is not signed"), "{}", err.message);

    let mut wrong_fp = input.clone();
    wrong_fp.ssh_fingerprint = Some("SHA256:nope".to_string());
    let err = store.set_self(&wrong_fp).unwrap_err();
    assert!(
        err.message.contains("fingerprint mismatch"),
        "{}",
        err.message
    );

    assert!(store.get_self().unwrap().is_none(), "nothing was written");
}

#[test]
fn identity_store_validates_the_provider_and_the_github_username() {
    let (_home, store) = fresh_store();
    let key = ed25519();
    let mut input = signed_self_input(&key);
    input.provider = "gitlab".to_string();
    let err = store.set_self(&input).unwrap_err();
    assert!(
        err.message.contains("Unknown identity provider: gitlab"),
        "{}",
        err.message
    );

    assert_eq!(
        get_provider(UNKNOWN).unwrap().display_id(&"a".repeat(64)),
        "aaaaaaaaaaaa@UNKNOWN"
    );
    assert!(
        get_provider(GITHUB)
            .unwrap()
            .validate_subject(Some("-bad"))
            .is_err()
    );
    assert!(
        get_provider(GITHUB)
            .unwrap()
            .validate_subject(Some(&"a".repeat(40)))
            .is_err()
    );
    assert_eq!(
        get_provider(GITHUB)
            .unwrap()
            .validate_subject(Some("OctoCat"))
            .unwrap(),
        "octocat"
    );
}

#[test]
fn put_peer_preserves_prior_status_fields_and_peer_files_are_0o600() {
    let (_home, store) = fresh_store();
    let id_hex = "ab".repeat(32);

    let mut first = serde_json::Map::new();
    first.insert("provider".into(), serde_json::json!("github"));
    first.insert("subject".into(), serde_json::json!("octocat"));
    first.insert("status".into(), serde_json::json!("verified"));
    first.insert(
        "lastVerifiedAt".into(),
        serde_json::json!(1_750_000_000_000i64),
    );
    first.insert("lastSeenAt".into(), serde_json::json!(1_750_000_000_001i64));
    first.insert("sshFingerprint".into(), serde_json::json!("SHA256:abc"));
    store.put_peer(&id_hex, first).expect("first put_peer");

    let mut annotate = serde_json::Map::new();
    annotate.insert("localName".into(), serde_json::json!("Alice"));
    annotate.insert("localComment".into(), serde_json::json!("laptop"));
    let annotated = store.put_peer(&id_hex, annotate).expect("annotate");

    assert_eq!(annotated.status, "verified");
    assert_eq!(annotated.last_verified_at, Some(1_750_000_000_000));
    assert_eq!(annotated.ssh_fingerprint.as_deref(), Some("SHA256:abc"));
    assert_eq!(annotated.display_id, "octocat@github");
    assert_eq!(annotated.local_name.as_deref(), Some("Alice"));
    assert_eq!(annotated.local_comment.as_deref(), Some("laptop"));
    assert_eq!(
        mode(&store.root().join("peers").join(format!("{id_hex}.json"))),
        0o600
    );

    let mut reseen = serde_json::Map::new();
    reseen.insert("status".into(), serde_json::json!("pending"));
    reseen.insert("lastSeenAt".into(), serde_json::json!(1_750_000_000_002i64));
    let reseen = store.put_peer(&id_hex, reseen).expect("reseen");
    assert_eq!(
        reseen.local_name.as_deref(),
        Some("Alice"),
        "a status patch never drops local annotations"
    );
    assert_eq!(reseen.local_comment.as_deref(), Some("laptop"));

    let unknown_id = "cd".repeat(32);
    let unknown_peer = store
        .put_peer(&unknown_id, serde_json::Map::new())
        .expect("unknown peer");
    assert_eq!(unknown_peer.status, "unknown");
    assert_eq!(
        unknown_peer.display_id,
        format!("{}@UNKNOWN", &unknown_id[..12])
    );

    assert_eq!(store.list_peers().expect("list peers").len(), 2);
}

#[test]
fn clear_self_drops_to_unknown_and_leaves_peers_intact() {
    let (_home, store) = fresh_store();
    let key = ed25519();
    let input = signed_self_input(&key);
    store.set_self(&input).expect("set self");

    let mut patch = serde_json::Map::new();
    patch.insert("status".into(), serde_json::json!("verified"));
    patch.insert("localName".into(), serde_json::json!("Alice"));
    store.put_peer(&"ab".repeat(32), patch).expect("put peer");

    let cleared = store.clear_self(None).expect("clear self");
    let self_record = store.get_self().expect("get self").expect("present");
    let peers = store.list_peers().expect("list peers");

    assert_eq!(cleared.provider, "unknown");
    assert_eq!(self_record.provider, "unknown");
    assert_eq!(self_record.identity_key, input.identity_key);
    assert!(self_record.signature.is_none());
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].local_name.as_deref(), Some("Alice"));
}

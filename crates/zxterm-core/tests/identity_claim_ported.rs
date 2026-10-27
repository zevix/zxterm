//! Ports every case of ZBTerm `test/identity-claim.test.js` (12 `test(`
//! cases, recounted 2026-09-29). The SSHSIG container itself (armor, parse,
//! verify, `fingerprint`) is `zxterm_core::ssh::sshsig`/`ssh::key` (K2, from
//! this same JS source file); this file exercises those plus
//! `zxterm_core::identity::claim`'s own additions (`claim_bytes`,
//! `challenge_bytes`, `sign_challenge`, `verify_challenge`).

mod support;

use std::path::Path;
use std::process::Command;

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey};

use zxterm_core::identity::claim::{
    Challenge, Claim, challenge_bytes, claim_bytes, encode_ed25519_public_key, sign_challenge,
    verify_challenge,
};
use zxterm_core::ssh::key::{RsaFields, fingerprint, parse_openssh_private_key};
use zxterm_core::ssh::sshsig::{self, build_armored_signature, parse_armored_signature};
use zxterm_core::wire;

fn require_ssh_keygen() -> Option<String> {
    zxterm_testkit::require_tool("ssh-keygen")
}

fn base_claim() -> Claim {
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

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn write_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn read_ed25519_private(file: &Path) -> zxterm_core::ssh::key::ParsedPrivateKey {
    let text = std::fs::read_to_string(file).unwrap();
    parse_openssh_private_key(&text).expect("parse ed25519 private key")
}

#[test]
fn claim_bytes_are_the_frozen_canonical_encoding() {
    let claim = base_claim();
    let expected = format!(
        "zbterm-identity-claim/v1\nprovider=github\nsubject=octocat\nidentityKey={}\nauthKey={}\nsshFingerprint=SHA256:placeholder\nissuedAt=1750000000000\nnonce={}\n",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    );
    assert_eq!(String::from_utf8(claim_bytes(&claim)).unwrap(), expected);
}

#[test]
fn challenge_bytes_are_the_frozen_canonical_encoding() {
    let challenge = Challenge {
        session_id: Some("sess-1".into()),
        challenge_id: Some("0".repeat(32)),
        nonce: Some("1".repeat(64)),
        verifier_dht_key: Some("2".repeat(64)),
        prover_dht_key: Some("3".repeat(64)),
        role: Some("viewer".into()),
    };
    let expected = format!(
        "zbterm-identity-challenge/v1\nsessionId=sess-1\nchallengeId={}\nnonce={}\nverifierDhtKey={}\nproverDhtKey={}\nrole=viewer\n",
        "0".repeat(32),
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64)
    );
    assert_eq!(
        String::from_utf8(challenge_bytes(&challenge)).unwrap(),
        expected
    );

    let empty = Challenge {
        session_id: None,
        ..challenge
    };
    let bytes = String::from_utf8(challenge_bytes(&empty)).unwrap();
    assert!(
        bytes.contains("\nsessionId=\n"),
        "a missing sessionId encodes as an empty value"
    );
}

#[test]
fn challenge_signatures_round_trip_and_reject_tampering() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&[9u8; 32]);
    secret[32..].copy_from_slice(&public);

    let challenge = Challenge {
        session_id: Some("sess-1".into()),
        challenge_id: Some("0".repeat(32)),
        nonce: Some("1".repeat(64)),
        verifier_dht_key: Some("2".repeat(64)),
        prover_dht_key: Some("3".repeat(64)),
        role: Some("viewer".into()),
    };
    let signature = sign_challenge(&secret, &challenge).expect("sign challenge");
    assert!(verify_challenge(&public, &challenge, &signature));
    assert!(!verify_challenge(
        &public,
        &Challenge {
            role: Some("host".into()),
            ..challenge.clone()
        },
        &signature
    ));
    assert!(!verify_challenge(
        &public,
        &Challenge {
            prover_dht_key: Some("4".repeat(64)),
            ..challenge
        },
        &signature
    ));
}

#[test]
fn our_armored_claim_signature_verifies_with_real_ssh_keygen_y_verify() {
    let Some(reason) = require_ssh_keygen() else {
        return run_our_armored_claim_signature_verifies();
    };
    println!("SKIP our_armored_claim_signature_verifies_with_real_ssh_keygen_y_verify: {reason}");
}

fn run_our_armored_claim_signature_verifies() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = dir.join("id");
    support::keygen(dir, "id", "ed25519", "");
    let key = read_ed25519_private(&key_file);
    let secret = key.secret_key.expect("unencrypted ed25519 key");

    let claim = Claim {
        ssh_fingerprint: Some(fingerprint(&key.public_key_blob)),
        ..base_claim()
    };
    let message = claim_bytes(&claim);
    let signing_key = SigningKey::from_bytes(&{
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[..32]);
        seed
    });
    let blob = sshsig::signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &message);
    let raw_sig: Ed25519Signature = signing_key.sign(&blob);
    let armored = build_armored_signature(
        &key.public_key_blob,
        &raw_sig.to_bytes(),
        wire::NAMESPACE,
        wire::HASH_ALG,
    )
    .expect("build armored signature");

    let msg_file = dir.join("claim.txt");
    let sig_file = dir.join("claim.txt.sig");
    let signers = dir.join("allowed_signers");
    std::fs::write(&msg_file, &message).unwrap();
    std::fs::write(&sig_file, &armored).unwrap();
    std::fs::write(
        &signers,
        format!(
            "zbterm@test ssh-ed25519 {}\n",
            base64_of(&key.public_key_blob)
        ),
    )
    .unwrap();

    let verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", "zbterm@test", "-n", wire::NAMESPACE, "-s"])
        .arg(&sig_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(&message)?;
            child.wait_with_output()
        })
        .expect("run ssh-keygen -Y verify");
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        sshsig::verify(&armored, &message, None, None, None).expect("verify"),
        "and it verifies with our own verifier"
    );
}

#[test]
fn a_real_ssh_keygen_y_sign_ed25519_signature_verifies() {
    let Some(reason) = require_ssh_keygen() else {
        return run_ssh_keygen_sign_ed25519();
    };
    println!("SKIP a_real_ssh_keygen_y_sign_ed25519_signature_verifies: {reason}");
}

fn run_ssh_keygen_sign_ed25519() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = support::keygen(dir, "id", "ed25519", "");
    let pub_text = std::fs::read_to_string(key_file.with_extension("pub")).unwrap();
    let pubkey_blob = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(pub_text.split_whitespace().nth(1).unwrap())
            .unwrap()
    };

    let claim = Claim {
        ssh_fingerprint: Some(fingerprint(&pubkey_blob)),
        ..base_claim()
    };
    let message = claim_bytes(&claim);
    let msg_file = dir.join("claim.txt");
    std::fs::write(&msg_file, &message).unwrap();
    let sign = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&key_file)
        .args(["-n", wire::NAMESPACE])
        .arg(&msg_file)
        .output()
        .expect("run ssh-keygen -Y sign");
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let armored = std::fs::read_to_string(dir.join("claim.txt.sig")).unwrap();

    let parsed = parse_armored_signature(&armored).expect("parse armor");
    assert_eq!(parsed.namespace, wire::NAMESPACE);
    assert_eq!(parsed.hash_alg, wire::HASH_ALG);
    assert_eq!(parsed.pubkey_blob, pubkey_blob);
    assert!(sshsig::verify(&armored, &message, None, None, None).unwrap());
    assert!(sshsig::verify(&armored, &message, None, None, Some(&pubkey_blob)).unwrap());
    let other_key = encode_ed25519_public_key(
        &SigningKey::from_bytes(&[2u8; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    assert!(!sshsig::verify(&armored, &message, None, None, Some(&other_key)).unwrap());
    assert!(!sshsig::verify(&armored, &message, Some("other"), None, None).unwrap());
    assert!(!sshsig::verify(&armored, &message, None, Some("sha256"), None).unwrap());
}

#[test]
fn fingerprints_match_ssh_keygen_lf_byte_for_byte() {
    if let Some(reason) = require_ssh_keygen() {
        println!("SKIP fingerprints_match_ssh_keygen_lf_byte_for_byte: {reason}");
        return;
    }
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = support::keygen(dir, "id", "ed25519", "");
    let pub_file = key_file.with_extension("pub");
    let pub_text = std::fs::read_to_string(&pub_file).unwrap();
    let blob = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(pub_text.split_whitespace().nth(1).unwrap())
            .unwrap()
    };
    let listed = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(&pub_file)
        .output()
        .unwrap();
    assert!(listed.status.success());
    let expected = String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    assert_eq!(fingerprint(&blob), expected);
}

#[test]
fn flipping_any_claim_field_breaks_verification() {
    let Some(reason) = require_ssh_keygen() else {
        return run_flip_claim_fields();
    };
    println!("SKIP flipping_any_claim_field_breaks_verification: {reason}");
}

fn run_flip_claim_fields() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = dir.join("id");
    support::keygen(dir, "id", "ed25519", "");
    let key = read_ed25519_private(&key_file);
    let secret = key.secret_key.unwrap();
    let claim = Claim {
        ssh_fingerprint: Some(fingerprint(&key.public_key_blob)),
        ..base_claim()
    };
    let signing_key = SigningKey::from_bytes(&{
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[..32]);
        seed
    });
    let blob = sshsig::signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &claim_bytes(&claim));
    let raw_sig: Ed25519Signature = signing_key.sign(&blob);
    let armored = build_armored_signature(
        &key.public_key_blob,
        &raw_sig.to_bytes(),
        wire::NAMESPACE,
        wire::HASH_ALG,
    )
    .unwrap();

    assert!(sshsig::verify(&armored, &claim_bytes(&claim), None, None, None).unwrap());

    let mutate = |mut c: Claim, field: &str, value: &str| -> Claim {
        match field {
            "provider" => c.provider = Some(value.to_string()),
            "subject" => c.subject = Some(value.to_string()),
            "identityKey" => c.identity_key = Some(value.to_string()),
            "authKey" => c.auth_key = Some(value.to_string()),
            "sshFingerprint" => c.ssh_fingerprint = Some(value.to_string()),
            "nonce" => c.nonce = Some(value.to_string()),
            _ => unreachable!(),
        }
        c
    };
    for (field, value) in [
        ("provider", "gitlab"),
        ("subject", "not-octocat"),
        ("identityKey", &"d".repeat(64)),
        ("authKey", &"e".repeat(64)),
        ("sshFingerprint", "SHA256:other"),
        ("nonce", &"f".repeat(32)),
    ] {
        let tampered = mutate(claim.clone(), field, value);
        assert!(
            !sshsig::verify(&armored, &claim_bytes(&tampered), None, None, None).unwrap(),
            "tampering with {field} must fail verification"
        );
    }
    let tampered_issued = Claim {
        issued_at: Some(1_750_000_000_001),
        ..claim.clone()
    };
    assert!(!sshsig::verify(&armored, &claim_bytes(&tampered_issued), None, None, None).unwrap());
}

#[test]
fn an_rsa_claim_we_sign_verifies_with_real_ssh_keygen_y_verify() {
    let Some(reason) = require_ssh_keygen() else {
        return run_rsa_claim_verifies();
    };
    println!("SKIP an_rsa_claim_we_sign_verifies_with_real_ssh_keygen_y_verify: {reason}");
}

fn run_rsa_claim_verifies() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = dir.join("id_rsa");
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-C",
            "zbterm-test",
            "-f",
        ])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(status.success());

    let text = std::fs::read_to_string(&key_file).unwrap();
    let parsed = parse_openssh_private_key(&text).expect("parse rsa private key");
    let RsaFields { n, e, .. } = parsed.rsa.clone().expect("rsa fields");
    let pubkey_blob = zxterm_core::identity::claim::encode_rsa_public_key(&e, &n);
    let published_text = std::fs::read_to_string(key_file.with_extension("pub")).unwrap();
    let published = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(published_text.split_whitespace().nth(1).unwrap())
            .unwrap()
    };
    assert_eq!(
        pubkey_blob, published,
        "encode_rsa_public_key rebuilds the exact ssh-rsa blob"
    );
    let listed = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(key_file.with_extension("pub"))
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listed_fp = String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    assert_eq!(
        fingerprint(&pubkey_blob),
        listed_fp,
        "RSA fingerprint matches -lf"
    );

    let claim = Claim {
        ssh_fingerprint: Some(fingerprint(&pubkey_blob)),
        ..base_claim()
    };
    let message = claim_bytes(&claim);
    let env = std::collections::HashMap::new();
    let result = sshsig::sign(&base64_of(&message), Some(&key_file), None, &env).expect("sign rsa");
    assert_eq!(
        parse_armored_signature(&result.signature).unwrap().sig_type,
        wire::RSA_SIG_ALG,
        "never a bare ssh-rsa signature"
    );

    let msg_file = dir.join("claim.txt");
    let sig_file = dir.join("claim.txt.sig");
    let signers = dir.join("allowed_signers");
    std::fs::write(&msg_file, &message).unwrap();
    std::fs::write(&sig_file, &result.signature).unwrap();
    std::fs::write(
        &signers,
        format!("zbterm@test ssh-rsa {}\n", base64_of(&pubkey_blob)),
    )
    .unwrap();
    let verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", "zbterm@test", "-n", wire::NAMESPACE, "-s"])
        .arg(&sig_file)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(&message)?;
            child.wait_with_output()
        })
        .expect("run ssh-keygen -Y verify");
    assert!(verify.status.success());
    assert!(sshsig::verify(&result.signature, &message, None, None, None).unwrap());

    let tampered = Claim {
        subject: Some("mallory".into()),
        ..claim
    };
    assert!(!sshsig::verify(&result.signature, &claim_bytes(&tampered), None, None, None).unwrap());
}

#[test]
fn a_real_ssh_keygen_y_sign_rsa_signature_verifies_its_sha1_variant_does_not() {
    let Some(reason) = require_ssh_keygen() else {
        return run_rsa_sha1_rejected();
    };
    println!(
        "SKIP a_real_ssh_keygen_y_sign_rsa_signature_verifies_its_sha1_variant_does_not: {reason}"
    );
}

fn run_rsa_sha1_rejected() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = support::keygen(dir, "id_rsa", "rsa", "");
    let pub_text = std::fs::read_to_string(key_file.with_extension("pub")).unwrap();
    let pubkey_blob = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(pub_text.split_whitespace().nth(1).unwrap())
            .unwrap()
    };
    let claim = Claim {
        ssh_fingerprint: Some(fingerprint(&pubkey_blob)),
        ..base_claim()
    };
    let message = claim_bytes(&claim);
    let msg_file = dir.join("claim.txt");
    std::fs::write(&msg_file, &message).unwrap();
    let sign = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&key_file)
        .args(["-n", wire::NAMESPACE])
        .arg(&msg_file)
        .output()
        .unwrap();
    assert!(sign.status.success());
    let armored = std::fs::read_to_string(dir.join("claim.txt.sig")).unwrap();
    let parsed = parse_armored_signature(&armored).unwrap();
    assert_eq!(parsed.sig_type, wire::RSA_SIG_ALG);
    assert!(sshsig::verify(&armored, &message, None, None, Some(&pubkey_blob)).unwrap());
    assert!(!sshsig::verify(&armored, &message, Some("other"), None, None).unwrap());

    let tampered = Claim {
        nonce: Some("9".repeat(32)),
        ..claim
    };
    assert!(!sshsig::verify(&armored, &claim_bytes(&tampered), None, None, None).unwrap());

    // Re-tag the same signature bytes as the bare `ssh-rsa` (SHA-1)
    // algorithm: the digest no longer matches, and it is refused by name.
    let sig_blob = {
        let mut v = write_string(b"ssh-rsa");
        v.extend_from_slice(&write_string(&parsed.raw_sig));
        v
    };
    let mut container = Vec::new();
    container.extend_from_slice(wire::SSHSIG_MAGIC.as_bytes());
    container.extend_from_slice(&1u32.to_be_bytes());
    container.extend_from_slice(&write_string(&parsed.pubkey_blob));
    container.extend_from_slice(&write_string(parsed.namespace.as_bytes()));
    container.extend_from_slice(&write_string(b""));
    container.extend_from_slice(&write_string(parsed.hash_alg.as_bytes()));
    container.extend_from_slice(&write_string(&sig_blob));
    let b64 = base64_of(&container);
    let mut lines = vec!["-----BEGIN SSH SIGNATURE-----".to_string()];
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 70).min(bytes.len());
        lines.push(String::from_utf8_lossy(&bytes[i..end]).into_owned());
        i = end;
    }
    lines.push("-----END SSH SIGNATURE-----".to_string());
    let re_armored = lines.join("\n") + "\n";

    let err = sshsig::verify(&re_armored, &message, None, None, None).unwrap_err();
    assert!(
        err.message
            .starts_with("Unsupported SSH signature algorithm: ssh-rsa"),
        "a bare ssh-rsa (SHA-1) SSHSIG is rejected, not accepted: {}",
        err.message
    );
}

#[test]
fn an_ecdsa_sshsig_is_still_rejected_with_a_clear_error() {
    let Some(reason) = require_ssh_keygen() else {
        return run_ecdsa_rejected();
    };
    println!("SKIP an_ecdsa_sshsig_is_still_rejected_with_a_clear_error: {reason}");
}

fn run_ecdsa_rejected() {
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let dir = home.path();
    let key_file = support::keygen(dir, "id_ecdsa", "ecdsa", "");
    let message = claim_bytes(&base_claim());
    let msg_file = dir.join("claim.txt");
    std::fs::write(&msg_file, &message).unwrap();
    let sign = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&key_file)
        .args(["-n", wire::NAMESPACE])
        .arg(&msg_file)
        .output()
        .unwrap();
    assert!(sign.status.success());
    let armored = std::fs::read_to_string(dir.join("claim.txt.sig")).unwrap();

    assert!(
        parse_armored_signature(&armored).is_ok(),
        "the container still parses"
    );
    let err = sshsig::verify(&armored, &message, None, None, None).unwrap_err();
    assert!(
        err.message
            .starts_with("Unsupported SSH key type: ecdsa-sha2-"),
        "{}",
        err.message
    );
}

#[test]
fn malformed_armor_is_refused_not_crashed_on() {
    assert!(parse_armored_signature("not a signature").is_err());
    assert!(sshsig::verify("", b"x", None, None, None).is_err());
}

#[test]
fn armored_signatures_wrap_base64_at_70_characters() {
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let public = signing_key.verifying_key().to_bytes();
    let pubkey_blob = encode_ed25519_public_key(&public).unwrap();
    let blob = sshsig::signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, b"hello");
    let raw_sig: Ed25519Signature = signing_key.sign(&blob);
    let armored = build_armored_signature(
        &pubkey_blob,
        &raw_sig.to_bytes(),
        wire::NAMESPACE,
        wire::HASH_ALG,
    )
    .unwrap();
    let lines: Vec<&str> = armored.trim().lines().collect();
    assert_eq!(lines[0], wire::ARMOR_BEGIN);
    assert_eq!(*lines.last().unwrap(), wire::ARMOR_END);
    for line in &lines[1..lines.len() - 1] {
        assert!(line.len() <= 70, "base64 line is at most 70 chars");
    }
    assert!(sshsig::verify(&armored, b"hello", None, None, None).unwrap());
}

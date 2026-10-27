//! Canonical claim/challenge byte encodings and challenge signing, ported
//! from ZBTerm `engine/identity/claim.js`. The SSHSIG container itself
//! (armor, parse, verify, `fingerprint`) is already ported in
//! `crate::ssh::sshsig`/`crate::ssh::key` (K2, from this same source file) —
//! this module only adds the pieces `crate::ssh` does not need: the claim
//! and challenge line encodings, and raw ed25519 challenge signing/
//! verification (never SSHSIG — the live challenge is signed by the plain
//! device auth key, not an SSH key).

use ed25519_dalek::ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::error::{Code, Error};
use crate::ssh::codec::write_string;

/// An identity claim's fields (`claimBytes`'s input shape). Every field is
/// `None` for "omitted", encoded as an empty string — exactly as
/// `claim.js::field()` treats `null`/`undefined`.
#[derive(Debug, Clone, Default)]
pub struct Claim {
    pub provider: Option<String>,
    pub subject: Option<String>,
    pub identity_key: Option<String>,
    pub auth_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub issued_at: Option<i64>,
    pub nonce: Option<String>,
    /// Not part of `claimBytes`'s own encoding, but carried on the claim
    /// everywhere it travels (`verify.rs`/`store.rs`): the armored SSHSIG
    /// over `claimBytes(self)`.
    pub signature: Option<String>,
    /// Not part of `claimBytes`'s own encoding: the base64 SSH wire-format
    /// public-key blob the claim was signed with, when the caller supplied
    /// one explicitly (`claim.js::claimProof`'s `sshPublicKey`).
    pub ssh_public_key: Option<String>,
}

/// A live handshake challenge's fields (`challengeBytes`'s input shape).
#[derive(Debug, Clone, Default)]
pub struct Challenge {
    pub session_id: Option<String>,
    pub challenge_id: Option<String>,
    pub nonce: Option<String>,
    pub verifier_dht_key: Option<String>,
    pub prover_dht_key: Option<String>,
    pub role: Option<String>,
}

/// `field` (claim.js): `null`/`undefined` (here, `None`) encodes as `""`,
/// never an omitted line.
fn field(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

fn field_i64(value: Option<i64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

/// `claimBytes` (claim.js): ASCII, LF-joined, trailing LF. Line order:
/// `CLAIM_MAGIC`, then `provider=`, `subject=`, `identityKey=`, `authKey=`,
/// `sshFingerprint=`, `issuedAt=`, `nonce=`.
pub fn claim_bytes(claim: &Claim) -> Vec<u8> {
    let lines = [
        crate::wire::CLAIM_MAGIC.to_string(),
        format!("provider={}", field(claim.provider.as_deref())),
        format!("subject={}", field(claim.subject.as_deref())),
        format!("identityKey={}", field(claim.identity_key.as_deref())),
        format!("authKey={}", field(claim.auth_key.as_deref())),
        format!("sshFingerprint={}", field(claim.ssh_fingerprint.as_deref())),
        format!("issuedAt={}", field_i64(claim.issued_at)),
        format!("nonce={}", field(claim.nonce.as_deref())),
    ];
    (lines.join("\n") + "\n").into_bytes()
}

/// `challengeBytes` (claim.js): magic `CHALLENGE_MAGIC`, then `sessionId=`,
/// `challengeId=`, `nonce=`, `verifierDhtKey=`, `proverDhtKey=`, `role=`,
/// same LF-join/trailing-LF rule.
pub fn challenge_bytes(challenge: &Challenge) -> Vec<u8> {
    let lines = [
        crate::wire::CHALLENGE_MAGIC.to_string(),
        format!("sessionId={}", field(challenge.session_id.as_deref())),
        format!("challengeId={}", field(challenge.challenge_id.as_deref())),
        format!("nonce={}", field(challenge.nonce.as_deref())),
        format!(
            "verifierDhtKey={}",
            field(challenge.verifier_dht_key.as_deref())
        ),
        format!(
            "proverDhtKey={}",
            field(challenge.prover_dht_key.as_deref())
        ),
        format!("role={}", field(challenge.role.as_deref())),
    ];
    (lines.join("\n") + "\n").into_bytes()
}

/// `encodeEd25519PublicKey` (claim.js): `writeString(KEY_TYPE) ||
/// writeString(rawKey)`. `E_AUTH` if `public_key` is not 32 bytes.
pub fn encode_ed25519_public_key(public_key: &[u8]) -> Result<Vec<u8>, Error> {
    if public_key.len() != 32 {
        return Err(Error::new(
            Code::EAuth,
            "ed25519 public key must be 32 bytes",
        ));
    }
    let mut out = write_string(crate::wire::KEY_TYPE.as_bytes());
    out.extend_from_slice(&write_string(public_key));
    Ok(out)
}

/// `writeMpint` (claim.js): ssh mpints are signed big-endian, so a leading
/// `0x00` byte is added only when the high bit of the first (already
/// zero-stripped) byte is set.
fn write_mpint(value: &[u8]) -> Vec<u8> {
    let stripped = crate::ssh::codec::strip_mpint(value);
    if !stripped.is_empty() && (stripped[0] & 0x80) != 0 {
        let mut padded = Vec::with_capacity(stripped.len() + 1);
        padded.push(0u8);
        padded.extend_from_slice(stripped);
        write_string(&padded)
    } else {
        write_string(stripped)
    }
}

/// `encodeRsaPublicKey` (claim.js): `writeString(RSA_KEY_TYPE) ||
/// writeMpint(e) || writeMpint(n)`.
pub fn encode_rsa_public_key(e: &[u8], n: &[u8]) -> Vec<u8> {
    let mut out = write_string(crate::wire::RSA_KEY_TYPE.as_bytes());
    out.extend_from_slice(&write_mpint(e));
    out.extend_from_slice(&write_mpint(n));
    out
}

/// `signChallenge` (claim.js): an ed25519 detached signature over
/// `challengeBytes(challenge)`, with the 64-byte libsodium secret key
/// (32-byte seed || 32-byte public key — only the seed half is used).
/// `E_AUTH` if `secret_key` is not 64 bytes.
pub fn sign_challenge(secret_key: &[u8], challenge: &Challenge) -> Result<[u8; 64], Error> {
    if secret_key.len() != 64 {
        return Err(Error::new(
            Code::EAuth,
            "ed25519 secret key must be 64 bytes",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret_key[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    let signature: Signature = signing_key.sign(&challenge_bytes(challenge));
    Ok(signature.to_bytes())
}

/// `verifyChallenge` (claim.js): never throws — any malformed input
/// (wrong-sized key or signature, bad bytes) is `false`, exactly as the JS
/// twin's `try { ... } catch { return false }`.
pub fn verify_challenge(public_key: &[u8], challenge: &Challenge, signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key
        .verify(&challenge_bytes(challenge), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_bytes_are_the_frozen_canonical_encoding() {
        let claim = Claim {
            provider: Some("github".into()),
            subject: Some("octocat".into()),
            identity_key: Some("a".repeat(64)),
            auth_key: Some("b".repeat(64)),
            ssh_fingerprint: Some("SHA256:placeholder".into()),
            issued_at: Some(1750000000000),
            nonce: Some("c".repeat(32)),
            ..Default::default()
        };
        let expected = format!(
            "zbterm-identity-claim/v1\nprovider=github\nsubject=octocat\nidentityKey={}\nauthKey={}\nsshFingerprint=SHA256:placeholder\nissuedAt=1750000000000\nnonce={}\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(32)
        );
        assert_eq!(String::from_utf8(claim_bytes(&claim)).unwrap(), expected);
    }

    #[test]
    fn challenge_bytes_are_the_frozen_canonical_encoding_and_a_missing_field_is_empty() {
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

        let missing_session = Challenge {
            session_id: None,
            ..challenge
        };
        let bytes = String::from_utf8(challenge_bytes(&missing_session)).unwrap();
        assert!(bytes.contains("\nsessionId=\n"));
    }

    #[test]
    fn challenge_signatures_round_trip_and_reject_tampering() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing_key.verifying_key().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&[7u8; 32]);
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
        let tampered_role = Challenge {
            role: Some("host".into()),
            ..challenge.clone()
        };
        assert!(!verify_challenge(&public, &tampered_role, &signature));
        let tampered_prover = Challenge {
            prover_dht_key: Some("4".repeat(64)),
            ..challenge
        };
        assert!(!verify_challenge(&public, &tampered_prover, &signature));
    }

    #[test]
    fn verify_challenge_never_panics_on_malformed_input() {
        let challenge = Challenge::default();
        assert!(!verify_challenge(&[0u8; 4], &challenge, &[0u8; 64]));
        assert!(!verify_challenge(&[0u8; 32], &challenge, &[0u8; 4]));
    }
}

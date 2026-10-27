//! SSHSIG signed-data blob, armor, signing (from a private-key file or via
//! ssh-agent) and verification, ported from ZBTerm `engine/identity/
//! claim.js` (the canonical byte encodings — a claim signed by this module
//! must verify with stock `ssh-keygen -Y verify -n zbterm-identity`) and
//! `electron/ssh-keys.js` (`signBytes`, the file/agent orchestration).
//!
//! RSA is hand-rolled RSASSA-PKCS1-v1.5/SHA-512 (`rsa::BigUint` modpow),
//! matching `claim.js::verifyRsaSha512`'s exact modulus-bound and
//! Bleichenbacher-guard checks byte for byte, rather than the `rsa` crate's
//! own higher-level sign/verify API (`K2`'s re-planning signal).
//!
//! Passphrase handling: never. Signing from a file requires an unencrypted
//! key; an encrypted file falls through to ssh-agent, never a prompt.

use std::collections::HashMap;
use std::path::Path;

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rsa::BigUint;
use sha2::{Digest, Sha512};

use super::agent::agent_sign;
use super::codec::{
    base64_decode, base64_decode_lenient, base64_encode, read_string, strip_mpint, write_string,
};
use super::key::{
    describe_file, fingerprint, key_type_of, parse_openssh_private_key, unsupported_key_type_reason,
};
use crate::error::{Code, Error};

const SSHSIG_VERSION: u32 = 1;
const ARMOR_WIDTH: usize = 70;
/// 1024 bits is the smallest modulus `ssh-keygen` will make; 8192 bits is the
/// largest anyone ships. Anything outside that is not a key this verifies.
const RSA_MIN_MODULUS_BYTES: usize = 128;
const RSA_MAX_MODULUS_BYTES: usize = 1024;

/// The SSHSIG signature algorithm an SSH key of this type must use. `None`
/// for a type neither signed nor verified here (ECDSA, `sk-*`).
pub(crate) fn signature_algorithm_for(key_type: &str) -> Option<&'static str> {
    if key_type == crate::wire::KEY_TYPE {
        Some(crate::wire::KEY_TYPE)
    } else if key_type == crate::wire::RSA_KEY_TYPE {
        Some(crate::wire::RSA_SIG_ALG)
    } else {
        None
    }
}

/// `claim.js`'s own "Unsupported SSH key type" wording — distinct from
/// `key::unsupported_key_type_reason` (ssh-keys.js's own text), even though
/// both name the same two supported types.
fn claim_unsupported_key_type_message(key_type: &str) -> String {
    format!(
        "Unsupported SSH key type: {key_type} (supported: {}, {})",
        crate::wire::KEY_TYPE,
        crate::wire::RSA_KEY_TYPE,
    )
}

/// `signedDataBlob` (claim.js): `"SSHSIG" || writeString(namespace) ||
/// writeString("") || writeString(hashAlg) || writeString(sha512(message))`
/// — the raw message is never signed directly. `pub` (not `pub(crate)`):
/// `signedDataBlob` is in claim.js's own export list, and K3's ported
/// `identity-claim.test.js` cases need it to sign with a real key the same
/// way `ssh-keygen -Y sign` and the JS test file's own inline helpers do.
pub fn signed_data_blob(namespace: &str, hash_alg: &str, message: &[u8]) -> Vec<u8> {
    let digest = Sha512::digest(message);
    let mut out = Vec::new();
    out.extend_from_slice(crate::wire::SSHSIG_MAGIC.as_bytes());
    out.extend_from_slice(&write_string(namespace.as_bytes()));
    out.extend_from_slice(&write_string(b""));
    out.extend_from_slice(&write_string(hash_alg.as_bytes()));
    out.extend_from_slice(&write_string(&digest));
    out
}

/// `armor` (claim.js): base64, wrapped at `ARMOR_WIDTH` columns, between the
/// `BEGIN`/`END SSH SIGNATURE` markers.
fn armor(buffer: &[u8]) -> String {
    let b64 = base64_encode(buffer);
    let mut lines = vec![crate::wire::ARMOR_BEGIN.to_string()];
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + ARMOR_WIDTH).min(bytes.len());
        lines.push(String::from_utf8_lossy(&bytes[i..end]).into_owned());
        i = end;
    }
    lines.push(crate::wire::ARMOR_END.to_string());
    lines.join("\n") + "\n"
}

/// `buildArmoredSignature` (claim.js).
pub fn build_armored_signature(
    pubkey_blob: &[u8],
    raw_sig: &[u8],
    namespace: &str,
    hash_alg: &str,
) -> Result<String, Error> {
    let key_type_read = read_string(pubkey_blob, 0)?;
    let key_type = String::from_utf8_lossy(key_type_read.value).into_owned();
    let sig_type = signature_algorithm_for(&key_type)
        .ok_or_else(|| Error::new(Code::EAuth, claim_unsupported_key_type_message(&key_type)))?;

    let mut sig_blob = write_string(sig_type.as_bytes());
    sig_blob.extend_from_slice(&write_string(raw_sig));

    let mut container = Vec::new();
    container.extend_from_slice(crate::wire::SSHSIG_MAGIC.as_bytes());
    container.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    container.extend_from_slice(&write_string(pubkey_blob));
    container.extend_from_slice(&write_string(namespace.as_bytes()));
    container.extend_from_slice(&write_string(b""));
    container.extend_from_slice(&write_string(hash_alg.as_bytes()));
    container.extend_from_slice(&write_string(&sig_blob));
    Ok(armor(&container))
}

/// A parsed armored SSHSIG (`parseArmoredSignature`, claim.js).
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub pubkey_blob: Vec<u8>,
    pub namespace: String,
    pub hash_alg: String,
    pub sig_type: String,
    pub raw_sig: Vec<u8>,
}

/// `parseArmoredSignature` (claim.js), byte-for-byte.
pub fn parse_armored_signature(armored: &str) -> Result<ParsedSignature, Error> {
    let begin = armored.find(crate::wire::ARMOR_BEGIN);
    let end = armored.find(crate::wire::ARMOR_END);
    let (begin, end) = match (begin, end) {
        (Some(b), Some(e)) if e >= b => (b, e),
        _ => {
            return Err(Error::new(
                Code::EAuth,
                "Malformed SSH signature: missing armor",
            ));
        }
    };
    let body = &armored[begin + crate::wire::ARMOR_BEGIN.len()..end];
    let b64: String = body.split('\n').map(str::trim).collect::<Vec<_>>().concat();
    let container = base64_decode(&b64)
        .map_err(|_| Error::new(Code::EAuth, "Malformed SSH signature: bad base64"))?;
    if container.len() < 6 || &container[0..6] != crate::wire::SSHSIG_MAGIC.as_bytes() {
        return Err(Error::new(
            Code::EAuth,
            "Malformed SSH signature: bad magic",
        ));
    }
    if container.len() < 10 {
        return Err(Error::new(
            Code::EAuth,
            "Malformed SSH signature: truncated",
        ));
    }
    let version = u32::from_be_bytes(container[6..10].try_into().unwrap());
    if version != SSHSIG_VERSION {
        return Err(Error::new(
            Code::EAuth,
            format!("Unsupported SSH signature version: {version}"),
        ));
    }
    let pubkey = read_string(&container, 10)?;
    let namespace = read_string(&container, pubkey.offset)?;
    let reserved = read_string(&container, namespace.offset)?;
    let hash_alg = read_string(&container, reserved.offset)?;
    let signature = read_string(&container, hash_alg.offset)?;
    let sig_type = read_string(signature.value, 0)?;
    let raw_sig = read_string(signature.value, sig_type.offset)?;
    Ok(ParsedSignature {
        pubkey_blob: pubkey.value.to_vec(),
        namespace: String::from_utf8_lossy(namespace.value).into_owned(),
        hash_alg: String::from_utf8_lossy(hash_alg.value).into_owned(),
        sig_type: String::from_utf8_lossy(sig_type.value).into_owned(),
        raw_sig: raw_sig.value.to_vec(),
    })
}

/// An RSA public key's `(e, n)`, already mpint-stripped.
#[derive(Debug, Clone)]
pub struct RsaPublic {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
}

/// A decoded SSH wire-format public-key blob (`decodePublicKeyBlob`,
/// claim.js).
#[derive(Debug, Clone)]
pub struct DecodedKey {
    pub key_type: String,
    pub ed25519_public: Option<[u8; 32]>,
    pub rsa: Option<RsaPublic>,
}

/// `decodePublicKeyBlob` (claim.js).
pub fn decode_public_key_blob(blob: &[u8]) -> Result<DecodedKey, Error> {
    let type_read = read_string(blob, 0)?;
    let key_type = String::from_utf8_lossy(type_read.value).into_owned();
    if key_type == crate::wire::RSA_KEY_TYPE {
        let e = read_string(blob, type_read.offset)?;
        let n = read_string(blob, e.offset)?;
        return Ok(DecodedKey {
            key_type,
            ed25519_public: None,
            rsa: Some(RsaPublic {
                e: strip_mpint(e.value).to_vec(),
                n: strip_mpint(n.value).to_vec(),
            }),
        });
    }
    if key_type != crate::wire::KEY_TYPE {
        return Ok(DecodedKey {
            key_type,
            ed25519_public: None,
            rsa: None,
        });
    }
    let key = read_string(blob, type_read.offset)?;
    if key.value.len() != 32 {
        return Err(Error::new(
            Code::EAuth,
            "ed25519 public key must be 32 bytes",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key.value);
    Ok(DecodedKey {
        key_type,
        ed25519_public: Some(arr),
        rsa: None,
    })
}

/// PKCS#1 v1.5 DigestInfo prefix for SHA-512 (`wire::PKCS1_SHA512_PREFIX_HEX`,
/// decoded once).
fn pkcs1_sha512_prefix() -> Vec<u8> {
    hex::decode(crate::wire::PKCS1_SHA512_PREFIX_HEX).expect("PKCS1_SHA512_PREFIX_HEX is valid hex")
}

/// `verifyRsaSha512` (claim.js): RSASSA-PKCS1-v1_5/SHA-512 verification by
/// hand. The whole encoded message is rebuilt and compared byte for byte —
/// never parsed — so a short/loose DigestInfo cannot be smuggled past this
/// (the Bleichenbacher low-exponent forgery).
fn verify_rsa_sha512(rsa: &RsaPublic, message: &[u8], raw_sig: &[u8]) -> bool {
    let k = rsa.n.len();
    if !(RSA_MIN_MODULUS_BYTES..=RSA_MAX_MODULUS_BYTES).contains(&k) {
        return false;
    }
    if raw_sig.len() != k {
        return false;
    }
    let n = BigUint::from_bytes_be(&rsa.n);
    let e = BigUint::from_bytes_be(&rsa.e);
    if e < BigUint::from(3u32) || &e & BigUint::from(1u32) == BigUint::from(0u32) || e >= n {
        return false;
    }
    let s = BigUint::from_bytes_be(raw_sig);
    if s >= n {
        return false;
    }
    let em_int = s.modpow(&e, &n);
    let em_bytes = em_int.to_bytes_be();
    if em_bytes.len() > k {
        return false;
    }
    let mut em = vec![0u8; k - em_bytes.len()];
    em.extend_from_slice(&em_bytes);

    let digest = Sha512::digest(message);
    let mut suffix = pkcs1_sha512_prefix();
    suffix.extend_from_slice(&digest);
    let Some(padding_len) = k.checked_sub(suffix.len() + 3) else {
        return false;
    };
    if padding_len < 8 {
        return false;
    }
    let mut expected = Vec::with_capacity(k);
    expected.push(0x00);
    expected.push(0x01);
    expected.extend(std::iter::repeat_n(0xffu8, padding_len));
    expected.push(0x00);
    expected.extend_from_slice(&suffix);
    em == expected
}

/// `verifySshSignature` (claim.js). Throws (returns `Err`) only for an
/// unsupported key type or a signature-algorithm mismatch (the SHA-1
/// `ssh-rsa`-over-an-RSA-key case) — every other failure (namespace/hashAlg
/// mismatch, expected-key mismatch, bad signature) returns `Ok(false)`.
pub fn verify(
    armored: &str,
    message: &[u8],
    namespace: Option<&str>,
    hash_alg: Option<&str>,
    expected_public_key_blob: Option<&[u8]>,
) -> Result<bool, Error> {
    let parsed = parse_armored_signature(armored)?;
    let key = decode_public_key_blob(&parsed.pubkey_blob)?;
    let sig_type = signature_algorithm_for(&key.key_type).ok_or_else(|| {
        Error::new(
            Code::EAuth,
            claim_unsupported_key_type_message(&key.key_type),
        )
    })?;
    if parsed.sig_type != sig_type {
        return Err(Error::new(
            Code::EAuth,
            format!(
                "Unsupported SSH signature algorithm: {} ({} must sign with {sig_type})",
                parsed.sig_type, key.key_type
            ),
        ));
    }

    let namespace = namespace.unwrap_or(crate::wire::NAMESPACE);
    let hash_alg = hash_alg.unwrap_or(crate::wire::HASH_ALG);
    if parsed.namespace != namespace {
        return Ok(false);
    }
    if parsed.hash_alg != hash_alg {
        return Ok(false);
    }
    if let Some(expected) = expected_public_key_blob
        && expected != parsed.pubkey_blob.as_slice()
    {
        return Ok(false);
    }

    let blob = signed_data_blob(&parsed.namespace, &parsed.hash_alg, message);
    if key.key_type == crate::wire::RSA_KEY_TYPE {
        let rsa = key.rsa.as_ref().expect("RSA key type decodes an RsaPublic");
        return Ok(verify_rsa_sha512(rsa, &blob, &parsed.raw_sig));
    }
    if parsed.raw_sig.len() != 64 {
        return Ok(false);
    }
    let public = key
        .ed25519_public
        .expect("ed25519 key type decodes a public key");
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public) else {
        return Ok(false);
    };
    let Ok(sig) = Signature::from_slice(&parsed.raw_sig) else {
        return Ok(false);
    };
    Ok(verifying_key.verify(&blob, &sig).is_ok())
}

/// `signWithPrivateKey` (ssh-keys.js): ed25519 signs with the 32-byte seed
/// half of the OpenSSH/libsodium 64-byte secret key; RSA signs by hand
/// (`sign_rsa_sha512`) rather than through Node's PKCS#1-v1.5/SHA-512 path.
fn sign_with_private_key(
    parsed: &super::key::ParsedPrivateKey,
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    if parsed.key_type == crate::wire::KEY_TYPE {
        let secret = parsed
            .secret_key
            .ok_or_else(|| Error::new(Code::EAuth, "ed25519 secret key is missing"))?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[..32]);
        let signing_key = SigningKey::from_bytes(&seed);
        let signature: Signature = signing_key.sign(blob);
        return Ok(signature.to_bytes().to_vec());
    }
    if parsed.key_type == crate::wire::RSA_KEY_TYPE {
        let rsa = parsed
            .rsa
            .as_ref()
            .ok_or_else(|| Error::new(Code::EAuth, "RSA private key fields are missing"))?;
        return sign_rsa_sha512(rsa, blob);
    }
    Err(Error::new(
        Code::EAuth,
        unsupported_key_type_reason(&parsed.key_type),
    ))
}

/// RSASSA-PKCS1-v1_5/SHA-512 signing by hand, using the plain private
/// exponent `d` (no CRT shortcut — mathematically identical to Node's
/// CRT-optimized path, avoiding that path's own `dp`/`dq` derivation as a
/// separate source of bugs).
fn sign_rsa_sha512(rsa: &super::key::RsaFields, message: &[u8]) -> Result<Vec<u8>, Error> {
    let n_bytes = strip_mpint(&rsa.n);
    let k = n_bytes.len();
    if !(RSA_MIN_MODULUS_BYTES..=RSA_MAX_MODULUS_BYTES).contains(&k) {
        return Err(Error::new(Code::EAuth, "RSA modulus size is out of range"));
    }
    let n = BigUint::from_bytes_be(n_bytes);
    let d = BigUint::from_bytes_be(strip_mpint(&rsa.d));

    let digest = Sha512::digest(message);
    let mut suffix = pkcs1_sha512_prefix();
    suffix.extend_from_slice(&digest);
    let padding_len = k
        .checked_sub(suffix.len() + 3)
        .filter(|&p| p >= 8)
        .ok_or_else(|| {
            Error::new(
                Code::EAuth,
                "RSA modulus too small for SHA-512 PKCS#1 padding",
            )
        })?;

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat_n(0xffu8, padding_len));
    em.push(0x00);
    em.extend_from_slice(&suffix);

    let m = BigUint::from_bytes_be(&em);
    let s = m.modpow(&d, &n);
    let s_bytes = s.to_bytes_be();
    let mut sig = vec![0u8; k.saturating_sub(s_bytes.len())];
    sig.extend_from_slice(&s_bytes);
    Ok(sig)
}

/// Which path produced a signature: a private-key file, or ssh-agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    File,
    Agent,
}

/// `signBytes`'s return shape (ssh-keys.js).
#[derive(Debug, Clone)]
pub struct SignResult {
    pub signature: String,
    pub public_key_blob_base64: String,
    pub fingerprint: String,
    pub via: Via,
}

/// `signBytes` (ssh-keys.js): produces an armored SSHSIG over
/// `message_base64` in the `zbterm-identity` namespace, from `key_path`'s
/// unencrypted private key if given, else via ssh-agent.
pub fn sign(
    message_base64: &str,
    key_path: Option<&Path>,
    public_key_blob_base64: Option<&str>,
    env: &HashMap<String, String>,
) -> Result<SignResult, Error> {
    if message_base64.is_empty() {
        return Err(Error::new(Code::EAuth, "messageBase64 is required"));
    }
    let message = base64_decode_lenient(message_base64);
    let blob = signed_data_blob(crate::wire::NAMESPACE, crate::wire::HASH_ALG, &message);
    let mut public_key_blob: Option<Vec<u8>> = public_key_blob_base64.map(base64_decode_lenient);
    let mut file_error: Option<String> = None;

    if let Some(key_path) = key_path {
        let info = describe_file(key_path);
        if let Some(b) = &info.public_key_blob {
            public_key_blob = Some(b.clone());
        }
        if let Some(kt) = &info.key_type
            && signature_algorithm_for(kt).is_none()
        {
            return Err(Error::new(Code::EAuth, unsupported_key_type_reason(kt)));
        }
        if info.has_private && !info.encrypted {
            let text = std::fs::read_to_string(key_path).map_err(|e| {
                Error::new(
                    Code::EAuth,
                    format!("cannot read {}: {e}", key_path.display()),
                )
            })?;
            let parsed = parse_openssh_private_key(&text)?;
            let raw_sig = sign_with_private_key(&parsed, &blob)?;
            let signature = build_armored_signature(
                &parsed.public_key_blob,
                &raw_sig,
                crate::wire::NAMESPACE,
                crate::wire::HASH_ALG,
            )?;
            return Ok(SignResult {
                signature,
                public_key_blob_base64: base64_encode(&parsed.public_key_blob),
                fingerprint: fingerprint(&parsed.public_key_blob),
                via: Via::File,
            });
        }
        file_error = if info.encrypted {
            Some("the key file is passphrase-protected".to_string())
        } else {
            info.error.clone()
        };
    }

    let public_key_blob = match public_key_blob.filter(|b| !b.is_empty()) {
        Some(b) => b,
        None => {
            let message = match (&file_error, key_path) {
                (Some(fe), Some(kp)) => format!(
                    "Cannot sign with {}: {fe}, and no public key was supplied for ssh-agent",
                    kp.display()
                ),
                _ => "Either keyPath or publicKeyBlobBase64 is required".to_string(),
            };
            return Err(Error::new(Code::EAuth, message));
        }
    };
    let key_type = key_type_of(&public_key_blob)?;
    if signature_algorithm_for(&key_type).is_none() {
        return Err(Error::new(
            Code::EAuth,
            unsupported_key_type_reason(&key_type),
        ));
    }
    let raw_sig = agent_sign(&public_key_blob, &blob, env)?;
    let signature = build_armored_signature(
        &public_key_blob,
        &raw_sig,
        crate::wire::NAMESPACE,
        crate::wire::HASH_ALG,
    )?;
    Ok(SignResult {
        signature,
        public_key_blob_base64: base64_encode(&public_key_blob),
        fingerprint: fingerprint(&public_key_blob),
        via: Via::Agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_then_verify_round_trips() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let mut pubkey_blob = write_string(crate::wire::KEY_TYPE.as_bytes());
        pubkey_blob.extend_from_slice(&write_string(verifying_key.as_bytes()));

        let message = b"hello sshsig";
        let blob = signed_data_blob(crate::wire::NAMESPACE, crate::wire::HASH_ALG, message);
        let signature: Signature = signing_key.sign(&blob);
        let armored = build_armored_signature(
            &pubkey_blob,
            &signature.to_bytes(),
            crate::wire::NAMESPACE,
            crate::wire::HASH_ALG,
        )
        .expect("build armored signature");

        assert!(armored.starts_with(crate::wire::ARMOR_BEGIN));
        let ok = verify(&armored, message, None, None, None).expect("verify");
        assert!(ok);
        // A different message must not verify.
        let ok2 = verify(&armored, b"a different message", None, None, None).expect("verify");
        assert!(!ok2);
    }

    #[test]
    fn armor_wraps_at_70_columns() {
        let text = armor(&[0u8; 200]);
        for line in text.lines() {
            if line == crate::wire::ARMOR_BEGIN || line == crate::wire::ARMOR_END {
                continue;
            }
            assert!(line.len() <= ARMOR_WIDTH, "line too long: {}", line.len());
        }
    }

    #[test]
    fn verify_rejects_unsupported_key_type_by_name() {
        // A blob claiming to be `ecdsa-sha2-nistp256` decodes but has no
        // signature algorithm.
        let mut pubkey_blob = write_string(b"ecdsa-sha2-nistp256");
        pubkey_blob.extend_from_slice(b"junk");
        let sig_blob = {
            let mut v = write_string(b"ecdsa-sha2-nistp256");
            v.extend_from_slice(&write_string(b"sig"));
            v
        };
        let mut container = Vec::new();
        container.extend_from_slice(crate::wire::SSHSIG_MAGIC.as_bytes());
        container.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
        container.extend_from_slice(&write_string(&pubkey_blob));
        container.extend_from_slice(&write_string(crate::wire::NAMESPACE.as_bytes()));
        container.extend_from_slice(&write_string(b""));
        container.extend_from_slice(&write_string(crate::wire::HASH_ALG.as_bytes()));
        container.extend_from_slice(&write_string(&sig_blob));
        let armored = armor(&container);

        let err = verify(&armored, b"msg", None, None, None).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert!(
            err.message.starts_with("Unsupported SSH key type:"),
            "{}",
            err.message
        );
    }
}

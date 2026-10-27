//! Signalling entries and pointer records of a Freenet link (design §4.3,
//! §6; K5), one to one with ZBTerm `engine/backends/freenet/signal.js`.
//!
//! The signed bytes are exactly what `signalling-v1` checks (source of
//! truth: ZBTerm `engine/backends/freenet/contracts/src/signalling/src/
//! lib.rs`'s module comment, cross-checked against `signal.js`):
//!
//! ```text
//! SIGNAL_DOMAIN ‖ lp(params) ‖ lp(utf8(l)) ‖ lp(utf8(r)) ‖ u32le(s) ‖
//! u64le(t) ‖ u8(d) ‖ lp(utf8(p))
//! ```
//!
//! with `lp(x) = u32le(len(x)) ‖ x`. `pointer-v1`'s record bytes are the
//! same shape under `POINTER_DOMAIN` (`contracts/src/pointer/src/
//! lib.rs`). Every domain string is `crate::wire`'s, never redefined here.
//!
//! `verify_entry`/`verify_record` never fail loudly: a malformed or
//! mis-signed entry/record is `false`, not an `Err`, exactly as
//! `signal.js::verifyEntry`/`verifyRecord` return `false` rather than
//! throw — callers treat a bad remote entry as "ignored", not "connection
//! error".

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_secretbox::{
    KeyInit as SecretboxKeyInit,
    aead::{Aead, AeadCore, generic_array::GenericArray},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::wire;

/// The largest integer JS's `Number.isSafeInteger` accepts: 2^53 - 1.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `lp(x) = u32le(len(x)) ‖ x` (`signal.js::lp`).
fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// A signalling entry, `signal.js`'s `e` shape plus `g`
/// (`{l, r, s, t, d, p, g}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Connection id: 32 random hex chars, one per dial.
    pub l: String,
    /// `"v:<viewer hex>"` for a viewer's entry, `"h:<viewer hex>"` for the
    /// host's, addressed to that viewer.
    pub r: String,
    /// Sequence number per `(l, r)`, from 0.
    pub s: u32,
    /// `Date.now()`-style millisecond timestamp.
    pub t: u64,
    /// Tombstone flag.
    pub d: bool,
    /// The sealed payload (see `seal`/`open`), or empty for a tombstone.
    pub p: String,
    /// hex ed25519 signature over `entry_bytes(params, self)`.
    pub g: String,
}

/// The bytes `Entry::g` signs (`signal.js::entryBytes`).
pub fn entry_bytes(params: &[u8], l: &str, r: &str, s: u32, t: u64, d: bool, p: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        wire::SIGNAL_DOMAIN.len()
            + 4
            + params.len()
            + 4
            + l.len()
            + 4
            + r.len()
            + 4
            + 8
            + 1
            + 4
            + p.len(),
    );
    out.extend_from_slice(wire::SIGNAL_DOMAIN.as_bytes());
    lp(&mut out, params);
    lp(&mut out, l.as_bytes());
    lp(&mut out, r.as_bytes());
    out.extend_from_slice(&s.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.push(if d { 1 } else { 0 });
    lp(&mut out, p.as_bytes());
    out
}

fn sign_bytes(secret_key: &SigningKey, message: &[u8]) -> String {
    let sig: Signature = secret_key.sign(message);
    hex::encode(sig.to_bytes())
}

/// `false` on any malformed signature text or key, never panics
/// (`signal.js::verify`).
fn verify_bytes(public_key: &VerifyingKey, message: &[u8], g: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(g) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    public_key.verify(message, &sig).is_ok()
}

/// The unsigned fields of an `Entry` (`signal.js::signEntry`'s destructured
/// `{l, r, s, t, d, p}` argument), grouped so `sign_entry` stays under
/// clippy's argument-count lint rather than taking each field loose.
pub struct EntryFields<'a> {
    pub l: &'a str,
    pub r: &'a str,
    pub s: u32,
    pub t: u64,
    pub d: bool,
    pub p: &'a str,
}

/// Signs a fresh entry, `g` set (`signal.js::signEntry`).
pub fn sign_entry(secret_key: &SigningKey, params: &[u8], fields: &EntryFields<'_>) -> Entry {
    let bytes = entry_bytes(
        params, fields.l, fields.r, fields.s, fields.t, fields.d, fields.p,
    );
    Entry {
        l: fields.l.to_string(),
        r: fields.r.to_string(),
        s: fields.s,
        t: fields.t,
        d: fields.d,
        p: fields.p.to_string(),
        g: sign_bytes(secret_key, &bytes),
    }
}

/// Whether `entry` is well formed and `g` verifies under `public_key`
/// (`signal.js::verifyEntry`). Never fails loudly: a malformed `t` (out of
/// JS's safe-integer range) or a bad signature is `false`. `s` needs no
/// runtime range check: `u32` already is exactly JS's `0..=0xffffffff`.
pub fn verify_entry(public_key: &VerifyingKey, params: &[u8], entry: &Entry) -> bool {
    if entry.t > MAX_SAFE_INTEGER {
        return false;
    }
    let bytes = entry_bytes(
        params, &entry.l, &entry.r, entry.s, entry.t, entry.d, &entry.p,
    );
    verify_bytes(public_key, &bytes, &entry.g)
}

/// `"v:"` or `"h:"` plus the 64-lowercase-hex-char role (`signal.js::roleOf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    Viewer,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub kind: RoleKind,
    pub viewer: String,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `signal.js::roleOf`: `r` must be exactly `"v:"` or `"h:"` plus 64
/// lowercase hex chars.
pub fn role_of(r: &str) -> Option<Role> {
    if r.len() < 2 {
        return None;
    }
    let (prefix, rest) = r.split_at(2);
    if !is_lower_hex(rest, 64) {
        return None;
    }
    let kind = match prefix {
        "v:" => RoleKind::Viewer,
        "h:" => RoleKind::Host,
        _ => return None,
    };
    Some(Role {
        kind,
        viewer: rest.to_string(),
    })
}

/// `crypto_generichash(out=32, PAYLOAD_CONTEXT, key = fromBase64url(k))`:
/// the payload key of a route (`signal.js::payloadKey`), keyed BLAKE2b-256
/// (libsodium's `crypto_generichash`, output length 32, no salt/personal).
pub fn payload_key(k: &str) -> [u8; 32] {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(k)
        .expect("payload_key: k is not valid base64url");
    let mut hasher = <blake2::Blake2bMac<blake2::digest::consts::U32> as blake2::digest::KeyInit>::new_from_slice(
        &key_bytes,
    )
    .expect("payload_key: key length rejected by BLAKE2b keyed MAC");
    blake2::digest::Update::update(&mut hasher, wire::PAYLOAD_CONTEXT.as_bytes());
    let out = blake2::digest::FixedOutput::finalize_fixed(hasher);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// `seal(key, message)`: JSON-encodes `message`, then
/// `nonce(24) ‖ crypto_secretbox_easy(plain, nonce, key)`
/// (XSalsa20-Poly1305, 16-byte MAC), base64url with no padding
/// (`signal.js::seal`).
pub fn seal(key: &[u8; 32], message: &serde_json::Value) -> String {
    let plain = serde_json::to_vec(message).expect("seal: message did not serialize to JSON");
    let cipher_key = GenericArray::from_slice(key);
    let cipher = crypto_secretbox::XSalsa20Poly1305::new(cipher_key);
    let nonce =
        crypto_secretbox::XSalsa20Poly1305::generate_nonce(&mut crypto_secretbox::aead::OsRng);
    let box_bytes = cipher
        .encrypt(&nonce, plain.as_slice())
        .expect("seal: secretbox encryption failed");
    let mut out = Vec::with_capacity(24 + box_bytes.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&box_bytes);
    URL_SAFE_NO_PAD.encode(out)
}

/// `open(key, p)`: the message, or `None` when `p` was not sealed under
/// `key` or its plaintext is not JSON. Never panics or throws
/// (`signal.js::open`).
pub fn open(key: &[u8; 32], p: &str) -> Option<serde_json::Value> {
    let bytes = URL_SAFE_NO_PAD.decode(p).ok()?;
    const NONCE_LEN: usize = 24;
    const MAC_LEN: usize = 16;
    if bytes.len() < NONCE_LEN + MAC_LEN {
        return None;
    }
    let (nonce_bytes, box_bytes) = bytes.split_at(NONCE_LEN);
    let cipher_key = GenericArray::from_slice(key);
    let cipher = crypto_secretbox::XSalsa20Poly1305::new(cipher_key);
    let nonce = GenericArray::from_slice(nonce_bytes);
    let plain = cipher.decrypt(nonce, box_bytes).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// hex(BLAKE3(utf8(p))): the hex BLAKE3 of the sealed payload, used to name
/// the offer an answer answers (`signal.js::offerRef`).
pub fn offer_ref(p: &str) -> String {
    blake3::hash(p.as_bytes()).to_hex().to_string()
}

/// `'<algo lowercase> <HEX UPPERCASE>'` from an SDP's `a=fingerprint:` line
/// (case-insensitive prefix, mirroring `/a=fingerprint:(\S+) (\S+)/i`), or
/// `None` if absent. Pure string function: K5 does not parse SDP beyond
/// this (`signal.js::sdpFingerprint`).
pub fn sdp_fingerprint(sdp: &str) -> Option<String> {
    let needle = "a=fingerprint:";
    let lower = sdp.to_ascii_lowercase();
    let idx = lower.find(needle)?;
    let rest = &sdp[idx + needle.len()..];
    let mut parts = rest.split_whitespace();
    let algo = parts.next()?;
    let hex_part = parts.next()?;
    Some(format!(
        "{} {}",
        algo.to_ascii_lowercase(),
        hex_part.to_ascii_uppercase()
    ))
}

/// A pointer record, `signal.js`'s `rec` shape plus `g`
/// (`{ver, sig, code, params, g}`, `contracts/src/pointer/src/lib.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `POINTER_VER` today (`index.js`); the highest valid `ver` wins.
    pub ver: u64,
    /// The signalling instance id this pointer names, base58.
    pub sig: String,
    /// hex BLAKE3 of that instance's signalling wasm.
    pub code: String,
    /// That instance's raw parameter bytes, as text.
    pub params: String,
    /// hex ed25519 signature over `record_bytes(own_params, self)`.
    pub g: String,
}

/// The bytes `Record::g` signs: `POINTER_DOMAIN ‖ lp(own_params) ‖
/// u64le(ver) ‖ lp(utf8(sig)) ‖ lp(utf8(code)) ‖ lp(utf8(params))`
/// (`signal.js::recordBytes`).
pub fn record_bytes(own_params: &[u8], ver: u64, sig: &str, code: &str, params: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        wire::POINTER_DOMAIN.len()
            + 4
            + own_params.len()
            + 8
            + 4
            + sig.len()
            + 4
            + code.len()
            + 4
            + params.len(),
    );
    out.extend_from_slice(wire::POINTER_DOMAIN.as_bytes());
    lp(&mut out, own_params);
    out.extend_from_slice(&ver.to_le_bytes());
    lp(&mut out, sig.as_bytes());
    lp(&mut out, code.as_bytes());
    lp(&mut out, params.as_bytes());
    out
}

/// Signs a fresh pointer record, `g` set (`signal.js::signRecord`).
pub fn sign_record(
    secret_key: &SigningKey,
    own_params: &[u8],
    ver: u64,
    sig: &str,
    code: &str,
    params: &str,
) -> Record {
    let bytes = record_bytes(own_params, ver, sig, code, params);
    Record {
        ver,
        sig: sig.to_string(),
        code: code.to_string(),
        params: params.to_string(),
        g: sign_bytes(secret_key, &bytes),
    }
}

/// Whether `record` is well formed and `g` verifies under `public_key`
/// (`signal.js::verifyRecord`). Never fails loudly.
pub fn verify_record(public_key: &VerifyingKey, own_params: &[u8], record: &Record) -> bool {
    if record.ver > MAX_SAFE_INTEGER {
        return false;
    }
    let bytes = record_bytes(
        own_params,
        record.ver,
        &record.sig,
        &record.code,
        &record.params,
    );
    verify_bytes(public_key, &bytes, &record.g)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair(seed: u8) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn entry_bytes_matches_fixed_layout() {
        let params = b"{\"ttl_ms\":120000,\"host\":\"aa\",\"n\":\"bb\"}";
        let bytes = entry_bytes(params, "cid", "v:host", 7, 12345, false, "payload");
        // SIGNAL_DOMAIN, then lp(params), lp("cid"), lp("v:host"), u32le(7),
        // u64le(12345), u8(0), lp("payload").
        let mut expected = Vec::new();
        expected.extend_from_slice(wire::SIGNAL_DOMAIN.as_bytes());
        expected.extend_from_slice(&(params.len() as u32).to_le_bytes());
        expected.extend_from_slice(params);
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.extend_from_slice(b"cid");
        expected.extend_from_slice(&6u32.to_le_bytes());
        expected.extend_from_slice(b"v:host");
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&12345u64.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(b"payload");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn record_bytes_matches_fixed_layout() {
        let own_params = b"{\"host\":\"aa\"}";
        let bytes = record_bytes(own_params, 1, "sigtext", "codetext", "paramstext");
        let mut expected = Vec::new();
        expected.extend_from_slice(wire::POINTER_DOMAIN.as_bytes());
        expected.extend_from_slice(&(own_params.len() as u32).to_le_bytes());
        expected.extend_from_slice(own_params);
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(b"sigtext");
        expected.extend_from_slice(&8u32.to_le_bytes());
        expected.extend_from_slice(b"codetext");
        expected.extend_from_slice(&10u32.to_le_bytes());
        expected.extend_from_slice(b"paramstext");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn sign_and_verify_entry_round_trip() {
        let (sk, vk) = key_pair(1);
        let params = b"params-bytes";
        let entry = sign_entry(
            &sk,
            params,
            &EntryFields {
                l: "cid",
                r: "v:abc",
                s: 0,
                t: 1_000,
                d: false,
                p: "p",
            },
        );
        assert!(verify_entry(&vk, params, &entry));
    }

    #[test]
    fn verify_entry_rejects_tampered_field() {
        let (sk, vk) = key_pair(1);
        let params = b"params-bytes";
        let mut entry = sign_entry(
            &sk,
            params,
            &EntryFields {
                l: "cid",
                r: "v:abc",
                s: 0,
                t: 1_000,
                d: false,
                p: "p",
            },
        );
        entry.s = 1;
        assert!(!verify_entry(&vk, params, &entry));
    }

    #[test]
    fn verify_entry_rejects_t_beyond_safe_integer() {
        let (sk, vk) = key_pair(1);
        let params = b"params-bytes";
        let mut entry = sign_entry(
            &sk,
            params,
            &EntryFields {
                l: "cid",
                r: "v:abc",
                s: 0,
                t: 1_000,
                d: false,
                p: "p",
            },
        );
        entry.t = MAX_SAFE_INTEGER + 1;
        // g no longer matches entry_bytes either, but the t bound alone
        // must already refuse it.
        assert!(!verify_entry(&vk, params, &entry));
    }

    #[test]
    fn sign_and_verify_record_round_trip() {
        let (sk, vk) = key_pair(2);
        let own_params = b"own-params";
        let record = sign_record(&sk, own_params, 1, "sig", "code", "params");
        assert!(verify_record(&vk, own_params, &record));
    }

    #[test]
    fn verify_record_rejects_tampered_field() {
        let (sk, vk) = key_pair(2);
        let own_params = b"own-params";
        let mut record = sign_record(&sk, own_params, 1, "sig", "code", "params");
        record.ver = 2;
        assert!(!verify_record(&vk, own_params, &record));
    }

    #[test]
    fn role_of_accepts_viewer_and_host() {
        let hex64 = "a".repeat(64);
        let v = role_of(&format!("v:{hex64}")).expect("viewer role");
        assert_eq!(v.kind, RoleKind::Viewer);
        assert_eq!(v.viewer, hex64);
        let h = role_of(&format!("h:{hex64}")).expect("host role");
        assert_eq!(h.kind, RoleKind::Host);
    }

    #[test]
    fn role_of_rejects_bad_prefix_and_bad_hex() {
        let hex64 = "a".repeat(64);
        assert!(role_of(&format!("x:{hex64}")).is_none());
        assert!(role_of("v:tooshort").is_none());
        assert!(role_of(&format!("v:{}", "A".repeat(64))).is_none()); // uppercase hex rejected
    }

    #[test]
    fn seal_open_round_trip() {
        let key = payload_key(&URL_SAFE_NO_PAD.encode([5u8; 32]));
        let message = serde_json::json!({"kind": "offer", "sdp": "v=0..."});
        let sealed = seal(&key, &message);
        let opened = open(&key, &sealed).expect("open sealed payload");
        assert_eq!(opened, message);
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = payload_key(&URL_SAFE_NO_PAD.encode([5u8; 32]));
        let message = serde_json::json!({"a": 1});
        let sealed = seal(&key, &message);
        let mut bytes = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert!(open(&key, &tampered).is_none());
    }

    #[test]
    fn open_rejects_too_short_input() {
        let key = payload_key(&URL_SAFE_NO_PAD.encode([5u8; 32]));
        let short = URL_SAFE_NO_PAD.encode([0u8; 10]);
        assert!(open(&key, &short).is_none());
    }

    #[test]
    fn payload_key_matches_libsodium_generichash_vector() {
        // crypto_generichash(out=32, "zbterm/fnet-payload/1", key=[1;32]),
        // cross-checked against sodium-native (K5 handoff notes).
        let k = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let out = payload_key(&k);
        let hexstr = hex::encode(out);
        assert_eq!(
            hexstr,
            "c818bdaa6312d05ad4b16d6d6acb910d3e1b29b4de43f56a3612bb09d45c3ac2"
        );
    }

    #[test]
    fn offer_ref_is_hex_blake3() {
        let r = offer_ref("hello world");
        assert_eq!(
            r,
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }

    #[test]
    fn sdp_fingerprint_extracts_algo_and_hex() {
        let sdp = "v=0\r\na=fingerprint:sha-256 AB:CD:EF\r\n";
        assert_eq!(sdp_fingerprint(sdp), Some("sha-256 AB:CD:EF".to_string()));
    }

    #[test]
    fn sdp_fingerprint_uppercases_hex_and_lowercases_algo() {
        let sdp = "a=fingerprint:SHA-256 ab:cd:ef";
        assert_eq!(sdp_fingerprint(sdp), Some("sha-256 AB:CD:EF".to_string()));
    }

    #[test]
    fn sdp_fingerprint_none_when_absent() {
        assert_eq!(sdp_fingerprint("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n"), None);
    }
}

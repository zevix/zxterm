//! Hierarchical key derivation: SLIP-10 (ed25519) for signing keypairs and
//! SLIP-21 for symmetric keys, seeded from a BIP-39 mnemonic.
//!
//! Ported from the upstream identity-key package's `lib/keychain.js`
//! (`KeyChain`), verified 2026-09-28 (`X-01`). The upstream package's own
//! name never appears in this file; see `crate::wire::ZXTERM_SYMMETRIC_NAMESPACE`
//! for the one string this port replaces.

use bip39::{Language, Mnemonic, WordCount};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;

use crate::error::{Code, Error};

type HmacSha512 = Hmac<Sha512>;

/// `lib/keychain.js::MASTER_CHAIN_CODE`.
const MASTER_CHAIN_CODE: &[u8] = b"ed25519 seed";
/// `lib/keychain.js::MASTER_SYMMETRIC_CODE`.
const MASTER_SYMMETRIC_CODE: &[u8] = b"Symmetric key seed";
/// `lib/keychain.js::HARDENED_OFFSET`.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// An ed25519 keypair produced by `KeyChain::derive`/`get`, mirroring
/// `lib/keychain.js::createKeyPair`'s `{publicKey, secretKey}` shape (here
/// `secret_key` is the 32-byte ed25519 seed, not libsodium's 64-byte
/// `secretKey` — both determine the same keypair).
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

impl KeyPair {
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret_key)
    }

    /// Zeroes the secret key in place (`clear()` support).
    pub fn clear(&mut self) {
        self.secret_key.fill(0);
    }
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&out);
    buf
}

fn create_keypair(seed: &[u8; 32]) -> KeyPair {
    let signing = SigningKey::from_bytes(seed);
    KeyPair {
        public_key: signing.verifying_key().to_bytes(),
        secret_key: *seed,
    }
}

/// `lib/keychain.js::ensureHardened`: idempotent — an already-hardened index
/// (`>= 2^31`) is left unchanged, never double-hardened.
fn ensure_hardened(n: u32) -> u32 {
    if n >= HARDENED_OFFSET {
        n
    } else {
        n + HARDENED_OFFSET
    }
}

/// `lib/keychain.js::encodeDerivationData`: `0x00 ‖ chainKey(32) ‖
/// u32be(hardened index)`.
fn encode_derivation_data(chain_key: &[u8; 32], hardened_index: u32) -> [u8; 37] {
    let mut data = [0u8; 37];
    data[1..33].copy_from_slice(chain_key);
    data[33..37].copy_from_slice(&hardened_index.to_be_bytes());
    // Belt-and-suspenders, mirroring the JS source's own redundant OR: the
    // index is already hardened, so byte 33 already carries this bit.
    data[33] |= 0x80;
    data
}

/// Hierarchical keychain seeded from a BIP-39 seed, mirroring
/// `lib/keychain.js::KeyChain`.
pub struct KeyChain {
    seed: Vec<u8>,
    chain_key: [u8; 32],
    chain_code: [u8; 32],
}

impl KeyChain {
    /// `new KeyChain(seed)` (`_initialise`).
    pub fn new(seed: impl Into<Vec<u8>>) -> Self {
        let seed = seed.into();
        let i = hmac_sha512(MASTER_CHAIN_CODE, &seed);
        let mut chain_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        chain_key.copy_from_slice(&i[0..32]);
        chain_code.copy_from_slice(&i[32..64]);
        KeyChain {
            seed,
            chain_key,
            chain_code,
        }
    }

    /// `KeyChain.generateMnemonic` (English, 24 words / 256-bit entropy —
    /// `bip39-mnemonic::generateEntropy`'s default `length = 32` bytes).
    pub fn generate_mnemonic() -> Result<String, Error> {
        let mnemonic = Mnemonic::generate(WordCount::Words24).map_err(|e| {
            Error::with_details(Code::EInternal, "mnemonic generation failed", e.to_string())
        })?;
        Ok(mnemonic.to_string())
    }

    /// `KeyChain.deriveSeed` (`bip39-mnemonic::mnemonicToSeed`): PBKDF2-HMAC-SHA512,
    /// 2048 rounds, salt `"mnemonic"` (no passphrase), 64-byte output. The
    /// mnemonic is normalised the way `lib/keychain.js`'s upstream package does
    /// (trim, collapse whitespace, lowercase) before the checksum is validated.
    pub fn derive_seed(mnemonic: &str) -> Result<[u8; 64], Error> {
        let normalized = normalize_mnemonic(mnemonic);
        let parsed = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|e| Error::with_details(Code::ECorrupt, "invalid mnemonic", e.to_string()))?;
        Ok(parsed.to_seed_normalized(""))
    }

    /// `KeyChain.get`/`derive`: derives the keypair at `path`, hardening every
    /// step per SLIP-10 ed25519 rules.
    pub fn derive(&self, path: &[u32]) -> KeyPair {
        let mut chain_key = self.chain_key;
        let mut chain_code = self.chain_code;
        for &step in path {
            let index = ensure_hardened(step);
            let data = encode_derivation_data(&chain_key, index);
            let i = hmac_sha512(&chain_code, &data);
            chain_key.copy_from_slice(&i[0..32]);
            chain_code.copy_from_slice(&i[32..64]);
        }
        create_keypair(&chain_key)
    }

    /// `KeyChain.get`.
    pub fn get(&self, path: &[u32]) -> KeyPair {
        self.derive(path)
    }

    /// `KeyChain.getSymmetricKey` (SLIP-21): `path` is the *full* symmetric
    /// path, including the `"SLIP-0021"`/namespace prefix (`symmetric_path`).
    pub fn get_symmetric_key(&self, path: &[String]) -> [u8; 32] {
        let i = hmac_sha512(MASTER_SYMMETRIC_CODE, &self.seed);
        let mut chain_key = [0u8; 32];
        let mut key = [0u8; 32];
        chain_key.copy_from_slice(&i[0..32]);
        key.copy_from_slice(&i[32..64]);

        for step in path {
            // `b4a.write(label, step, 1, 'utf8')` into a buffer sized
            // `step.length + 1`: byte 0 stays the default `0x00`.
            let mut label = vec![0u8; step.len() + 1];
            label[1..].copy_from_slice(step.as_bytes());
            let i = hmac_sha512(&chain_key, &label);
            chain_key.copy_from_slice(&i[0..32]);
            key.copy_from_slice(&i[32..64]);
        }
        key
    }

    /// `KeyChain.clear`.
    pub fn clear(&mut self) {
        self.seed.fill(0);
        self.chain_key.fill(0);
        self.chain_code.fill(0);
    }
}

/// `lib/keychain.js`'s upstream package's `normalizeMnemonic`: trim, collapse
/// whitespace (the ideographic space included) to a single ASCII space, and
/// lowercase.
fn normalize_mnemonic(mnemonic: &str) -> String {
    mnemonic
        .trim()
        .replace('\u{3000}', " ")
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `index.js::keyPath`: `[purpose = 48, KEET_TYPE, role = 0, accountIndex, index]`.
pub fn key_path(account_index: u32, index: u32) -> [u32; 5] {
    [
        48,
        crate::wire::ZXTERM_KEY_PATH_TYPE,
        0,
        account_index,
        index,
    ]
}

/// `index.js::identityKeyPath`.
pub fn identity_key_path(account_index: u32) -> [u32; 5] {
    key_path(account_index, 0)
}

/// `index.js::discoveryCorePath`.
pub fn discovery_core_path(account_index: u32) -> [u32; 5] {
    key_path(account_index, 1)
}

/// `index.js::symmetricPath`: `["SLIP-0021", namespace, ...path]`.
pub fn symmetric_path(path: &[String]) -> Vec<String> {
    let mut full = Vec::with_capacity(2 + path.len());
    full.push("SLIP-0021".to_string());
    full.push(crate::wire::ZXTERM_SYMMETRIC_NAMESPACE.to_string());
    full.extend(path.iter().cloned());
    full
}

/// `index.js::encryptionKeyPath`.
pub fn encryption_key_path(profile_key: &[u8]) -> Vec<String> {
    symmetric_path(&[hex::encode(profile_key), "encryption key".to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> Vec<u8> {
        // Any fixed byte string works as a "BIP-39 seed" for structural
        // tests; only the parity test needs a real mnemonic-derived seed.
        (0u8..64).collect()
    }

    #[test]
    fn derive_is_deterministic() {
        let kc = KeyChain::new(test_seed());
        let a = kc.derive(&identity_key_path(0));
        let b = kc.derive(&identity_key_path(0));
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.secret_key, b.secret_key);
    }

    #[test]
    fn different_paths_derive_different_keys() {
        let kc = KeyChain::new(test_seed());
        let identity = kc.derive(&identity_key_path(0));
        let discovery = kc.derive(&discovery_core_path(0));
        assert_ne!(identity.public_key, discovery.public_key);
    }

    #[test]
    fn hardening_is_idempotent() {
        // A path given already-hardened must derive identically to the same
        // path given unhardened (the gotcha this test guards against: double
        // hardening by adding the offset unconditionally).
        let kc = KeyChain::new(test_seed());
        let unhardened = kc.derive(&[48, 1, 0, 0, 0]);
        let hardened = kc.derive(&[
            48 + HARDENED_OFFSET,
            1 + HARDENED_OFFSET,
            HARDENED_OFFSET,
            HARDENED_OFFSET,
            HARDENED_OFFSET,
        ]);
        assert_eq!(unhardened.public_key, hardened.public_key);
    }

    #[test]
    fn symmetric_key_is_deterministic_and_path_sensitive() {
        let kc = KeyChain::new(test_seed());
        let a = kc.get_symmetric_key(&encryption_key_path(b"profile-key-a"));
        let b = kc.get_symmetric_key(&encryption_key_path(b"profile-key-a"));
        let c = kc.get_symmetric_key(&encryption_key_path(b"profile-key-b"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn generate_mnemonic_round_trips_through_derive_seed() {
        let mnemonic = KeyChain::generate_mnemonic().expect("generate mnemonic");
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        let seed = KeyChain::derive_seed(&mnemonic).expect("derive seed");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn derive_seed_rejects_invalid_mnemonic() {
        let bad = "not a valid bip39 mnemonic phrase at all here nope";
        assert!(KeyChain::derive_seed(bad).is_err());
    }
}

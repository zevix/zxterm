//! `zxterm_core::idkey`: the identity-key scheme ZBTerm uses today (mnemonic
//! → identity key → device proof), ported algorithmically unchanged from the
//! upstream identity-key package except for the two name-bearing constants
//! `crate::wire::ZXTERM_KEY_PATH_TYPE`/`crate::wire::ZXTERM_SYMMETRIC_NAMESPACE`
//! (`X-01`/`A-4`). The upstream package's own name never appears in this
//! module; see `THIRD-PARTY-NOTICES.md` for its attribution.
//!
//! Mirrors the upstream `index.js`'s `IdentityKey` class:
//! - [`IdentityKey::generate_mnemonic`] / [`IdentityKey::from_mnemonic`] /
//!   [`IdentityKey::from_seed`] — `IdentityKey.generateMnemonic`/`from`.
//! - [`IdentityKey::identity_public_key`] / [`IdentityKey::profile_discovery_public_key`].
//! - [`IdentityKey::get_profile_discovery_encryption_key`] / [`IdentityKey::get_encryption_key`].
//! - [`IdentityKey::bootstrap`] — mints a device proof under this identity.
//! - [`IdentityKey::clear`] — zeroes every secret this type holds.

pub mod keychain;
pub mod proof;

use keychain::{KeyChain, KeyPair};

use crate::error::Error;

/// `index.js::NS_PROFILE_DISC_ENC = hash(utf8("profile discovery"))` — not
/// name-bearing (it names a purpose, not the upstream package), unchanged.
const PROFILE_DISCOVERY_PURPOSE: &[u8] = b"profile discovery";

/// Mirrors `index.js`'s `IdentityKey` class.
pub struct IdentityKey {
    keychain: KeyChain,
    identity_key_pair: KeyPair,
    profile_discovery_key_pair: KeyPair,
}

impl IdentityKey {
    /// `IdentityKey.generateMnemonic` (`KeyChain.generateMnemonic`).
    pub fn generate_mnemonic() -> Result<String, Error> {
        KeyChain::generate_mnemonic()
    }

    /// `IdentityKey.deriveSeed` (`KeyChain.deriveSeed`).
    pub fn derive_seed(mnemonic: &str) -> Result<[u8; 64], Error> {
        KeyChain::derive_seed(mnemonic)
    }

    /// `IdentityKey.from({seed})`.
    pub fn from_seed(seed: impl Into<Vec<u8>>) -> Self {
        Self::from_keychain(KeyChain::new(seed))
    }

    /// `IdentityKey.from({mnemonic})`.
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, Error> {
        let seed = Self::derive_seed(mnemonic)?;
        Ok(Self::from_seed(seed.to_vec()))
    }

    fn from_keychain(keychain: KeyChain) -> Self {
        let identity_key_pair = keychain.get(&keychain::identity_key_path(0));
        let profile_discovery_key_pair = keychain.get(&keychain::discovery_core_path(0));
        IdentityKey {
            keychain,
            identity_key_pair,
            profile_discovery_key_pair,
        }
    }

    /// `identity.identityPublicKey`.
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity_key_pair.public_key
    }

    /// `identity.profileDiscoveryPublicKey`.
    pub fn profile_discovery_public_key(&self) -> [u8; 32] {
        self.profile_discovery_key_pair.public_key
    }

    /// `identity.getProfileDiscoveryEncryptionKey()`.
    pub fn get_profile_discovery_encryption_key(&self) -> [u8; 32] {
        let ns = proof::blake2b_256(PROFILE_DISCOVERY_PURPOSE);
        self.get_encryption_key(&ns)
    }

    /// `identity.getEncryptionKey(profileKey)`.
    pub fn get_encryption_key(&self, profile_key: &[u8]) -> [u8; 32] {
        self.keychain
            .get_symmetric_key(&keychain::encryption_key_path(profile_key))
    }

    /// `identity.bootstrap(device)`.
    pub fn bootstrap(&self, device_public_key: [u8; 32], epoch_ms: u64) -> Vec<u8> {
        proof::bootstrap(&self.identity_key_pair, device_public_key, epoch_ms)
    }

    /// `identity.clear()`.
    pub fn clear(&mut self) {
        self.keychain.clear();
        self.identity_key_pair.clear();
        self.profile_discovery_key_pair.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_derives_distinct_identity_and_discovery_keys() {
        let identity = IdentityKey::from_seed(vec![7u8; 64]);
        assert_ne!(
            identity.identity_public_key(),
            identity.profile_discovery_public_key()
        );
    }

    #[test]
    fn same_seed_is_deterministic() {
        let a = IdentityKey::from_seed(vec![9u8; 64]);
        let b = IdentityKey::from_seed(vec![9u8; 64]);
        assert_eq!(a.identity_public_key(), b.identity_public_key());
        assert_eq!(
            a.get_profile_discovery_encryption_key(),
            b.get_profile_discovery_encryption_key()
        );
    }

    #[test]
    fn encryption_key_is_profile_key_sensitive() {
        let identity = IdentityKey::from_seed(vec![1u8; 64]);
        let a = identity.get_encryption_key(b"profile-a");
        let b = identity.get_encryption_key(b"profile-b");
        assert_ne!(a, b);
    }

    #[test]
    fn bootstrap_proof_verifies_under_this_identity() {
        let identity = IdentityKey::from_seed(vec![2u8; 64]);
        let device_public_key = [42u8; 32];
        let proof_bytes = identity.bootstrap(device_public_key, 1_700_000_000_000);

        let result = proof::verify(&proof_bytes, None, &proof::VerifyOpts::default())
            .expect("bootstrap proof verifies");
        assert_eq!(result.identity_public_key, identity.identity_public_key());
        assert_eq!(result.device_public_key, device_public_key);
    }

    #[test]
    fn clear_zeroes_every_secret() {
        let mut identity = IdentityKey::from_seed(vec![3u8; 64]);
        identity.clear();
        assert_eq!(identity.identity_key_pair.secret_key, [0u8; 32]);
        assert_eq!(identity.profile_discovery_key_pair.secret_key, [0u8; 32]);
    }
}

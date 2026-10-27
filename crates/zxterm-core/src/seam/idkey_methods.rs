//! The identity-key (`X-01`) methods of the seam (K9): what ZBTerm's
//! `engine/crypto.js` and `engine/account-store.js` used the upstream
//! identity-key package for, now answered by `crate::idkey` (K4).
//!
//! - `idkey.create {mnemonic?, devicePublicKeyHex}` → `{mnemonic,
//!   identityPublicKey, identityProof, profileDiscoveryPublicKey,
//!   profileDiscoveryEncryptionKey}`: mints (or re-derives, when a mnemonic
//!   is given) an identity and bootstraps a proof binding the device key to
//!   it. Hex everywhere, as ZBTerm's account records store it.
//! - `idkey.derive {mnemonic}` → `{identityPublicKey,
//!   profileDiscoveryPublicKey, profileDiscoveryEncryptionKey}`: the keys
//!   this scheme derives from a mnemonic. ZBTerm compares the identity key
//!   with the one a profile stored to tell an identity made by the old
//!   (upstream-package) scheme from one made by this one (ZBTerm `D-32`).
//! - `idkey.verify {proofHex, identityPublicKeyHex, devicePublicKeyHex}` →
//!   `{valid}`: `IdentityKey.verify(proof, null, {expectedIdentity,
//!   expectedDevice})`; never an error, any malformed input is `false`.
//!
//! Runs on a blocking thread (`Dispatcher::dispatch_value`): a mnemonic's
//! seed is 2048 rounds of PBKDF2-HMAC-SHA512.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::error::{Code, Error};
use crate::idkey::{IdentityKey, proof};

use super::methods::parse_args;

pub(super) fn dispatch_idkey(method: &str, args_json: &str) -> Result<Value, Error> {
    let args = parse_args(args_json)?;
    match method {
        "idkey.create" => idkey_create(&args),
        "idkey.derive" => idkey_derive(&args),
        "idkey.verify" => Ok(idkey_verify(&args)),
        other => Err(Error::new(
            Code::EBackendUnsupported,
            format!("no such seam method: {other}"),
        )),
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn key32(args: &Value, key: &str) -> Result<[u8; 32], Error> {
    let text = str_arg(args, key)
        .ok_or_else(|| Error::new(Code::EInternal, format!("{key} is required")))?;
    let bytes =
        hex::decode(text).map_err(|_| Error::new(Code::EAuth, format!("{key} is not hex")))?;
    bytes
        .try_into()
        .map_err(|_| Error::new(Code::EAuth, format!("{key} must be 32 bytes")))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn idkey_create(args: &Value) -> Result<Value, Error> {
    let device = key32(args, "devicePublicKeyHex")?;
    let mnemonic = match str_arg(args, "mnemonic").filter(|m| !m.is_empty()) {
        Some(m) => m.to_string(),
        None => IdentityKey::generate_mnemonic()?,
    };
    let mut identity = IdentityKey::from_mnemonic(&mnemonic)?;
    let proof = identity.bootstrap(device, now_ms());
    let mut value = derived_keys(&identity);
    identity.clear();
    value["mnemonic"] = json!(mnemonic);
    value["identityProof"] = json!(hex::encode(proof));
    Ok(value)
}

fn derived_keys(identity: &IdentityKey) -> Value {
    json!({
        "identityPublicKey": hex::encode(identity.identity_public_key()),
        "profileDiscoveryPublicKey": hex::encode(identity.profile_discovery_public_key()),
        "profileDiscoveryEncryptionKey":
            hex::encode(identity.get_profile_discovery_encryption_key()),
    })
}

fn idkey_derive(args: &Value) -> Result<Value, Error> {
    let mnemonic = str_arg(args, "mnemonic")
        .ok_or_else(|| Error::new(Code::EInternal, "mnemonic is required"))?;
    let mut identity = IdentityKey::from_mnemonic(mnemonic)?;
    let value = derived_keys(&identity);
    identity.clear();
    Ok(value)
}

fn idkey_verify(args: &Value) -> Value {
    let valid = (|| {
        let proof_bytes = hex::decode(str_arg(args, "proofHex")?).ok()?;
        let identity = key32(args, "identityPublicKeyHex").ok()?;
        let device = key32(args, "devicePublicKeyHex").ok()?;
        proof::verify(
            &proof_bytes,
            None,
            &proof::VerifyOpts {
                receipt: None,
                expected_identity: Some(&identity),
                expected_device: Some(&device),
            },
        )
    })()
    .is_some();
    json!({ "valid": valid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_verify_round_trips_and_refuses_the_wrong_device() {
        let device = [7u8; 32];
        let created = idkey_create(&json!({ "devicePublicKeyHex": hex::encode(device) })).unwrap();
        let proof = created["identityProof"].as_str().unwrap();
        let identity = created["identityPublicKey"].as_str().unwrap();
        let ok = idkey_verify(&json!({
            "proofHex": proof,
            "identityPublicKeyHex": identity,
            "devicePublicKeyHex": hex::encode(device),
        }));
        assert_eq!(ok["valid"], true);
        let wrong = idkey_verify(&json!({
            "proofHex": proof,
            "identityPublicKeyHex": identity,
            "devicePublicKeyHex": hex::encode([9u8; 32]),
        }));
        assert_eq!(wrong["valid"], false);
        let garbage = idkey_verify(&json!({ "proofHex": "zz" }));
        assert_eq!(garbage["valid"], false);
    }

    #[test]
    fn a_given_mnemonic_re_derives_the_same_identity() {
        let device = hex::encode([1u8; 32]);
        let a = idkey_create(&json!({ "devicePublicKeyHex": device })).unwrap();
        let mnemonic = a["mnemonic"].as_str().unwrap();
        let b =
            idkey_create(&json!({ "devicePublicKeyHex": device, "mnemonic": mnemonic })).unwrap();
        assert_eq!(a["identityPublicKey"], b["identityPublicKey"]);
        let key = idkey_derive(&json!({ "mnemonic": mnemonic })).unwrap();
        assert_eq!(key["identityPublicKey"], a["identityPublicKey"]);
        assert_eq!(
            key["profileDiscoveryPublicKey"],
            a["profileDiscoveryPublicKey"]
        );
    }
}

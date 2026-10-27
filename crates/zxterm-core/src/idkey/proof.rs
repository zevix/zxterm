//! Device-proof minting/verification and its `compact-encoding`-equivalent
//! wire format.
//!
//! Ported from the upstream identity-key package's `lib/encoding.js`
//! (`ProofEncoding`/`AttestedDevice`/`AttestedData`/`ReceiptEncoding`) and
//! `index.js` (`IdentityKey.bootstrap`/`attestDevice`/`attestData`/`verify`),
//! verified 2026-09-28 (`X-01`).
//!
//! Wire shapes (all integers little-endian unless noted):
//! - `uint`: a `compact-encoding` varint — `n <= 0xfc` as one byte; `0xfd` +
//!   `u16`; `0xfe` + `u32`; `0xff` + `u64`.
//! - `Epoch`: always 8 bytes, the epoch **in whole seconds**, floored from
//!   milliseconds on encode and multiplied back by 1000 on decode (a proof's
//!   epoch is not millisecond-exact after a round trip).
//! - `AttestedDevice` (signable, never decoded): `u8(0) ‖ Epoch ‖
//!   fixed32(identity) ‖ fixed32(device)`.
//! - `AttestedData` (signable, never decoded): `u8(1) ‖ Epoch ‖
//!   fixed32(identity) ‖ fixed32(data hash)`.
//! - `DeviceAttestation`: `fixed32(publicKey) ‖ fixed64(signature)`.
//! - `ProofEncoding`: `uint(version) ‖ Epoch ‖ fixed32(identity) ‖
//!   uint(chain.len) ‖ chain[...DeviceAttestation] ‖ uint(flags) ‖
//!   [fixed64(signature) if flags & 1]`. Version 0 decodes to a sentinel
//!   (`Proof::version == 0`) and is rejected by every caller.
//! - `ReceiptEncoding`: `Epoch`.

use blake2::{Blake2b256, Digest};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use super::keychain::KeyPair;

/// `index.js::PROOF_VERSION`.
pub const PROOF_VERSION: u64 = 1;

const ATTESTED_DEVICE_TAG: u8 = 0;
const ATTESTED_DATA_TAG: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAttestation {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataAttestation {
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub version: u64,
    /// Epoch, in milliseconds (matching the upstream package's in-memory
    /// representation); truncated to whole seconds on the wire.
    pub epoch_ms: u64,
    pub identity: [u8; 32],
    pub chain: Vec<DeviceAttestation>,
    pub data: Option<DataAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    OutOfBounds,
    ArrayTooBig,
    /// `"Version 0 proofs are not supported"` — decoded fine (as the
    /// sentinel `Proof::version == 0`), but any caller that tries to attest
    /// with it must reject it.
    VersionZero,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::OutOfBounds => write!(f, "out of bounds"),
            DecodeError::ArrayTooBig => write!(f, "array is too big"),
            DecodeError::VersionZero => write!(f, "Version 0 proofs are not supported"),
        }
    }
}

impl std::error::Error for DecodeError {}

// --- compact-encoding-equivalent primitives -------------------------------

fn encode_uint(out: &mut Vec<u8>, n: u64) {
    if n <= 0xfc {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn decode_uint(buf: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    let a = read_bytes::<1>(buf, pos)?[0];
    if a <= 0xfc {
        return Ok(a as u64);
    }
    match a {
        0xfd => Ok(u16::from_le_bytes(read_bytes::<2>(buf, pos)?) as u64),
        0xfe => Ok(u32::from_le_bytes(read_bytes::<4>(buf, pos)?) as u64),
        _ => Ok(u64::from_le_bytes(read_bytes::<8>(buf, pos)?)),
    }
}

fn read_bytes<const N: usize>(buf: &[u8], pos: &mut usize) -> Result<[u8; N], DecodeError> {
    if buf.len() - *pos < N {
        return Err(DecodeError::OutOfBounds);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

fn encode_epoch_seconds(out: &mut Vec<u8>, epoch_ms: u64) {
    out.extend_from_slice(&(epoch_ms / 1000).to_le_bytes());
}

fn decode_epoch_ms(buf: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(read_bytes::<8>(buf, pos)?) * 1000)
}

fn encode_attested_device(epoch_ms: u64, identity: &[u8; 32], device: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 32 + 32);
    out.push(ATTESTED_DEVICE_TAG);
    encode_epoch_seconds(&mut out, epoch_ms);
    out.extend_from_slice(identity);
    out.extend_from_slice(device);
    out
}

fn encode_attested_data(epoch_ms: u64, identity: &[u8; 32], data_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 32 + 32);
    out.push(ATTESTED_DATA_TAG);
    encode_epoch_seconds(&mut out, epoch_ms);
    out.extend_from_slice(identity);
    out.extend_from_slice(data_hash);
    out
}

/// `lib/crypto.js::hash` (`sodium.crypto_generichash`, unkeyed BLAKE2b-256).
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sign(msg: &[u8], key_pair: &KeyPair) -> [u8; 64] {
    key_pair.signing_key().sign(msg).to_bytes()
}

fn verify_signature(msg: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(msg, &sig).is_ok()
}

// --- ProofEncoding / ReceiptEncoding ---------------------------------------

pub fn encode_proof(p: &Proof) -> Vec<u8> {
    let mut out = Vec::new();
    encode_uint(&mut out, p.version);
    encode_epoch_seconds(&mut out, p.epoch_ms);
    out.extend_from_slice(&p.identity);

    encode_uint(&mut out, p.chain.len() as u64);
    for link in &p.chain {
        out.extend_from_slice(&link.public_key);
        out.extend_from_slice(&link.signature);
    }

    let flags: u64 = if p.data.is_some() { 1 } else { 0 };
    encode_uint(&mut out, flags);
    if let Some(data) = &p.data {
        out.extend_from_slice(&data.signature);
    }
    out
}

const MAX_ARRAY_LEN: u64 = 0x10_0000;

pub fn decode_proof(buf: &[u8]) -> Result<Proof, DecodeError> {
    let mut pos = 0usize;
    let version = decode_uint(buf, &mut pos)?;

    // `ProofEncoding.decode`: version 0 is a sentinel, ignored by every
    // caller, never parsed further.
    if version == 0 {
        return Ok(Proof {
            version: 0,
            epoch_ms: 0,
            identity: [0u8; 32],
            chain: Vec::new(),
            data: None,
        });
    }

    let epoch_ms = decode_epoch_ms(buf, &mut pos)?;
    let identity = read_bytes::<32>(buf, &mut pos)?;

    let chain_len = decode_uint(buf, &mut pos)?;
    if chain_len > MAX_ARRAY_LEN {
        return Err(DecodeError::ArrayTooBig);
    }
    let mut chain = Vec::with_capacity(chain_len as usize);
    for _ in 0..chain_len {
        let public_key = read_bytes::<32>(buf, &mut pos)?;
        let signature = read_bytes::<64>(buf, &mut pos)?;
        chain.push(DeviceAttestation {
            public_key,
            signature,
        });
    }

    let flags = decode_uint(buf, &mut pos)?;
    let data = if flags & 1 != 0 {
        Some(DataAttestation {
            signature: read_bytes::<64>(buf, &mut pos)?,
        })
    } else {
        None
    };

    Ok(Proof {
        version,
        epoch_ms,
        identity,
        chain,
        data,
    })
}

pub fn encode_receipt(epoch_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    encode_epoch_seconds(&mut out, epoch_ms);
    out
}

pub fn decode_receipt(buf: &[u8]) -> Result<u64, DecodeError> {
    let mut pos = 0usize;
    decode_epoch_ms(buf, &mut pos)
}

// --- bootstrap / attest / verify -------------------------------------------

fn attest_device_on(device_public_key: [u8; 32], parent: &KeyPair, mut proof: Proof) -> Vec<u8> {
    let signable = encode_attested_device(proof.epoch_ms, &proof.identity, &device_public_key);
    let signature = sign(&signable, parent);
    proof.chain.push(DeviceAttestation {
        public_key: device_public_key,
        signature,
    });
    encode_proof(&proof)
}

/// `IdentityKey.bootstrap({identity}, device)`: mints a fresh proof (empty
/// chain) and attests `device_public_key` under it.
pub fn bootstrap(identity: &KeyPair, device_public_key: [u8; 32], epoch_ms: u64) -> Vec<u8> {
    let proof = Proof {
        version: PROOF_VERSION,
        epoch_ms,
        identity: identity.public_key,
        chain: Vec::new(),
        data: None,
    };
    attest_device_on(device_public_key, identity, proof)
}

/// `IdentityKey.attestDevice(publicKey, parent, proof)` where `proof` is
/// already-encoded bytes: decodes, appends a link signed by `parent`, and
/// re-encodes.
pub fn attest_device(
    device_public_key: [u8; 32],
    parent: &KeyPair,
    proof_bytes: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let proof = decode_proof(proof_bytes)?;
    if proof.version == 0 {
        return Err(DecodeError::VersionZero);
    }
    Ok(attest_device_on(device_public_key, parent, proof))
}

/// `IdentityKey.attestData`: attaches a `data` attestation (signed by the
/// chain's own key pair, i.e. the device or identity key doing the
/// attesting) to a proof, either fresh (`proof_bytes = None`) or existing.
pub fn attest_data(
    attested_data: &[u8],
    key_pair: &KeyPair,
    proof_bytes: Option<&[u8]>,
    now_epoch_ms: u64,
) -> Result<Vec<u8>, DecodeError> {
    let mut proof = match proof_bytes {
        Some(bytes) => {
            let p = decode_proof(bytes)?;
            if p.version == 0 {
                return Err(DecodeError::VersionZero);
            }
            p
        }
        None => Proof {
            version: PROOF_VERSION,
            epoch_ms: now_epoch_ms,
            identity: key_pair.public_key,
            chain: Vec::new(),
            data: None,
        },
    };

    let hash = blake2b_256(attested_data);
    let signable = encode_attested_data(proof.epoch_ms, &proof.identity, &hash);
    let signature = sign(&signable, key_pair);
    proof.data = Some(DataAttestation { signature });
    Ok(encode_proof(&proof))
}

#[derive(Default)]
pub struct VerifyOpts<'a> {
    pub receipt: Option<&'a [u8]>,
    pub expected_identity: Option<&'a [u8; 32]>,
    pub expected_device: Option<&'a [u8; 32]>,
}

pub struct VerifyResult {
    pub receipt: Vec<u8>,
    pub identity_public_key: [u8; 32],
    pub device_public_key: [u8; 32],
}

fn last_key(chain: &[DeviceAttestation]) -> Option<[u8; 32]> {
    chain.last().map(|l| l.public_key)
}

fn validate_attested_data(has_data: bool, attested_data: Option<&[u8]>) -> bool {
    has_data || attested_data.is_none()
}

fn validate_proof(proof: &Proof, attested_data: Option<&[u8]>, opts: &VerifyOpts) -> bool {
    if proof.version == 0 {
        return false;
    }
    if proof.version > PROOF_VERSION {
        return false;
    }
    if let Some(receipt_bytes) = opts.receipt {
        let Ok(receipt_epoch) = decode_receipt(receipt_bytes) else {
            return false;
        };
        if proof.epoch_ms < receipt_epoch {
            return false;
        }
    }
    if let Some(expected_identity) = opts.expected_identity
        && proof.identity != *expected_identity
    {
        return false;
    }
    validate_attested_data(proof.data.is_some(), attested_data)
}

/// `IdentityKey.verify(proof, attestedData, opts)`: `None` on any failure,
/// matching the upstream `null` return.
pub fn verify(
    proof_bytes: &[u8],
    attested_data: Option<&[u8]>,
    opts: &VerifyOpts,
) -> Option<VerifyResult> {
    let proof = decode_proof(proof_bytes).ok()?;
    if !validate_proof(&proof, attested_data, opts) {
        return None;
    }

    let candidate = last_key(&proof.chain).unwrap_or(proof.identity);

    if let Some(expected_device) = opts.expected_device
        && candidate != *expected_device
    {
        return None;
    }

    let mut parent = proof.identity;
    for link in &proof.chain {
        let signable = encode_attested_device(proof.epoch_ms, &proof.identity, &link.public_key);
        if !verify_signature(&signable, &link.signature, &parent) {
            return None;
        }
        parent = link.public_key;
    }

    if let Some(data) = &proof.data {
        let attested = attested_data?;
        let hash = blake2b_256(attested);
        let signable = encode_attested_data(proof.epoch_ms, &proof.identity, &hash);
        if !verify_signature(&signable, &data.signature, &parent) {
            return None;
        }
    }

    Some(VerifyResult {
        receipt: encode_receipt(proof.epoch_ms),
        identity_public_key: proof.identity,
        device_public_key: candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair_from(byte: u8) -> KeyPair {
        let secret_key = [byte; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        KeyPair {
            public_key: signing.verifying_key().to_bytes(),
            secret_key,
        }
    }

    #[test]
    fn bootstrap_then_verify_round_trips() {
        let identity = key_pair_from(1);
        let device = key_pair_from(2);
        let proof = bootstrap(&identity, device.public_key, 1_700_000_000_123);

        let result = verify(&proof, None, &VerifyOpts::default()).expect("verify succeeds");
        assert_eq!(result.identity_public_key, identity.public_key);
        assert_eq!(result.device_public_key, device.public_key);
    }

    #[test]
    fn epoch_truncates_to_seconds_on_the_wire() {
        let identity = key_pair_from(3);
        let device = key_pair_from(4);
        let epoch_ms = 1_700_000_000_999;
        let proof_bytes = bootstrap(&identity, device.public_key, epoch_ms);
        let decoded = decode_proof(&proof_bytes).expect("decode");
        assert_eq!(decoded.epoch_ms, (epoch_ms / 1000) * 1000);
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let identity = key_pair_from(5);
        let device = key_pair_from(6);
        let mut proof = bootstrap(&identity, device.public_key, 1_700_000_000_000);

        // Flip a byte inside the chain's signature.
        let last = proof.len() - 1;
        proof[last] ^= 0x01;

        assert!(verify(&proof, None, &VerifyOpts::default()).is_none());
    }

    #[test]
    fn expected_identity_and_device_are_enforced() {
        let identity = key_pair_from(7);
        let device = key_pair_from(8);
        let other = key_pair_from(9);
        let proof = bootstrap(&identity, device.public_key, 1_700_000_000_000);

        assert!(
            verify(
                &proof,
                None,
                &VerifyOpts {
                    expected_identity: Some(&identity.public_key),
                    expected_device: Some(&device.public_key),
                    ..Default::default()
                }
            )
            .is_some()
        );
        assert!(
            verify(
                &proof,
                None,
                &VerifyOpts {
                    expected_device: Some(&other.public_key),
                    ..Default::default()
                }
            )
            .is_none()
        );
    }

    #[test]
    fn version_zero_is_rejected() {
        let mut bytes = Vec::new();
        encode_uint(&mut bytes, 0);
        assert!(verify(&bytes, None, &VerifyOpts::default()).is_none());
        let identity = key_pair_from(10);
        assert_eq!(
            attest_device(key_pair_from(11).public_key, &identity, &bytes),
            Err(DecodeError::VersionZero)
        );
    }
}

//! The signed head and the BLAKE3 chain root (design §4.5).
//!
//! **Chain construction (`X-24`, pinned by this module's tests).** For the segment records `r_0 … r_{n-1}` of a
//! file, in file order:
//!
//! ```text
//! h_i    = blake3(r_i)                     // the whole record, header included
//! root_0 = 32 zero bytes                   // ROOT_0, the empty chain
//! root_{i+1} = blake3(root_i ‖ h_i)        // 64 bytes in, 32 out
//! ```
//!
//! The head is `(length = n, chain_root = root_n)`, signed by the host's
//! Ed25519 device key over
//! `HISTORY_HEAD_CONTEXT ‖ session_id (64 hex bytes) ‖ u64le(length) ‖
//! chain_root`. A segment's AEAD proves that its bytes are unchanged since
//! they were sealed; only the chain proves that it is still segment `i` of
//! the file the head signs, so a segment swapped for another validly
//! sealed one (anyone holding the history key can make one) or reordered,
//! dropped or duplicated changes `root_n`.
//!
//! Encoded (`SignedHead::encode`): `u64le(length) ‖ chain_root ‖
//! signature`, 104 bytes.

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Code, Error};
use crate::wire;

/// The root of the empty chain.
pub const ROOT_0: [u8; 32] = [0u8; 32];
/// Bytes of an encoded [`SignedHead`].
pub const HEAD_BYTES: usize = 8 + 32 + 64;

/// `h_i = blake3(record)`.
pub fn record_hash(record: &[u8]) -> [u8; 32] {
    *blake3::hash(record).as_bytes()
}

/// `root_{i+1} = blake3(root_i ‖ h_i)`.
pub fn chain_step(prev_root: &[u8; 32], record_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev_root);
    h.update(record_hash);
    *h.finalize().as_bytes()
}

/// The chain root of `records`.
pub fn chain_root<'a>(records: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    records
        .into_iter()
        .fold(ROOT_0, |root, r| chain_step(&root, &record_hash(r)))
}

/// `(length, chain root)` and the host's signature over them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedHead {
    /// Segments in the chain.
    pub length: u64,
    pub chain_root: [u8; 32],
    pub signature: [u8; 64],
}

fn signed_message(session_id: &str, length: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(wire::HISTORY_HEAD_CONTEXT.len() + session_id.len() + 40);
    m.extend_from_slice(wire::HISTORY_HEAD_CONTEXT.as_bytes());
    m.extend_from_slice(session_id.as_bytes());
    m.extend_from_slice(&length.to_le_bytes());
    m.extend_from_slice(root);
    m
}

impl SignedHead {
    /// Signs `(length, root)` for `session_id`.
    pub fn sign(session_id: &str, length: u64, root: [u8; 32], key: &SigningKey) -> SignedHead {
        let sig = key.sign(&signed_message(session_id, length, &root));
        SignedHead {
            length,
            chain_root: root,
            signature: sig.to_bytes(),
        }
    }

    /// `E_AUTH` unless the host's key signed this head for `session_id`.
    pub fn verify(&self, session_id: &str, key: &VerifyingKey) -> Result<(), Error> {
        let sig = Signature::from_bytes(&self.signature);
        key.verify_strict(
            &signed_message(session_id, self.length, &self.chain_root),
            &sig,
        )
        .map_err(|_| Error::new(Code::EAuth, "History head signature is invalid"))
    }

    pub fn encode(&self) -> [u8; HEAD_BYTES] {
        let mut b = [0u8; HEAD_BYTES];
        b[..8].copy_from_slice(&self.length.to_le_bytes());
        b[8..40].copy_from_slice(&self.chain_root);
        b[40..].copy_from_slice(&self.signature);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedHead, Error> {
        if bytes.len() != HEAD_BYTES {
            return Err(Error::new(Code::ECorrupt, "History head is malformed"));
        }
        Ok(SignedHead {
            length: u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            chain_root: bytes[8..40].try_into().expect("32 bytes"),
            signature: bytes[40..].try_into().expect("64 bytes"),
        })
    }
}

/// What a viewer needs, besides the segments themselves, to check a run
/// of segments against a head: the chain root before the run, the hash of
/// every segment in the run, and the hash of every segment after it.
/// (A chain has no shorter proof; `R-22` records the cost and K16's option
/// of a tree.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProof {
    /// The encoded [`SignedHead`].
    pub head: Vec<u8>,
    /// Index of the run's first segment.
    pub first_index: u64,
    /// `root_{first_index}`.
    pub prev_root: [u8; 32],
    /// `h_i` of each segment of the run.
    pub hashes: Vec<[u8; 32]>,
    /// `h_i` of every segment after the run, up to the head's length.
    pub after: Vec<[u8; 32]>,
}

impl RangeProof {
    /// The head, checked against `session_id` and the host's key, and the
    /// run's hashes walked to the head's chain root (`E_AUTH` for a bad
    /// signature, `E_CORRUPT` when the walk does not end at the root).
    pub fn verify(&self, session_id: &str, key: &VerifyingKey) -> Result<SignedHead, Error> {
        let head = SignedHead::decode(&self.head)?;
        head.verify(session_id, key)?;
        let total = self
            .first_index
            .checked_add(self.hashes.len() as u64)
            .and_then(|n| n.checked_add(self.after.len() as u64));
        if total != Some(head.length) {
            return Err(Error::new(
                Code::ECorrupt,
                "History proof does not span the signed head",
            ));
        }
        let root = self
            .hashes
            .iter()
            .chain(self.after.iter())
            .fold(self.prev_root, |root, h| chain_step(&root, h));
        if root != head.chain_root {
            return Err(Error::new(
                Code::ECorrupt,
                "History chain root does not match the signed head",
            ));
        }
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn the_chain_is_pinned_and_order_sensitive() {
        assert_eq!(chain_root([] as [&[u8]; 0]), ROOT_0);
        let (a, b) = (b"segment a".as_slice(), b"segment b".as_slice());
        let expected = {
            let r1 = blake3::hash(&[&ROOT_0[..], blake3::hash(a).as_bytes()].concat());
            *blake3::hash(&[r1.as_bytes().as_slice(), blake3::hash(b).as_bytes()].concat())
                .as_bytes()
        };
        assert_eq!(chain_root([a, b]), expected);
        assert_ne!(chain_root([b, a]), expected);
        assert_ne!(chain_root([a, a]), expected);
        assert_ne!(chain_root([a]), expected);
    }

    #[test]
    fn a_head_signs_the_session_length_and_root() {
        let sid = "aa".repeat(32);
        let k = key();
        let vk = k.verifying_key();
        let head = SignedHead::sign(&sid, 3, [5u8; 32], &k);
        head.verify(&sid, &vk).unwrap();
        assert_eq!(SignedHead::decode(&head.encode()).unwrap(), head);
        assert!(head.verify(&"bb".repeat(32), &vk).is_err());
        let mut other = head;
        other.length = 4;
        assert_eq!(other.verify(&sid, &vk).unwrap_err().code, Code::EAuth);
        other = head;
        other.chain_root[0] ^= 1;
        assert!(other.verify(&sid, &vk).is_err());
        assert!(
            head.verify(&sid, &SigningKey::from_bytes(&[8u8; 32]).verifying_key())
                .is_err()
        );
    }

    #[test]
    fn a_range_proof_walks_to_the_head() {
        let sid = "cc".repeat(32);
        let k = key();
        let recs: Vec<Vec<u8>> = (0..6u8).map(|i| vec![i; 10]).collect();
        let hashes: Vec<[u8; 32]> = recs.iter().map(|r| record_hash(r)).collect();
        let mut roots = vec![ROOT_0];
        for h in &hashes {
            roots.push(chain_step(roots.last().unwrap(), h));
        }
        let head = SignedHead::sign(&sid, 6, roots[6], &k);
        let proof = RangeProof {
            head: head.encode().to_vec(),
            first_index: 2,
            prev_root: roots[2],
            hashes: hashes[2..4].to_vec(),
            after: hashes[4..].to_vec(),
        };
        proof.verify(&sid, &k.verifying_key()).unwrap();
        let mut bad = proof.clone();
        bad.hashes[0][0] ^= 1;
        assert_eq!(
            bad.verify(&sid, &k.verifying_key()).unwrap_err().code,
            Code::ECorrupt
        );
        let mut short = proof.clone();
        short.after.pop();
        assert!(short.verify(&sid, &k.verifying_key()).is_err());
    }
}

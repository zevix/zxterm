//! The core's side of `segment-v1`, the offline-history contract
//! (`contracts/src/segment`, `X-26`, K16): its state codec, the host's
//! signing of records, and the viewer's verification of a state read from
//! it with the host offline.
//!
//! The contract stores, per shared session, write-once sealed segments
//! (the very records of [`super::segment`]) and the host's latest head. It
//! checks the host's Ed25519 signatures and its bounds, and merges by
//! union; it does not hash, so the chain check is the viewer's:
//! [`verify_state`] walks `root_{i+1} = blake3(root_i ‖ blake3(record_i))`
//! from the signed `prev_root` of the first retained segment to the
//! head's `root` (`E_CORRUPT` on any difference) after checking every
//! signature itself, so a node that served a forged state is as refused as
//! a forged peer. [`OfflineView::open`] then opens a segment exactly as
//! [`super::fetch::RangeVerifier`] does a live-fetched one.
//!
//! The wire form is the contract's canonical JSON (its module doc is the
//! specification; `tests/history_contract.rs` pins the two sides
//! byte for byte): `{"h":head|null,"s":[{"i","p","c","g"},...]}`.
//!
//! Signed bytes (`crate::wire::SEGMENT_CONTRACT_DOMAIN`), `lp(x) =
//! u32le(len(x)) ‖ x`, `params` the instance's raw parameter bytes
//! ([`params_bytes`]):
//!
//! ```text
//! segment: DOMAIN ‖ u8(1) ‖ lp(params) ‖ u32le(index) ‖ prev_root ‖ lp(record)
//! head:    DOMAIN ‖ u8(2) ‖ lp(params) ‖ u64le(length) ‖ chain_root
//! ```
//!
//! **`R-22` (settled, `X-27`).** A viewer that reads the contract holds
//! every retained segment, so it has every hash the chain needs: no proof
//! travels and no Merkle tree is needed here. The chain stays the head's
//! construction; the channel's `after` list is unchanged.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;

use crate::error::{Code, Error};
use crate::wire;

use super::fetch::VerifiedSegment;
use super::head::{self, ROOT_0};
use super::segment::{self, SegmentHeader};

/// `contracts/src/segment`'s `MAX_SEGMENTS`: records a state holds.
pub const MAX_SEGMENTS: usize = 512;
/// `MAX_SEGMENT_BYTES`: bytes of one sealed record.
pub const MAX_SEGMENT_BYTES: usize = 1_048_576 + 4096;
/// `MAX_TOTAL_BYTES`: bytes of sealed records a state holds.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

const TAG_SEGMENT: u8 = 1;
const TAG_HEAD: u8 = 2;

/// The instance's parameter bytes, written by hand as the contract's
/// `Params` reads them: `{"host":"<64 hex>","session":"<session id>"}`.
pub fn params_bytes(host: &[u8; 32], session_id: &str) -> Vec<u8> {
    format!(
        "{{\"host\":\"{}\",\"session\":\"{}\"}}",
        hex::encode(host),
        session_id
    )
    .into_bytes()
}

/// One segment as the contract holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    pub index: u32,
    /// `root_index`, the chain root before this segment.
    pub prev_root: [u8; 32],
    /// The sealed record, header included.
    pub record: Vec<u8>,
    pub signature: [u8; 64],
}

/// The host's head as the contract holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractHead {
    /// Segments in the chain.
    pub length: u64,
    pub chain_root: [u8; 32],
    pub signature: [u8; 64],
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn segment_bytes(params: &[u8], index: u32, prev_root: &[u8; 32], record: &[u8]) -> Vec<u8> {
    let d = wire::SEGMENT_CONTRACT_DOMAIN.as_bytes();
    let mut m = Vec::with_capacity(d.len() + params.len() + record.len() + 64);
    m.extend_from_slice(d);
    m.push(TAG_SEGMENT);
    lp(&mut m, params);
    m.extend_from_slice(&index.to_le_bytes());
    m.extend_from_slice(prev_root);
    lp(&mut m, record);
    m
}

fn head_bytes(params: &[u8], length: u64, chain_root: &[u8; 32]) -> Vec<u8> {
    let d = wire::SEGMENT_CONTRACT_DOMAIN.as_bytes();
    let mut m = Vec::with_capacity(d.len() + params.len() + 48);
    m.extend_from_slice(d);
    m.push(TAG_HEAD);
    lp(&mut m, params);
    m.extend_from_slice(&length.to_le_bytes());
    m.extend_from_slice(chain_root);
    m
}

/// Signs a segment record for the instance with `params`.
pub fn sign_segment(
    key: &SigningKey,
    params: &[u8],
    index: u32,
    prev_root: [u8; 32],
    record: Vec<u8>,
) -> SegmentRecord {
    let signature = key
        .sign(&segment_bytes(params, index, &prev_root, &record))
        .to_bytes();
    SegmentRecord {
        index,
        prev_root,
        record,
        signature,
    }
}

/// Signs a head for the instance with `params`.
pub fn sign_head(
    key: &SigningKey,
    params: &[u8],
    length: u64,
    chain_root: [u8; 32],
) -> ContractHead {
    let signature = key
        .sign(&head_bytes(params, length, &chain_root))
        .to_bytes();
    ContractHead {
        length,
        chain_root,
        signature,
    }
}

impl SegmentRecord {
    /// `E_AUTH` unless `host` signed this record for `params`.
    pub fn verify(&self, host: &VerifyingKey, params: &[u8]) -> Result<(), Error> {
        host.verify_strict(
            &segment_bytes(params, self.index, &self.prev_root, &self.record),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::new(Code::EAuth, "A history segment is not signed by the host"))
    }
}

impl ContractHead {
    /// `E_AUTH` unless `host` signed this head for `params`.
    pub fn verify(&self, host: &VerifyingKey, params: &[u8]) -> Result<(), Error> {
        host.verify_strict(
            &head_bytes(params, self.length, &self.chain_root),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::new(Code::EAuth, "The history head is not signed by the host"))
    }
}

/// A contract state (or a delta, which has the same form).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContractState {
    pub head: Option<ContractHead>,
    pub segments: BTreeMap<u32, SegmentRecord>,
}

fn corrupt(msg: &str) -> Error {
    Error::new(Code::ECorrupt, msg.to_string())
}

#[derive(Deserialize)]
struct WireHead {
    n: u64,
    r: String,
    g: String,
}

#[derive(Deserialize)]
struct WireSegment {
    i: u32,
    p: String,
    c: String,
    g: String,
}

#[derive(Deserialize, Default)]
struct WireState {
    #[serde(default)]
    h: Option<WireHead>,
    #[serde(default)]
    s: Vec<WireSegment>,
}

fn hex_n<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    hex::decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| corrupt("The history contract state holds a malformed field"))
}

/// Encodes `head` and `segments` in the contract's canonical form (the
/// only form it accepts as a state): segments in ascending index order.
pub fn encode_parts<'a>(
    head: Option<&ContractHead>,
    segments: impl IntoIterator<Item = &'a SegmentRecord>,
) -> Vec<u8> {
    let mut out = String::from("{\"h\":");
    match head {
        None => out.push_str("null"),
        Some(h) => out.push_str(&format!(
            "{{\"n\":{},\"r\":\"{}\",\"g\":\"{}\"}}",
            h.length,
            hex::encode(h.chain_root),
            hex::encode(h.signature)
        )),
    }
    out.push_str(",\"s\":[");
    for (k, s) in segments.into_iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"i\":{},\"p\":\"{}\",\"c\":\"{}\",\"g\":\"{}\"}}",
            s.index,
            hex::encode(s.prev_root),
            B64.encode(&s.record),
            hex::encode(s.signature)
        ));
    }
    out.push_str("]}");
    out.into_bytes()
}

impl ContractState {
    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        encode_parts(self.head.as_ref(), self.segments.values())
    }

    /// Parses a state or delta (zero bytes are the empty state).
    pub fn decode(bytes: &[u8]) -> Result<ContractState, Error> {
        if bytes.is_empty() {
            return Ok(ContractState::default());
        }
        let wire: WireState = serde_json::from_slice(bytes)
            .map_err(|_| corrupt("The history contract state is malformed"))?;
        let head = match wire.h {
            None => None,
            Some(h) => Some(ContractHead {
                length: h.n,
                chain_root: hex_n(&h.r)?,
                signature: hex_n(&h.g)?,
            }),
        };
        let mut segments = BTreeMap::new();
        for s in wire.s {
            let record = B64
                .decode(&s.c)
                .map_err(|_| corrupt("The history contract state holds a malformed segment"))?;
            let rec = SegmentRecord {
                index: s.i,
                prev_root: hex_n(&s.p)?,
                record,
                signature: hex_n(&s.g)?,
            };
            if segments.insert(rec.index, rec).is_some() {
                return Err(corrupt("The history contract state repeats an index"));
            }
        }
        Ok(ContractState { head, segments })
    }

    /// Bytes of sealed records held.
    pub fn record_bytes(&self) -> usize {
        self.segments.values().map(|s| s.record.len()).sum()
    }
}

/// The lowest segment index of the closed segments `0..count` (with the
/// given record `sizes`) a fresh publisher should send so that what it
/// sends fits the contract's count and size bounds: the highest-index
/// suffix the contract would retain anyway.
pub fn retained_start(sizes: &[usize]) -> usize {
    let mut total = 0usize;
    let mut start = sizes.len();
    while start > 0 {
        let size = sizes[start - 1];
        if sizes.len() - start + 1 > MAX_SEGMENTS || total + size > MAX_TOTAL_BYTES {
            break;
        }
        total += size;
        start -= 1;
    }
    start
}

/// A contract state whose signatures and chain have been checked.
#[derive(Debug, Clone)]
pub struct OfflineView {
    session_id: String,
    host: VerifyingKey,
    /// Index of the first retained segment.
    pub first_index: u64,
    /// The head's length: segments `first_index..head_length` are held
    /// and verified.
    pub head_length: u64,
    pub chain_root: [u8; 32],
    /// Retained segments at or beyond the head's length: signed by the
    /// host but not covered by any head; they are not returned.
    pub beyond_head: u64,
    /// The verified records, `records[k]` being segment `first_index + k`.
    records: Vec<Vec<u8>>,
}

/// Checks a state read from the contract (with `host` offline or not):
/// the head's signature, every retained segment's signature, and the
/// chain from the first retained segment's signed `prev_root` to the
/// head's root. `min_head_length` refuses a head shorter than one already
/// seen. A state with no head has no history yet: an empty view.
pub fn verify_state(
    state: &[u8],
    host: &VerifyingKey,
    session_id: &str,
    min_head_length: u64,
) -> Result<OfflineView, Error> {
    let st = ContractState::decode(state)?;
    let params = params_bytes(&host.to_bytes(), session_id);
    let empty = |first: u64| OfflineView {
        session_id: session_id.to_string(),
        host: *host,
        first_index: first,
        head_length: 0,
        chain_root: ROOT_0,
        beyond_head: st.segments.len() as u64,
        records: Vec::new(),
    };
    let Some(h) = st.head else {
        if min_head_length > 0 {
            return Err(corrupt("History head is shorter than one already seen"));
        }
        return Ok(empty(0));
    };
    h.verify(host, &params)?;
    if h.length < min_head_length {
        return Err(corrupt("History head is shorter than one already seen"));
    }
    for s in st.segments.values() {
        s.verify(host, &params)?;
        if s.record.is_empty() || s.record.len() > MAX_SEGMENT_BYTES {
            return Err(corrupt("A history segment has an impossible size"));
        }
    }
    if h.length == 0 {
        return Ok(OfflineView {
            chain_root: h.chain_root,
            ..empty(0)
        });
    }
    let first = *st
        .segments
        .keys()
        .next()
        .ok_or_else(|| corrupt("The history contract holds no segment the head covers"))?;
    if u64::from(first) >= h.length {
        return Err(corrupt(
            "The history contract holds no segment the head covers",
        ));
    }
    let mut root = st.segments[&first].prev_root;
    let mut records = Vec::new();
    for index in u64::from(first)..h.length {
        let s = st
            .segments
            .get(&(index as u32))
            .ok_or_else(|| corrupt("A history segment the head covers is missing"))?;
        if s.prev_root != root {
            return Err(corrupt("History chain is broken at a segment"));
        }
        root = head::chain_step(&root, &head::record_hash(&s.record));
        records.push(s.record.clone());
    }
    if root != h.chain_root {
        return Err(corrupt("History chain root does not match the signed head"));
    }
    let beyond = st
        .segments
        .keys()
        .filter(|&&i| u64::from(i) >= h.length)
        .count() as u64;
    Ok(OfflineView {
        session_id: session_id.to_string(),
        host: *host,
        first_index: u64::from(first),
        head_length: h.length,
        chain_root: h.chain_root,
        beyond_head: beyond,
        records,
    })
}

impl OfflineView {
    /// Verified segments held.
    pub fn len(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Opens segment `index` under the history key of its epoch: the
    /// AEAD first (any changed byte is `E_CORRUPT`), then the packets'
    /// count, as for a live-fetched segment.
    pub fn open(
        &self,
        index: u64,
        keys: &BTreeMap<u32, [u8; 32]>,
    ) -> Result<VerifiedSegment, Error> {
        let k = index
            .checked_sub(self.first_index)
            .filter(|k| *k < self.records.len() as u64)
            .ok_or_else(|| corrupt("The history contract does not hold this segment"))?;
        let record = &self.records[k as usize];
        let epoch = SegmentHeader::decode(record)?.epoch;
        let key = keys
            .get(&epoch)
            .ok_or_else(|| Error::new(Code::ENoKey, format!("No history key for epoch {epoch}")))?;
        let (header, packets) =
            segment::open(key, &self.session_id, &self.host.to_bytes(), record)?;
        Ok(VerifiedSegment {
            index,
            header,
            packets: packets
                .into_iter()
                .enumerate()
                .map(|(n, p)| (header.first_seq + n as u64, p))
                .collect(),
        })
    }

    /// Opens segments `[from, from + count)` (clamped to what is held),
    /// checking that each starts where the previous ended.
    pub fn open_range(
        &self,
        from: u64,
        count: u64,
        keys: &BTreeMap<u32, [u8; 32]>,
    ) -> Result<Vec<VerifiedSegment>, Error> {
        let from = from.max(self.first_index);
        let end = (from.saturating_add(count)).min(self.first_index + self.len());
        let mut out: Vec<VerifiedSegment> = Vec::new();
        for index in from..end {
            let seg = self.open(index, keys)?;
            if out
                .last()
                .is_some_and(|prev| prev.header.end_seq() != seg.header.first_seq)
            {
                return Err(corrupt("Segments are not contiguous"));
            }
            out.push(seg);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::packet::PlainPacket;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// `n` chained segments of one packet each, sealed under one key.
    fn chain(n: u32, sid: &str, host: &SigningKey) -> (Vec<SegmentRecord>, [u8; 32], Vec<u8>) {
        let params = params_bytes(&host.verifying_key().to_bytes(), sid);
        let hist_key = [3u8; 32];
        let mut root = ROOT_0;
        let mut recs = Vec::new();
        for i in 0..n {
            let header = SegmentHeader {
                epoch: 1,
                first_seq: u64::from(i),
                count: 1,
            };
            let record = segment::seal(
                &hist_key,
                sid,
                &host.verifying_key().to_bytes(),
                &header,
                &[PlainPacket::data(
                    u64::from(i),
                    format!("line {i}").into_bytes(),
                    false,
                )],
            )
            .unwrap();
            let next = head::chain_step(&root, &head::record_hash(&record));
            recs.push(sign_segment(host, &params, i, root, record));
            root = next;
        }
        (recs, root, params)
    }

    fn state_of(recs: &[SegmentRecord], head: Option<ContractHead>) -> Vec<u8> {
        encode_parts(head.as_ref(), recs)
    }

    #[test]
    fn a_state_round_trips_and_its_chain_verifies() {
        let sid = "ab".repeat(32);
        let host = key();
        let (recs, root, params) = chain(5, &sid, &host);
        let head = sign_head(&host, &params, 5, root);
        let bytes = state_of(&recs, Some(head));
        let st = ContractState::decode(&bytes).unwrap();
        assert_eq!(st.encode(), bytes);
        let view = verify_state(&bytes, &host.verifying_key(), &sid, 0).unwrap();
        assert_eq!((view.first_index, view.head_length, view.len()), (0, 5, 5));
        let keys = BTreeMap::from([(1u32, [3u8; 32])]);
        let segs = view.open_range(0, 100, &keys).unwrap();
        assert_eq!(segs.len(), 5);
        assert_eq!(segs[4].packets[0].0, 4);
        // A retained suffix verifies from its signed prev_root.
        let tail: Vec<_> = recs[2..].to_vec();
        let view =
            verify_state(&state_of(&tail, Some(head)), &host.verifying_key(), &sid, 0).unwrap();
        assert_eq!((view.first_index, view.len()), (2, 3));
        assert_eq!(view.open_range(0, 100, &keys).unwrap().len(), 3);
    }

    #[test]
    fn every_kind_of_tampering_is_refused() {
        let sid = "ab".repeat(32);
        let host = key();
        let vk = host.verifying_key();
        let (recs, root, params) = chain(4, &sid, &host);
        let head = sign_head(&host, &params, 4, root);
        let check = |recs: &[SegmentRecord], head: Option<ContractHead>| {
            verify_state(&state_of(recs, head), &vk, &sid, 0)
        };
        // Another key's head or record.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(
            check(&recs, Some(sign_head(&other, &params, 4, root)))
                .unwrap_err()
                .code,
            Code::EAuth
        );
        let mut forged = recs.clone();
        forged[1] = sign_segment(
            &other,
            &params,
            1,
            recs[1].prev_root,
            recs[1].record.clone(),
        );
        assert_eq!(check(&forged, Some(head)).unwrap_err().code, Code::EAuth);
        // A changed byte of a record.
        let mut flipped = recs.clone();
        flipped[2].record[20] ^= 1;
        assert_eq!(check(&flipped, Some(head)).unwrap_err().code, Code::EAuth);
        // A hole, and a head longer than the segments.
        let mut hole = recs.clone();
        hole.remove(2);
        assert_eq!(check(&hole, Some(head)).unwrap_err().code, Code::ECorrupt);
        let longer = sign_head(&host, &params, 5, root);
        assert_eq!(check(&recs, Some(longer)).unwrap_err().code, Code::ECorrupt);
        // A head whose root is not the chain's.
        let wrong = sign_head(&host, &params, 4, [9u8; 32]);
        assert_eq!(check(&recs, Some(wrong)).unwrap_err().code, Code::ECorrupt);
        // A validly signed segment from another chain in the middle.
        let (alien, _, _) = chain(4, &sid, &host);
        let mut mixed = recs.clone();
        let mut swapped = alien[2].clone();
        swapped.record[30] ^= 1;
        swapped = sign_segment(&host, &params, 2, recs[2].prev_root, swapped.record);
        mixed[2] = swapped;
        assert_eq!(check(&mixed, Some(head)).unwrap_err().code, Code::ECorrupt);
        // Another session's head.
        assert!(verify_state(&state_of(&recs, Some(head)), &vk, &"cd".repeat(32), 0).is_err());
        // A head shorter than one already seen.
        assert!(verify_state(&state_of(&recs, Some(head)), &vk, &sid, 5).is_err());
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_caught_by_the_aead_when_the_host_signs_it() {
        // The host itself can sign anything; the AEAD still refuses it.
        let sid = "ab".repeat(32);
        let host = key();
        let (mut recs, _, params) = chain(1, &sid, &host);
        recs[0].record[25] ^= 1;
        let bad = sign_segment(&host, &params, 0, ROOT_0, recs[0].record.clone());
        let root = head::chain_step(&ROOT_0, &head::record_hash(&bad.record));
        let head = sign_head(&host, &params, 1, root);
        let view = verify_state(
            &state_of(std::slice::from_ref(&bad), Some(head)),
            &host.verifying_key(),
            &sid,
            0,
        )
        .unwrap();
        let keys = BTreeMap::from([(1u32, [3u8; 32])]);
        assert_eq!(view.open(0, &keys).unwrap_err().code, Code::ECorrupt);
    }

    #[test]
    fn no_head_is_an_empty_history_and_the_start_rule_fits_the_bounds() {
        let sid = "ab".repeat(32);
        let host = key();
        let view = verify_state(
            &ContractState::default().encode(),
            &host.verifying_key(),
            &sid,
            0,
        )
        .unwrap();
        assert!(view.is_empty());
        assert_eq!(ContractState::default().encode(), br#"{"h":null,"s":[]}"#);
        assert_eq!(retained_start(&[]), 0);
        assert_eq!(retained_start(&[10; 5]), 0);
        assert_eq!(retained_start(&vec![1; MAX_SEGMENTS + 3]), 3);
        assert_eq!(retained_start(&[MAX_TOTAL_BYTES, 1]), 1);
        assert_eq!(retained_start(&[1, MAX_TOTAL_BYTES]), 1);
        assert_eq!(retained_start(&[1, MAX_TOTAL_BYTES + 1]), 2);
    }
}

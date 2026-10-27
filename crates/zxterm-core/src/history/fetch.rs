//! The viewer's half: [`RangeVerifier`] checks the segments of one range
//! request against the host's signed head before any packet is trusted.
//!
//! The first `Segment` of a request carries the
//! [`super::head::RangeProof`]: the head (signature checked against the
//! host's key and this session), and the hashes that walk the request's
//! segments to the head's chain root. Every segment is then checked, as it
//! arrives, in this order: its AEAD under the history key of its epoch
//! (`E_CORRUPT 'Encrypted data failed authentication'` for any changed
//! byte), then its hash against the proven hash of its place in the chain
//! (`E_CORRUPT` for a segment that authenticates but is not the one the
//! head signs, e.g. one re-sealed by another holder of the history key),
//! then its header against the previous segment's.

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use crate::error::{Code, Error};

use super::head::{self, SignedHead};
use super::packet::PlainPacket;
use super::segment::{self, SegmentHeader};
use super::serve::SegmentData;

/// One segment, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSegment {
    pub index: u64,
    pub header: SegmentHeader,
    /// The segment's packets with their sequence numbers.
    pub packets: Vec<(u64, PlainPacket)>,
}

/// Verifies the segments of one request, in order.
pub struct RangeVerifier {
    session_id: String,
    host_key: VerifyingKey,
    keys: BTreeMap<u32, [u8; 32]>,
    min_head_length: u64,
    state: Option<State>,
}

struct State {
    head: SignedHead,
    first_index: u64,
    hashes: Vec<[u8; 32]>,
    delivered: u64,
    prev_end: Option<u64>,
}

fn corrupt(msg: &str) -> Error {
    Error::new(Code::ECorrupt, msg.to_string())
}

impl RangeVerifier {
    /// `host_key` is the host's device signing key; `keys` the history
    /// key of each epoch the viewer holds.
    pub fn new(
        session_id: &str,
        host_key: VerifyingKey,
        keys: BTreeMap<u32, [u8; 32]>,
    ) -> RangeVerifier {
        RangeVerifier {
            session_id: session_id.to_string(),
            host_key,
            keys,
            min_head_length: 0,
            state: None,
        }
    }

    /// Refuses a head shorter than one the viewer already saw (a host, or
    /// a replay, cannot take history back).
    pub fn with_min_head_length(mut self, length: u64) -> RangeVerifier {
        self.min_head_length = length;
        self
    }

    /// The head the request's proof verified, once its first segment has.
    pub fn head(&self) -> Option<&SignedHead> {
        self.state.as_ref().map(|s| &s.head)
    }

    /// Segments verified so far.
    pub fn delivered(&self) -> u64 {
        self.state.as_ref().map_or(0, |s| s.delivered)
    }

    /// Checks one `Segment`'s `data` (a [`SegmentData`]).
    pub fn accept(&mut self, data: &[u8]) -> Result<VerifiedSegment, Error> {
        let seg = SegmentData::decode(data)?;
        if self.state.is_none() {
            let proof = seg
                .proof
                .as_ref()
                .ok_or_else(|| corrupt("First segment of a request carries no proof"))?;
            let head = proof.verify(&self.session_id, &self.host_key)?;
            if head.length < self.min_head_length {
                return Err(corrupt("History head is shorter than one already seen"));
            }
            if seg.index != proof.first_index {
                return Err(corrupt("First segment is not the proof's first"));
            }
            self.state = Some(State {
                head,
                first_index: proof.first_index,
                hashes: proof.hashes.clone(),
                delivered: 0,
                prev_end: None,
            });
        }
        let st = self.state.as_mut().expect("state");
        if seg.index != st.first_index + st.delivered {
            return Err(corrupt("Segment is out of order"));
        }
        let expected = st
            .hashes
            .get(st.delivered as usize)
            .ok_or_else(|| corrupt("More segments than the proof covers"))?;
        let epoch = SegmentHeader::decode(&seg.record)?.epoch;
        let key = self
            .keys
            .get(&epoch)
            .ok_or_else(|| Error::new(Code::ENoKey, format!("No history key for epoch {epoch}")))?;
        let signer = self.host_key.to_bytes();
        let (header, packets) = segment::open(key, &self.session_id, &signer, &seg.record)?;
        if head::record_hash(&seg.record) != *expected {
            return Err(corrupt("Segment is not the one the signed head covers"));
        }
        if st.prev_end.is_some_and(|end| end != header.first_seq) {
            return Err(corrupt("Segments are not contiguous"));
        }
        st.prev_end = Some(header.end_seq());
        st.delivered += 1;
        let packets = packets
            .into_iter()
            .enumerate()
            .map(|(k, p)| (header.first_seq + k as u64, p))
            .collect();
        Ok(VerifiedSegment {
            index: seg.index,
            header,
            packets,
        })
    }

    /// `Done {next}` arrived: every planned segment must have been
    /// delivered, and `next` must be where the last one ended.
    pub fn finish(&self, next: u64, start: u64) -> Result<(), Error> {
        match &self.state {
            None if next == start => Ok(()),
            None => Err(corrupt("Done names segments that were never served")),
            Some(st) if st.delivered != st.hashes.len() as u64 => {
                Err(corrupt("Request ended before every segment was served"))
            }
            Some(st) if st.prev_end != Some(next) => {
                Err(corrupt("Done does not follow the last segment"))
            }
            Some(_) => Ok(()),
        }
    }
}

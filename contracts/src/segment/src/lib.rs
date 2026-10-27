//! zxterm's offline-history contract, v1 (design §4.5; docs/projects/260928_zxterm-core/, K16,
//! `X-26`). One instance per shared session: it holds the session's sealed history segments and the
//! host's signed head, so a viewer with `READ_HISTORY` can read the history with the host offline.
//!
//! THIS CODE IS MEANT NEVER TO CHANGE. The instance key is the hash of this code and the
//! parameters, so any edit here, in Cargo.toml or Cargo.lock, or a toolchain change that moves the
//! bytes, moves every instance's key. A fix is a new contract next to this one, never an edit of it.
//!
//! Parameters: JSON `{"host":hex,"session":str}`; `host` is the session's host device Ed25519
//! public key (the key that signs `zxterm_core::history`'s head and is bound into every segment's
//! associated data). Other fields are ignored but still change the instance. Only `host` writes.
//!
//! State: a set of write-once segment records and the host's latest head.
//!
//!   segment `{i:u32, p:hex32, c:base64, g:hex64}`: `i` the segment's index in the session's chain,
//!   `p` the chain root before it (`root_i`, `zxterm_core::history::head`), `c` the sealed record
//!   (`zxterm_core::history::segment`, header included: the AEAD ciphertext the history key opens),
//!   `g` the host's signature over
//!
//!   ```text
//!   "zxterm/segment/1" ‖ u8(1) ‖ lp(params) ‖ u32le(i) ‖ p ‖ lp(c)
//!   ```
//!
//!   head `{n:u64, r:hex32, g:hex64}`: `n` segments in the chain, `r` the chain root `root_n`, `g`
//!   the host's signature over
//!
//!   ```text
//!   "zxterm/segment/1" ‖ u8(2) ‖ lp(params) ‖ u64le(n) ‖ r
//!   ```
//!
//! with `lp(x) = u32le(len(x)) ‖ x` and `params` the raw parameter bytes. The tag byte keeps a
//! segment's signed bytes from ever being a head's. Nothing signed names the instance id: a
//! contract never learns its own code hash (as `signalling-v1` notes), the parameters bind a
//! record to one session just as well. The contract does not hash: it cannot check that `p`, `c`
//! and the head agree. The viewer walks the chain itself (`p` of the first retained segment, then
//! `blake3(c)` of each) and compares it with `r`; every value it walks is host-signed.
//!
//! Merge: segments are the union by index, and an index is WRITE-ONCE: a record for an index that
//! already holds different bytes is REFUSED (the whole update fails), it is not merged and no
//! writer wins. The head is last-writer-wins by `(n, r, g)`, the higher tuple, so the merge is a
//! total order and needs no clock. Unsigned and mis-signed records are refused in `validate_state`
//! and in every merge. (freenet-stdlib 0.10.0 has no `validate_delta`: a delta is checked where it
//! is merged.)
//!
//! Bounds (`X-26`): a record's `c` is 1..=`MAX_SEGMENT_BYTES` bytes, a state holds at most
//! `MAX_SEGMENTS` records and `MAX_TOTAL_BYTES` bytes of `c`. `MAX_SEGMENTS` is set by the node's
//! compute limit, not by storage: `validate_state` checks one signature per record, about 1.3 ms
//! each here, and a call of about 5 s or more is cut off (measured: 4000 records took 4.3 s, 8000
//! failed), so 512 records validate in about 0.7 s, which leaves a margin of several times (with 1024, two of
//! `fdev verify-merge`'s 352 cases ran past the 5 s budget). When a merge exceeds a count or size
//! bound the OLDEST indices go first until it fits, which keeps the result independent of merge
//! order (an evicted prefix is never held by a longer merge either: the retained set is always the
//! highest-index suffix that fits). The head is never evicted; a viewer whose first retained
//! segment is after index 0 starts its walk at that segment's signed `p`.
//!
//! Wire form (state, delta): JSON `{"h":head|null,"s":[segment,...]}` with segments sorted by
//! index and base64 (standard alphabet, padded) for `c`, so equal states have equal bytes; only
//! that canonical encoding is a valid state. Summary: `{"n":u64|null,"r":[[first,end],...]}`, the
//! head's `n` and the held indices as half-open ranges. A delta holds the segments the summary's
//! ranges lack and the head when the summary has none or a lower `n`; nothing (zero bytes) when it
//! would hold neither.
use std::collections::BTreeMap;

use ed25519_compact::{PublicKey, Signature};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

/// The signed-bytes prefix of both record kinds (design §4.9).
pub const DOMAIN: &[u8] = b"zxterm/segment/1";
const TAG_SEGMENT: u8 = 1;
const TAG_HEAD: u8 = 2;

/// Most segment records a state holds.
pub const MAX_SEGMENTS: usize = 512;
/// Most bytes of one record's sealed segment (`c`).
pub const MAX_SEGMENT_BYTES: usize = 1_048_576 + 4096;
/// Most bytes of sealed segments a state holds.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn from_hex(text: &str, out: &mut [u8]) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != out.len() * 2 {
        return false;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for (i, pair) in bytes.chunks(2).enumerate() {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => out[i] = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

const fn b64_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        table[B64[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const B64_VALUE: [u8; 256] = b64_table();

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.len() / 4;
    for (q, quad) in bytes.chunks_exact(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && q + 1 != quads) {
            return None;
        }
        let mut n = 0u32;
        for (k, &c) in quad.iter().enumerate() {
            n <<= 6;
            if k < 4 - pad {
                let v = B64_VALUE[c as usize];
                if v == 255 {
                    return None;
                }
                n |= v as u32;
            }
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

mod hexa {
    use super::{from_hex, HEX};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(N * 2);
        for b in v {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(d)?;
        let mut out = [0u8; N];
        if from_hex(&text, &mut out) {
            Ok(out)
        } else {
            Err(D::Error::custom("bad hex"))
        }
    }
}

mod b64 {
    use super::{b64_decode, b64_encode};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        b64_decode(&text).ok_or_else(|| D::Error::custom("bad base64"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SegmentRecord {
    pub i: u32,
    #[serde(with = "hexa")]
    pub p: [u8; 32],
    #[serde(with = "b64")]
    pub c: Vec<u8>,
    #[serde(with = "hexa")]
    pub g: [u8; 64],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub n: u64,
    #[serde(with = "hexa")]
    pub r: [u8; 32],
    #[serde(with = "hexa")]
    pub g: [u8; 64],
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Wire {
    #[serde(default)]
    pub h: Option<Head>,
    #[serde(default)]
    pub s: Vec<SegmentRecord>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Summary {
    #[serde(default)]
    pub n: Option<u64>,
    #[serde(default)]
    pub r: Vec<(u32, u64)>,
}

#[derive(Deserialize)]
pub struct Params {
    pub host: String,
}

/// What every check needs from the parameters, parsed once per call.
struct Ctx {
    raw: Vec<u8>,
    host: PublicKey,
}

fn bad(reason: &str) -> ContractError {
    ContractError::InvalidUpdateWithInfo {
        reason: reason.into(),
    }
}

fn context(parameters: &Parameters<'_>) -> Result<Ctx, ContractError> {
    let params: Params = serde_json::from_slice(parameters.as_ref())
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    let mut key = [0u8; 32];
    if !from_hex(&params.host, &mut key) {
        return Err(bad("bad host key"));
    }
    Ok(Ctx {
        raw: parameters.as_ref().to_vec(),
        host: PublicKey::new(key),
    })
}

fn parse(bytes: &[u8]) -> Result<Wire, ContractError> {
    if bytes.is_empty() {
        return Ok(Wire::default());
    }
    serde_json::from_slice(bytes).map_err(|e| ContractError::Deser(e.to_string()))
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes the host signs for a segment record.
pub fn segment_bytes(params: &[u8], rec: &SegmentRecord) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + params.len() + rec.c.len() + 64);
    m.extend_from_slice(DOMAIN);
    m.push(TAG_SEGMENT);
    lp(&mut m, params);
    m.extend_from_slice(&rec.i.to_le_bytes());
    m.extend_from_slice(&rec.p);
    lp(&mut m, &rec.c);
    m
}

/// The bytes the host signs for a head.
pub fn head_bytes(params: &[u8], head: &Head) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + params.len() + 48);
    m.extend_from_slice(DOMAIN);
    m.push(TAG_HEAD);
    lp(&mut m, params);
    m.extend_from_slice(&head.n.to_le_bytes());
    m.extend_from_slice(&head.r);
    m
}

fn check_segment(ctx: &Ctx, rec: &SegmentRecord) -> Result<(), ContractError> {
    if rec.c.is_empty() || rec.c.len() > MAX_SEGMENT_BYTES {
        return Err(bad("bad segment size"));
    }
    ctx.host
        .verify(segment_bytes(&ctx.raw, rec), &Signature::new(rec.g))
        .map_err(|_| bad("bad segment signature"))
}

fn check_head(ctx: &Ctx, head: &Head) -> Result<(), ContractError> {
    ctx.host
        .verify(head_bytes(&ctx.raw, head), &Signature::new(head.g))
        .map_err(|_| bad("bad head signature"))
}

#[derive(Default)]
struct Model {
    head: Option<Head>,
    segs: BTreeMap<u32, SegmentRecord>,
}

fn head_higher(new: &Head, cur: &Head) -> bool {
    (new.n, new.r, new.g) > (cur.n, cur.r, cur.g)
}

/// Adds checked records. A record already present byte for byte was checked when it came in; an
/// index that holds other bytes is a forged or confused overwrite and fails the whole update.
fn absorb(ctx: &Ctx, model: &mut Model, wire: Wire) -> Result<(), ContractError> {
    for rec in wire.s {
        match model.segs.get(&rec.i) {
            Some(cur) if *cur == rec => {}
            Some(_) => return Err(bad("segment index already holds other bytes")),
            None => {
                check_segment(ctx, &rec)?;
                model.segs.insert(rec.i, rec);
            }
        }
    }
    if let Some(head) = wire.h {
        if model.head.as_ref() != Some(&head) {
            check_head(ctx, &head)?;
            if model
                .head
                .as_ref()
                .map_or(true, |cur| head_higher(&head, cur))
            {
                model.head = Some(head);
            }
        }
    }
    Ok(())
}

/// The current state, taken as stored: the node only stores states `validate_state` accepted (a
/// PUT) or an earlier `update_state` produced, so an update re-verifies nothing already held and
/// checks only the incoming records (`X-26`: verifying is about 1.3 ms a record in the node's
/// WASM runtime, and the node's compute limit is about 5 s per call, which is what
/// `MAX_SEGMENTS` is sized against). An index held twice with other bytes is still refused.
fn load(wire: Wire) -> Result<Model, ContractError> {
    let mut model = Model::default();
    for rec in wire.s {
        match model.segs.get(&rec.i) {
            Some(cur) if *cur == rec => {}
            Some(_) => return Err(bad("segment index already holds other bytes")),
            None => {
                model.segs.insert(rec.i, rec);
            }
        }
    }
    model.head = wire.h;
    Ok(model)
}

fn total_bytes(model: &Model) -> usize {
    model.segs.values().map(|r| r.c.len()).sum()
}

/// Drops the lowest indices until the count and size bounds hold.
fn evict(model: &mut Model) {
    let mut total = total_bytes(model);
    while model.segs.len() > MAX_SEGMENTS || total > MAX_TOTAL_BYTES {
        match model.segs.pop_first() {
            Some((_, rec)) => total -= rec.c.len(),
            None => break,
        }
    }
}

fn encode(model: Model) -> Result<Vec<u8>, ContractError> {
    let wire = Wire {
        h: model.head,
        s: model.segs.into_values().collect(),
    };
    serde_json::to_vec(&wire).map_err(|e| ContractError::Deser(e.to_string()))
}

pub struct Segment;

#[contract]
impl ContractInterface for Segment {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let ctx = match context(&parameters) {
            Ok(ctx) => ctx,
            Err(_) => return Ok(ValidateResult::Invalid),
        };
        let wire = match parse(state.as_ref()) {
            Ok(w) => w,
            Err(_) => return Ok(ValidateResult::Invalid),
        };
        if wire.s.len() > MAX_SEGMENTS {
            return Ok(ValidateResult::Invalid);
        }
        let mut model = Model::default();
        if absorb(&ctx, &mut model, wire).is_err() || total_bytes(&model) > MAX_TOTAL_BYTES {
            return Ok(ValidateResult::Invalid);
        }
        // Only the canonical form is valid (sorted, deduplicated, within the bounds): the node
        // stores PUT bytes without running update_state, so a non-canonical state would be
        // rewritten by the first merge and `fdev verify-merge` reports state_idempotence.
        match encode(model) {
            Ok(bytes) if bytes.as_slice() == state.as_ref() => Ok(ValidateResult::Valid),
            _ => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let ctx = context(&parameters)?;
        let mut model = load(parse(state.as_ref())?)?;
        for update in data {
            match update {
                UpdateData::State(s) => absorb(&ctx, &mut model, parse(s.as_ref())?)?,
                UpdateData::Delta(d) => absorb(&ctx, &mut model, parse(d.as_ref())?)?,
                UpdateData::StateAndDelta { state, delta } => {
                    absorb(&ctx, &mut model, parse(state.as_ref())?)?;
                    absorb(&ctx, &mut model, parse(delta.as_ref())?)?;
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        evict(&mut model);
        Ok(UpdateModification::valid(State::from(encode(model)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let wire = parse(state.as_ref())?;
        let mut ranges: Vec<(u32, u64)> = Vec::new();
        for rec in &wire.s {
            match ranges.last_mut() {
                Some((_, end)) if *end == rec.i as u64 => *end += 1,
                _ => ranges.push((rec.i, rec.i as u64 + 1)),
            }
        }
        let summary = Summary {
            n: wire.h.as_ref().map(|h| h.n),
            r: ranges,
        };
        let bytes =
            serde_json::to_vec(&summary).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let wire = parse(state.as_ref())?;
        let known: Summary = if summary.as_ref().is_empty() {
            Summary::default()
        } else {
            serde_json::from_slice(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        let held = |i: u32| {
            known
                .r
                .iter()
                .any(|&(a, b)| (a as u64) <= i as u64 && (i as u64) < b)
        };
        let s: Vec<SegmentRecord> = wire.s.into_iter().filter(|r| !held(r.i)).collect();
        let h = wire.h.filter(|h| known.n.map_or(true, |n| h.n > n));
        if s.is_empty() && h.is_none() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let bytes =
            serde_json::to_vec(&Wire { h, s }).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateDelta::from(bytes))
    }
}

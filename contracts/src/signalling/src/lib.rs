//! ZBTerm's signalling mailbox contract, v1 (design: docs/projects/260918_backend-abstraction/
//! freenet-backend-design.md §5, §6, §7; grown from the P-5 probe in
//! spikes/freenet/contracts/signalling/). One instance per share link.
//!
//! State: a last-writer-wins map keyed by (linkId, role, seq). Each entry carries the writer's
//! timestamp `t` (ms). A tombstone is an entry with `d: true` and an empty payload.
//!
//! Every entry is signed. `r` is `v:<key hex>` for a viewer's entry, signed by that key, or
//! `h:<key hex>` for the host's entry addressed to that viewer, signed by `params.host`. The
//! signed bytes are
//!
//!   "zbterm/fnet-signal/1" ‖ lp(params) ‖ lp(l) ‖ lp(r) ‖ u32le(s) ‖ u64le(t) ‖ u8(d) ‖ lp(p)
//!
//! where `lp(x)` is `u32le(len(x)) ‖ x` and `params` are this instance's raw parameter bytes.
//! The design's `sig` (the instance id) cannot be used: a contract never learns its own code
//! hash. The parameters carry the per-link nonce `n`, so they bind an entry to one instance just
//! as well. Unsigned and mis-signed entries are refused in `validate_state` and in every merge.
//! (freenet-stdlib 0.10.0 has no `validate_delta`: a delta is checked where it is merged.)
//!
//! Bounds (design §7): at most 16 live entries per `v:` key; `v:` entries share 448 of the
//! 512-entry cap and `h:` entries have the other 64 to themselves, so viewer spam cannot evict
//! an answer; payloads up to 16 KiB. Whenever a bound is exceeded, the oldest entries of that
//! group go first (by `t`, then key), which keeps the result independent of merge order.
//!
//! TTL without a clock: the contract never calls `time::now()`, because a wall-clock read inside
//! merge breaks order-independence. The TTL is a contract PARAMETER (`ttl_ms`), an entry expires
//! at `t + ttl_ms`, and the "clock" is the highest `t` in the merged state. Because expiry is
//! monotone in `t`, the LWW winner for a key always expires last, which makes purge-after-merge
//! commutative, associative and idempotent.
//!
//! Wire form (state, delta): JSON `{"e":[{"l":str,"r":str,"s":u32,"t":u64,"d":bool,"p":str,
//! "g":hex}]}` with entries sorted by key, so equal maps have equal bytes; only that canonical
//! encoding is a valid state. Parameters: JSON `{"ttl_ms":u64,"host":hex,"n":str}`.
//! Summary: `[[l,r,s,t],...]`.
use std::collections::BTreeMap;

use ed25519_compact::{PublicKey, Signature};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

const MAX_ENTRIES: usize = 512;
const HOST_SHARE: usize = 64;
const VIEWER_SHARE: usize = MAX_ENTRIES - HOST_SHARE;
const PER_VIEWER_KEY: usize = 16;
const MAX_PAYLOAD: usize = 16 * 1024;
const MAX_LINK_ID: usize = 128;
const DEFAULT_TTL_MS: u64 = 120_000;
const DOMAIN: &[u8] = b"zbterm/fnet-signal/1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub l: String,
    pub r: String,
    pub s: u32,
    pub t: u64,
    #[serde(default)]
    pub d: bool,
    #[serde(default)]
    pub p: String,
    pub g: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Wire {
    #[serde(default)]
    pub e: Vec<Entry>,
}

#[derive(Deserialize, Default)]
pub struct Params {
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
}

type Key = (String, String, u32);
type Map = BTreeMap<Key, Entry>;

/// What every check needs from the parameters, parsed once per call.
struct Ctx {
    raw: Vec<u8>,
    ttl_ms: u64,
    host: Option<PublicKey>,
}

fn bad(reason: &str) -> ContractError {
    ContractError::InvalidUpdateWithInfo { reason: reason.into() }
}

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

fn public_key(text: &str) -> Option<PublicKey> {
    let mut bytes = [0u8; 32];
    if from_hex(text, &mut bytes) {
        Some(PublicKey::new(bytes))
    } else {
        None
    }
}

fn context(parameters: &Parameters<'_>) -> Result<Ctx, ContractError> {
    let raw: &[u8] = parameters.as_ref();
    let params: Params = if raw.is_empty() {
        Params::default()
    } else {
        serde_json::from_slice(raw).map_err(|e| ContractError::Deser(e.to_string()))?
    };
    let host = match params.host {
        Some(hex) => Some(public_key(&hex).ok_or_else(|| bad("bad host key"))?),
        None => None,
    };
    Ok(Ctx { raw: raw.to_vec(), ttl_ms: params.ttl_ms.unwrap_or(DEFAULT_TTL_MS), host })
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

/// The bytes `g` signs.
fn signed_bytes(ctx: &Ctx, e: &Entry) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + ctx.raw.len() + e.l.len() + e.r.len() + e.p.len() + 40);
    m.extend_from_slice(DOMAIN);
    lp(&mut m, &ctx.raw);
    lp(&mut m, e.l.as_bytes());
    lp(&mut m, e.r.as_bytes());
    m.extend_from_slice(&e.s.to_le_bytes());
    m.extend_from_slice(&e.t.to_le_bytes());
    m.push(e.d as u8);
    lp(&mut m, e.p.as_bytes());
    m
}

/// The key that must have signed `e`: the viewer's own for `v:`, the host's for `h:`. Both
/// prefixes name a viewer key, which must be well-formed either way.
fn signer(ctx: &Ctx, r: &str) -> Option<PublicKey> {
    let named = public_key(r.get(2..)?)?;
    match r.get(..2)? {
        "v:" => Some(named),
        "h:" => ctx.host,
        _ => None,
    }
}

fn check(ctx: &Ctx, e: &Entry) -> Result<(), ContractError> {
    if e.l.is_empty() || e.l.len() > MAX_LINK_ID {
        return Err(bad("bad link id"));
    }
    if e.p.len() > MAX_PAYLOAD || (e.d && !e.p.is_empty()) {
        return Err(bad("bad payload"));
    }
    let key = signer(ctx, &e.r).ok_or_else(|| bad("bad role"))?;
    let mut g = [0u8; 64];
    if !from_hex(&e.g, &mut g) {
        return Err(bad("unsigned entry"));
    }
    key.verify(signed_bytes(ctx, e), &Signature::new(g))
        .map_err(|_| bad("bad signature"))
}

/// Total order on two entries for one key: later `t` wins, then tombstone, then payload bytes,
/// then signature bytes.
fn wins(a: &Entry, b: &Entry) -> bool {
    (a.t, a.d, a.p.as_bytes(), a.g.as_bytes()) > (b.t, b.d, b.p.as_bytes(), b.g.as_bytes())
}

/// Adds checked entries; an entry already present byte for byte was checked when it came in.
fn absorb(ctx: &Ctx, map: &mut Map, entries: Vec<Entry>) -> Result<(), ContractError> {
    for e in entries {
        let k = (e.l.clone(), e.r.clone(), e.s);
        match map.get(&k) {
            Some(cur) if *cur == e => {}
            Some(cur) if !wins(&e, cur) => check(ctx, &e)?,
            _ => {
                check(ctx, &e)?;
                map.insert(k, e);
            }
        }
    }
    Ok(())
}

/// Keeps the newest `limit` of the entries `pick` selects (by `t`, then key).
fn keep_newest(map: &mut Map, limit: usize, pick: impl Fn(&Key) -> bool) {
    let mut group: Vec<(u64, Key)> =
        map.iter().filter(|(k, _)| pick(k)).map(|(k, e)| (e.t, k.clone())).collect();
    if group.len() <= limit {
        return;
    }
    group.sort();
    let excess = group.len() - limit;
    for (_, k) in group.into_iter().take(excess) {
        map.remove(&k);
    }
}

fn purge(map: &mut Map, ttl_ms: u64) {
    let high = map.values().map(|e| e.t).max().unwrap_or(0);
    map.retain(|_, e| e.t.saturating_add(ttl_ms) >= high);
    let mut viewers: Vec<String> =
        map.keys().filter(|k| k.1.starts_with("v:")).map(|k| k.1.clone()).collect();
    viewers.sort();
    viewers.dedup();
    for r in viewers {
        keep_newest(map, PER_VIEWER_KEY, |k| k.1 == r);
    }
    keep_newest(map, VIEWER_SHARE, |k| k.1.starts_with("v:"));
    keep_newest(map, HOST_SHARE, |k| k.1.starts_with("h:"));
}

fn encode(map: Map) -> Result<Vec<u8>, ContractError> {
    let wire = Wire { e: map.into_values().collect() };
    serde_json::to_vec(&wire).map_err(|e| ContractError::Deser(e.to_string()))
}

pub struct Signalling;

#[contract]
impl ContractInterface for Signalling {
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
        if wire.e.len() > MAX_ENTRIES {
            return Ok(ValidateResult::Invalid);
        }
        // Only the canonical form is valid (sorted, deduplicated, purged, within quota). The
        // node stores PUT bytes without running update_state, so a non-canonical state would be
        // rewritten by the first merge and `fdev verify-merge` reports state_idempotence.
        let mut map = Map::new();
        if absorb(&ctx, &mut map, wire.e).is_err() {
            return Ok(ValidateResult::Invalid);
        }
        purge(&mut map, ctx.ttl_ms);
        match encode(map) {
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
        let mut map = Map::new();
        absorb(&ctx, &mut map, parse(state.as_ref())?.e)?;
        for update in data {
            match update {
                UpdateData::State(s) => absorb(&ctx, &mut map, parse(s.as_ref())?.e)?,
                UpdateData::Delta(d) => absorb(&ctx, &mut map, parse(d.as_ref())?.e)?,
                UpdateData::StateAndDelta { state, delta } => {
                    absorb(&ctx, &mut map, parse(state.as_ref())?.e)?;
                    absorb(&ctx, &mut map, parse(delta.as_ref())?.e)?;
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        purge(&mut map, ctx.ttl_ms);
        Ok(UpdateModification::valid(State::from(encode(map)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let wire = parse(state.as_ref())?;
        let summary: Vec<(String, String, u32, u64)> =
            wire.e.into_iter().map(|e| (e.l, e.r, e.s, e.t)).collect();
        let bytes = serde_json::to_vec(&summary).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let wire = parse(state.as_ref())?;
        let known: Vec<(String, String, u32, u64)> = if summary.as_ref().is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?
        };
        let known: BTreeMap<Key, u64> =
            known.into_iter().map(|(l, r, s, t)| ((l, r, s), t)).collect();
        let mut out = Map::new();
        for e in wire.e {
            let k = (e.l.clone(), e.r.clone(), e.s);
            if known.get(&k).map_or(true, |t| *t < e.t) {
                out.insert(k, e);
            }
        }
        if out.is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        Ok(StateDelta::from(encode(out)?))
    }
}

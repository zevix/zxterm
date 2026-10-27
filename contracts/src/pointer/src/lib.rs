//! ZBTerm's pointer record contract, v1 (design: docs/projects/260918_backend-abstraction/
//! freenet-backend-design.md §5.2).
//!
//! THIS CODE IS MEANT NEVER TO CHANGE. The pointer's contract key is what an invite's `ptr`
//! names; any edit here, in Cargo.toml or Cargo.lock, or a toolchain change that moves the
//! bytes, moves every pointer's key and strands the invites that carry it. A fix is a new
//! contract next to this one, never an edit of it. Keep it tiny.
//!
//! State: nothing (zero bytes) or one record naming the signalling contract instance a viewer
//! should use: JSON `{"ver":u64,"sig":str,"code":hex,"params":str,"g":hex}`, where `sig` is the
//! instance id (base58), `code` the hex BLAKE3 of its raw WASM, `params` its parameter bytes as
//! text, and `g` an ed25519 signature by `params.host` of this contract's parameters over
//!
//!   "zbterm/fnet-pointer/1" ‖ lp(own params) ‖ u64le(ver) ‖ lp(sig) ‖ lp(code) ‖ lp(params)
//!
//! with `lp(x) = u32le(len(x)) ‖ x`. The highest valid `ver` wins; equal `ver`s are ordered by
//! `g`, so the merge is a total order and needs no clock. Unsigned and mis-signed records are
//! refused in `validate_state` and in every merge. The record's contents are not interpreted:
//! the viewer re-checks them (design §5.1).
//!
//! Parameters: JSON `{"host":hex}`; other fields are ignored (they still change the instance).
//! Summary: `[ver,g]`, or nothing for an empty state.
use ed25519_compact::{PublicKey, Signature};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"zbterm/fnet-pointer/1";
const MAX_SIG: usize = 64;
const MAX_PARAMS: usize = 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub ver: u64,
    pub sig: String,
    pub code: String,
    pub params: String,
    pub g: String,
}

#[derive(Deserialize)]
pub struct Params {
    pub host: String,
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

fn host(parameters: &Parameters<'_>) -> Result<PublicKey, ContractError> {
    let params: Params = serde_json::from_slice(parameters.as_ref())
        .map_err(|e| ContractError::Deser(e.to_string()))?;
    let mut key = [0u8; 32];
    if !from_hex(&params.host, &mut key) {
        return Err(bad("bad host key"));
    }
    Ok(PublicKey::new(key))
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn check(parameters: &Parameters<'_>, key: &PublicKey, rec: &Record) -> Result<(), ContractError> {
    let mut code = [0u8; 32];
    if rec.sig.is_empty() || rec.sig.len() > MAX_SIG || rec.params.len() > MAX_PARAMS {
        return Err(bad("bad record"));
    }
    if !from_hex(&rec.code, &mut code) {
        return Err(bad("bad code hash"));
    }
    let mut g = [0u8; 64];
    if !from_hex(&rec.g, &mut g) {
        return Err(bad("unsigned record"));
    }
    let mut m = Vec::with_capacity(DOMAIN.len() + 128 + rec.params.len());
    m.extend_from_slice(DOMAIN);
    lp(&mut m, parameters.as_ref());
    m.extend_from_slice(&rec.ver.to_le_bytes());
    lp(&mut m, rec.sig.as_bytes());
    lp(&mut m, rec.code.as_bytes());
    lp(&mut m, rec.params.as_bytes());
    key.verify(m, &Signature::new(g)).map_err(|_| bad("bad signature"))
}

fn parse(bytes: &[u8]) -> Result<Option<Record>, ContractError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(bytes).map(Some).map_err(|e| ContractError::Deser(e.to_string()))
}

fn encode(rec: &Option<Record>) -> Result<Vec<u8>, ContractError> {
    match rec {
        None => Ok(Vec::new()),
        Some(rec) => serde_json::to_vec(rec).map_err(|e| ContractError::Deser(e.to_string())),
    }
}

/// Keeps the higher of `best` and a checked `rec`, by `(ver, g)`.
fn absorb(
    parameters: &Parameters<'_>,
    key: &PublicKey,
    best: &mut Option<Record>,
    rec: Option<Record>,
) -> Result<(), ContractError> {
    let rec = match rec {
        Some(rec) => rec,
        None => return Ok(()),
    };
    if best.as_ref() == Some(&rec) {
        return Ok(());
    }
    check(parameters, key, &rec)?;
    let higher = match best {
        Some(cur) => (rec.ver, rec.g.as_bytes()) > (cur.ver, cur.g.as_bytes()),
        None => true,
    };
    if higher {
        *best = Some(rec);
    }
    Ok(())
}

pub struct Pointer;

#[contract]
impl ContractInterface for Pointer {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let key = match host(&parameters) {
            Ok(key) => key,
            Err(_) => return Ok(ValidateResult::Invalid),
        };
        let rec = match parse(state.as_ref()) {
            Ok(rec) => rec,
            Err(_) => return Ok(ValidateResult::Invalid),
        };
        let mut best = None;
        if absorb(&parameters, &key, &mut best, rec).is_err() {
            return Ok(ValidateResult::Invalid);
        }
        // Only the canonical encoding is valid, so a PUT stores what a merge would.
        match encode(&best) {
            Ok(bytes) if bytes.as_slice() == state.as_ref() => Ok(ValidateResult::Valid),
            _ => Ok(ValidateResult::Invalid),
        }
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let key = host(&parameters)?;
        let mut best = None;
        absorb(&parameters, &key, &mut best, parse(state.as_ref())?)?;
        for update in data {
            match update {
                UpdateData::State(s) => absorb(&parameters, &key, &mut best, parse(s.as_ref())?)?,
                UpdateData::Delta(d) => absorb(&parameters, &key, &mut best, parse(d.as_ref())?)?,
                UpdateData::StateAndDelta { state, delta } => {
                    absorb(&parameters, &key, &mut best, parse(state.as_ref())?)?;
                    absorb(&parameters, &key, &mut best, parse(delta.as_ref())?)?;
                }
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        Ok(UpdateModification::valid(State::from(encode(&best)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let bytes = match parse(state.as_ref())? {
            None => Vec::new(),
            Some(rec) => serde_json::to_vec(&(rec.ver, rec.g))
                .map_err(|e| ContractError::Deser(e.to_string()))?,
        };
        Ok(StateSummary::from(bytes))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let rec = match parse(state.as_ref())? {
            None => return Ok(StateDelta::from(Vec::new())),
            Some(rec) => rec,
        };
        let newer = if summary.as_ref().is_empty() {
            true
        } else {
            let (ver, g): (u64, String) = serde_json::from_slice(summary.as_ref())
                .map_err(|e| ContractError::Deser(e.to_string()))?;
            (rec.ver, rec.g.as_bytes()) > (ver, g.as_bytes())
        };
        if !newer {
            return Ok(StateDelta::from(Vec::new()));
        }
        Ok(StateDelta::from(encode(&Some(rec))?))
    }
}

//! The v2 session messages (`protocol.md` §7): one `postcard` enum per
//! channel, [`CtlMsg`] on `zxterm/ctl`, [`LiveMsg`] on `zxterm/live` and
//! [`HistoryMsg`] on `zxterm/history`, with the shared [`SealedFrame`] live
//! header and [`SealedInput`], the sealed plaintext of [`CtlMsg::Input`]
//! (§10).
//!
//! **Variant order and field order are the wire, and they are
//! append-only** (§7): a new variant goes last, an existing one is never
//! reordered, and a new field needs a new route protocol version `pv`.
//! `tests/session_golden.rs` pins one instance of every variant with the
//! golden bytes in `tests/session-golden/*.bin`.
//!
//! A value that does not decode, or leaves bytes over, is a protocol error
//! ([`decode`] answers `E_CORRUPT`); the receiver closes the peer's
//! channels and does not guess.

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error};
use crate::identity::claim::Claim;

/// A 32-byte key (`protocol.md` §7's `Key32`).
pub type Key32 = [u8; 32];

/// `[u8; 64]` as 64 raw bytes (serde implements arrays up to 32 only).
mod bytes64 {
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(64)?;
        for b in v {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(64, V)
    }
}

/// `Vec<u8>` as serde bytes: postcard writes a byte string exactly as it
/// writes a sequence of `u8` (varint length, then the bytes), so the wire
/// is unchanged, but a debug build no longer serialises it element by
/// element (the golden fixtures pin the bytes).
mod bytes {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// `engine/share-manager.js::JOIN_REASONS`, verbatim and in declaration
/// order (`protocol.md` §1); the discriminant is the index. The seam and
/// the UI keep the string values ([`JoinReason::as_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JoinReason {
    Denied,
    Revoked,
    Consumed,
    Full,
    Ended,
    BadProof,
    DeviceRevoked,
    Identity,
    Unreachable,
    NoAnswer,
    Closed,
    HostMismatch,
}

impl JoinReason {
    /// All twelve, in `JOIN_REASONS` order.
    pub const ALL: [JoinReason; 12] = [
        JoinReason::Denied,
        JoinReason::Revoked,
        JoinReason::Consumed,
        JoinReason::Full,
        JoinReason::Ended,
        JoinReason::BadProof,
        JoinReason::DeviceRevoked,
        JoinReason::Identity,
        JoinReason::Unreachable,
        JoinReason::NoAnswer,
        JoinReason::Closed,
        JoinReason::HostMismatch,
    ];

    /// The `JOIN_REASONS` string value.
    pub const fn as_str(self) -> &'static str {
        match self {
            JoinReason::Denied => "denied",
            JoinReason::Revoked => "revoked",
            JoinReason::Consumed => "consumed",
            JoinReason::Full => "full",
            JoinReason::Ended => "ended",
            JoinReason::BadProof => "bad-identity-proof",
            JoinReason::DeviceRevoked => "device-revoked",
            JoinReason::Identity => "identity",
            JoinReason::Unreachable => "unreachable",
            JoinReason::NoAnswer => "no-answer",
            JoinReason::Closed => "closed",
            JoinReason::HostMismatch => "host-mismatch",
        }
    }

    /// Parses a `JOIN_REASONS` string value.
    pub fn parse(s: &str) -> Option<JoinReason> {
        JoinReason::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// `engine/errors.js::CODES` in declaration order, as it travels in
/// [`CtlMsg::Error`] (the variant index is the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    ENet,
    EAuth,
    ENoKey,
    ECorrupt,
    EHostUnreachable,
    EBackendUnsupported,
    EBackendUnavailable,
    EInternal,
}

impl From<Code> for ErrorCode {
    fn from(c: Code) -> Self {
        match c {
            Code::ENet => ErrorCode::ENet,
            Code::EAuth => ErrorCode::EAuth,
            Code::ENoKey => ErrorCode::ENoKey,
            Code::ECorrupt => ErrorCode::ECorrupt,
            Code::EHostUnreachable => ErrorCode::EHostUnreachable,
            Code::EBackendUnsupported => ErrorCode::EBackendUnsupported,
            Code::EBackendUnavailable => ErrorCode::EBackendUnavailable,
            Code::EInternal => ErrorCode::EInternal,
        }
    }
}

impl From<ErrorCode> for Code {
    fn from(c: ErrorCode) -> Self {
        match c {
            ErrorCode::ENet => Code::ENet,
            ErrorCode::EAuth => Code::EAuth,
            ErrorCode::ENoKey => Code::ENoKey,
            ErrorCode::ECorrupt => Code::ECorrupt,
            ErrorCode::EHostUnreachable => Code::EHostUnreachable,
            ErrorCode::EBackendUnsupported => Code::EBackendUnsupported,
            ErrorCode::EBackendUnavailable => Code::EBackendUnavailable,
            ErrorCode::EInternal => Code::EInternal,
        }
    }
}

/// The challenged party (`protocol.md` §9); signed as `'viewer'`/`'host'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Viewer,
    Host,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Host => "host",
        }
    }
}

/// A session's input mode (`'host'`/`'all'`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputMode {
    Host,
    All,
}

impl InputMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            InputMode::Host => "host",
            InputMode::All => "all",
        }
    }

    pub fn parse(s: &str) -> Option<InputMode> {
        match s {
            "host" => Some(InputMode::Host),
            "all" => Some(InputMode::All),
            _ => None,
        }
    }
}

/// `schema.js::SessionInfo` minus `version` (`protocol.md` §7).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    pub created_at: u64,
    pub sensitive: bool,
    pub quick_catchup_kb: u32,
    pub cols: u32,
    pub rows: u32,
}

/// A session's exit (`end.exit`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Exit {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

/// `zxterm_core::identity::claim::Claim` on the wire: its nine fields, in
/// that struct's declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WireClaim {
    pub provider: Option<String>,
    pub subject: Option<String>,
    pub identity_key: Option<String>,
    pub auth_key: Option<String>,
    pub ssh_fingerprint: Option<String>,
    pub issued_at: Option<i64>,
    pub nonce: Option<String>,
    pub signature: Option<String>,
    pub ssh_public_key: Option<String>,
}

impl From<&Claim> for WireClaim {
    fn from(c: &Claim) -> Self {
        WireClaim {
            provider: c.provider.clone(),
            subject: c.subject.clone(),
            identity_key: c.identity_key.clone(),
            auth_key: c.auth_key.clone(),
            ssh_fingerprint: c.ssh_fingerprint.clone(),
            issued_at: c.issued_at,
            nonce: c.nonce.clone(),
            signature: c.signature.clone(),
            ssh_public_key: c.ssh_public_key.clone(),
        }
    }
}

impl From<&WireClaim> for Claim {
    fn from(c: &WireClaim) -> Self {
        Claim {
            provider: c.provider.clone(),
            subject: c.subject.clone(),
            identity_key: c.identity_key.clone(),
            auth_key: c.auth_key.clone(),
            ssh_fingerprint: c.ssh_fingerprint.clone(),
            issued_at: c.issued_at,
            nonce: c.nonce.clone(),
            signature: c.signature.clone(),
            ssh_public_key: c.ssh_public_key.clone(),
        }
    }
}

/// Channel `zxterm/ctl <linkIdHex>` (`protocol.md` §6.2 rows 1–5, 11–14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtlMsg {
    /// 0, viewer → host. Today's `join-request`.
    JoinRequest {
        link_id: [u8; 16],
        device_key: Key32,
        identity_key: Key32,
        #[serde(with = "bytes")]
        identity_proof: Vec<u8>,
        device_name: String,
        identity_claim: Option<WireClaim>,
        auth_key: Option<Key32>,
        app_version: String,
    },
    /// 1, either direction. Today's `identity-challenge`.
    IdentityChallenge {
        challenge_id: String,
        nonce: String,
        session_id: String,
        role: Role,
    },
    /// 2, either direction. Today's `identity-response`.
    IdentityResponse {
        challenge_id: String,
        #[serde(with = "bytes64")]
        signature: [u8; 64],
    },
    /// 3, host → viewer. Today's `approval-pending`.
    ApprovalPending,
    /// 4, host → viewer. Today's `confirm`, minus `bootstrap`.
    Confirm {
        session_id: String,
        info: SessionInfo,
        input_mode: InputMode,
        log_key: Key32,
        meta_key: Key32,
        host_device_key: Key32,
        #[serde(with = "bytes")]
        envelope: Vec<u8>,
        host_identity_claim: Option<WireClaim>,
        host_auth_key: Option<Key32>,
    },
    /// 5, viewer → host. Today's `input`: `crypto_box_seal(postcard(
    /// SealedInput), host_device_key)`.
    Input {
        #[serde(with = "bytes")]
        sealed: Vec<u8>,
    },
    /// 6, host → viewer. Today's `end`.
    End {
        session_id: String,
        exit: Option<Exit>,
    },
    /// 7, host → viewer. Today's `info` (a partial update).
    Info {
        session_id: String,
        name: Option<String>,
        input_mode: Option<InputMode>,
    },
    /// 8, host → viewer. Today's `error`.
    Error {
        code: ErrorCode,
        message: String,
        reason: Option<JoinReason>,
    },
}

/// The common live-frame header (`protocol.md` §7): today's
/// `_encryptLiveMessage` `{epoch, seq, deviceKey, data}` with raw
/// ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedFrame {
    pub epoch: u32,
    pub seq: u64,
    pub device_key: Key32,
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
}

/// Channel `zxterm/live <linkIdHex>`, host → viewer only (`protocol.md`
/// §6.2 rows 6–10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveMsg {
    /// Variant 0, today's `data`; plaintext: raw PTY bytes.
    Data { frame: SealedFrame, hd: bool },
    /// Variant 1, today's `bootstrap`; plaintext: the caller's JSON, opaque.
    Bootstrap { frame: SealedFrame },
    /// Variant 2, today's `snapshot`; plaintext: the caller's JSON, opaque.
    Snapshot { frame: SealedFrame },
    /// Variant 3, today's `timeline`; plaintext: the caller's JSON, opaque.
    Timeline { frame: SealedFrame },
    /// Variant 4, today's `rekey`: an Envelope (`protocol.md` §3.2) sealed to the
    /// recipient's device key.
    Rekey {
        epoch: u32,
        #[serde(with = "bytes")]
        envelope: Vec<u8>,
    },
}

/// Channel `zxterm/history <linkIdHex>` (`protocol.md` §5, new in v2). K13
/// fixes the request/credit half; the bytes of a [`HistoryMsg::Segment`]
/// are K15's `crate::history::serve::SegmentData` (opaque here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryMsg {
    /// 0, viewer → host: the log range `[start, end)` wanted, with an
    /// initial credit of `credit` segments.
    RangeRequest {
        request_id: u32,
        start: u64,
        end: u64,
        credit: u32,
    },
    /// 1, viewer → host: `credit` more segments may be sent for the
    /// request.
    Credit { request_id: u32, credit: u32 },
    /// 2, host → viewer: one segment (`crate::history::serve::SegmentData`,
    /// K15), costs one credit.
    Segment {
        request_id: u32,
        start: u64,
        #[serde(with = "bytes")]
        data: Vec<u8>,
    },
    /// 3, host → viewer: the request is finished; `next` is the first
    /// sequence number not served (`start` when nothing was).
    Done { request_id: u32, next: u64 },
}

/// The sealed plaintext of [`CtlMsg::Input`] (`protocol.md` §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedInput {
    pub session_id: String,
    pub epoch: u32,
    pub input_ctr: u64,
    pub device_key: Key32,
    pub identity_key: Key32,
    #[serde(with = "bytes")]
    pub identity_proof: Vec<u8>,
    #[serde(with = "bytes")]
    pub data: Vec<u8>,
}

/// `postcard` bytes of `value`.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("session messages always serialize")
}

/// Decodes one whole message; `E_CORRUPT` for bytes that do not decode or
/// that leave bytes over.
pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((value, [])) => Ok(value),
        Ok(_) => Err(Error::with_details(
            Code::ECorrupt,
            "Session message is malformed",
            "trailing bytes",
        )),
        Err(e) => Err(Error::with_details(
            Code::ECorrupt,
            "Session message is malformed",
            e.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_reasons_are_verbatim_and_ordered() {
        let values: Vec<&str> = JoinReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            values,
            [
                "denied",
                "revoked",
                "consumed",
                "full",
                "ended",
                "bad-identity-proof",
                "device-revoked",
                "identity",
                "unreachable",
                "no-answer",
                "closed",
                "host-mismatch"
            ]
        );
        for (i, r) in JoinReason::ALL.iter().enumerate() {
            assert_eq!(encode(r), vec![i as u8]);
            assert_eq!(JoinReason::parse(r.as_str()), Some(*r));
        }
    }

    #[test]
    fn error_codes_follow_errors_js_order() {
        for (i, c) in Code::ALL.iter().enumerate() {
            let w = ErrorCode::from(*c);
            assert_eq!(encode(&w), vec![i as u8]);
            assert_eq!(Code::from(w), *c);
        }
    }

    #[test]
    fn a_signature_is_64_raw_bytes() {
        let msg = CtlMsg::IdentityResponse {
            challenge_id: "ab".into(),
            signature: [7; 64],
        };
        let bytes = encode(&msg);
        // variant 2, string len 2, "ab", then 64 raw bytes.
        assert_eq!(bytes.len(), 1 + 1 + 2 + 64);
        assert_eq!(decode::<CtlMsg>(&bytes).unwrap(), msg);
    }

    /// The `bytes` fields keep postcard's `Vec<u8>` wire: a length varint,
    /// then the bytes.
    #[test]
    fn byte_fields_encode_as_a_plain_u8_sequence() {
        #[derive(Serialize)]
        struct Plain {
            a: Vec<u8>,
        }
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let msg = CtlMsg::Input {
            sealed: data.clone(),
        };
        let mut want = vec![5u8];
        want.extend(postcard::to_allocvec(&Plain { a: data }).unwrap());
        assert_eq!(encode(&msg), want);
        assert_eq!(decode::<CtlMsg>(&want).unwrap(), msg);
    }

    #[test]
    fn trailing_bytes_and_garbage_are_ecorrupt() {
        let mut bytes = encode(&CtlMsg::ApprovalPending);
        bytes.push(0);
        assert_eq!(decode::<CtlMsg>(&bytes).unwrap_err().code, Code::ECorrupt);
        assert_eq!(decode::<CtlMsg>(&[200]).unwrap_err().code, Code::ECorrupt);
    }
}

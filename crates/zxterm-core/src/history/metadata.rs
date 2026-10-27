//! The signed metadata record (design §4.5): the session's epochs, the
//! sealed epoch envelopes (**omitted for a sensitive session**,
//! ARCHITECTURE §10.3, the same rule as `crate::session`'s `Epoch` events),
//! its members and its links, `postcard`-encoded and signed by the host's
//! device key. Stored beside the segment file as `metadata.zxm`.
//!
//! Encoded (`SignedMetadata::encode`): `u32le(body length) ‖ body ‖ 64-byte
//! signature`. The signature is Ed25519 over
//! `HISTORY_META_CONTEXT ‖ body`.
//!
//! A sensitive session never gets envelope material into a record:
//! [`MetadataBody::new`] empties `envelopes` whenever `info.sensitive`, and
//! [`SignedMetadata::sign`] and [`SignedMetadata::verify`] refuse a body
//! that holds any (a hand-built body cannot smuggle one in).

use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Code, Error};
use crate::wire;

/// The record body's format version.
pub const METADATA_VERSION: u32 = 1;

/// One epoch: its number and the first log sequence number it covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochEntry {
    pub epoch: u32,
    pub first_seq: u64,
}

/// An epoch envelope sealed to one member device (`Epoch` event's
/// `envelopes`/`history`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeEntry {
    pub epoch: u32,
    pub device_key: [u8; 32],
    pub sealed: Vec<u8>,
}

/// A member record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    pub identity_key: [u8; 32],
    pub device_key: [u8; 32],
    pub device_name: String,
    pub caps: u8,
    pub link_id: [u8; 16],
    pub revoked: bool,
}

/// A link record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkEntry {
    pub link_id: [u8; 16],
    /// `true` for a group link.
    pub group: bool,
    pub max_viewers: u32,
    pub auto_join: bool,
    pub caps: Option<u8>,
    pub revoked: bool,
}

/// `SessionInfo`'s fields that describe the session (no key material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoEntry {
    pub name: String,
    pub created_at: u64,
    pub sensitive: bool,
    pub cols: u32,
    pub rows: u32,
}

/// The record's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataBody {
    pub version: u32,
    pub session_id: String,
    pub info: InfoEntry,
    pub epochs: Vec<EpochEntry>,
    pub envelopes: Vec<EnvelopeEntry>,
    pub members: Vec<MemberEntry>,
    pub links: Vec<LinkEntry>,
}

impl MetadataBody {
    /// A body; `envelopes` are dropped when `info.sensitive`.
    pub fn new(
        session_id: &str,
        info: InfoEntry,
        epochs: Vec<EpochEntry>,
        envelopes: Vec<EnvelopeEntry>,
        members: Vec<MemberEntry>,
        links: Vec<LinkEntry>,
    ) -> MetadataBody {
        let envelopes = if info.sensitive {
            Vec::new()
        } else {
            envelopes
        };
        MetadataBody {
            version: METADATA_VERSION,
            session_id: session_id.to_string(),
            info,
            epochs,
            envelopes,
            members,
            links,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.info.sensitive && !self.envelopes.is_empty() {
            return Err(Error::new(
                Code::ECorrupt,
                "A sensitive session's metadata carries no envelopes",
            ));
        }
        if self.version != METADATA_VERSION {
            return Err(Error::new(Code::ECorrupt, "Unknown metadata version"));
        }
        Ok(())
    }
}

/// A body and the host's signature over its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMetadata {
    pub body_bytes: Vec<u8>,
    pub signature: [u8; 64],
}

fn message(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(wire::HISTORY_META_CONTEXT.len() + body.len());
    m.extend_from_slice(wire::HISTORY_META_CONTEXT.as_bytes());
    m.extend_from_slice(body);
    m
}

impl SignedMetadata {
    /// Signs `body` (refused when a sensitive body holds envelopes).
    pub fn sign(body: &MetadataBody, key: &SigningKey) -> Result<SignedMetadata, Error> {
        body.check()?;
        let body_bytes = postcard::to_allocvec(body)
            .map_err(|e| Error::new(Code::EInternal, format!("metadata: {e}")))?;
        let signature = key.sign(&message(&body_bytes)).to_bytes();
        Ok(SignedMetadata {
            body_bytes,
            signature,
        })
    }

    /// The body, when the host's key signed it.
    pub fn verify(&self, key: &VerifyingKey) -> Result<MetadataBody, Error> {
        key.verify_strict(
            &message(&self.body_bytes),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::new(Code::EAuth, "Metadata signature is invalid"))?;
        let body: MetadataBody = postcard::from_bytes(&self.body_bytes)
            .map_err(|_| Error::new(Code::ECorrupt, "Metadata is malformed"))?;
        body.check()?;
        Ok(body)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + self.body_bytes.len() + 64);
        b.extend_from_slice(&(self.body_bytes.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.body_bytes);
        b.extend_from_slice(&self.signature);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedMetadata, Error> {
        let bad = || Error::new(Code::ECorrupt, "Metadata record is malformed");
        let len =
            u32::from_le_bytes(bytes.get(..4).ok_or_else(bad)?.try_into().expect("4")) as usize;
        if bytes.len() != 4 + len + 64 {
            return Err(bad());
        }
        Ok(SignedMetadata {
            body_bytes: bytes[4..4 + len].to_vec(),
            signature: bytes[4 + len..].try_into().expect("64 bytes"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(sensitive: bool) -> MetadataBody {
        MetadataBody::new(
            &"ab".repeat(32),
            InfoEntry {
                name: "demo".into(),
                created_at: 5,
                sensitive,
                cols: 80,
                rows: 24,
            },
            vec![
                EpochEntry {
                    epoch: 1,
                    first_seq: 0,
                },
                EpochEntry {
                    epoch: 2,
                    first_seq: 40,
                },
            ],
            vec![EnvelopeEntry {
                epoch: 1,
                device_key: [3; 32],
                sealed: b"sealed-envelope-bytes-0123456789".to_vec(),
            }],
            vec![MemberEntry {
                identity_key: [1; 32],
                device_key: [3; 32],
                device_name: "laptop".into(),
                caps: 3,
                link_id: [9; 16],
                revoked: false,
            }],
            vec![LinkEntry {
                link_id: [9; 16],
                group: true,
                max_viewers: 99,
                auto_join: false,
                caps: Some(3),
                revoked: false,
            }],
        )
    }

    #[test]
    fn a_record_round_trips_and_only_the_host_key_verifies_it() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let signed = SignedMetadata::sign(&body(false), &k).unwrap();
        let back = SignedMetadata::decode(&signed.encode()).unwrap();
        assert_eq!(back.verify(&k.verifying_key()).unwrap(), body(false));
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert_eq!(back.verify(&other).unwrap_err().code, Code::EAuth);
        let mut bad = signed.clone();
        bad.body_bytes[10] ^= 1;
        assert!(bad.verify(&k.verifying_key()).is_err());
    }

    #[test]
    fn a_sensitive_session_records_no_envelope() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let needle = b"sealed-envelope-bytes-0123456789";
        let contains = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        let plain = SignedMetadata::sign(&body(false), &k).unwrap();
        assert!(contains(&plain.encode()), "control: a normal record has it");
        let sensitive = body(true);
        assert!(sensitive.envelopes.is_empty());
        let signed = SignedMetadata::sign(&sensitive, &k).unwrap();
        assert!(!contains(&signed.encode()));
        // A hand-built sensitive body with an envelope is refused both ways.
        let mut forged = body(false);
        forged.info.sensitive = true;
        assert_eq!(
            SignedMetadata::sign(&forged, &k).unwrap_err().code,
            Code::ECorrupt
        );
        let body_bytes = postcard::to_allocvec(&forged).unwrap();
        let signature = k.sign(&message(&body_bytes)).to_bytes();
        let smuggled = SignedMetadata {
            body_bytes,
            signature,
        };
        assert_eq!(
            smuggled.verify(&k.verifying_key()).unwrap_err().code,
            Code::ECorrupt
        );
    }
}

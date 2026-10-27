//! The Freenet session protocol v2 (stage C2, design §4.4; K13): the one
//! implementation of `docs/projects/260928_zxterm-core/protocol.md` (K12,
//! `X-21`), which is the source of truth for every wire shape, constant and
//! rule here.
//!
//! - [`messages`]: the per-channel `postcard` enums ([`messages::CtlMsg`],
//!   [`messages::LiveMsg`], [`messages::HistoryMsg`]) and
//!   [`messages::SealedInput`] (§7, §10).
//! - [`caps`]: `engine/caps.js`'s bits (§2).
//! - [`envelope`]: the compact-encoding key envelope and the sealed box
//!   (§3.2).
//! - [`epoch`]: epoch keys, the `crypto_kdf` derivation and rotation (§3.1,
//!   §4).
//! - [`packet`]: the live-frame AEAD (§3.3).
//! - [`input`]: sealed, replay-counted input (§10).
//! - [`host`]/[`viewer`]: the per-session and per-join state, with the
//!   pure rules (join checks, grant re-check, lag backoff).
//! - [`service`]: the state machines driven over a
//!   [`crate::freenet::backend::Backend`]'s connections: the three channels
//!   `zxterm/ctl`, `zxterm/live` and `zxterm/history` (binary message
//!   channels, `protocol.md` §5) on one peer connection, join/approval,
//!   the in-process identity challenge (§9), live output with lag resync
//!   (§11), input, rotation and revocation (§4, §13).
//!
//! - `crate::history` (K15): the segment file behind the `history` channel;
//!   [`service::ServiceOptions::history`] names the sources the host serves
//!   ranges from.
//!
//! The seam exposes the service as the `share.*` methods and events
//! (`crate::seam::share_methods`).
//!
//! Nothing here persists anything: envelopes and member records reach the
//! caller as [`service::SessionEvent`]s, and for a sensitive session
//! (`SessionInfo::sensitive`, ARCHITECTURE §10.3) the epoch events carry no
//! envelopes at all (`protocol.md` §13, the K13 gotcha).

pub mod caps;
pub mod envelope;
pub mod epoch;
pub mod host;
pub mod input;
pub mod messages;
pub mod packet;
pub mod service;
pub mod viewer;

pub use service::{SessionEvent, SessionService};

/// `share-manager.js::JOIN_TIMEOUT_MS`.
pub const JOIN_TIMEOUT_MS: u64 = 30 * 1000;
/// `share-manager.js::APPROVAL_TIMEOUT_MS`.
pub const APPROVAL_TIMEOUT_MS: u64 = 10 * 60 * 1000;
/// `share-manager.js::MAX_GROUP_VIEWERS`.
pub const MAX_GROUP_VIEWERS: u32 = 99;
/// `share-manager.js::LAG_RESYNC_MS`.
pub const LAG_RESYNC_MS: u64 = 500;
/// `share-manager.js::LAG_RESYNC_MAX_MS`.
pub const LAG_RESYNC_MAX_MS: u64 = 8000;
/// `share-manager.js::RESYNC_SCROLLBACK`: lines in a resync `Bootstrap`.
pub const RESYNC_SCROLLBACK: u32 = 500;
/// `share-manager.js::RESYNC_TAIL_BYTES`: the unrecorded tail cut into a
/// resync `Bootstrap`.
pub const RESYNC_TAIL_BYTES: u32 = 64 * 1024;
/// `share-manager.js::TIMELINE_SYNC_CHUNK`: timeline items per `Timeline`
/// the caller sends after a grant.
pub const TIMELINE_SYNC_CHUNK: u32 = 2048;
/// `share-manager.js::SNAPSHOT_SYNC_YIELD_EVERY`.
pub const SNAPSHOT_SYNC_YIELD_EVERY: u32 = 32;
/// `share-manager.js::SNAPSHOT_SYNC_MAX`.
pub const SNAPSHOT_SYNC_MAX: u32 = 96;
/// `identity/verify.js::IDENTITY_TIMEOUT_MS`.
pub const IDENTITY_TIMEOUT_MS: u64 = crate::identity::verify::IDENTITY_TIMEOUT_MS;
/// `share-manager.js`'s `appVersion` literal in `join-request`.
pub const APP_VERSION: &str = "1";

/// A device's session identity: its X25519 device key (envelopes and
/// sealed input are sealed to it), its identity key and the proof that
/// attests the device key under it, and optionally a signed identity claim
/// with the Ed25519 auth key that answers challenges for it.
#[derive(Clone)]
pub struct LocalIdentity {
    /// The X25519 device secret key (`crypto_box_keypair`'s secret half);
    /// the public half is derived.
    pub device_secret_key: [u8; 32],
    pub identity_key: messages::Key32,
    /// `zxterm_core::idkey` proof over the device public key.
    pub identity_proof: Vec<u8>,
    /// `process.env.USER || 'viewer'` on the viewer.
    pub device_name: String,
    /// The claim presented (`_selfIdentityClaim`); `None`: no verified
    /// identity, the peer records `unknown` and sends no challenge.
    pub claim: Option<crate::identity::claim::Claim>,
    /// The 64-byte Ed25519 auth secret key (seed ‖ public key) that signs
    /// challenges; `None`: challenges go unanswered.
    pub auth_secret_key: Option<[u8; 64]>,
}

impl LocalIdentity {
    /// The device's X25519 public key.
    pub fn device_key(&self) -> messages::Key32 {
        envelope::device_public_key(&self.device_secret_key)
    }

    /// The Ed25519 auth public key (the secret key's second half).
    pub fn auth_key(&self) -> Option<messages::Key32> {
        self.auth_secret_key
            .map(|sk| sk[32..].try_into().expect("32 bytes"))
    }
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("device_key", &hex::encode(self.device_key()))
            .field("identity_key", &hex::encode(self.identity_key))
            .field("claim", &self.claim.is_some())
            .finish_non_exhaustive()
    }
}

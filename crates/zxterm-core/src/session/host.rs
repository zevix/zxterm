//! The host's per-session state (`protocol.md` §4, §8, §11, §13): links,
//! members, peers, epochs, the replay window, and the pure rules the
//! service ([`super::service`]) applies to them: the join checks in
//! order, the grant re-check (ZBTerm `S-42`), the group-full count, and
//! the live channel's lag/resync backoff (`share-manager.js::_lagPeer`/
//! `_resyncPeer`).

use std::collections::{BTreeMap, HashMap};

use super::caps::{FULL_CAPS, normalize};
use super::epoch::{EpochState, MemberDevice};
use super::input::{ReplayWindow, VerifiedProofs};
use super::messages::{InputMode, JoinReason, Key32, SessionInfo, WireClaim};
use super::{LAG_RESYNC_MAX_MS, LAG_RESYNC_MS, LocalIdentity};
use crate::freenet::backend::{ChanHandle, ConnHandle};

/// A link's type (`'single'`/`'group'`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Single,
    Group,
}

/// What the caller registers for a link (`share.addLink`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSpec {
    pub link_id: [u8; 16],
    pub kind: LinkKind,
    /// A group link's limit; `MAX_GROUP_VIEWERS` by default.
    pub max_viewers: u32,
    pub auto_join: bool,
    /// The caps a member joining through it gets; `FULL_CAPS` when `None`
    /// (`_grantJoin`).
    pub caps: Option<u8>,
}

/// The host's link record (`link/<linkId>` in ZBTerm's meta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRecord {
    pub spec: LinkSpec,
    pub viewers: u32,
    pub consumed: bool,
    pub revoked: bool,
}

/// A member's standing (`member/<identityKeyHex>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Revoked,
}

/// A member record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub device_key: Key32,
    pub device_name: String,
    pub caps: u8,
    pub link_id: [u8; 16],
    pub status: MemberStatus,
}

/// The join request a peer made, as the host keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub link_id: [u8; 16],
    pub device_key: Key32,
    pub identity_key: Key32,
    pub identity_proof: Vec<u8>,
    pub device_name: String,
    pub identity_claim: Option<WireClaim>,
    pub auth_key: Option<Key32>,
}

/// Where a host peer is in the join (`peer.identityState`/`confirmed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Channels open, no `JoinRequest` yet.
    Open,
    /// A `JoinRequest` is being checked (identity step included).
    Requested,
    /// Waiting for the host's `approve`/`deny`.
    Pending,
    /// `Confirm` sent.
    Confirmed,
    /// Refused or disconnected; its channels are closing.
    Closed,
}

/// `share-manager.js::_lagPeer`/`_resyncPeer`'s per-peer state: whether
/// `Data` is being skipped, how many bytes were, and the backoff delay
/// (`LAG_RESYNC_MS` 500 doubling to `LAG_RESYNC_MAX_MS` 8000).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LagState {
    pub lagging: bool,
    pub skipped_bytes: u64,
    /// `peer.lagDelay`; 0 until the first lag.
    pub delay_ms: u64,
    /// Resyncs sent, and how many met back-pressure (reported by
    /// diagnostics, not gated).
    pub resyncs: u64,
    pub resyncs_backpressured: u64,
    /// The pending resync timer's token (0: none).
    pub timer: u64,
}

impl LagState {
    /// `broadcastData`'s skip: `true` (and the bytes counted) while
    /// lagging.
    pub fn skip(&mut self, bytes: usize) -> bool {
        if self.lagging {
            self.skipped_bytes += bytes as u64;
        }
        self.lagging
    }

    /// `_lagPeer`: enters lag; the delay to wait before the resync, or
    /// `None` when already lagging.
    pub fn enter(&mut self) -> Option<u64> {
        if self.lagging {
            return None;
        }
        self.lagging = true;
        self.skipped_bytes = 0;
        let current = if self.delay_ms == 0 {
            LAG_RESYNC_MS
        } else {
            self.delay_ms
        };
        self.delay_ms = LAG_RESYNC_MAX_MS.min(current);
        Some(self.delay_ms)
    }

    /// `_resyncPeer` after its `Bootstrap` went out: `ok` is the send's
    /// back-pressure signal. The delay before the next resync when this one
    /// met back-pressure too (the peer lags again, at double the delay).
    pub fn resynced(&mut self, ok: bool) -> Option<u64> {
        self.lagging = false;
        self.skipped_bytes = 0;
        self.resyncs += 1;
        if ok {
            self.delay_ms = LAG_RESYNC_MS;
            None
        } else {
            self.resyncs_backpressured += 1;
            self.delay_ms = LAG_RESYNC_MAX_MS.min(self.delay_ms * 2);
            self.enter()
        }
    }
}

/// `(connection, linkId)`: one peer of a hosted session.
pub type PeerKey = (ConnHandle, [u8; 16]);

/// A host-side peer (`_openHostChannel`'s `peer`).
#[derive(Debug)]
pub struct HostPeer {
    pub conn: ConnHandle,
    pub link_id: [u8; 16],
    pub remote_peer_key: Key32,
    /// The session it reached (set when its `ctl` opened on a known link).
    pub session_id: Option<String>,
    pub ctl: Option<ChanHandle>,
    pub live: Option<ChanHandle>,
    pub history: Option<ChanHandle>,
    pub state: PeerState,
    /// The host's handle for this join (`share.pending`'s `joinId`).
    pub join_id: String,
    pub request: Option<Request>,
    pub caps: u8,
    pub lag: LagState,
    /// The one outstanding identity challenge (`peer.identityPending`).
    pub challenge: Option<super::service::PendingChallenge>,
    pub identity_status: Option<String>,
    /// Confirmed, and its first `Bootstrap` not sent yet: `Data` is skipped
    /// (the `Bootstrap`, built later, covers it), so a viewer never gets
    /// output before its first screen (today `confirm` carried it).
    pub awaiting_bootstrap: bool,
    /// The `history` range requests being served, by request id (K15).
    pub history_requests: BTreeMap<u32, crate::history::serve::ServeRequest>,
}

/// One hosted session.
pub struct HostSession {
    pub session_id: String,
    pub info: SessionInfo,
    pub input_mode: InputMode,
    pub log_key: Key32,
    pub meta_key: Key32,
    pub local: LocalIdentity,
    pub device_key: Key32,
    pub epochs: EpochState,
    /// `share.liveSeq`: one counter for every live frame of this session.
    pub live_seq: u64,
    pub links: HashMap<[u8; 16], LinkRecord>,
    /// By identity key.
    pub members: BTreeMap<Key32, Member>,
    /// `joinId` -> the peer waiting for approval.
    pub pending: BTreeMap<String, PeerKey>,
    pub replay: ReplayWindow,
    pub verified: VerifiedProofs,
}

/// A join check's refusal: `CtlMsg::Error {E_AUTH, message, reason}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub message: &'static str,
    pub reason: JoinReason,
}

impl Refusal {
    pub const REVOKED: Refusal = Refusal {
        message: "Invite is no longer valid",
        reason: JoinReason::Revoked,
    };
    pub const CONSUMED: Refusal = Refusal {
        message: "Invite has already been used",
        reason: JoinReason::Consumed,
    };
    pub const FULL: Refusal = Refusal {
        message: "Invite is full",
        reason: JoinReason::Full,
    };
    pub const BAD_PROOF: Refusal = Refusal {
        message: "Device identity proof is invalid",
        reason: JoinReason::BadProof,
    };
    pub const DEVICE_REVOKED: Refusal = Refusal {
        message: "This device has been revoked",
        reason: JoinReason::DeviceRevoked,
    };
    pub const IDENTITY: Refusal = Refusal {
        message: "Identity verification failed",
        reason: JoinReason::Identity,
    };
    pub const DENIED: Refusal = Refusal {
        message: "Join request denied",
        reason: JoinReason::Denied,
    };
    pub const ENDED: Refusal = Refusal {
        message: "This share is no longer active",
        reason: JoinReason::Ended,
    };
}

impl HostSession {
    /// Checks 1–3 of `protocol.md` §8 (the link itself), in order.
    pub fn check_link(
        &self,
        link_id: &[u8; 16],
        confirmed_on_link: u32,
    ) -> Result<&LinkRecord, Refusal> {
        let Some(link) = self.links.get(link_id).filter(|l| !l.revoked) else {
            return Err(Refusal::REVOKED);
        };
        if link.spec.kind == LinkKind::Single && link.consumed {
            return Err(Refusal::CONSUMED);
        }
        if link.spec.kind == LinkKind::Group && confirmed_on_link >= link.spec.max_viewers {
            return Err(Refusal::FULL);
        }
        Ok(link)
    }

    /// Check 5: a revoked member (the host-account device check of
    /// `_isRevoked` has no store in the core and is ZBTerm's, K14).
    pub fn is_revoked(&self, identity_key: &Key32) -> bool {
        self.members
            .get(identity_key)
            .is_some_and(|m| m.status == MemberStatus::Revoked)
    }

    /// The grant's re-checks (`_grantJoin`), **v2**: the link is re-read and
    /// a link that is now revoked (or gone) refuses (`S-42`); then the
    /// group-full re-check. The caps the member gets.
    pub fn check_grant(&self, link_id: &[u8; 16], confirmed_on_link: u32) -> Result<u8, Refusal> {
        let Some(link) = self.links.get(link_id).filter(|l| !l.revoked) else {
            return Err(Refusal::REVOKED);
        };
        if link.spec.kind == LinkKind::Group && confirmed_on_link >= link.spec.max_viewers {
            return Err(Refusal::FULL);
        }
        Ok(link
            .spec
            .caps
            .map(|c| normalize(c as u64))
            .unwrap_or(FULL_CAPS))
    }

    /// Every active member's device (`listActiveMembers`).
    pub fn active_devices(&self) -> Vec<MemberDevice> {
        self.members
            .values()
            .filter(|m| m.status == MemberStatus::Active)
            .map(|m| MemberDevice {
                device_key: m.device_key,
                caps: m.caps,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::envelope::generate_device_key;

    fn session() -> HostSession {
        let (pk, sk) = generate_device_key();
        HostSession {
            session_id: "aa".repeat(32),
            info: SessionInfo::default(),
            input_mode: InputMode::Host,
            log_key: [0; 32],
            meta_key: [0; 32],
            local: LocalIdentity {
                device_secret_key: sk,
                identity_key: [0; 32],
                identity_proof: vec![],
                device_name: "host".into(),
                claim: None,
                auth_secret_key: None,
            },
            device_key: pk,
            epochs: EpochState::start(1),
            live_seq: 0,
            links: HashMap::new(),
            members: BTreeMap::new(),
            pending: BTreeMap::new(),
            replay: ReplayWindow::default(),
            verified: VerifiedProofs::default(),
        }
    }

    fn link(kind: LinkKind, max: u32) -> LinkRecord {
        LinkRecord {
            spec: LinkSpec {
                link_id: [1; 16],
                kind,
                max_viewers: max,
                auto_join: true,
                caps: None,
            },
            viewers: 0,
            consumed: false,
            revoked: false,
        }
    }

    #[test]
    fn link_checks_in_order() {
        let mut s = session();
        assert_eq!(s.check_link(&[1; 16], 0).unwrap_err(), Refusal::REVOKED);
        s.links.insert([1; 16], link(LinkKind::Single, 1));
        assert!(s.check_link(&[1; 16], 0).is_ok());
        s.links.get_mut(&[1; 16]).unwrap().consumed = true;
        assert_eq!(s.check_link(&[1; 16], 0).unwrap_err(), Refusal::CONSUMED);
        s.links.insert([1; 16], link(LinkKind::Group, 2));
        assert_eq!(s.check_link(&[1; 16], 2).unwrap_err(), Refusal::FULL);
        s.links.get_mut(&[1; 16]).unwrap().revoked = true;
        assert_eq!(s.check_link(&[1; 16], 0).unwrap_err(), Refusal::REVOKED);
    }

    /// ZBTerm `S-42`: a grant after `revokeLink` is refused (today it
    /// granted and wrote the link back un-revoked).
    #[test]
    fn s42_the_grant_rereads_the_link() {
        let mut s = session();
        s.links.insert([1; 16], link(LinkKind::Group, 5));
        assert_eq!(s.check_grant(&[1; 16], 0), Ok(FULL_CAPS));
        s.links.get_mut(&[1; 16]).unwrap().revoked = true;
        assert_eq!(s.check_grant(&[1; 16], 0).unwrap_err(), Refusal::REVOKED);
    }

    #[test]
    fn lag_backoff_doubles_to_the_cap_and_resets() {
        let mut lag = LagState::default();
        assert!(!lag.skip(10));
        assert_eq!(lag.enter(), Some(500));
        assert_eq!(lag.enter(), None, "already lagging");
        assert!(lag.skip(10));
        assert_eq!(lag.skipped_bytes, 10);
        let mut delays = vec![];
        for _ in 0..6 {
            delays.push(lag.resynced(false).unwrap());
        }
        assert_eq!(delays, [1000, 2000, 4000, 8000, 8000, 8000]);
        assert_eq!(lag.resynced(true), None);
        assert!(!lag.lagging);
        assert_eq!(lag.enter(), Some(500));
    }
}

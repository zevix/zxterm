//! The session service (K13): the host and viewer state machines of
//! `protocol.md` driven over one [`Backend`]'s peer connections.
//!
//! **Shape.** One [`SessionService`] per backend. A task reads the
//! backend's events ([`Backend::subscribe`]); the channels it cares about
//! are the three session channels of `protocol.md` §5, opened as binary
//! message channels ([`Backend::open_binary`]) with the 16-byte `linkId`
//! as their id: `zxterm/ctl` ([`CtlMsg`], ordered, never dropped),
//! `zxterm/live` ([`LiveMsg`]; only `Data` is ever skipped, while the peer
//! lags) and `zxterm/history` ([`HistoryMsg`]). Every other channel is left
//! to whoever else listens to the backend (the seam's `freenet.*`
//! forwarding). State sits behind one mutex that is never held across an
//! `.await`; timers and the identity verification (which may ask a
//! provider over HTTP) run on their own tasks and re-enter under the lock,
//! checking a token or the state they expect.
//!
//! **What the caller supplies.** The core never builds a terminal screen:
//! a `Bootstrap`'s plaintext is the caller's JSON (`protocol.md` §7), asked
//! for with [`SessionEvent::BootstrapNeeded`] and handed back with
//! [`SessionService::provide_bootstrap`]; `Timeline` and `Snapshot`
//! documents likewise ([`SessionService::send_live_json`]). The core
//! persists nothing: rotations reach the caller as [`SessionEvent::Epoch`]
//! (no member envelopes for a sensitive session), member input as
//! [`SessionEvent::Input`].
//!
//! **Rotation** (`protocol.md` §4, owner `Q-15`): on every join (the
//! joiner's envelope rides `Confirm`, every other confirmed peer gets a
//! `Rekey`, the `except` rule), on member revocation and on link
//! revocation when a member joined through the link. A viewer
//! disconnecting does not rotate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crypto_box::aead::OsRng;
use crypto_box::aead::rand_core::RngCore;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::caps::{READ_HISTORY, VIEW_LIVE, has_cap};
use super::envelope;
use super::epoch::EpochState;
use super::host::{
    HostPeer, HostSession, LagState, LinkKind, LinkRecord, LinkSpec, Member, MemberStatus, PeerKey,
    PeerState, Refusal, Request,
};
use super::input::{self, HostInput, InputPeer, ReplayWindow, VerifiedProofs};
use super::messages::{
    self, CtlMsg, ErrorCode, Exit, HistoryMsg, InputMode, JoinReason, Key32, LiveMsg, Role,
    SealedFrame, SessionInfo, WireClaim,
};
use super::packet;
use super::viewer::{Joined, ViewerJoin, ViewerKeys};
use super::{
    APP_VERSION, APPROVAL_TIMEOUT_MS, IDENTITY_TIMEOUT_MS, JOIN_TIMEOUT_MS, LocalIdentity,
    RESYNC_SCROLLBACK, RESYNC_TAIL_BYTES,
};
use crate::error::{Code, Error};
use crate::freenet::backend::{Backend, BackendEvent, ChanHandle, ConnHandle};
use crate::freenet::route::{self, Route};
use crate::history::MAX_REQUESTS_PER_PEER;
use crate::history::serve::{HistoryRegistry, ServeOut, ServeRequest};
use crate::identity::claim::{self, Challenge, Claim};
use crate::identity::resolver::{IdentityResolver, Resolve};
use crate::identity::store::IdentityStore;
use crate::identity::verify::{self, Outcome, Status, VerifyPeerIdentityOpts};
use crate::wire;

/// How long a refused peer's channels stay open after its `Error`, so the
/// `Error` is delivered before the close (`_denyPeer`'s `setImmediate`).
pub const DENY_CLOSE_MS: u64 = 1000;

/// An outstanding identity challenge this side issued
/// (`ctx.identityPending`).
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub challenge_id: String,
    pub challenge: Challenge,
}

/// Why an epoch was minted (`epoch/<n>.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// The first epoch of [`SessionService::host_open`].
    Open,
    Join,
    MemberRevoke,
    LinkRevoke,
}

impl RotationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            RotationReason::Open => "open",
            RotationReason::Join => "join",
            RotationReason::MemberRevoke => "member-revoke",
            RotationReason::LinkRevoke => "link-revoke",
        }
    }
}

/// The JSON documents a `live` channel carries besides PTY bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveKind {
    Bootstrap,
    Snapshot,
    Timeline,
}

impl LiveKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            LiveKind::Bootstrap => "bootstrap",
            LiveKind::Snapshot => "snapshot",
            LiveKind::Timeline => "timeline",
        }
    }
}

/// A viewer join's status (`join:changed`'s `status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinStatus {
    Connecting,
    ApprovalPending,
    /// `Confirm` applied: the caller registers the remote session (v2: the
    /// first `Bootstrap` is a separate `live` message).
    Confirmed,
    Joined,
    Syncing,
    Failed,
    Left,
}

impl JoinStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            JoinStatus::Connecting => "connecting",
            JoinStatus::ApprovalPending => "approval-pending",
            JoinStatus::Confirmed => "confirmed",
            JoinStatus::Joined => "joined",
            JoinStatus::Syncing => "syncing",
            JoinStatus::Failed => "failed",
            JoinStatus::Left => "left",
        }
    }
}

/// What `Confirm` told the viewer (for the caller's remote-session
/// registration; `envelope` is the sealed Envelope bytes to store).
#[derive(Debug, Clone)]
pub struct ConfirmInfo {
    pub session_id: String,
    pub info: SessionInfo,
    pub input_mode: InputMode,
    pub log_key: Key32,
    pub meta_key: Key32,
    pub host_device_key: Key32,
    pub envelope: Vec<u8>,
    pub epoch: u32,
    pub caps: u8,
}

/// One identity outcome (`share:peer-identity`).
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub session_id: Option<String>,
    /// The role of the peer the outcome is about.
    pub direction: Role,
    pub join_id: String,
    pub identity_key: Option<String>,
    pub device_key: Option<String>,
    pub display_id: String,
    pub provider: String,
    /// `pending`, `verified`, `unknown` or `failed`.
    pub status: String,
    pub reason: Option<String>,
}

/// `(device key, epoch, sealed history-only envelope)` of
/// `sealHistoryForMember`.
pub type HistoryEnvelopes = Vec<(Key32, u32, Vec<u8>)>;

/// Everything the service reports.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    // --- host ---
    /// A join waits for [`SessionService::approve`]/[`SessionService::deny`].
    Pending {
        session_id: String,
        join_id: String,
        link_id: [u8; 16],
        identity_key: Key32,
        device_key: Key32,
        device_name: String,
        caps: u8,
    },
    /// A pending approval went away (the peer left, or its link was
    /// revoked).
    ApprovalCancelled {
        session_id: String,
        join_id: String,
    },
    /// A join was granted and `Confirm` sent.
    Granted {
        session_id: String,
        join_id: String,
        link_id: [u8; 16],
        identity_key: Key32,
        device_key: Key32,
        caps: u8,
    },
    /// A confirmed peer is gone (no rotation, `Q-15`).
    PeerLeft {
        session_id: String,
        join_id: String,
    },
    /// An epoch was minted. `local` is the host's own envelope (sealed to
    /// its device key); `envelopes` one per member device and `history`
    /// the earlier epochs' history-key envelopes of a joiner
    /// (`sealHistoryForMember`), both empty when `persist` is `false` (a
    /// sensitive session, ARCHITECTURE §10.3).
    Epoch {
        session_id: String,
        epoch: u32,
        reason: RotationReason,
        persist: bool,
        local: Vec<u8>,
        envelopes: Vec<(Key32, Vec<u8>)>,
        history: HistoryEnvelopes,
    },
    /// The caller builds a `Bootstrap` document and hands it to
    /// [`SessionService::provide_bootstrap`]; `scrollback`/`tail_bytes`
    /// are set for a lag resync (`RESYNC_SCROLLBACK`, `RESYNC_TAIL_BYTES`).
    BootstrapNeeded {
        session_id: String,
        request_id: u64,
        scrollback: Option<u32>,
        tail_bytes: Option<u32>,
    },
    /// Input a member sent, opened and checked (for the caller's PTY).
    Input {
        session_id: String,
        join_id: String,
        data: Vec<u8>,
    },
    /// Input refused by one of `protocol.md` §10's checks (host-local,
    /// nothing is sent back).
    InputRefused {
        session_id: String,
        join_id: String,
        error: Error,
    },
    // --- both ---
    PeerIdentity(PeerIdentity),
    // --- viewer ---
    JoinChanged {
        join_id: String,
        status: JoinStatus,
        session_id: Option<String>,
        code: Option<Code>,
        reason: Option<JoinReason>,
        message: Option<String>,
        confirm: Option<Box<ConfirmInfo>>,
    },
    /// Decrypted PTY output.
    Output {
        session_id: String,
        data: Vec<u8>,
        hd: bool,
    },
    /// A decrypted `Bootstrap`/`Snapshot`/`Timeline` document.
    Live {
        session_id: String,
        kind: LiveKind,
        data: Vec<u8>,
    },
    /// An epoch envelope a `Rekey` carried (installed; for the caller's
    /// store).
    Rekey {
        session_id: String,
        epoch: u32,
        envelope: Vec<u8>,
    },
    End {
        session_id: String,
        exit: Option<Exit>,
    },
    Info {
        session_id: String,
        name: Option<String>,
        input_mode: Option<InputMode>,
    },
    /// The joined host's channels or connection closed.
    Offline {
        session_id: String,
    },
    HistorySegment {
        session_id: String,
        request_id: u32,
        start: u64,
        data: Vec<u8>,
    },
    HistoryDone {
        session_id: String,
        request_id: u32,
        next: u64,
    },
    /// Every `live` message as it arrived, before it is applied (only with
    /// [`ServiceOptions::tap_live`]; diagnostics and tests).
    LiveFrame {
        join_id: String,
        message: LiveMsg,
    },
    /// A local error that ends nothing (a live frame that did not decrypt).
    Error {
        session_id: Option<String>,
        error: Error,
    },
    Debug {
        event: String,
        details: Value,
    },
}

/// [`SessionService::new`]'s options.
#[derive(Default, Clone)]
pub struct ServiceOptions {
    /// Resolves an identity claim's provider keys (`None`: a claim that
    /// needs a resolver is `unknown`, `resolver-unreachable`).
    pub resolver: Option<Arc<IdentityResolver>>,
    /// Where identity outcomes are recorded (`verifyPeerIdentity`'s store).
    pub store: Option<IdentityStore>,
    /// Emit [`SessionEvent::LiveFrame`].
    pub tap_live: bool,
    /// Default [`IDENTITY_TIMEOUT_MS`].
    pub identity_timeout_ms: Option<u64>,
    /// The segment sources the `history` channel serves from (K15); a
    /// session without one answers every range `Done {next: start}`.
    pub history: Option<HistoryRegistry>,
}

/// [`SessionService::host_open`]'s arguments (`share.hostOpen`).
#[derive(Debug, Clone)]
pub struct HostOpen {
    /// 64 lowercase hex chars.
    pub session_id: String,
    pub info: SessionInfo,
    pub input_mode: InputMode,
    pub log_key: Key32,
    pub meta_key: Key32,
    pub local: LocalIdentity,
    /// The epoch number to mint first (1 for a new session; the stored
    /// epoch + 1 for one that already has epochs: `protocol.md` §3.3's
    /// nonce invariant, a host rotates before its first live frame).
    pub first_epoch: u32,
}

/// [`SessionService::join`]'s arguments (`share.join`).
#[derive(Debug, Clone)]
pub struct JoinSpec {
    pub route: Route,
    pub expected_peer_key: Key32,
    pub link_id: [u8; 16],
    pub local: LocalIdentity,
}

/// A hosted session's state, for diagnostics and tests.
#[derive(Debug, Clone)]
pub struct HostStatus {
    pub epoch: u32,
    pub input_mode: InputMode,
    /// `(joinId, identity key)` of every confirmed peer.
    pub confirmed: Vec<(String, Key32)>,
    pub pending: Vec<String>,
    pub members: Vec<(Key32, MemberStatus)>,
    pub links: Vec<LinkRecord>,
    pub lag: Vec<(String, LagState)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChanRole {
    Ctl,
    Live,
    History,
}

impl ChanRole {
    fn of(protocol: &str) -> Option<ChanRole> {
        match protocol {
            wire::SESSION_CTL_PROTOCOL => Some(ChanRole::Ctl),
            wire::SESSION_LIVE_PROTOCOL => Some(ChanRole::Live),
            wire::SESSION_HISTORY_PROTOCOL => Some(ChanRole::History),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum Owner {
    Host(PeerKey, ChanRole),
    Viewer(String, ChanRole),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootPurpose {
    Grant,
    Resync,
    Resize,
}

struct BootRequest {
    session_id: String,
    targets: Vec<(PeerKey, BootPurpose)>,
}

#[derive(Debug, Clone)]
enum Target {
    Host(PeerKey),
    Viewer(String),
}

#[derive(Default)]
struct State {
    hosts: HashMap<String, HostSession>,
    links: HashMap<[u8; 16], String>,
    peers: HashMap<PeerKey, HostPeer>,
    chans: HashMap<ChanHandle, Owner>,
    joins: HashMap<String, ViewerJoin>,
    boot: HashMap<u64, BootRequest>,
    next: u64,
}

impl State {
    fn token(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    fn confirmed_on_link(&self, session_id: &str, link_id: &[u8; 16]) -> u32 {
        self.peers
            .values()
            .filter(|p| {
                p.state == PeerState::Confirmed
                    && p.session_id.as_deref() == Some(session_id)
                    && p.link_id == *link_id
            })
            .count() as u32
    }

    fn peers_of(&self, session_id: &str) -> Vec<PeerKey> {
        let mut keys: Vec<PeerKey> = self
            .peers
            .iter()
            .filter(|(_, p)| p.session_id.as_deref() == Some(session_id))
            .map(|(k, _)| *k)
            .collect();
        keys.sort_unstable();
        keys
    }
}

struct Inner {
    backend: Backend,
    opts: ServiceOptions,
    events: mpsc::UnboundedSender<SessionEvent>,
    st: Mutex<State>,
}

/// The session service. Cheap to clone; every clone is the same service.
#[derive(Clone)]
pub struct SessionService {
    inner: Arc<Inner>,
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn no_session() -> Error {
    Error::new(Code::EAuth, "No active share for this session")
}

fn peer_identity_unknown(
    session_id: Option<String>,
    direction: Role,
    join_id: &str,
    identity_key: Option<String>,
    device_key: Option<String>,
) -> PeerIdentity {
    let display = crate::identity::providers::display_id_for(
        crate::identity::UNKNOWN,
        identity_key.as_deref().unwrap_or(""),
    )
    .unwrap_or_default();
    PeerIdentity {
        session_id,
        direction,
        join_id: join_id.to_string(),
        identity_key,
        device_key,
        display_id: display,
        provider: crate::identity::UNKNOWN.to_string(),
        status: "unknown".to_string(),
        reason: None,
    }
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Verified => "verified",
        Status::Unknown => "unknown",
        Status::Failed => "failed",
    }
}

impl SessionService {
    /// A service over `backend` (started or not); its events arrive on the
    /// returned receiver. Needs a Tokio runtime.
    pub fn new(
        backend: Backend,
        opts: ServiceOptions,
    ) -> (SessionService, mpsc::UnboundedReceiver<SessionEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut backend_events = backend.subscribe();
        let inner = Arc::new(Inner {
            backend,
            opts,
            events: tx,
            st: Mutex::new(State::default()),
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            while let Some(ev) = backend_events.recv().await {
                let Some(me) = weak.upgrade() else { break };
                me.on_backend(ev);
            }
        });
        (SessionService { inner }, rx)
    }

    /// The backend this service rides.
    pub fn backend(&self) -> &Backend {
        &self.inner.backend
    }

    // ------------------------------------------------------------------
    // host API
    // ------------------------------------------------------------------

    /// `share.hostOpen`: starts hosting `session_id` at a fresh epoch.
    pub fn host_open(&self, open: HostOpen) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        if st.hosts.contains_key(&open.session_id) {
            return Err(Error::new(Code::EInternal, "Session is already shared"));
        }
        let device_key = open.local.device_key();
        let epochs = EpochState::start(open.first_epoch.max(1));
        let keys = epochs.current().clone();
        let persist = !open.info.sensitive;
        let local = envelope::seal(&device_key, &keys.local_envelope(&open.session_id));
        st.hosts.insert(
            open.session_id.clone(),
            HostSession {
                session_id: open.session_id.clone(),
                info: open.info,
                input_mode: open.input_mode,
                log_key: open.log_key,
                meta_key: open.meta_key,
                local: open.local,
                device_key,
                epochs,
                live_seq: 0,
                links: HashMap::new(),
                members: Default::default(),
                pending: Default::default(),
                replay: ReplayWindow::default(),
                verified: VerifiedProofs::default(),
            },
        );
        me.emit(SessionEvent::Epoch {
            session_id: open.session_id,
            epoch: keys.number,
            reason: RotationReason::Open,
            persist,
            local,
            envelopes: Vec::new(),
            history: Vec::new(),
        });
        Ok(())
    }

    /// `share.addLink`: a link joins can arrive on (announcing its route is
    /// the backend's, `freenet.announce`).
    pub fn add_link(&self, session_id: &str, spec: LinkSpec) -> Result<(), Error> {
        let mut st = self.inner.st.lock().expect("session state");
        if let Some(other) = st.links.get(&spec.link_id)
            && other != session_id
        {
            return Err(Error::new(
                Code::EInternal,
                "Link belongs to another session",
            ));
        }
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        host.links.insert(
            spec.link_id,
            LinkRecord {
                spec: spec.clone(),
                viewers: 0,
                consumed: false,
                revoked: false,
            },
        );
        st.links.insert(spec.link_id, session_id.to_string());
        Ok(())
    }

    /// `share.approve`: grants a pending join.
    pub fn approve(&self, session_id: &str, join_id: &str) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        let key = host
            .pending
            .remove(join_id)
            .ok_or_else(|| Error::new(Code::EAuth, "Approval request is no longer pending"))?;
        me.grant(&mut st, key);
        Ok(())
    }

    /// `share.deny`: refuses a pending join (`DENIED`).
    pub fn deny(&self, session_id: &str, join_id: &str) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        let key = host
            .pending
            .remove(join_id)
            .ok_or_else(|| Error::new(Code::EAuth, "Approval request is no longer pending"))?;
        me.deny_peer(&mut st, key, &Refusal::DENIED);
        Ok(())
    }

    /// `share.revoke`: revokes a member by identity key; disconnects its
    /// peers and rotates (`'member-revoke'`). `false` when it is not an
    /// active member.
    pub fn revoke_member(&self, session_id: &str, identity_key: &Key32) -> Result<bool, Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        match host.members.get_mut(identity_key) {
            Some(m) if m.status == MemberStatus::Active => m.status = MemberStatus::Revoked,
            _ => return Ok(false),
        }
        for key in st.peers_of(session_id) {
            let matches = st.peers.get(&key).is_some_and(|p| {
                p.request
                    .as_ref()
                    .is_some_and(|r| r.identity_key == *identity_key)
                    && p.state == PeerState::Confirmed
            });
            if matches {
                me.disconnect(&mut st, key, false);
            }
        }
        me.rotate(&mut st, session_id, RotationReason::MemberRevoke, None);
        Ok(true)
    }

    /// `share.revokeLink`: marks the link revoked, withdraws it, cancels its
    /// pending approvals (**v2**, `S-42`), disconnects its confirmed peers,
    /// revokes every active member that joined through it and, if there
    /// was one, rotates (`'link-revoke'`). `false` for an unknown link.
    pub fn revoke_link(&self, session_id: &str, link_id: &[u8; 16]) -> Result<bool, Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        let Some(link) = host.links.get_mut(link_id) else {
            return Ok(false);
        };
        link.revoked = true;
        let backend = me.backend.clone();
        let link_hex = hex::encode(link_id);
        tokio::spawn(async move { backend.withdraw(&link_hex).await });
        // v2: a pending approval on the link is cancelled.
        let pending: Vec<(String, PeerKey)> = host
            .pending
            .iter()
            .filter(|(_, k)| k.1 == *link_id)
            .map(|(j, k)| (j.clone(), *k))
            .collect();
        for (join_id, key) in pending {
            if let Some(h) = st.hosts.get_mut(session_id) {
                h.pending.remove(&join_id);
            }
            me.emit(SessionEvent::ApprovalCancelled {
                session_id: session_id.to_string(),
                join_id,
            });
            me.deny_peer(&mut st, key, &Refusal::REVOKED);
        }
        for key in st.peers_of(session_id) {
            let on_link = st
                .peers
                .get(&key)
                .is_some_and(|p| p.link_id == *link_id && p.state == PeerState::Confirmed);
            if on_link {
                me.disconnect(&mut st, key, false);
            }
        }
        let host = st.hosts.get_mut(session_id).expect("checked above");
        let mut any = false;
        for m in host.members.values_mut() {
            if m.link_id == *link_id && m.status == MemberStatus::Active {
                m.status = MemberStatus::Revoked;
                any = true;
            }
        }
        if any {
            me.rotate(&mut st, session_id, RotationReason::LinkRevoke, None);
        }
        Ok(true)
    }

    /// `share.push`: PTY output to every confirmed `VIEW_LIVE` peer as
    /// `Data` (skipped while a peer lags, `protocol.md` §11).
    pub fn push(&self, session_id: &str, data: &[u8], hd: bool) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        if !st.hosts.contains_key(session_id) {
            return Err(no_session());
        }
        for key in st.peers_of(session_id) {
            let (live, skip) = {
                let p = st.peers.get_mut(&key).expect("listed");
                if p.state != PeerState::Confirmed || !has_cap(p.caps, VIEW_LIVE) {
                    continue;
                }
                let Some(live) = p.live else { continue };
                let skip = p.awaiting_bootstrap || p.lag.skip(data.len());
                (live, skip)
            };
            if skip {
                continue;
            }
            let frame = me.seal_live(&mut st, session_id, data);
            let ok = me.send_live(live, &LiveMsg::Data { frame, hd });
            if !ok {
                me.lag_peer(&mut st, key);
            }
        }
        Ok(())
    }

    /// `share.resize`: records the size and asks for a full `Bootstrap`
    /// for every confirmed `VIEW_LIVE` peer (`broadcastBootstrap`).
    pub fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        host.info.cols = cols;
        host.info.rows = rows;
        let targets: Vec<(PeerKey, BootPurpose)> = st
            .peers_of(session_id)
            .into_iter()
            .filter(|k| {
                st.peers
                    .get(k)
                    .is_some_and(|p| p.state == PeerState::Confirmed && has_cap(p.caps, VIEW_LIVE))
            })
            .map(|k| (k, BootPurpose::Resize))
            .collect();
        if !targets.is_empty() {
            me.request_bootstrap(&mut st, session_id, targets, false);
        }
        Ok(())
    }

    /// Answers a [`SessionEvent::BootstrapNeeded`]: `data` is the
    /// `Bootstrap` document's bytes.
    pub fn provide_bootstrap(
        &self,
        session_id: &str,
        request_id: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let req = match st.boot.remove(&request_id) {
            Some(r) if r.session_id == session_id => r,
            Some(r) => {
                st.boot.insert(request_id, r);
                return Err(Error::new(
                    Code::EInternal,
                    "Bootstrap request is not pending",
                ));
            }
            None => {
                return Err(Error::new(
                    Code::EInternal,
                    "Bootstrap request is not pending",
                ));
            }
        };
        for (key, purpose) in req.targets {
            let live = match st.peers.get(&key) {
                Some(p) if p.state == PeerState::Confirmed && has_cap(p.caps, VIEW_LIVE) => {
                    match p.live {
                        Some(l) => l,
                        None => continue,
                    }
                }
                _ => continue,
            };
            let frame = me.seal_live(&mut st, session_id, data);
            let ok = me.send_live(live, &LiveMsg::Bootstrap { frame });
            let p = st.peers.get_mut(&key).expect("checked");
            p.awaiting_bootstrap = false;
            if purpose == BootPurpose::Resync {
                let skipped = p.lag.skipped_bytes;
                let next = p.lag.resynced(ok);
                let join_id = p.join_id.clone();
                me.debug(
                    "host:peer:resync",
                    json!({"sessionId": session_id, "joinId": join_id, "skippedBytes": skipped,
                           "bytes": data.len(), "backpressure": !ok}),
                );
                if let Some(delay) = next {
                    // `_resyncPeer` -> `_lagPeer`: lagging again, longer.
                    me.debug(
                        "host:peer:lagging",
                        json!({"joinId": join_id, "retryMs": delay}),
                    );
                    me.schedule_resync(&mut st, key, delay);
                }
            }
        }
        Ok(())
    }

    /// `share.timeline`/`share.snapshot`: a caller-built JSON document to
    /// every confirmed `VIEW_LIVE` + `READ_HISTORY` peer, or to one join.
    pub fn send_live_json(
        &self,
        session_id: &str,
        kind: LiveKind,
        data: &[u8],
        join_id: Option<&str>,
    ) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        if !st.hosts.contains_key(session_id) {
            return Err(no_session());
        }
        for key in st.peers_of(session_id) {
            let live = match st.peers.get(&key) {
                Some(p)
                    if p.state == PeerState::Confirmed
                        && has_cap(p.caps, VIEW_LIVE)
                        && (kind == LiveKind::Bootstrap || has_cap(p.caps, READ_HISTORY))
                        && join_id.is_none_or(|j| j == p.join_id) =>
                {
                    match p.live {
                        Some(l) => l,
                        None => continue,
                    }
                }
                _ => continue,
            };
            let frame = me.seal_live(&mut st, session_id, data);
            let msg = match kind {
                LiveKind::Bootstrap => LiveMsg::Bootstrap { frame },
                LiveKind::Snapshot => LiveMsg::Snapshot { frame },
                LiveKind::Timeline => LiveMsg::Timeline { frame },
            };
            me.send_live(live, &msg);
        }
        Ok(())
    }

    /// `share.info`: updates the name or input mode and sends `Info` to
    /// every confirmed peer (`broadcastInfo`).
    pub fn set_info(
        &self,
        session_id: &str,
        name: Option<String>,
        input_mode: Option<InputMode>,
    ) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let host = st.hosts.get_mut(session_id).ok_or_else(no_session)?;
        if let Some(n) = &name {
            host.info.name = n.clone();
        }
        if let Some(m) = input_mode {
            host.input_mode = m;
        }
        me.broadcast_ctl(
            &st,
            session_id,
            &CtlMsg::Info {
                session_id: session_id.to_string(),
                name,
                input_mode,
            },
        );
        Ok(())
    }

    /// `share.end`: sends `End` to every confirmed peer (`broadcastEnd`).
    pub fn end(&self, session_id: &str, exit: Option<Exit>) -> Result<(), Error> {
        let me = &self.inner;
        let st = me.st.lock().expect("session state");
        if !st.hosts.contains_key(session_id) {
            return Err(no_session());
        }
        me.broadcast_ctl(
            &st,
            session_id,
            &CtlMsg::End {
                session_id: session_id.to_string(),
                exit,
            },
        );
        Ok(())
    }

    /// `share.hostClose`: stops hosting (peers disconnected, links
    /// forgotten; nothing rotates).
    pub fn host_close(&self, session_id: &str) -> Result<(), Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        if !st.hosts.contains_key(session_id) {
            return Err(no_session());
        }
        for key in st.peers_of(session_id) {
            me.disconnect(&mut st, key, false);
        }
        st.links.retain(|_, s| s != session_id);
        st.boot.retain(|_, r| r.session_id != session_id);
        st.hosts.remove(session_id);
        Ok(())
    }

    /// A hosted session's state.
    pub fn host_status(&self, session_id: &str) -> Option<HostStatus> {
        let st = self.inner.st.lock().expect("session state");
        let host = st.hosts.get(session_id)?;
        let mut confirmed = Vec::new();
        let mut lag = Vec::new();
        for key in st.peers_of(session_id) {
            let p = &st.peers[&key];
            if p.state == PeerState::Confirmed {
                if let Some(r) = &p.request {
                    confirmed.push((p.join_id.clone(), r.identity_key));
                }
                lag.push((p.join_id.clone(), p.lag.clone()));
            }
        }
        let mut links: Vec<LinkRecord> = host.links.values().cloned().collect();
        links.sort_by_key(|l| l.spec.link_id);
        Some(HostStatus {
            epoch: host.epochs.number(),
            input_mode: host.input_mode,
            confirmed,
            pending: host.pending.keys().cloned().collect(),
            members: host.members.iter().map(|(k, m)| (*k, m.status)).collect(),
            links,
            lag,
        })
    }

    // ------------------------------------------------------------------
    // viewer API
    // ------------------------------------------------------------------

    /// `share.join`: dials the route and joins through `link_id`. The
    /// `joinId`; progress arrives as [`SessionEvent::JoinChanged`]. A route
    /// that is not `pv: 2` is refused here, offline (rule PV-1).
    pub fn join(&self, spec: JoinSpec) -> Result<String, Error> {
        route::check_pv(spec.route.params.pv)?;
        let me = &self.inner;
        let join_id = random_hex(16);
        let handle = me.backend.dial(
            spec.route.clone(),
            spec.expected_peer_key,
            Some(json!({"linkId": hex::encode(spec.link_id)})),
        );
        let mut st = me.st.lock().expect("session state");
        let timer = st.token();
        st.joins.insert(
            join_id.clone(),
            ViewerJoin {
                join_id: join_id.clone(),
                link_id: spec.link_id,
                expected_peer_key: spec.expected_peer_key,
                device_key: spec.local.device_key(),
                local: spec.local,
                dial: handle.id,
                conn: None,
                ctl: None,
                live: None,
                history: None,
                done: false,
                confirmed: false,
                joined: false,
                timer,
                blocked: false,
                queue: Default::default(),
                held: Vec::new(),
                pending_confirm: None,
                challenge: None,
                session: None,
                keys: Default::default(),
                epoch: 0,
                input_ctr: 0,
                next_history_request: 1,
            },
        );
        me.arm_join_timer(&join_id, timer, JOIN_TIMEOUT_MS, JoinReason::Unreachable);
        me.emit(SessionEvent::JoinChanged {
            join_id: join_id.clone(),
            status: JoinStatus::Connecting,
            session_id: None,
            code: None,
            reason: None,
            message: None,
            confirm: None,
        });
        drop(st);
        let weak = Arc::downgrade(me);
        let jid = join_id.clone();
        tokio::spawn(async move {
            let res = handle.connected.await;
            let Some(me) = weak.upgrade() else { return };
            match res {
                Ok(Ok(conn)) => me.viewer_connected(&jid, conn),
                Ok(Err(e)) => me.viewer_dial_failed(&jid, e),
                Err(_) => {}
            }
        });
        Ok(join_id)
    }

    /// `share.input` (viewer): seals `data` to the host with the next
    /// counter of the current epoch and sends it.
    pub fn input(&self, session_id: &str, data: &[u8]) -> Result<u64, Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let join = st
            .joins
            .values_mut()
            .find(|j| {
                !j.done
                    && j.confirmed
                    && j.session
                        .as_ref()
                        .is_some_and(|s| s.session_id == session_id)
            })
            .ok_or_else(|| Error::new(Code::EInternal, "Remote session is not registered"))?;
        let joined = join.session.clone().expect("confirmed");
        let ctr = join.next_input_ctr();
        let sealed = input::seal(
            &joined.host_device_key,
            session_id,
            join.epoch,
            ctr,
            &join.device_key,
            &join.local.identity_key,
            &join.local.identity_proof,
            data,
        );
        let ctl = join
            .ctl
            .ok_or_else(|| Error::new(Code::EInternal, "no control channel"))?;
        me.send_ctl(ctl, &CtlMsg::Input { sealed });
        Ok(ctr)
    }

    /// Asks the host for the log range `[start, end)` on the `history`
    /// channel. The request id; answers arrive as
    /// [`SessionEvent::HistorySegment`]/[`SessionEvent::HistoryDone`].
    pub fn request_history(
        &self,
        session_id: &str,
        start: u64,
        end: u64,
        credit: u32,
    ) -> Result<u32, Error> {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        let join = st
            .joins
            .values_mut()
            .find(|j| {
                !j.done
                    && j.confirmed
                    && j.session
                        .as_ref()
                        .is_some_and(|s| s.session_id == session_id)
            })
            .ok_or_else(|| Error::new(Code::EInternal, "Remote session is not registered"))?;
        let request_id = join.next_history_request;
        join.next_history_request += 1;
        let chan = join
            .history
            .ok_or_else(|| Error::new(Code::EInternal, "no history channel"))?;
        me.backend.send_bytes(
            chan,
            &messages::encode(&HistoryMsg::RangeRequest {
                request_id,
                start,
                end,
                credit,
            }),
        );
        Ok(request_id)
    }

    /// Gives the host `credit` more segments for history request
    /// `request_id` (`HistoryMsg::Credit`).
    pub fn history_credit(
        &self,
        session_id: &str,
        request_id: u32,
        credit: u32,
    ) -> Result<(), Error> {
        let me = &self.inner;
        let st = me.st.lock().expect("session state");
        let join = st
            .joins
            .values()
            .find(|j| {
                !j.done
                    && j.confirmed
                    && j.session
                        .as_ref()
                        .is_some_and(|s| s.session_id == session_id)
            })
            .ok_or_else(|| Error::new(Code::EInternal, "Remote session is not registered"))?;
        let chan = join
            .history
            .ok_or_else(|| Error::new(Code::EInternal, "no history channel"))?;
        me.backend.send_bytes(
            chan,
            &messages::encode(&HistoryMsg::Credit { request_id, credit }),
        );
        Ok(())
    }

    /// Ends a join (`leaveJoinedSession`): `left`.
    pub fn leave(&self, join_id: &str) {
        let me = &self.inner;
        let mut st = me.st.lock().expect("session state");
        me.finish(&mut st, join_id, JoinStatus::Left, None, None, None);
    }
}

// ----------------------------------------------------------------------
// internals
// ----------------------------------------------------------------------

impl Inner {
    fn emit(&self, ev: SessionEvent) {
        let _ = self.events.send(ev);
    }

    fn debug(&self, event: &str, details: Value) {
        self.emit(SessionEvent::Debug {
            event: event.to_string(),
            details,
        });
    }

    fn send_ctl(&self, chan: ChanHandle, msg: &CtlMsg) -> bool {
        self.backend.send_bytes(chan, &messages::encode(msg))
    }

    fn send_live(&self, chan: ChanHandle, msg: &LiveMsg) -> bool {
        self.backend.send_bytes(chan, &messages::encode(msg))
    }

    fn broadcast_ctl(&self, st: &State, session_id: &str, msg: &CtlMsg) {
        for key in st.peers_of(session_id) {
            let p = &st.peers[&key];
            if p.state == PeerState::Confirmed
                && let Some(ctl) = p.ctl
            {
                self.send_ctl(ctl, msg);
            }
        }
    }

    /// `_encryptLiveMessage`: the next `seq` under the current epoch's
    /// live key.
    fn seal_live(&self, st: &mut State, session_id: &str, plain: &[u8]) -> SealedFrame {
        let host = st.hosts.get_mut(session_id).expect("hosted");
        host.live_seq += 1;
        let keys = host.epochs.current();
        SealedFrame {
            epoch: keys.number,
            seq: host.live_seq,
            device_key: host.device_key,
            ciphertext: packet::encrypt(
                &keys.live_key,
                session_id,
                keys.number,
                host.live_seq,
                &host.device_key,
                plain,
            ),
        }
    }

    fn request_bootstrap(
        &self,
        st: &mut State,
        session_id: &str,
        targets: Vec<(PeerKey, BootPurpose)>,
        resync: bool,
    ) {
        let request_id = st.token();
        st.boot.insert(
            request_id,
            BootRequest {
                session_id: session_id.to_string(),
                targets,
            },
        );
        self.emit(SessionEvent::BootstrapNeeded {
            session_id: session_id.to_string(),
            request_id,
            scrollback: resync.then_some(RESYNC_SCROLLBACK),
            tail_bytes: resync.then_some(RESYNC_TAIL_BYTES),
        });
    }

    /// `_lagPeer`.
    fn lag_peer(self: &Arc<Self>, st: &mut State, key: PeerKey) {
        let Some(p) = st.peers.get_mut(&key) else {
            return;
        };
        if let Some(delay) = p.lag.enter() {
            let join_id = p.join_id.clone();
            self.debug(
                "host:peer:lagging",
                json!({"joinId": join_id, "retryMs": delay}),
            );
            self.schedule_resync(st, key, delay);
        }
    }

    fn schedule_resync(self: &Arc<Self>, st: &mut State, key: PeerKey, delay: u64) {
        let token = st.token();
        if let Some(p) = st.peers.get_mut(&key) {
            p.lag.timer = token;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let Some(me) = weak.upgrade() else { return };
            let mut st = me.st.lock().expect("session state");
            let Some(p) = st.peers.get(&key) else { return };
            if p.lag.timer != token || !p.lag.lagging || p.state != PeerState::Confirmed {
                return;
            }
            let Some(sid) = p.session_id.clone() else {
                return;
            };
            me.request_bootstrap(&mut st, &sid, vec![(key, BootPurpose::Resync)], true);
        });
    }

    // ---------------- backend events ----------------

    fn on_backend(self: &Arc<Self>, ev: BackendEvent) {
        let mut st = self.st.lock().expect("session state");
        match ev {
            BackendEvent::IncomingChannel { conn, protocol, id } => {
                self.on_incoming(&mut st, conn, &protocol, &id)
            }
            BackendEvent::Bytes { chan, bytes } => match st.chans.get(&chan).cloned() {
                Some(Owner::Host(key, role)) => self.on_host_bytes(&mut st, key, role, &bytes),
                Some(Owner::Viewer(join_id, role)) => {
                    self.on_viewer_bytes(&mut st, &join_id, role, &bytes)
                }
                None => {}
            },
            BackendEvent::ChannelClosed { chan } => match st.chans.remove(&chan) {
                Some(Owner::Host(key, ChanRole::Ctl)) => self.disconnect(&mut st, key, false),
                Some(Owner::Host(key, role)) => {
                    if let Some(p) = st.peers.get_mut(&key) {
                        match role {
                            ChanRole::Live => p.live = None,
                            ChanRole::History => p.history = None,
                            ChanRole::Ctl => {}
                        }
                    }
                }
                Some(Owner::Viewer(join_id, ChanRole::Ctl)) => {
                    self.viewer_closed(&mut st, &join_id)
                }
                _ => {}
            },
            BackendEvent::ConnectionClosed { conn, .. } => {
                let keys: Vec<PeerKey> = st.peers.keys().filter(|k| k.0 == conn).copied().collect();
                for key in keys {
                    self.disconnect(&mut st, key, false);
                }
                let joins: Vec<String> = st
                    .joins
                    .values()
                    .filter(|j| j.conn == Some(conn))
                    .map(|j| j.join_id.clone())
                    .collect();
                for j in joins {
                    self.viewer_closed(&mut st, &j);
                }
            }
            _ => {}
        }
    }

    fn on_incoming(self: &Arc<Self>, st: &mut State, conn: ConnHandle, protocol: &str, id: &[u8]) {
        let Some(role) = ChanRole::of(protocol) else {
            return;
        };
        let Ok(link_id) = <[u8; 16]>::try_from(id) else {
            return;
        };
        if st.joins.values().any(|j| j.conn == Some(conn)) {
            return; // the viewer side opens its own channels
        }
        let Ok(chan) = self.backend.open_binary(conn, protocol, id) else {
            return;
        };
        if role != ChanRole::Ctl && !st.links.contains_key(&link_id) {
            // Only `ctl` answers an unknown link (with `ENDED`).
            self.backend.close_channel(chan);
            return;
        }
        let key = (conn, link_id);
        let remote = self
            .backend
            .connection_info(conn)
            .map(|i| i.0)
            .unwrap_or([0; 32]);
        let join_id = random_hex(16);
        let peer = st.peers.entry(key).or_insert_with(|| HostPeer {
            conn,
            link_id,
            remote_peer_key: remote,
            session_id: None,
            ctl: None,
            live: None,
            history: None,
            state: PeerState::Open,
            join_id,
            request: None,
            caps: 0,
            lag: LagState::default(),
            challenge: None,
            identity_status: None,
            awaiting_bootstrap: false,
            history_requests: Default::default(),
        });
        match role {
            ChanRole::Ctl => peer.ctl = Some(chan),
            ChanRole::Live => peer.live = Some(chan),
            ChanRole::History => peer.history = Some(chan),
        }
        st.chans.insert(chan, Owner::Host(key, role));
        if role == ChanRole::Ctl {
            match st.links.get(&link_id).cloned() {
                Some(sid) => {
                    if let Some(p) = st.peers.get_mut(&key) {
                        p.session_id = Some(sid.clone());
                    }
                    self.debug(
                        "host:ctl:open",
                        json!({"sessionId": sid, "linkId": hex::encode(link_id)}),
                    );
                }
                None => {
                    self.debug("host:unknown-link", json!({"linkId": hex::encode(link_id)}));
                    self.deny_peer(st, key, &Refusal::ENDED);
                }
            }
        }
    }

    // ---------------- host ----------------

    fn on_host_bytes(self: &Arc<Self>, st: &mut State, key: PeerKey, role: ChanRole, bytes: &[u8]) {
        match role {
            ChanRole::Ctl => {
                let msg = match messages::decode::<CtlMsg>(bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        self.debug("host:ctl:malformed", json!({"message": e.to_string()}));
                        self.disconnect(st, key, false);
                        return;
                    }
                };
                let Some(p) = st.peers.get(&key) else { return };
                let Some(sid) = p.session_id.clone() else {
                    return;
                };
                match msg {
                    CtlMsg::IdentityChallenge {
                        challenge_id,
                        nonce,
                        session_id,
                        role,
                    } => {
                        let secret = st.hosts.get(&sid).and_then(|h| h.local.auth_secret_key);
                        if let Some(ctl) = p.ctl {
                            self.answer_challenge(
                                ctl,
                                p.conn,
                                secret,
                                challenge_id,
                                nonce,
                                session_id,
                                role,
                            );
                        }
                    }
                    CtlMsg::IdentityResponse {
                        challenge_id,
                        signature,
                    } => {
                        self.settle_challenge(st, Target::Host(key), &challenge_id, Some(signature))
                    }
                    CtlMsg::JoinRequest {
                        link_id,
                        device_key,
                        identity_key,
                        identity_proof,
                        device_name,
                        identity_claim,
                        auth_key,
                        ..
                    } => self.on_join_request(
                        st,
                        key,
                        Request {
                            link_id,
                            device_key,
                            identity_key,
                            identity_proof,
                            device_name,
                            identity_claim,
                            auth_key,
                        },
                    ),
                    CtlMsg::Input { sealed } => self.on_input(st, key, &sid, &sealed),
                    _ => {}
                }
            }
            ChanRole::Live => {}
            ChanRole::History => {
                let Some(p) = st.peers.get(&key) else { return };
                if p.state != PeerState::Confirmed || !has_cap(p.caps, READ_HISTORY) {
                    return;
                }
                let Some(chan) = p.history else { return };
                match messages::decode::<HistoryMsg>(bytes) {
                    Ok(HistoryMsg::RangeRequest {
                        request_id,
                        start,
                        end,
                        credit,
                    }) => {
                        let source = self
                            .opts
                            .history
                            .as_ref()
                            .zip(p.session_id.as_deref())
                            .and_then(|(r, sid)| r.get(sid));
                        let busy = p.history_requests.len() >= MAX_REQUESTS_PER_PEER
                            || p.history_requests.contains_key(&request_id);
                        let started = match (source, busy) {
                            (Some(source), false) => {
                                ServeRequest::start(source, start, end, credit)
                                    .ok()
                                    .flatten()
                            }
                            _ => None,
                        };
                        match started {
                            Some(req) => {
                                if let Some(p) = st.peers.get_mut(&key) {
                                    p.history_requests.insert(request_id, req);
                                }
                                self.pump_history(st, key, request_id);
                            }
                            // Nothing to serve (no source, the range is in
                            // the open segment, or the peer is busy): the
                            // viewer reads the rest from `live`.
                            None => {
                                self.backend.send_bytes(
                                    chan,
                                    &messages::encode(&HistoryMsg::Done {
                                        request_id,
                                        next: start,
                                    }),
                                );
                            }
                        }
                    }
                    Ok(HistoryMsg::Credit { request_id, credit }) => {
                        if let Some(p) = st.peers.get_mut(&key)
                            && let Some(req) = p.history_requests.get_mut(&request_id)
                        {
                            req.add_credit(credit);
                            self.pump_history(st, key, request_id);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => self.disconnect(st, key, false),
                }
            }
        }
    }

    /// Sends what a history request's credit allows; a finished request is
    /// dropped. Waits (sends nothing) when the viewer has given no credit.
    fn pump_history(&self, st: &mut State, key: PeerKey, request_id: u32) {
        let Some(p) = st.peers.get_mut(&key) else {
            return;
        };
        let Some(chan) = p.history else { return };
        let Some(req) = p.history_requests.get_mut(&request_id) else {
            return;
        };
        for out in req.pump() {
            let msg = match out {
                ServeOut::Segment { start, data } => HistoryMsg::Segment {
                    request_id,
                    start,
                    data,
                },
                ServeOut::Done { next } => HistoryMsg::Done { request_id, next },
            };
            self.backend.send_bytes(chan, &messages::encode(&msg));
        }
        if req.is_finished() {
            p.history_requests.remove(&request_id);
        }
    }

    /// `_confirmJoin`: checks 0–6 of `protocol.md` §8, in order.
    fn on_join_request(self: &Arc<Self>, st: &mut State, key: PeerKey, request: Request) {
        let Some(p) = st.peers.get_mut(&key) else {
            return;
        };
        if p.state != PeerState::Open {
            self.debug("host:join-request:duplicate", json!({"joinId": p.join_id}));
            return;
        }
        p.state = PeerState::Requested;
        p.request = Some(request.clone());
        let sid = p.session_id.clone().expect("ctl on a known link");
        let join_id = p.join_id.clone();
        self.debug(
            "host:join-request",
            json!({"sessionId": sid, "joinId": join_id, "linkId": hex::encode(request.link_id),
                   "deviceKey": hex::encode(request.device_key), "deviceName": request.device_name}),
        );
        let on_link = st.confirmed_on_link(&sid, &request.link_id);
        let host = st.hosts.get_mut(&sid).expect("hosted");
        if let Err(r) = host.check_link(&request.link_id, on_link) {
            return self.deny_peer(st, key, &r);
        }
        if !host.verified.verify(
            &request.identity_proof,
            &request.identity_key,
            &request.device_key,
        ) {
            return self.deny_peer(st, key, &Refusal::BAD_PROOF);
        }
        if host.is_revoked(&request.identity_key) {
            return self.deny_peer(st, key, &Refusal::DEVICE_REVOKED);
        }
        // The identity gate (`_verifyViewerIdentity`).
        let identity_hex = hex::encode(request.identity_key);
        let device_hex = hex::encode(request.device_key);
        match &request.identity_claim {
            None => {
                let outcome = verify::verify_peer_identity(
                    &VerifyPeerIdentityOpts {
                        claim: None,
                        identity_key: Some(&identity_hex),
                        ..Default::default()
                    },
                    self.opts.store.as_ref(),
                );
                self.emit_identity(
                    Some(sid),
                    Role::Viewer,
                    &join_id,
                    Some(identity_hex),
                    Some(device_hex),
                    Some(&outcome),
                );
                self.after_identity(st, key);
            }
            Some(claim) => {
                self.emit(SessionEvent::PeerIdentity(PeerIdentity {
                    session_id: Some(sid.clone()),
                    direction: Role::Viewer,
                    join_id: join_id.clone(),
                    identity_key: Some(identity_hex),
                    device_key: Some(device_hex),
                    display_id: String::new(),
                    provider: claim
                        .provider
                        .clone()
                        .unwrap_or_else(|| crate::identity::UNKNOWN.to_string()),
                    status: "pending".to_string(),
                    reason: None,
                }));
                let p = st.peers.get_mut(&key).expect("present");
                let (ctl, conn) = (p.ctl, p.conn);
                if let Some(ctl) = ctl {
                    let pending =
                        self.issue_challenge(ctl, conn, &sid, Role::Viewer, Target::Host(key));
                    st.peers.get_mut(&key).expect("present").challenge = Some(pending);
                }
            }
        }
    }

    /// After the identity gate: approval or grant.
    fn after_identity(self: &Arc<Self>, st: &mut State, key: PeerKey) {
        let Some(p) = st.peers.get_mut(&key) else {
            return;
        };
        if p.state != PeerState::Requested {
            return;
        }
        let sid = p.session_id.clone().expect("known");
        let request = p.request.clone().expect("requested");
        let join_id = p.join_id.clone();
        let host = st.hosts.get_mut(&sid).expect("hosted");
        let Some(link) = host.links.get(&request.link_id).cloned() else {
            return self.deny_peer(st, key, &Refusal::REVOKED);
        };
        if link.spec.auto_join {
            return self.grant(st, key);
        }
        host.pending.insert(join_id.clone(), key);
        let p = st.peers.get_mut(&key).expect("present");
        p.state = PeerState::Pending;
        if let Some(ctl) = p.ctl {
            self.send_ctl(ctl, &CtlMsg::ApprovalPending);
        }
        self.emit(SessionEvent::Pending {
            session_id: sid,
            join_id,
            link_id: request.link_id,
            identity_key: request.identity_key,
            device_key: request.device_key,
            device_name: request.device_name,
            caps: link.spec.caps.unwrap_or(super::caps::FULL_CAPS),
        });
    }

    /// `_grantJoin`, **v2**: re-reads the link (`S-42`).
    fn grant(self: &Arc<Self>, st: &mut State, key: PeerKey) {
        let Some(p) = st.peers.get(&key) else { return };
        if !matches!(p.state, PeerState::Requested | PeerState::Pending) {
            return;
        }
        let sid = p.session_id.clone().expect("known");
        let request = p.request.clone().expect("requested");
        let join_id = p.join_id.clone();
        let on_link = st.confirmed_on_link(&sid, &request.link_id);
        let host = st.hosts.get_mut(&sid).expect("hosted");
        let caps = match host.check_grant(&request.link_id, on_link) {
            Ok(c) => c,
            Err(r) => return self.deny_peer(st, key, &r),
        };
        host.members.insert(
            request.identity_key,
            Member {
                device_key: request.device_key,
                device_name: request.device_name.clone(),
                caps,
                link_id: request.link_id,
                status: MemberStatus::Active,
            },
        );
        // `sealHistoryForMember`: every epoch so far, history key only.
        let history: HistoryEnvelopes = if has_cap(caps, READ_HISTORY) {
            host.epochs
                .all()
                .map(|k| {
                    (
                        request.device_key,
                        k.number,
                        envelope::seal(&request.device_key, &k.history_envelope(&sid, caps)),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        let Some(envelope) = self.rotate(
            st,
            &sid,
            RotationReason::Join,
            Some((request.device_key, history)),
        ) else {
            return;
        };
        let host = st.hosts.get_mut(&sid).expect("hosted");
        if let Some(link) = host.links.get_mut(&request.link_id) {
            link.viewers += 1;
            if link.spec.kind == LinkKind::Single {
                link.consumed = true;
            }
        }
        let confirm = CtlMsg::Confirm {
            session_id: sid.clone(),
            info: host.info.clone(),
            input_mode: host.input_mode,
            log_key: host.log_key,
            meta_key: host.meta_key,
            host_device_key: host.device_key,
            envelope,
            host_identity_claim: host.local.claim.as_ref().map(WireClaim::from),
            host_auth_key: host.local.auth_key(),
        };
        let p = st.peers.get_mut(&key).expect("present");
        p.state = PeerState::Confirmed;
        p.caps = caps;
        p.awaiting_bootstrap = has_cap(caps, VIEW_LIVE);
        if let Some(ctl) = p.ctl {
            self.send_ctl(ctl, &confirm);
        }
        self.debug(
            "host:join-confirm",
            json!({"sessionId": sid, "joinId": join_id, "linkId": hex::encode(request.link_id)}),
        );
        if has_cap(caps, VIEW_LIVE) {
            self.request_bootstrap(st, &sid, vec![(key, BootPurpose::Grant)], false);
        }
        self.emit(SessionEvent::Granted {
            session_id: sid,
            join_id,
            link_id: request.link_id,
            identity_key: request.identity_key,
            device_key: request.device_key,
            caps,
        });
    }

    /// `rotateEpoch` + `_broadcastRekey`. With `joiner`, the joiner's
    /// device is the `except` and its envelope is returned (for
    /// `Confirm`).
    fn rotate(
        self: &Arc<Self>,
        st: &mut State,
        session_id: &str,
        reason: RotationReason,
        joiner: Option<(Key32, HistoryEnvelopes)>,
    ) -> Option<Vec<u8>> {
        let host = st.hosts.get_mut(session_id)?;
        let members = host.active_devices();
        let rotation = host.epochs.rotate(session_id, &host.device_key, &members);
        let persist = !host.info.sensitive;
        let except = joiner.as_ref().map(|j| j.0);
        for key in st.peers_of(session_id) {
            let p = &st.peers[&key];
            let (Some(live), Some(r)) = (p.live, p.request.as_ref()) else {
                continue;
            };
            if p.state != PeerState::Confirmed || Some(r.device_key) == except {
                continue;
            }
            let Some(env) = rotation.envelopes.get(&r.device_key) else {
                continue;
            };
            self.send_live(
                live,
                &LiveMsg::Rekey {
                    epoch: rotation.epoch,
                    envelope: env.clone(),
                },
            );
        }
        let joiner_env = except.and_then(|d| rotation.envelopes.get(&d).cloned());
        self.emit(SessionEvent::Epoch {
            session_id: session_id.to_string(),
            epoch: rotation.epoch,
            reason,
            persist,
            local: rotation.local,
            envelopes: if persist {
                rotation.envelopes.into_iter().collect()
            } else {
                Vec::new()
            },
            history: match (persist, joiner) {
                (true, Some((_, h))) => h,
                _ => Vec::new(),
            },
        });
        joiner_env
    }

    /// `_denyPeer`: `Error` then the peer's channels close (the
    /// connection stays).
    fn deny_peer(self: &Arc<Self>, st: &mut State, key: PeerKey, r: &Refusal) {
        let Some(p) = st.peers.get(&key) else { return };
        self.debug(
            "host:join-deny",
            json!({"joinId": p.join_id, "linkId": hex::encode(key.1), "reason": r.reason.as_str()}),
        );
        if let Some(ctl) = p.ctl {
            self.send_ctl(
                ctl,
                &CtlMsg::Error {
                    code: ErrorCode::EAuth,
                    message: r.message.to_string(),
                    reason: Some(r.reason),
                },
            );
        }
        self.disconnect(st, key, true);
    }

    /// `_disconnectHostPeer` + `_cleanupHostPeer`: the peer's channels close
    /// (after [`DENY_CLOSE_MS`] when `delayed`), its pending approval is
    /// cancelled, and a session left with no confirmed peer turns input
    /// back to `'host'`. Never rotates (`Q-15`).
    fn disconnect(self: &Arc<Self>, st: &mut State, key: PeerKey, delayed: bool) {
        let Some(mut p) = st.peers.remove(&key) else {
            return;
        };
        let was = p.state;
        p.state = PeerState::Closed;
        let chans: Vec<ChanHandle> = [p.ctl, p.live, p.history].into_iter().flatten().collect();
        for c in &chans {
            st.chans.remove(c);
        }
        if delayed {
            let backend = self.backend.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(DENY_CLOSE_MS)).await;
                for c in chans {
                    backend.close_channel(c);
                }
            });
        } else {
            for c in chans {
                self.backend.close_channel(c);
            }
        }
        let Some(sid) = p.session_id.clone() else {
            return;
        };
        if let Some(host) = st.hosts.get_mut(&sid) {
            let pending: Vec<String> = host
                .pending
                .iter()
                .filter(|(_, k)| **k == key)
                .map(|(j, _)| j.clone())
                .collect();
            for j in pending {
                host.pending.remove(&j);
                self.emit(SessionEvent::ApprovalCancelled {
                    session_id: sid.clone(),
                    join_id: j,
                });
            }
        }
        self.debug(
            "host:socket:close",
            json!({"sessionId": sid, "joinId": p.join_id}),
        );
        if was == PeerState::Confirmed {
            self.emit(SessionEvent::PeerLeft {
                session_id: sid.clone(),
                join_id: p.join_id.clone(),
            });
            // `_disableInputWhenEmpty`.
            let any = st
                .peers
                .values()
                .any(|q| q.session_id.as_deref() == Some(&sid) && q.state == PeerState::Confirmed);
            if let Some(host) = st.hosts.get_mut(&sid)
                && !any
                && host.input_mode == InputMode::All
            {
                host.input_mode = InputMode::Host;
                self.debug(
                    "host:input:disabled",
                    json!({"sessionId": sid, "reason": "no-viewers"}),
                );
            }
        }
    }

    /// `_openInputMessage` (`protocol.md` §10).
    fn on_input(self: &Arc<Self>, st: &mut State, key: PeerKey, sid: &str, sealed: &[u8]) {
        let Some(host) = st.hosts.get_mut(sid) else {
            return;
        };
        let Some(p) = st.peers.get(&key) else { return };
        if host.input_mode != InputMode::All {
            self.debug(
                "host:input:dropped",
                json!({"sessionId": sid, "joinId": p.join_id, "reason": "input-mode",
                       "mode": host.input_mode.as_str()}),
            );
            return;
        }
        let empty = [0u8; 32];
        let (device, identity, proof) = match &p.request {
            Some(r) => (&r.device_key, &r.identity_key, r.identity_proof.as_slice()),
            None => (&empty, &empty, &[][..]),
        };
        let epoch = host.epochs.number();
        let res = input::open(
            &HostInput {
                session_id: sid,
                epoch,
                device_secret_key: &host.local.device_secret_key,
                verified: &host.verified,
            },
            &InputPeer {
                confirmed: p.state == PeerState::Confirmed,
                caps: p.caps,
                device_key: device,
                identity_key: identity,
                identity_proof: proof,
            },
            &mut host.replay,
            sealed,
        );
        match res {
            Ok(data) => {
                self.debug(
                    "host:input:accepted",
                    json!({"sessionId": sid, "joinId": p.join_id, "bytes": data.len()}),
                );
                self.emit(SessionEvent::Input {
                    session_id: sid.to_string(),
                    join_id: p.join_id.clone(),
                    data,
                });
            }
            Err(error) => {
                self.debug(
                    "host:input:error",
                    json!({"sessionId": sid, "joinId": p.join_id, "code": error.code.as_str(),
                           "message": error.message}),
                );
                self.emit(SessionEvent::InputRefused {
                    session_id: sid.to_string(),
                    join_id: p.join_id.clone(),
                    error,
                });
            }
        }
    }

    // ---------------- identity challenge (both roles) ----------------

    /// `_issueIdentityChallenge`: sends the challenge and arms the
    /// `IDENTITY_TIMEOUT_MS` timer; the transport keys are never sent.
    fn issue_challenge(
        self: &Arc<Self>,
        ctl: ChanHandle,
        conn: ConnHandle,
        session_id: &str,
        role: Role,
        target: Target,
    ) -> PendingChallenge {
        let challenge_id = random_hex(16);
        let nonce = random_hex(32);
        let local = self.backend.local_peer_key().map(hex::encode);
        let remote = self.backend.connection_info(conn).map(|i| hex::encode(i.0));
        let challenge = Challenge {
            session_id: Some(session_id.to_string()),
            challenge_id: Some(challenge_id.clone()),
            nonce: Some(nonce.clone()),
            verifier_dht_key: local,
            prover_dht_key: remote,
            role: Some(role.as_str().to_string()),
        };
        self.send_ctl(
            ctl,
            &CtlMsg::IdentityChallenge {
                challenge_id: challenge_id.clone(),
                nonce,
                session_id: session_id.to_string(),
                role,
            },
        );
        let weak = Arc::downgrade(self);
        let id = challenge_id.clone();
        let ms = self.opts.identity_timeout_ms.unwrap_or(IDENTITY_TIMEOUT_MS);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            let Some(me) = weak.upgrade() else { return };
            let mut st = me.st.lock().expect("session state");
            me.settle_challenge(&mut st, target, &id, None);
        });
        PendingChallenge {
            challenge_id,
            challenge,
        }
    }

    /// `_answerIdentityChallenge`: the prover mirrors the verifier's view
    /// of the transport keys; without an auth key it sends nothing.
    #[allow(clippy::too_many_arguments)]
    fn answer_challenge(
        &self,
        ctl: ChanHandle,
        conn: ConnHandle,
        secret: Option<[u8; 64]>,
        challenge_id: String,
        nonce: String,
        session_id: String,
        role: Role,
    ) {
        let Some(secret) = secret else { return };
        let challenge = Challenge {
            session_id: Some(session_id),
            challenge_id: Some(challenge_id.clone()),
            nonce: Some(nonce),
            verifier_dht_key: self.backend.connection_info(conn).map(|i| hex::encode(i.0)),
            prover_dht_key: self.backend.local_peer_key().map(hex::encode),
            role: Some(role.as_str().to_string()),
        };
        match claim::sign_challenge(&secret, &challenge) {
            Ok(signature) => {
                self.send_ctl(
                    ctl,
                    &CtlMsg::IdentityResponse {
                        challenge_id,
                        signature,
                    },
                );
            }
            Err(e) => self.debug("identity:sign-failed", json!({"message": e.message})),
        }
    }

    /// `_settleIdentityChallenge` (a response, or the timeout with `None`),
    /// then `verifyPeerIdentity` off the lock.
    fn settle_challenge(
        self: &Arc<Self>,
        st: &mut State,
        target: Target,
        challenge_id: &str,
        signature: Option<[u8; 64]>,
    ) {
        // Take the pending challenge and what the verification needs.
        let (pending, claim, identity_key, auth_key) = match &target {
            Target::Host(key) => {
                let Some(p) = st.peers.get_mut(key) else {
                    return;
                };
                if p.challenge.as_ref().map(|c| c.challenge_id.as_str()) != Some(challenge_id) {
                    return;
                }
                let r = p.request.clone().expect("requested");
                (
                    p.challenge.take().expect("checked"),
                    r.identity_claim.as_ref().map(Claim::from),
                    Some(hex::encode(r.identity_key)),
                    r.auth_key.map(hex::encode),
                )
            }
            Target::Viewer(join_id) => {
                let Some(j) = st.joins.get_mut(join_id) else {
                    return;
                };
                if j.challenge.as_ref().map(|c| c.challenge_id.as_str()) != Some(challenge_id) {
                    return;
                }
                let Some(CtlMsg::Confirm {
                    host_identity_claim,
                    host_auth_key,
                    ..
                }) = &j.pending_confirm
                else {
                    return;
                };
                let claim = host_identity_claim.as_ref().map(Claim::from);
                let identity_key = claim.as_ref().and_then(|c| c.identity_key.clone());
                (
                    j.challenge.take().expect("checked"),
                    claim,
                    identity_key,
                    host_auth_key.map(hex::encode),
                )
            }
        };
        let resolver = self.opts.resolver.clone();
        let store = self.opts.store.clone();
        let weak = Arc::downgrade(self);
        tokio::task::spawn_blocking(move || {
            let sig_hex = signature.map(hex::encode);
            let outcome = verify::verify_peer_identity(
                &VerifyPeerIdentityOpts {
                    claim: claim.as_ref(),
                    identity_key: identity_key.as_deref(),
                    auth_key: auth_key.as_deref(),
                    challenge: Some(&pending.challenge),
                    signature: sig_hex.as_deref(),
                    resolver: resolver.as_deref().map(|r| r as &dyn Resolve),
                },
                store.as_ref(),
            );
            let Some(me) = weak.upgrade() else { return };
            let mut st = me.st.lock().expect("session state");
            me.after_verify(&mut st, target, outcome);
        });
    }

    fn after_verify(self: &Arc<Self>, st: &mut State, target: Target, outcome: Outcome) {
        match target {
            Target::Host(key) => {
                let Some(p) = st.peers.get_mut(&key) else {
                    return;
                };
                if p.state != PeerState::Requested {
                    return;
                }
                p.identity_status = Some(status_str(outcome.status).to_string());
                let r = p.request.clone().expect("requested");
                let (sid, join_id) = (p.session_id.clone(), p.join_id.clone());
                self.emit_identity(
                    sid,
                    Role::Viewer,
                    &join_id,
                    Some(hex::encode(r.identity_key)),
                    Some(hex::encode(r.device_key)),
                    Some(&outcome),
                );
                if outcome.status == Status::Failed {
                    self.deny_peer(st, key, &Refusal::IDENTITY);
                } else {
                    self.after_identity(st, key);
                }
            }
            Target::Viewer(join_id) => {
                let Some(j) = st.joins.get_mut(&join_id) else {
                    return;
                };
                if j.done {
                    return;
                }
                let Some(confirm) = j.pending_confirm.take() else {
                    return;
                };
                let CtlMsg::Confirm {
                    session_id,
                    host_device_key,
                    ..
                } = &confirm
                else {
                    return;
                };
                let conn = j.conn;
                let identity_key = outcome_identity(&confirm);
                self.emit_identity(
                    Some(session_id.clone()),
                    Role::Host,
                    &join_id,
                    identity_key,
                    Some(hex::encode(host_device_key)),
                    Some(&outcome),
                );
                if outcome.status == Status::Failed {
                    self.finish(
                        st,
                        &join_id,
                        JoinStatus::Failed,
                        Some(Code::EAuth),
                        None,
                        Some("Host identity verification failed".to_string()),
                    );
                    if let Some(conn) = conn {
                        self.backend.close_connection(conn, "host-identity-failed");
                    }
                    return;
                }
                self.apply_confirm(st, &join_id, confirm);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_identity(
        &self,
        session_id: Option<String>,
        direction: Role,
        join_id: &str,
        identity_key: Option<String>,
        device_key: Option<String>,
        outcome: Option<&Outcome>,
    ) {
        let ev = match outcome {
            Some(o) => PeerIdentity {
                session_id,
                direction,
                join_id: join_id.to_string(),
                identity_key,
                device_key,
                display_id: o.display_id.clone(),
                provider: o.provider.clone(),
                status: status_str(o.status).to_string(),
                reason: o.reason.clone(),
            },
            None => peer_identity_unknown(session_id, direction, join_id, identity_key, device_key),
        };
        self.emit(SessionEvent::PeerIdentity(ev));
    }

    // ---------------- viewer ----------------

    fn arm_join_timer(self: &Arc<Self>, join_id: &str, token: u64, ms: u64, reason: JoinReason) {
        let weak = Arc::downgrade(self);
        let join_id = join_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            let Some(me) = weak.upgrade() else { return };
            let mut st = me.st.lock().expect("session state");
            let Some(j) = st.joins.get(&join_id) else {
                return;
            };
            if j.done || j.timer != token {
                return;
            }
            let message = match reason {
                JoinReason::NoAnswer => "The host did not answer the join request",
                _ => "Share host was not found or the invite is no longer valid",
            };
            me.debug(
                if reason == JoinReason::NoAnswer {
                    "viewer:approval-timeout"
                } else {
                    "viewer:join-timeout"
                },
                json!({"joinId": join_id}),
            );
            me.finish_with(
                &mut st,
                &join_id,
                JoinStatus::Failed,
                Some(Code::EAuth),
                Some(reason),
                Some(message.to_string()),
                None,
            );
        });
    }

    fn viewer_dial_failed(self: &Arc<Self>, join_id: &str, e: Error) {
        let mut st = self.st.lock().expect("session state");
        let Some(j) = st.joins.get(join_id) else {
            return;
        };
        if j.done || j.conn.is_some() {
            return;
        }
        self.debug(
            "viewer:dial-failed",
            json!({"joinId": join_id, "code": e.code.as_str(), "detail": e.details}),
        );
        self.finish_with(
            &mut st,
            join_id,
            JoinStatus::Failed,
            Some(e.code),
            Some(JoinReason::Unreachable),
            Some(e.message),
            None,
        );
    }

    /// `_handleViewerConnection`: pins the host key, opens the three
    /// channels and sends `JoinRequest`.
    fn viewer_connected(self: &Arc<Self>, join_id: &str, conn: ConnHandle) {
        let mut st = self.st.lock().expect("session state");
        let Some(j) = st.joins.get(join_id) else {
            return;
        };
        if j.done || j.conn.is_some() {
            return;
        }
        let remote = self.backend.connection_info(conn).map(|i| i.0);
        if remote != Some(j.expected_peer_key) {
            self.debug("viewer:socket:host-mismatch", json!({"joinId": join_id}));
            self.finish_with(
                &mut st,
                join_id,
                JoinStatus::Failed,
                Some(Code::EAuth),
                Some(JoinReason::HostMismatch),
                Some("Share host key did not match the invite".to_string()),
                None,
            );
            self.backend.close_connection(conn, "host-key-mismatch");
            return;
        }
        let link_id = j.link_id;
        let mut opened = Vec::new();
        for (protocol, role) in [
            (wire::SESSION_CTL_PROTOCOL, ChanRole::Ctl),
            (wire::SESSION_LIVE_PROTOCOL, ChanRole::Live),
            (wire::SESSION_HISTORY_PROTOCOL, ChanRole::History),
        ] {
            match self.backend.open_binary(conn, protocol, &link_id) {
                Ok(chan) => opened.push((chan, role)),
                Err(e) => {
                    self.finish_with(
                        &mut st,
                        join_id,
                        JoinStatus::Failed,
                        Some(e.code),
                        None,
                        Some(e.message),
                        None,
                    );
                    return;
                }
            }
        }
        let j = st.joins.get_mut(join_id).expect("present");
        j.conn = Some(conn);
        for (chan, role) in &opened {
            match role {
                ChanRole::Ctl => j.ctl = Some(*chan),
                ChanRole::Live => j.live = Some(*chan),
                ChanRole::History => j.history = Some(*chan),
            }
        }
        let request = CtlMsg::JoinRequest {
            link_id,
            device_key: j.device_key,
            identity_key: j.local.identity_key,
            identity_proof: j.local.identity_proof.clone(),
            device_name: j.local.device_name.clone(),
            identity_claim: j.local.claim.as_ref().map(WireClaim::from),
            auth_key: j.local.auth_key(),
            app_version: APP_VERSION.to_string(),
        };
        let ctl = j.ctl.expect("opened");
        for (chan, role) in opened {
            st.chans
                .insert(chan, Owner::Viewer(join_id.to_string(), role));
        }
        self.send_ctl(ctl, &request);
        self.debug("viewer:join-request:sent", json!({"joinId": join_id}));
    }

    fn on_viewer_bytes(
        self: &Arc<Self>,
        st: &mut State,
        join_id: &str,
        role: ChanRole,
        bytes: &[u8],
    ) {
        match role {
            ChanRole::Ctl => {
                let msg = match messages::decode::<CtlMsg>(bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        return self.finish_with(
                            st,
                            join_id,
                            JoinStatus::Failed,
                            Some(e.code),
                            None,
                            Some(e.message),
                            None,
                        );
                    }
                };
                let Some(j) = st.joins.get_mut(join_id) else {
                    return;
                };
                match msg {
                    // The two identity frames bypass the queue.
                    CtlMsg::IdentityChallenge {
                        challenge_id,
                        nonce,
                        session_id,
                        role,
                    } => {
                        if let (Some(ctl), Some(conn)) = (j.ctl, j.conn) {
                            let secret = j.local.auth_secret_key;
                            self.answer_challenge(
                                ctl,
                                conn,
                                secret,
                                challenge_id,
                                nonce,
                                session_id,
                                role,
                            );
                        }
                    }
                    CtlMsg::IdentityResponse {
                        challenge_id,
                        signature,
                    } => self.settle_challenge(
                        st,
                        Target::Viewer(join_id.to_string()),
                        &challenge_id,
                        Some(signature),
                    ),
                    other => {
                        j.queue.push_back(other);
                        self.drain_queue(st, join_id);
                    }
                }
            }
            ChanRole::Live => {
                let msg = match messages::decode::<LiveMsg>(bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        return self.finish_with(
                            st,
                            join_id,
                            JoinStatus::Failed,
                            Some(e.code),
                            None,
                            Some(e.message),
                            None,
                        );
                    }
                };
                if self.opts.tap_live {
                    self.emit(SessionEvent::LiveFrame {
                        join_id: join_id.to_string(),
                        message: msg.clone(),
                    });
                }
                let Some(j) = st.joins.get_mut(join_id) else {
                    return;
                };
                if !j.confirmed {
                    if !j.done {
                        j.held.push(msg);
                    }
                    return;
                }
                self.process_live(st, join_id, msg);
            }
            ChanRole::History => {
                let Some(j) = st.joins.get(join_id) else {
                    return;
                };
                let Some(sid) = j.session.as_ref().map(|s| s.session_id.clone()) else {
                    return;
                };
                match messages::decode::<HistoryMsg>(bytes) {
                    Ok(HistoryMsg::Segment {
                        request_id,
                        start,
                        data,
                    }) => self.emit(SessionEvent::HistorySegment {
                        session_id: sid,
                        request_id,
                        start,
                        data,
                    }),
                    Ok(HistoryMsg::Done { request_id, next }) => {
                        self.emit(SessionEvent::HistoryDone {
                            session_id: sid,
                            request_id,
                            next,
                        })
                    }
                    _ => {}
                }
            }
        }
    }

    fn drain_queue(self: &Arc<Self>, st: &mut State, join_id: &str) {
        loop {
            let Some(j) = st.joins.get_mut(join_id) else {
                return;
            };
            if j.blocked {
                return;
            }
            let Some(msg) = j.queue.pop_front() else {
                return;
            };
            self.handle_viewer_ctl(st, join_id, msg);
        }
    }

    /// `_handleViewerCtlMessage` (everything but the identity frames).
    fn handle_viewer_ctl(self: &Arc<Self>, st: &mut State, join_id: &str, msg: CtlMsg) {
        let Some(j) = st.joins.get_mut(join_id) else {
            return;
        };
        if j.done && !j.confirmed {
            return;
        }
        match msg {
            CtlMsg::ApprovalPending => {
                let token = st.token();
                st.joins.get_mut(join_id).expect("present").timer = token;
                self.arm_join_timer(join_id, token, APPROVAL_TIMEOUT_MS, JoinReason::NoAnswer);
                self.emit(SessionEvent::JoinChanged {
                    join_id: join_id.to_string(),
                    status: JoinStatus::ApprovalPending,
                    session_id: None,
                    code: None,
                    reason: None,
                    message: None,
                    confirm: None,
                });
            }
            CtlMsg::Confirm {
                ref session_id,
                ref host_identity_claim,
                ref host_device_key,
                ..
            } => {
                if j.confirmed || j.pending_confirm.is_some() {
                    return;
                }
                let sid = session_id.clone();
                let device_hex = hex::encode(host_device_key);
                match host_identity_claim {
                    None => {
                        self.emit(SessionEvent::PeerIdentity(peer_identity_unknown(
                            Some(sid),
                            Role::Host,
                            join_id,
                            None,
                            Some(device_hex),
                        )));
                        self.apply_confirm(st, join_id, msg);
                    }
                    Some(claim) => {
                        self.emit(SessionEvent::PeerIdentity(PeerIdentity {
                            session_id: Some(sid.clone()),
                            direction: Role::Host,
                            join_id: join_id.to_string(),
                            identity_key: claim.identity_key.clone(),
                            device_key: Some(device_hex),
                            display_id: String::new(),
                            provider: claim
                                .provider
                                .clone()
                                .unwrap_or_else(|| crate::identity::UNKNOWN.to_string()),
                            status: "pending".to_string(),
                            reason: None,
                        }));
                        let (Some(ctl), Some(conn)) = (j.ctl, j.conn) else {
                            return;
                        };
                        j.blocked = true;
                        j.pending_confirm = Some(msg.clone());
                        let pending = self.issue_challenge(
                            ctl,
                            conn,
                            &sid,
                            Role::Host,
                            Target::Viewer(join_id.to_string()),
                        );
                        st.joins.get_mut(join_id).expect("present").challenge = Some(pending);
                    }
                }
            }
            CtlMsg::End { session_id, exit } => {
                self.emit(SessionEvent::End { session_id, exit });
                self.settle(st, join_id);
            }
            CtlMsg::Info {
                session_id,
                name,
                input_mode,
            } => {
                if let Some(s) = j.session.as_mut() {
                    if let Some(n) = &name {
                        s.info.name = n.clone();
                    }
                    if let Some(m) = input_mode {
                        s.input_mode = m;
                    }
                }
                self.emit(SessionEvent::Info {
                    session_id,
                    name,
                    input_mode,
                });
            }
            CtlMsg::Error {
                code,
                message,
                reason,
            } => {
                self.debug(
                    "viewer:join-error",
                    json!({"joinId": join_id, "code": Code::from(code).as_str(), "message": message}),
                );
                self.finish_with(
                    st,
                    join_id,
                    JoinStatus::Failed,
                    Some(Code::from(code)),
                    reason,
                    Some(if message.is_empty() {
                        "Share failed".to_string()
                    } else {
                        message
                    }),
                    None,
                );
            }
            _ => {}
        }
    }

    /// Registers the joined session from `Confirm` (its envelope opened,
    /// the epoch installed), then applies the held `live` messages and the
    /// queued `ctl` ones in order.
    fn apply_confirm(self: &Arc<Self>, st: &mut State, join_id: &str, msg: CtlMsg) {
        let CtlMsg::Confirm {
            session_id,
            info,
            input_mode,
            log_key,
            meta_key,
            host_device_key,
            envelope: sealed,
            ..
        } = msg
        else {
            return;
        };
        let Some(j) = st.joins.get_mut(join_id) else {
            return;
        };
        let env = match envelope::open(&j.local.device_secret_key, &sealed) {
            Ok(e) => e,
            Err(e) => {
                return self.finish_with(
                    st,
                    join_id,
                    JoinStatus::Failed,
                    Some(e.code),
                    None,
                    Some(e.message),
                    None,
                );
            }
        };
        let epoch = u32::try_from(env.epoch).unwrap_or(u32::MAX);
        let keys = viewer_keys(&env);
        let caps = super::caps::normalize(env.caps);
        let has_live = keys.live_key.is_some();
        j.install(epoch, keys);
        j.confirmed = true;
        j.blocked = false;
        j.session = Some(Joined {
            session_id: session_id.clone(),
            info: info.clone(),
            input_mode,
            host_device_key,
            caps,
        });
        self.debug(
            "viewer:join-confirmed",
            json!({"joinId": join_id, "sessionId": session_id, "epoch": epoch}),
        );
        self.emit(SessionEvent::JoinChanged {
            join_id: join_id.to_string(),
            status: JoinStatus::Confirmed,
            session_id: Some(session_id.clone()),
            code: None,
            reason: None,
            message: None,
            confirm: Some(Box::new(ConfirmInfo {
                session_id: session_id.clone(),
                info,
                input_mode,
                log_key,
                meta_key,
                host_device_key,
                envelope: sealed,
                epoch,
                caps,
            })),
        });
        if !has_live {
            j.timer = 0;
            self.emit(SessionEvent::JoinChanged {
                join_id: join_id.to_string(),
                status: JoinStatus::Syncing,
                session_id: Some(session_id),
                code: None,
                reason: None,
                message: None,
                confirm: None,
            });
        }
        let held = std::mem::take(&mut st.joins.get_mut(join_id).expect("present").held);
        for m in held {
            self.process_live(st, join_id, m);
        }
        self.drain_queue(st, join_id);
    }

    /// The viewer's `live` messages (`protocol.md` §7, §11): **v2**, a frame
    /// not from `Confirm.host_device_key` is refused.
    fn process_live(self: &Arc<Self>, st: &mut State, join_id: &str, msg: LiveMsg) {
        let Some(j) = st.joins.get_mut(join_id) else {
            return;
        };
        let Some(joined) = j.session.clone() else {
            return;
        };
        let sid = joined.session_id.clone();
        let (frame, kind, hd) = match msg {
            LiveMsg::Rekey { epoch, envelope } => {
                match envelope::open(&j.local.device_secret_key, &envelope) {
                    Ok(env) => {
                        j.install(epoch, viewer_keys(&env));
                        self.emit(SessionEvent::Rekey {
                            session_id: sid,
                            epoch,
                            envelope,
                        });
                    }
                    Err(error) => self.emit(SessionEvent::Error {
                        session_id: Some(sid),
                        error,
                    }),
                }
                return;
            }
            LiveMsg::Data { frame, hd } => (frame, None, hd),
            LiveMsg::Bootstrap { frame } => (frame, Some(LiveKind::Bootstrap), false),
            LiveMsg::Snapshot { frame } => (frame, Some(LiveKind::Snapshot), false),
            LiveMsg::Timeline { frame } => (frame, Some(LiveKind::Timeline), false),
        };
        if frame.device_key != joined.host_device_key {
            self.debug("viewer:frame:foreign-device", json!({"joinId": join_id}));
            return self.emit(SessionEvent::Error {
                session_id: Some(sid),
                error: Error::new(Code::EAuth, "Live frame is not from the joined host"),
            });
        }
        let Some(key) = j.keys.get(&frame.epoch).and_then(|k| k.live_key) else {
            return self.emit(SessionEvent::Error {
                session_id: Some(sid),
                error: Error::new(Code::ENoKey, "No live key for this epoch"),
            });
        };
        let plain = match packet::decrypt(
            &key,
            &sid,
            frame.epoch,
            frame.seq,
            &frame.device_key,
            &frame.ciphertext,
        ) {
            Ok(p) => p,
            Err(error) => {
                self.debug(
                    "viewer:decrypt-failed",
                    json!({"sessionId": sid, "messageEpoch": frame.epoch, "localEpoch": j.epoch,
                           "seq": frame.seq, "epochMismatch": frame.epoch != j.epoch}),
                );
                return self.emit(SessionEvent::Error {
                    session_id: Some(sid),
                    error,
                });
            }
        };
        match kind {
            None => self.emit(SessionEvent::Output {
                session_id: sid,
                data: plain,
                hd,
            }),
            Some(kind) => {
                let first = kind == LiveKind::Bootstrap && !j.joined;
                if first {
                    j.joined = true;
                    j.timer = 0;
                }
                self.emit(SessionEvent::Live {
                    session_id: sid.clone(),
                    kind,
                    data: plain,
                });
                if first {
                    self.emit(SessionEvent::JoinChanged {
                        join_id: join_id.to_string(),
                        status: JoinStatus::Joined,
                        session_id: Some(sid),
                        code: None,
                        reason: None,
                        message: None,
                        confirm: None,
                    });
                }
            }
        }
    }

    /// The `ctl` channel or the connection closed.
    fn viewer_closed(self: &Arc<Self>, st: &mut State, join_id: &str) {
        let Some(j) = st.joins.get(join_id) else {
            return;
        };
        if j.done {
            return;
        }
        if j.confirmed {
            let sid = j
                .session
                .as_ref()
                .map(|s| s.session_id.clone())
                .unwrap_or_default();
            self.emit(SessionEvent::Offline { session_id: sid });
            self.settle(st, join_id);
        } else {
            self.finish_with(
                st,
                join_id,
                JoinStatus::Failed,
                Some(Code::EAuth),
                Some(JoinReason::Closed),
                Some("Share connection closed before the session was joined".to_string()),
                None,
            );
        }
    }

    /// `state.settle`: the join is over; its dial is cancelled and its
    /// channels close (the connection stays, it may carry others).
    fn settle(self: &Arc<Self>, st: &mut State, join_id: &str) {
        let Some(j) = st.joins.get_mut(join_id) else {
            return;
        };
        if j.done {
            return;
        }
        j.done = true;
        j.timer = 0;
        let chans: Vec<ChanHandle> = [j.ctl, j.live, j.history].into_iter().flatten().collect();
        let dial = j.dial;
        for c in &chans {
            st.chans.remove(c);
        }
        self.backend.cancel_dial(dial);
        for c in chans {
            self.backend.close_channel(c);
        }
    }

    fn finish(
        self: &Arc<Self>,
        st: &mut State,
        join_id: &str,
        status: JoinStatus,
        code: Option<Code>,
        reason: Option<JoinReason>,
        message: Option<String>,
    ) {
        self.finish_with(st, join_id, status, code, reason, message, None);
    }

    /// `state.finish`: settles and reports once.
    #[allow(clippy::too_many_arguments)]
    fn finish_with(
        self: &Arc<Self>,
        st: &mut State,
        join_id: &str,
        status: JoinStatus,
        code: Option<Code>,
        reason: Option<JoinReason>,
        message: Option<String>,
        confirm: Option<Box<ConfirmInfo>>,
    ) {
        let Some(j) = st.joins.get(join_id) else {
            return;
        };
        if j.done {
            return;
        }
        let session_id = j.session.as_ref().map(|s| s.session_id.clone());
        self.settle(st, join_id);
        self.emit(SessionEvent::JoinChanged {
            join_id: join_id.to_string(),
            status,
            session_id,
            code,
            reason,
            message,
            confirm,
        });
    }
}

fn viewer_keys(env: &envelope::Envelope) -> ViewerKeys {
    let k32 = |k: &Option<Vec<u8>>| k.as_deref().and_then(|b| <[u8; 32]>::try_from(b).ok());
    ViewerKeys {
        history_key: k32(&env.history_key),
        live_key: k32(&env.live_key),
    }
}

fn outcome_identity(confirm: &CtlMsg) -> Option<String> {
    match confirm {
        CtlMsg::Confirm {
            host_identity_claim: Some(c),
            ..
        } => c.identity_key.clone(),
        _ => None,
    }
}

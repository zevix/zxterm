//! The Freenet transport service (K10, stage C1), the Rust twin of ZBTerm
//! `engine/backends/freenet/index.js::FreenetBackend`: every
//! `BACKEND_MEMBERS` method of `zbterm:engine/backends/types.js`
//! (`describe`, `start`, `stop`, `health`, `localPeerKey`, `announce`,
//! `withdraw`, `routeFor`, `dial`, `setAdmission`, `serveHistory`,
//! `attachHistory`, `historyRouteFor`, `diagnostics`) with its events, the
//! per-link admission limits of design §7 layer 4, and channels on a
//! connection: JSON ones (`channel.js`) and raw ordered byte channels
//! (`history.js::HistoryChannel`), which carry ZBTerm's session messages
//! and Hypercore replication stream uninterpreted (design §4.3: in C1 the
//! JS session protocol is unchanged). `crate::seam::freenet_methods`
//! exposes it to ZBTerm, whose `FreenetBackend` proxies to it from K11.
//!
//! The wire is `index.js`'s exactly: the same signalling entries
//! (`{l, r, s, t, d, p, g}`, sealed batches `{cid, re?, m}` flushed within
//! [`node::FLUSH_MS`]), the same pointer record, the same bootstrap
//! channel, the same channel labels and `READY_PART` rule, so a Rust
//! backend and a JS one connect in both directions
//! (`tests/freenet_backend_js.rs`).
//!
//! **Shape.** One [`node::Shared`] socket carries every put, get, update
//! and subscription (subscriptions are per WebSocket connection); one
//! [`RtcHost`] carries every peer connection. A task started by
//! [`Backend::start`] owns both event streams and the timers (entry
//! flushes, half-open deadlines); state sits behind one mutex that is never
//! held across an `.await`. Node writes run on their own tasks, never
//! awaited by the event loop (`index.js::_write` does not await either).
//!
//! **Differences from `index.js`, all deliberate:**
//! - `setAdmission` takes an [`Admission`] (all, none, a key set, or a
//!   Rust closure), not a JS function; the seam offers the first three.
//! - `serveHistory`/`attachHistory` open the connection's history channel
//!   (`zbterm/history 00`) as a raw channel and return it: the Hypercore
//!   side (`history.js`'s Noise stream and `replicate`) runs in whoever
//!   holds the channel (ZBTerm's JS, K11). The core never parses it.
//! - `describe()` never claims `RELAY`: this core has no TURN client
//!   (`super::stun`), so a `turn:` URL is ignored, not used.
//! - The refusal reasons of `_overLimit` are also [`Refusal`] values with
//!   an [`Error`] mapping, so the seam can report them one to one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_stdlib::prelude::ContractKey;
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::error::{Code, Error};
use crate::wire;

use super::channel::ChannelKind;
use super::connection::{ConnEvent, Connection, Path};
use super::node::{self, NodeEvent, Shared};
use super::route::{self, Route, RouteParams};
use super::rtc::{ConnId, IceState, RtcEvent, RtcHost, SignalMsg};
use super::{contracts, signal};

/// `index.js::MAX_ANSWERS_PER_MINUTE`.
pub const MAX_ANSWERS_PER_MINUTE: usize = 30;
/// `index.js::ANSWER_WINDOW_MS`.
pub const ANSWER_WINDOW_MS: u64 = 60_000;
/// `index.js::MAX_HALF_OPEN`.
pub const MAX_HALF_OPEN: usize = 8;
/// `index.js::HALF_OPEN_TIMEOUT_MS`.
pub const HALF_OPEN_TIMEOUT_MS: u64 = 15_000;
/// `index.js::MAX_HALF_OPEN_PER_VIEWER`.
pub const MAX_HALF_OPEN_PER_VIEWER: usize = 2;
/// `index.js::EMPTY_STATE`: the canonical empty signalling state.
pub const EMPTY_STATE: &[u8] = b"{\"e\":[]}";
/// `history.js::HISTORY_ID`.
pub const HISTORY_ID: [u8; 1] = [0];
/// The `BackendDescriptor.id`.
pub const BACKEND_ID: &str = "freenet";
/// The `BackendDescriptor.label`.
pub const BACKEND_LABEL: &str = "Freenet (experimental)";
/// `index.js::CAPABILITIES`, the `types.js::CAP` bits
/// `AUTHENTICATED_PEER | MULTIPLEXED_STREAMS | ORDERED_STREAM |
/// EPHEMERAL_DELIVERY | NAT_TRAVERSAL | BROKERED | HISTORY_SPARSE_READ |
/// HISTORY_HEAD_WATCH`.
pub const CAPABILITIES: u32 =
    1 | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9) | (1 << 10);

/// Milliseconds on the backend's clock (`index.js`'s `clock`, default
/// `Date.now`): times the answer window and the half-open deadlines.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn wall_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// The node's address as a person would type it: scheme, host and port
/// (`index.js::nodeAddress`).
pub fn node_address(node_url: &str) -> String {
    let lower = node_url.to_ascii_lowercase();
    let scheme = if lower.starts_with("wss://") {
        6
    } else if lower.starts_with("ws://") {
        5
    } else {
        return node_url.to_string();
    };
    let rest = &node_url[scheme..];
    let end = rest.find('/').unwrap_or(rest.len());
    if end == 0 {
        return node_url.to_string();
    }
    node_url[..scheme + end].to_string()
}

/// The health report's detail when no node answers (`D-12`,
/// `index.js::FreenetBackend.probe`): `no Freenet node at <address>`.
/// ZBTerm adds its README pointer on the JS side.
pub fn no_node_detail(node_url: &str) -> String {
    format!("no Freenet node at {}", node_address(node_url))
}

/// An ICE URL without its credentials (`index.js::redactIceServer`).
pub fn redact_ice_server(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    for scheme in ["turns:", "turn:"] {
        if lower.starts_with(scheme)
            && let Some(at) = url.find('@')
        {
            return format!("{}{}", &url[..scheme.len()], &url[at + 1..]);
        }
    }
    url.to_string()
}

/// An error as one line, details included (for debug events).
fn err_text(e: &Error) -> String {
    match &e.details {
        Some(d) => format!("{e}: {d}"),
        None => e.to_string(),
    }
}

fn unavailable(message: impl Into<String>, detail: impl Into<String>) -> Error {
    Error::with_details(Code::EBackendUnavailable, message, detail)
}

/// Why an offer was refused: `index.js::_overLimit`'s strings, and
/// `'admission'` for one the policy refused. Each maps to one [`Error`]
/// (`E_BACKEND_UNAVAILABLE`, details = the reason string) so the seam
/// reports it one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `'half-open'`: the link holds [`MAX_HALF_OPEN`] half-open peer
    /// connections.
    HalfOpen,
    /// `'half-open-viewer'`: this viewer key holds
    /// [`MAX_HALF_OPEN_PER_VIEWER`] of them.
    HalfOpenViewer,
    /// `'rate'`: [`MAX_ANSWERS_PER_MINUTE`] offers answered in the window.
    Rate,
    /// `'admission'`: the admission policy refused the key.
    Admission,
}

impl Refusal {
    /// The JS reason string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Refusal::HalfOpen => "half-open",
            Refusal::HalfOpenViewer => "half-open-viewer",
            Refusal::Rate => "rate",
            Refusal::Admission => "admission",
        }
    }

    /// Parses a JS reason string.
    pub fn parse(reason: &str) -> Option<Refusal> {
        match reason {
            "half-open" => Some(Refusal::HalfOpen),
            "half-open-viewer" => Some(Refusal::HalfOpenViewer),
            "rate" => Some(Refusal::Rate),
            "admission" => Some(Refusal::Admission),
            _ => None,
        }
    }

    /// The error this refusal is reported as.
    pub fn to_error(self) -> Error {
        Error::with_details(
            Code::EBackendUnavailable,
            "The Freenet offer was refused",
            self.as_str(),
        )
    }
}

/// `policy(remotePeerKey, linkId)`: whether to answer an offer.
pub type Policy = Arc<dyn Fn(&[u8; 32], &str) -> bool + Send + Sync>;

/// `setAdmission`'s policy: decides whether an offer from a remote key is
/// answered. A key pinned by an active dial is always admitted. Unlike
/// Pear, a refusal is not sticky.
#[derive(Clone)]
pub enum Admission {
    /// `setAdmission(true)` / `setAdmission(false)`.
    All(bool),
    /// Exactly these 32-byte keys.
    Keys(HashSet<[u8; 32]>),
    /// `policy(remotePeerKey, linkId)`.
    Policy(Policy),
}

/// A handle to a surfaced peer connection (its RTC connection id).
pub type ConnHandle = u64;
/// A handle to a channel on a connection, unique per backend.
pub type ChanHandle = u64;

/// What a backend reports, to every [`Backend::subscribe`]r.
#[derive(Debug, Clone)]
pub enum BackendEvent {
    /// `'connection'`: fires once per connection on both sides.
    Connection {
        conn: ConnHandle,
        remote_peer_key: [u8; 32],
        initiator: bool,
        /// The announced link it arrived on; `None` on the dialing side.
        link_id: Option<String>,
        path: Path,
    },
    /// The connection closed (`connection.js`'s `'close'`).
    ConnectionClosed { conn: ConnHandle, reason: String },
    /// The remote opened `(protocol, id)`; open it with the same pair to
    /// take it (`onChannel`).
    IncomingChannel {
        conn: ConnHandle,
        protocol: String,
        id: Vec<u8>,
    },
    /// A channel this side opened is open on the remote too.
    ChannelOpened { chan: ChanHandle },
    /// A JSON message on a JSON channel.
    Message { chan: ChanHandle, value: Value },
    /// One data-channel message on a raw channel, uninterpreted.
    Bytes { chan: ChanHandle, bytes: Vec<u8> },
    /// A raw channel refused a send ([`Backend::send_bytes`] returned
    /// `false`): once per episode, and always before the [`Self::Drain`]
    /// that ends it (K11, `R-12`).
    Backpressure { chan: ChanHandle },
    /// A raw channel that reported back-pressure takes more again.
    Drain { chan: ChanHandle },
    /// The channel closed (either side, or with its connection).
    ChannelClosed { chan: ChanHandle },
    /// A dial settled: connected.
    DialConnected { dial: u64, conn: ConnHandle },
    /// A dial settled: failed or cancelled.
    DialError { dial: u64, error: Error },
    /// `'debug'`: `{event, details}`, JSON-safe, no secrets.
    Debug { event: String, details: Value },
}

/// [`Backend::new`]'s options (`index.js`'s constructor options).
#[derive(Clone)]
pub struct BackendOptions {
    /// Default [`node::DEFAULT_NODE_URL`]. Tests always pass their own
    /// `LocalNode`'s.
    pub node_url: String,
    /// `D-11`: the ICE servers every new peer connection gets; `Some(vec![])`
    /// means host candidates only, `None` the RTC half's own list
    /// ([`super::rtc::DEFAULT_ICE_SERVERS`]).
    pub ice_servers: Option<Vec<String>>,
    /// Default the wall clock.
    pub clock: Option<Clock>,
    /// Bind the loopback interface only ([`RtcHost::loopback_only`]).
    pub loopback_only: bool,
    /// K13: mint and accept v1 (`pv`-less) routes, as every build before
    /// the v2 session protocol did (`route::mint_v1`/`route::verify_v1`).
    /// Only the interop tests against the frozen v1 JS reference (`X-19`)
    /// set it; the seam never does, and a v2 backend (the default) mints
    /// `pv: 2` routes and refuses any other (`protocol.md` §12, PV-1–PV-3).
    pub legacy_v1_routes: bool,
}

impl Default for BackendOptions {
    fn default() -> Self {
        BackendOptions {
            node_url: node::DEFAULT_NODE_URL.to_string(),
            ice_servers: None,
            clock: None,
            loopback_only: false,
            legacy_v1_routes: false,
        }
    }
}

/// `dial()`'s handle: `connected` settles with the connection whose
/// remote key is the expected one, or the error; [`Backend::cancel_dial`]
/// with `id` cancels it.
pub struct DialHandle {
    pub id: u64,
    pub connected: oneshot::Receiver<Result<ConnHandle, Error>>,
}

/// `announce()`'s answer.
#[derive(Debug, Clone)]
pub struct Announcement {
    pub route: Route,
    pub link_id: String,
}

// ---------------------------------------------------------------------
// route <-> JSON
// ---------------------------------------------------------------------

/// A route as `route.js` writes it: `{sig, code, params: {ttl_ms, host, n},
/// ptr, k}`, with `params.pv` when the route has one (K13, `protocol.md`
/// §12).
pub fn route_to_json(r: &Route) -> Value {
    let mut params = json!({"ttl_ms": r.params.ttl_ms, "host": r.params.host, "n": r.params.n});
    if let Some(pv) = r.params.pv {
        params["pv"] = json!(pv);
    }
    json!({
        "sig": r.sig,
        "code": r.code,
        "params": params,
        "ptr": r.ptr,
        "k": r.k,
    })
}

/// Parses a v2 route object. Rule PV-1 (`route::check_pv_json`) runs
/// before a single field is extracted, so a `pv`-less route is refused as
/// an older protocol (`E_BACKEND_UNSUPPORTED`), never as malformed; then
/// `E_CORRUPT` for one that is not shaped like a route (K13).
pub fn route_from_json(v: &Value) -> Result<Route, Error> {
    route::check_pv_json(v)?;
    route_from_json_v1(v)
}

/// Parses a route object without rule PV-1 (a v1 route, or a v2 one): only
/// for a [`BackendOptions::legacy_v1_routes`] backend and the interop tests
/// against the frozen v1 JS reference (`X-19`). `E_CORRUPT` for one that is
/// not shaped like a route.
pub fn route_from_json_v1(v: &Value) -> Result<Route, Error> {
    let bad = || {
        Error::with_details(
            Code::ECorrupt,
            "The Freenet route is malformed",
            "malformed route",
        )
    };
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let params = v.get("params").ok_or_else(bad)?;
    Ok(Route {
        sig: s(v, "sig").ok_or_else(bad)?,
        code: s(v, "code").ok_or_else(bad)?,
        params: RouteParams {
            ttl_ms: params
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .ok_or_else(bad)?,
            host: s(params, "host").ok_or_else(bad)?,
            n: s(params, "n").ok_or_else(bad)?,
            pv: match params.get("pv") {
                None => None,
                Some(pv) => Some(pv.as_u64().ok_or_else(bad)?),
            },
        },
        ptr: s(v, "ptr"),
        k: s(v, "k").ok_or_else(bad)?,
    })
}

// ---------------------------------------------------------------------
// signalling helpers
// ---------------------------------------------------------------------

fn random_cid_hex() -> String {
    use crypto_secretbox::aead::rand_core::RngCore;
    let mut buf = [0u8; 16];
    crypto_secretbox::aead::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn signal_to_json(msg: &SignalMsg) -> Value {
    match msg {
        SignalMsg::Offer { sdp } => json!({"type": "offer", "sdp": sdp}),
        SignalMsg::Answer { sdp } => json!({"type": "answer", "sdp": sdp}),
        SignalMsg::Candidate { candidate, mid } => {
            json!({"type": "candidate", "candidate": candidate, "mid": mid})
        }
    }
}

fn entry_to_json(e: &signal::Entry) -> Value {
    json!({"l": e.l, "r": e.r, "s": e.s, "t": e.t, "d": e.d, "p": e.p, "g": e.g})
}

fn parse_entry(v: &Value) -> Option<signal::Entry> {
    let s = v.get("s")?.as_u64()?;
    Some(signal::Entry {
        l: v.get("l")?.as_str()?.to_string(),
        r: v.get("r")?.as_str()?.to_string(),
        s: u32::try_from(s).ok()?,
        t: v.get("t")?.as_u64()?,
        d: v.get("d").and_then(Value::as_bool).unwrap_or(false),
        p: v.get("p").and_then(Value::as_str).unwrap_or("").to_string(),
        g: v.get("g")?.as_str()?.to_string(),
    })
}

/// `index.js::entriesOf`: the entries of a state or delta, `[]` for
/// anything else.
fn entries_of(bytes: &[u8]) -> Vec<Value> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("e").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

fn key_from_hex(h: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(h).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

// ---------------------------------------------------------------------
// state
// ---------------------------------------------------------------------

/// What an owner of a peer connection queues for the signalling contract.
#[derive(Default)]
struct Outbox {
    queue: Vec<Value>,
    own: Vec<signal::Entry>,
    seq: u32,
    flush_at: Option<Instant>,
}

struct Link {
    uid: u64,
    link_id: String,
    route: Route,
    id: String,
    key: ContractKey,
    params: Vec<u8>,
    payload_key: [u8; 32],
    ttl_ms: u64,
    tag: Value,
    /// `"l\nr\ns"` -> `(g, t)` of every viewer entry seen.
    seen: HashMap<String, (String, u64)>,
    /// `"<viewer hex>:<cid>"` -> the session's RTC id.
    sessions: HashMap<String, ConnId>,
    /// Clock times of the offers answered within the window.
    answers: VecDeque<u64>,
    refused: u64,
}

struct HostSession {
    link_uid: u64,
    link_id: String,
    session_key: String,
    viewer: String,
    remote: [u8; 32],
    cid: String,
    r: String,
    re: String,
    fingerprint: Option<String>,
    out: Outbox,
    /// Clock time after which it no longer holds a slot (`S-22`).
    deadline: u64,
    /// When the real timer backing `deadline` fires.
    deadline_timer: Option<Instant>,
    surfaced: bool,
    /// RTC events before it surfaced (`index.js::_surface`'s `early`).
    early: Vec<RtcEvent>,
    tag: Value,
}

struct Dial {
    expected: [u8; 32],
    expected_hex: String,
    tag: Value,
    done: bool,
    reply: Option<oneshot::Sender<Result<ConnHandle, Error>>>,
    // Set by start_dial:
    conn_id: Option<ConnId>,
    instance: Option<String>,
    key: Option<ContractKey>,
    params: Vec<u8>,
    payload_key: [u8; 32],
    cid: String,
    r: String,
    host_r: String,
    ready: bool,
    out: Outbox,
    seen: HashMap<u32, String>,
    re: Option<String>,
    answered: bool,
    fingerprint: Option<String>,
    /// Remote candidates before the answer.
    held: Vec<SignalMsg>,
    /// This side's candidates, kept back until the answer applies (`S-26`).
    own_held: Vec<Value>,
    /// The connection being built (bootstrap channel open), until it
    /// surfaces.
    conn: Option<Connection>,
    early: Vec<ConnEvent>,
    surfaced: Option<ConnHandle>,
    started_at: Instant,
    offer_at: Option<Instant>,
}

struct Sub {
    link_uid: Option<u64>,
    dials: HashSet<u64>,
    subscribed: bool,
    entries: usize,
}

struct Live {
    conn: Connection,
    remote: [u8; 32],
    initiator: bool,
    link_id: Option<String>,
    ice_state: &'static str,
    /// channel key -> handle.
    chans: HashMap<String, ChanHandle>,
}

enum Owner {
    Dial(u64),
    Host,
}

struct Write {
    key: ContractKey,
    entries: Vec<Value>,
    timeout_ms: u64,
}

struct State {
    started: bool,
    node: Option<Shared>,
    node_problem: Option<String>,
    node_url: String,
    secret: Option<SigningKey>,
    ice_given: Option<Vec<String>>,
    links: HashMap<String, Link>,
    subs: HashMap<String, Sub>,
    dials: HashMap<u64, Dial>,
    sessions: HashMap<ConnId, HostSession>,
    owners: HashMap<ConnId, Owner>,
    conns: HashMap<ConnId, Live>,
    chans: HashMap<ChanHandle, (ConnId, String)>,
    /// Channels whose events wait for [`Backend::release`].
    hold: HashMap<ChanHandle, Vec<BackendEvent>>,
    /// Raw channels that reported [`BackendEvent::Backpressure`] and have
    /// not drained yet.
    backpressured: HashSet<ChanHandle>,
    pinned: HashMap<String, usize>,
    minted: HashSet<String>,
    admission: Admission,
    refused: u64,
    next_conn_id: u64,
    next_dial: u64,
    next_chan: u64,
    next_link_uid: u64,
    out: Vec<BackendEvent>,
    writes: Vec<Write>,
    /// RTC connections to close once the state lock is released.
    pending_rtc_close: Vec<(ConnId, String)>,
}

struct Inner {
    state: Mutex<State>,
    rtc: Arc<RtcHost>,
    clock: Clock,
    wake: Notify,
    shutdown: Notify,
    start_lock: tokio::sync::Mutex<()>,
    subscribers: Mutex<Vec<mpsc::UnboundedSender<BackendEvent>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// [`BackendOptions::legacy_v1_routes`].
    legacy_v1_routes: bool,
}

/// The Freenet transport service. Cheap to clone; every clone is the same
/// backend.
#[derive(Clone)]
pub struct Backend {
    inner: Arc<Inner>,
}

impl State {
    fn debug(&mut self, event: &str, details: Value) {
        self.out.push(BackendEvent::Debug {
            event: event.to_string(),
            details,
        });
    }

    fn refuse(&mut self, event: &str, details: Value) {
        self.refused += 1;
        self.debug(event, details);
    }

    fn my_hex(&self) -> Option<String> {
        self.secret
            .as_ref()
            .map(|s| hex::encode(s.verifying_key().to_bytes()))
    }

    /// Events ready to emit, with held channels' events set aside.
    fn take_out(&mut self) -> Vec<BackendEvent> {
        let events = std::mem::take(&mut self.out);
        let mut ready = Vec::with_capacity(events.len());
        for ev in events {
            let chan = match &ev {
                BackendEvent::ChannelOpened { chan }
                | BackendEvent::Message { chan, .. }
                | BackendEvent::Bytes { chan, .. }
                | BackendEvent::Backpressure { chan }
                | BackendEvent::Drain { chan }
                | BackendEvent::ChannelClosed { chan } => Some(*chan),
                _ => None,
            };
            match chan.and_then(|c| self.hold.get_mut(&c)) {
                Some(held) => held.push(ev),
                None => ready.push(ev),
            }
        }
        ready
    }

    fn usable(&self) -> Result<Shared, Error> {
        match (&self.node, self.started) {
            (Some(node), true) => Ok(node.clone()),
            _ => Err(unavailable(
                "The 'freenet' share backend is not started",
                "not started",
            )),
        }
    }

    fn ice(&self) -> Option<Vec<String>> {
        self.ice_given.clone()
    }

    // --- admission ---

    fn admits(&self, remote: &[u8; 32], link_id: &str) -> bool {
        if self.pinned.contains_key(&hex::encode(remote)) {
            return true;
        }
        match &self.admission {
            Admission::All(b) => *b,
            Admission::Keys(keys) => keys.contains(remote),
            Admission::Policy(f) => {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(remote, link_id)))
                    .unwrap_or(false)
            }
        }
    }

    fn half_open(&self, link_uid: u64, viewer: Option<&str>) -> usize {
        self.sessions
            .values()
            .filter(|s| {
                s.link_uid == link_uid && !s.surfaced && viewer.is_none_or(|v| s.viewer == v)
            })
            .count()
    }

    fn answered_in_window(&mut self, link_id: &str, now: u64) -> usize {
        let Some(link) = self.links.get_mut(link_id) else {
            return 0;
        };
        let since = now.saturating_sub(ANSWER_WINDOW_MS);
        while link.answers.front().is_some_and(|t| *t <= since) {
            link.answers.pop_front();
        }
        link.answers.len()
    }

    /// `index.js::_overLimit`.
    fn over_limit(&mut self, link_id: &str, viewer: &str, now: u64) -> Option<Refusal> {
        self.expire_half_open(link_id, now);
        let uid = self.links.get(link_id)?.uid;
        if self.half_open(uid, None) >= MAX_HALF_OPEN {
            return Some(Refusal::HalfOpen);
        }
        if self.half_open(uid, Some(viewer)) >= MAX_HALF_OPEN_PER_VIEWER {
            return Some(Refusal::HalfOpenViewer);
        }
        if self.answered_in_window(link_id, now) >= MAX_ANSWERS_PER_MINUTE {
            return Some(Refusal::Rate);
        }
        None
    }

    /// `index.js::_expireHalfOpen`: every half-open session of the link
    /// past its deadline is closed and counted as refused.
    fn expire_half_open(&mut self, link_id: &str, now: u64) {
        let Some(link) = self.links.get(link_id) else {
            return;
        };
        let uid = link.uid;
        let stale: Vec<ConnId> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.link_uid == uid && !s.surfaced && s.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for conn_id in stale {
            if let Some(link) = self.links.get_mut(link_id) {
                link.refused += 1;
            }
            let (tag, peer) = match self.sessions.get(&conn_id) {
                Some(s) => (s.tag.clone(), s.viewer.clone()),
                None => continue,
            };
            let mut details = tag;
            merge(&mut details, json!({"linkId": link_id, "peer": peer}));
            self.refuse("host:half-open-expired", details);
            self.drop_session(conn_id, "half-open timeout");
        }
    }

    fn pin(&mut self, key_hex: &str) {
        *self.pinned.entry(key_hex.to_string()).or_insert(0) += 1;
    }

    fn unpin(&mut self, key_hex: &str) {
        if let Some(n) = self.pinned.get_mut(key_hex) {
            *n -= 1;
            if *n == 0 {
                self.pinned.remove(key_hex);
            }
        }
    }

    // --- subscriptions ---

    fn subscription(&mut self, id: &str) -> &mut Sub {
        self.subs.entry(id.to_string()).or_insert(Sub {
            link_uid: None,
            dials: HashSet::new(),
            subscribed: false,
            entries: 0,
        })
    }

    fn release(&mut self, id: &str) {
        if let Some(sub) = self.subs.get(id)
            && sub.link_uid.is_none()
            && sub.dials.is_empty()
        {
            self.subs.remove(id);
        }
    }

    // --- notifications ---

    fn on_state(&mut self, rtc: &RtcHost, clock: &Clock, id: &str, parts: &[Vec<u8>]) {
        if !self.subs.contains_key(id) {
            return;
        }
        let mut entries = Vec::new();
        for part in parts {
            entries.extend(entries_of(part));
        }
        let (link_uid, dials) = {
            let sub = self.subs.get_mut(id).expect("checked above");
            sub.entries = entries.len();
            (sub.link_uid, sub.dials.iter().copied().collect::<Vec<_>>())
        };
        if let Some(uid) = link_uid
            && let Some(link_id) = self
                .links
                .values()
                .find(|l| l.uid == uid)
                .map(|l| l.link_id.clone())
        {
            self.host_entries(rtc, clock, &link_id, &entries);
        }
        for dial in dials {
            self.dial_entries(rtc, dial, &entries);
        }
    }

    // --- host role ---

    /// `index.js::_hostEntries`.
    fn host_entries(&mut self, rtc: &RtcHost, clock: &Clock, link_id: &str, entries: &[Value]) {
        let mut fresh = Vec::new();
        {
            let Some(link) = self.links.get_mut(link_id) else {
                return;
            };
            let mut high = 0u64;
            for v in entries {
                let Some(e) = parse_entry(v) else { continue };
                if !e.r.starts_with("v:") {
                    continue;
                }
                high = high.max(e.t);
                let id = format!("{}\n{}\n{}", e.l, e.r, e.s);
                if link.seen.get(&id).is_some_and(|(g, _)| *g == e.g) {
                    continue;
                }
                link.seen.insert(id, (e.g.clone(), e.t));
                fresh.push(e);
            }
            let ttl = link.ttl_ms;
            link.seen.retain(|_, (_, t)| *t + 2 * ttl >= high);
        }
        fresh.sort_by_key(|e| e.s);
        for e in fresh {
            self.host_entry(rtc, clock, link_id, e);
        }
    }

    /// `index.js::_hostEntry`.
    fn host_entry(&mut self, rtc: &RtcHost, clock: &Clock, link_id: &str, e: signal::Entry) {
        let (params, payload_key, tag, uid) = match self.links.get(link_id) {
            Some(l) => (l.params.clone(), l.payload_key, l.tag.clone(), l.uid),
            None => return,
        };
        let refused_details = |reason: &str| {
            let mut d = tag.clone();
            merge(&mut d, json!({"linkId": link_id, "reason": reason}));
            d
        };
        let role = signal::role_of(&e.r);
        let viewer_key = role.as_ref().and_then(|r| key_from_hex(&r.viewer));
        let (Some(role), Some(viewer_key)) = (role, viewer_key) else {
            self.refuse("host:entry-refused", refused_details("signature"));
            return;
        };
        if !signal::verify_entry(&viewer_key, &params, &e) {
            self.refuse("host:entry-refused", refused_details("signature"));
            return;
        }
        let session_key = format!("{}:{}", role.viewer, e.l);
        let session = self
            .links
            .get(link_id)
            .and_then(|l| l.sessions.get(&session_key))
            .copied();
        if e.d {
            // The viewer cancelled: a connection that never surfaced goes.
            if let Some(conn_id) = session
                && self.sessions.get(&conn_id).is_some_and(|s| !s.surfaced)
            {
                self.drop_session(conn_id, "viewer cancelled");
            }
            return;
        }
        let Some(msg) = signal::open(&payload_key, &e.p) else {
            self.refuse("host:entry-refused", refused_details("payload"));
            return;
        };
        let ms = match (msg.get("cid").and_then(Value::as_str), msg.get("m")) {
            (Some(cid), Some(Value::Array(ms))) if cid == e.l => ms.clone(),
            _ => {
                self.refuse("host:entry-refused", refused_details("payload"));
                return;
            }
        };
        let Some(conn_id) = session else {
            // Only an offer opens a session.
            let Some(offer) = ms.iter().find(|m| {
                m.get("type").and_then(Value::as_str) == Some("offer")
                    && m.get("sdp").and_then(Value::as_str).is_some()
            }) else {
                return;
            };
            let now = clock();
            let remote = viewer_key.to_bytes();
            let refusal = self
                .over_limit(link_id, &role.viewer, now)
                .or_else(|| (!self.admits(&remote, link_id)).then_some(Refusal::Admission));
            if let Some(refusal) = refusal {
                if let Some(link) = self.links.get_mut(link_id) {
                    link.refused += 1;
                }
                let err = refusal.to_error();
                let mut d = tag.clone();
                merge(
                    &mut d,
                    json!({
                        "linkId": link_id,
                        "peer": role.viewer,
                        "reason": refusal.as_str(),
                        "code": err.code.as_str(),
                    }),
                );
                self.refuse("host:offer-refused", d);
                return;
            }
            if let Some(link) = self.links.get_mut(link_id) {
                link.answers.push_back(now);
            }
            let conn_id = self.next_conn_id;
            self.next_conn_id += 1;
            let sdp = offer.get("sdp").and_then(Value::as_str).unwrap_or("");
            self.sessions.insert(
                conn_id,
                HostSession {
                    link_uid: uid,
                    link_id: link_id.to_string(),
                    session_key: session_key.clone(),
                    viewer: role.viewer.clone(),
                    remote,
                    cid: e.l.clone(),
                    r: format!("h:{}", role.viewer),
                    re: signal::offer_ref(&e.p),
                    fingerprint: signal::sdp_fingerprint(sdp),
                    out: Outbox::default(),
                    deadline: now + HALF_OPEN_TIMEOUT_MS,
                    deadline_timer: Some(
                        Instant::now() + Duration::from_millis(HALF_OPEN_TIMEOUT_MS),
                    ),
                    surfaced: false,
                    early: Vec::new(),
                    tag: tag.clone(),
                },
            );
            if let Some(link) = self.links.get_mut(link_id) {
                link.sessions.insert(session_key, conn_id);
            }
            self.owners.insert(conn_id, Owner::Host);
            let mut d = tag.clone();
            merge(&mut d, json!({"linkId": link_id, "peer": role.viewer}));
            self.debug("host:offer", d);
            rtc.open(conn_id, self.ice());
            for m in &ms {
                apply_remote(rtc, conn_id, m, true);
            }
            return;
        };
        if self.sessions.get(&conn_id).is_some_and(|s| !s.surfaced) {
            for m in &ms {
                apply_remote(rtc, conn_id, m, false);
            }
        }
    }

    fn drop_session(&mut self, conn_id: ConnId, reason: &str) {
        let Some(session) = self.sessions.remove(&conn_id) else {
            return;
        };
        if let Some(link) = self.links.get_mut(&session.link_id)
            && link.uid == session.link_uid
        {
            link.sessions.remove(&session.session_key);
        }
        if matches!(self.owners.get(&conn_id), Some(Owner::Host)) {
            self.owners.remove(&conn_id);
            self.rtc_close(conn_id, reason);
        }
    }

    fn rtc_close(&mut self, conn_id: ConnId, reason: &str) {
        self.pending_rtc_close.push((conn_id, reason.to_string()));
    }

    // --- viewer role ---

    /// `index.js::_dialEntries`.
    fn dial_entries(&mut self, rtc: &RtcHost, dial_id: u64, entries: &[Value]) {
        let Some(dial) = self.dials.get_mut(&dial_id) else {
            return;
        };
        if dial.done || dial.surfaced.is_some() || dial.re.is_none() {
            return;
        }
        let mut fresh = Vec::new();
        for v in entries {
            let Some(e) = parse_entry(v) else { continue };
            if e.l != dial.cid || e.r != dial.host_r {
                continue;
            }
            if dial.seen.get(&e.s) == Some(&e.g) {
                continue;
            }
            dial.seen.insert(e.s, e.g.clone());
            fresh.push(e);
        }
        fresh.sort_by_key(|e| e.s);
        let Ok(expected) = VerifyingKey::from_bytes(&dial.expected) else {
            return;
        };
        let tag = dial.tag.clone();
        let mut refusals = Vec::new();
        let mut debug = Vec::new();
        for e in fresh {
            if !signal::verify_entry(&expected, &dial.params, &e) {
                refusals.push("signature");
                continue;
            }
            if e.d {
                continue;
            }
            let Some(msg) = signal::open(&dial.payload_key, &e.p) else {
                refusals.push("payload");
                continue;
            };
            let ms = match (msg.get("cid").and_then(Value::as_str), msg.get("m")) {
                (Some(cid), Some(Value::Array(ms))) if cid == dial.cid => ms.clone(),
                _ => {
                    refusals.push("payload");
                    continue;
                }
            };
            if msg.get("re").and_then(Value::as_str) != dial.re.as_deref() {
                refusals.push("offer");
                continue;
            }
            let Some(conn_id) = dial.conn_id else {
                continue;
            };
            for m in &ms {
                let ty = m.get("type").and_then(Value::as_str);
                if ty == Some("answer") && !dial.answered {
                    let Some(sdp) = m.get("sdp").and_then(Value::as_str) else {
                        continue;
                    };
                    dial.answered = true;
                    dial.fingerprint = signal::sdp_fingerprint(sdp);
                    let mut d = tag.clone();
                    merge(
                        &mut d,
                        json!({
                            "ms": dial.started_at.elapsed().as_millis() as u64,
                            "sinceOfferMs": dial.offer_at.map(|t| t.elapsed().as_millis() as u64),
                        }),
                    );
                    debug.push(("viewer:answer", d));
                    rtc.signal(
                        conn_id,
                        SignalMsg::Answer {
                            sdp: sdp.to_string(),
                        },
                    );
                    for held in dial.held.drain(..) {
                        rtc.signal(conn_id, held);
                    }
                    if !dial.own_held.is_empty() {
                        let own: Vec<Value> = dial.own_held.drain(..).collect();
                        dial.out.queue.extend(own);
                        schedule_flush(&mut dial.out, node::FLUSH_MS);
                    }
                } else if ty == Some("candidate")
                    && let Some(msg) = candidate_of(m)
                {
                    if dial.answered {
                        rtc.signal(conn_id, msg);
                    } else {
                        dial.held.push(msg);
                    }
                }
            }
        }
        for reason in refusals {
            let mut d = tag.clone();
            merge(&mut d, json!({"reason": reason}));
            self.refuse("viewer:answer-refused", d);
        }
        for (event, d) in debug {
            self.debug(event, d);
        }
    }

    /// `index.js::_endDial`.
    fn end_dial(&mut self, dial_id: u64, err: Error) {
        let Some(dial) = self.dials.get_mut(&dial_id) else {
            return;
        };
        if dial.done {
            return;
        }
        dial.done = true;
        let expected_hex = dial.expected_hex.clone();
        let instance = dial.instance.clone();
        let surfaced = dial.surfaced.is_some();
        self.unpin(&expected_hex);
        if let Some(id) = instance {
            if let Some(sub) = self.subs.get_mut(&id) {
                sub.dials.remove(&dial_id);
            }
            self.release(&id);
        }
        let mut dial = self.dials.remove(&dial_id).expect("present");
        if surfaced {
            return;
        }
        dial.out.flush_at = None;
        dial.out.queue.clear();
        let tombstones = self.tombstones(&mut dial.out, &dial.params);
        if !tombstones.is_empty()
            && let Some(key) = dial.key
        {
            self.writes.push(Write {
                key,
                entries: tombstones,
                timeout_ms: node::TOMBSTONE_TIMEOUT_MS,
            });
        }
        if let Some(conn_id) = dial.conn_id
            && matches!(self.owners.get(&conn_id), Some(Owner::Dial(d)) if *d == dial_id)
        {
            self.owners.remove(&conn_id);
            self.rtc_close(conn_id, "cancelled");
        }
        self.out.push(BackendEvent::DialError {
            dial: dial_id,
            error: err.clone(),
        });
        if let Some(reply) = dial.reply.take() {
            let _ = reply.send(Err(err));
        }
    }

    // --- writing entries ---

    /// `index.js::_tombstones`.
    fn tombstones(&self, out: &mut Outbox, params: &[u8]) -> Vec<Value> {
        let Some(secret) = &self.secret else {
            return Vec::new();
        };
        let at = wall_ms();
        out.own
            .drain(..)
            .map(|e| {
                let t = signal::sign_entry(
                    secret,
                    params,
                    &signal::EntryFields {
                        l: &e.l,
                        r: &e.r,
                        s: e.s,
                        t: at.max(e.t + 1),
                        d: true,
                        p: "",
                    },
                );
                entry_to_json(&t)
            })
            .collect()
    }

    /// `index.js::_flush` for a host session.
    fn flush_session(&mut self, conn_id: ConnId) {
        let Some(secret) = self.secret.clone() else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&conn_id) else {
            return;
        };
        session.out.flush_at = None;
        if session.out.queue.is_empty() || session.surfaced {
            return;
        }
        // A withdrawn link answers nothing more.
        let Some(link) = self
            .links
            .get(&session.link_id)
            .filter(|l| l.uid == session.link_uid)
        else {
            session.out.queue.clear();
            return;
        };
        let m: Vec<Value> = session.out.queue.drain(..).collect();
        let payload = json!({"cid": session.cid, "re": session.re, "m": m});
        let p = signal::seal(&link.payload_key, &payload);
        let entry = signal::sign_entry(
            &secret,
            &link.params,
            &signal::EntryFields {
                l: &session.cid,
                r: &session.r,
                s: session.out.seq,
                t: wall_ms(),
                d: false,
                p: &p,
            },
        );
        session.out.seq += 1;
        session.out.own.push(entry.clone());
        let key = link.key;
        self.writes.push(Write {
            key,
            entries: vec![entry_to_json(&entry)],
            timeout_ms: node::REQUEST_TIMEOUT_MS,
        });
    }

    /// `index.js::_flush` for a dial.
    fn flush_dial(&mut self, dial_id: u64) {
        let Some(secret) = self.secret.clone() else {
            return;
        };
        let Some(dial) = self.dials.get_mut(&dial_id) else {
            return;
        };
        dial.out.flush_at = None;
        if !dial.ready || dial.out.queue.is_empty() || dial.done || dial.surfaced.is_some() {
            return;
        }
        let Some(key) = dial.key else { return };
        let m: Vec<Value> = dial.out.queue.drain(..).collect();
        let has_offer = m
            .iter()
            .any(|x| x.get("type").and_then(Value::as_str) == Some("offer"));
        let payload = json!({"cid": dial.cid, "m": m});
        let p = signal::seal(&dial.payload_key, &payload);
        let entry = signal::sign_entry(
            &secret,
            &dial.params,
            &signal::EntryFields {
                l: &dial.cid,
                r: &dial.r,
                s: dial.out.seq,
                t: wall_ms(),
                d: false,
                p: &p,
            },
        );
        dial.out.seq += 1;
        if dial.re.is_none() && has_offer {
            dial.re = Some(signal::offer_ref(&p));
            dial.offer_at = Some(Instant::now());
        }
        dial.out.own.push(entry.clone());
        self.writes.push(Write {
            key,
            entries: vec![entry_to_json(&entry)],
            timeout_ms: node::REQUEST_TIMEOUT_MS,
        });
    }

    // --- RTC events ---

    fn on_rtc(&mut self, rtc: &RtcHost, ev: RtcEvent) {
        let conn_id = match &ev {
            RtcEvent::Signal { conn_id, .. }
            | RtcEvent::State { conn_id, .. }
            | RtcEvent::Channel { conn_id, .. }
            | RtcEvent::Data { conn_id, .. }
            | RtcEvent::Flow { conn_id, .. }
            | RtcEvent::Close { conn_id, .. } => *conn_id,
        };
        if self.conns.contains_key(&conn_id) {
            self.on_live(rtc, conn_id, ev);
            return;
        }
        let Some(owner) = self.owners.get(&conn_id) else {
            return;
        };
        let dial_id = match owner {
            Owner::Dial(d) => Some(*d),
            Owner::Host => None,
        };
        match ev {
            RtcEvent::Signal { msg, .. } => {
                let m = signal_to_json(&msg);
                if let Some(d) = dial_id {
                    let Some(dial) = self.dials.get_mut(&d) else {
                        return;
                    };
                    if dial.done {
                        return;
                    }
                    // S-26: this side's candidates wait for the answer.
                    if matches!(msg, SignalMsg::Candidate { .. }) && !dial.answered {
                        dial.own_held.push(m);
                        return;
                    }
                    dial.out.queue.push(m);
                    schedule_flush(&mut dial.out, node::FLUSH_MS);
                } else if let Some(s) = self.sessions.get_mut(&conn_id) {
                    s.out.queue.push(m);
                    schedule_flush(&mut s.out, node::FLUSH_MS);
                }
            }
            RtcEvent::State {
                state: IceState::Connected,
                remote_fingerprint,
                path_kind,
                ..
            } => {
                let expected = match dial_id {
                    Some(d) => self.dials.get(&d).and_then(|x| x.fingerprint.clone()),
                    None => self
                        .sessions
                        .get(&conn_id)
                        .and_then(|s| s.fingerprint.clone()),
                };
                // Design §6 step 5.
                match (expected, remote_fingerprint) {
                    (Some(e), Some(p)) if e == p => self.surface(rtc, conn_id, path_kind),
                    _ => self.auth_failed(conn_id),
                }
            }
            RtcEvent::State { state, .. } => {
                let reason = if state == IceState::Failed {
                    "ice-failed"
                } else {
                    "closed"
                };
                self.lost(conn_id, reason);
            }
            RtcEvent::Close { reason, .. } => {
                self.owners.remove(&conn_id);
                let reason = if reason == "failed" {
                    "ice-failed".to_string()
                } else {
                    reason
                };
                self.lost_owner(dial_id, conn_id, &reason);
            }
            other => {
                if let Some(d) = dial_id {
                    if let Some(dial) = self.dials.get_mut(&d)
                        && let Some(conn) = dial.conn.as_mut()
                    {
                        let evs = conn.handle_rtc_event(rtc, &other);
                        dial.early.extend(evs);
                    }
                } else if let Some(s) = self.sessions.get_mut(&conn_id) {
                    s.early.push(other);
                }
            }
        }
    }

    fn auth_failed(&mut self, conn_id: ConnId) {
        let owner = self.owners.remove(&conn_id);
        self.rtc_close(conn_id, "fingerprint mismatch");
        match owner {
            Some(Owner::Dial(d)) => {
                let (tag, peer) = self
                    .dials
                    .get(&d)
                    .map(|x| (x.tag.clone(), x.expected_hex.clone()))
                    .unwrap_or((json!({}), String::new()));
                let mut details = tag;
                merge(&mut details, json!({"peer": peer}));
                self.refuse("viewer:fingerprint-mismatch", details);
                self.end_dial(
                    d,
                    Error::with_details(
                        Code::EAuth,
                        "The Freenet peer presented a certificate its signed SDP does not name",
                        "fingerprint mismatch",
                    ),
                );
            }
            Some(Owner::Host) => {
                let (tag, peer) = self
                    .sessions
                    .get(&conn_id)
                    .map(|s| (s.tag.clone(), s.viewer.clone()))
                    .unwrap_or((json!({}), String::new()));
                let mut details = tag;
                merge(&mut details, json!({"peer": peer}));
                self.refuse("host:fingerprint-mismatch", details);
                // Owner already removed: drop without a second close.
                if let Some(s) = self.sessions.remove(&conn_id)
                    && let Some(link) = self.links.get_mut(&s.link_id)
                    && link.uid == s.link_uid
                {
                    link.sessions.remove(&s.session_key);
                }
            }
            None => {}
        }
    }

    fn lost(&mut self, conn_id: ConnId, reason: &str) {
        let dial_id = match self.owners.get(&conn_id) {
            Some(Owner::Dial(d)) => Some(*d),
            Some(Owner::Host) => None,
            None => return,
        };
        self.lost_owner(dial_id, conn_id, reason);
    }

    /// `index.js::_lost`: a peer connection that ended before it surfaced.
    fn lost_owner(&mut self, dial_id: Option<u64>, conn_id: ConnId, reason: &str) {
        match dial_id {
            Some(d) => self.end_dial(
                d,
                Error::with_details(
                    Code::EHostUnreachable,
                    "The Freenet peer connection failed",
                    reason,
                ),
            ),
            None => {
                if let Some(s) = self.sessions.get(&conn_id) {
                    let mut details = s.tag.clone();
                    merge(&mut details, json!({"peer": s.viewer, "reason": reason}));
                    self.debug("host:connection-lost", details);
                }
                self.drop_session(conn_id, reason);
            }
        }
    }

    /// `index.js::_surface`.
    fn surface(&mut self, rtc: &RtcHost, conn_id: ConnId, path_kind: Option<String>) {
        let owner = self.owners.remove(&conn_id);
        match owner {
            Some(Owner::Dial(d)) => {
                let Some(dial) = self.dials.get_mut(&d) else {
                    return;
                };
                let Some(conn) = dial.conn.take() else { return };
                dial.surfaced = Some(conn_id);
                dial.out.flush_at = None;
                dial.out.queue.clear();
                let early = std::mem::take(&mut dial.early);
                let remote = dial.expected;
                let tag = dial.tag.clone();
                let mut details = tag.clone();
                merge(
                    &mut details,
                    json!({
                        "peer": dial.expected_hex,
                        "path": path_str(conn.path()),
                        "ms": dial.started_at.elapsed().as_millis() as u64,
                    }),
                );
                let reply = dial.reply.take();
                let path = conn.path();
                self.conns.insert(
                    conn_id,
                    Live {
                        conn,
                        remote,
                        initiator: true,
                        link_id: None,
                        ice_state: "connected",
                        chans: HashMap::new(),
                    },
                );
                self.debug("viewer:connected", details);
                if let Some(reply) = reply {
                    let _ = reply.send(Ok(conn_id));
                }
                self.out.push(BackendEvent::DialConnected {
                    dial: d,
                    conn: conn_id,
                });
                self.out.push(BackendEvent::Connection {
                    conn: conn_id,
                    remote_peer_key: remote,
                    initiator: true,
                    link_id: None,
                    path,
                });
                for ev in early {
                    self.map_conn_event(conn_id, ev);
                }
            }
            Some(Owner::Host) => {
                let Some(s) = self.sessions.get_mut(&conn_id) else {
                    return;
                };
                s.surfaced = true;
                s.deadline_timer = None;
                s.out.flush_at = None;
                s.out.queue.clear();
                let early = std::mem::take(&mut s.early);
                let remote = s.remote;
                let link_id = s.link_id.clone();
                let tag = s.tag.clone();
                let mut details = tag.clone();
                merge(&mut details, json!({"linkId": link_id, "peer": s.viewer}));
                let conn = Connection::new(conn_id, remote.to_vec(), false, path_kind);
                let path = conn.path();
                self.conns.insert(
                    conn_id,
                    Live {
                        conn,
                        remote,
                        initiator: false,
                        link_id: Some(link_id.clone()),
                        ice_state: "connected",
                        chans: HashMap::new(),
                    },
                );
                self.debug("host:connected", details);
                self.out.push(BackendEvent::Connection {
                    conn: conn_id,
                    remote_peer_key: remote,
                    initiator: false,
                    link_id: Some(link_id),
                    path,
                });
                for ev in early {
                    self.on_live(rtc, conn_id, ev);
                }
            }
            None => {}
        }
    }

    fn on_live(&mut self, rtc: &RtcHost, conn_id: ConnId, ev: RtcEvent) {
        if let RtcEvent::State { state, .. } = &ev {
            if let Some(live) = self.conns.get_mut(&conn_id) {
                live.ice_state = match state {
                    IceState::Connected => "connected",
                    IceState::Failed => "failed",
                    IceState::Closed => "closed",
                };
            }
            return;
        }
        let Some(live) = self.conns.get_mut(&conn_id) else {
            return;
        };
        let evs = live.conn.handle_rtc_event(rtc, &ev);
        for ce in evs {
            self.map_conn_event(conn_id, ce);
        }
    }

    fn map_conn_event(&mut self, conn_id: ConnId, ev: ConnEvent) {
        let chan_of = |st: &State, key: &str| -> Option<ChanHandle> {
            st.conns
                .get(&conn_id)
                .and_then(|l| l.chans.get(key))
                .copied()
        };
        match ev {
            ConnEvent::ChannelOpened { key } => {
                if let Some(chan) = chan_of(self, &key) {
                    self.out.push(BackendEvent::ChannelOpened { chan });
                }
            }
            ConnEvent::IncomingChannel { protocol, id } => {
                self.out.push(BackendEvent::IncomingChannel {
                    conn: conn_id,
                    protocol,
                    id,
                });
            }
            ConnEvent::Message { key, value } => {
                if let Some(chan) = chan_of(self, &key) {
                    self.out.push(BackendEvent::Message { chan, value });
                }
            }
            ConnEvent::Bytes { key, bytes } => {
                if let Some(chan) = chan_of(self, &key) {
                    self.out.push(BackendEvent::Bytes { chan, bytes });
                }
            }
            ConnEvent::Drain { key } => {
                if let Some(chan) = chan_of(self, &key) {
                    self.backpressured.remove(&chan);
                    self.out.push(BackendEvent::Drain { chan });
                }
            }
            ConnEvent::ChannelClosed { key } => {
                if let Some(chan) = chan_of(self, &key) {
                    if let Some(live) = self.conns.get_mut(&conn_id) {
                        live.chans.remove(&key);
                    }
                    self.chans.remove(&chan);
                    self.out.push(BackendEvent::ChannelClosed { chan });
                    self.release_hold(chan);
                }
            }
            ConnEvent::Closed { reason } => self.conn_closed(conn_id, &reason),
        }
    }

    /// `index.js::_connClosed`.
    fn conn_closed(&mut self, conn_id: ConnId, reason: &str) {
        let Some(live) = self.conns.remove(&conn_id) else {
            return;
        };
        let mut chans: Vec<ChanHandle> = live.chans.values().copied().collect();
        chans.sort_unstable();
        for chan in chans {
            self.chans.remove(&chan);
            self.out.push(BackendEvent::ChannelClosed { chan });
            self.release_hold(chan);
        }
        if let Some(s) = self.sessions.remove(&conn_id)
            && let Some(link) = self.links.get_mut(&s.link_id)
            && link.uid == s.link_uid
        {
            link.sessions.remove(&s.session_key);
        }
        self.out.push(BackendEvent::ConnectionClosed {
            conn: conn_id,
            reason: reason.to_string(),
        });
    }

    fn release_hold(&mut self, chan: ChanHandle) {
        if let Some(held) = self.hold.remove(&chan) {
            self.out.extend(held);
        }
    }
}

fn path_str(p: Path) -> &'static str {
    match p {
        Path::Direct => "DIRECT",
        Path::Relay => "RELAY",
    }
}

fn merge(into: &mut Value, extra: Value) {
    if !into.is_object() {
        *into = json!({});
    }
    if let (Some(a), Value::Object(b)) = (into.as_object_mut(), extra) {
        for (k, v) in b {
            a.insert(k, v);
        }
    }
}

fn schedule_flush(out: &mut Outbox, ms: u64) {
    if out.flush_at.is_none() && !out.queue.is_empty() {
        out.flush_at = Some(Instant::now() + Duration::from_millis(ms));
    }
}

fn candidate_of(m: &Value) -> Option<SignalMsg> {
    let candidate = m.get("candidate").and_then(Value::as_str)?;
    Some(SignalMsg::Candidate {
        candidate: candidate.to_string(),
        mid: m
            .get("mid")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string(),
    })
}

/// `index.js::_applyRemote` for a host session: the offer once, and
/// candidates.
fn apply_remote(rtc: &RtcHost, conn_id: ConnId, m: &Value, first: bool) {
    match m.get("type").and_then(Value::as_str) {
        Some("candidate") => {
            if let Some(msg) = candidate_of(m) {
                rtc.signal(conn_id, msg);
            }
        }
        Some("offer") if first => {
            if let Some(sdp) = m.get("sdp").and_then(Value::as_str) {
                rtc.signal(
                    conn_id,
                    SignalMsg::Offer {
                        sdp: sdp.to_string(),
                    },
                );
            }
        }
        _ => {}
    }
}

impl Backend {
    /// A backend that is not started (`new FreenetBackend(opts)`).
    pub fn new(opts: BackendOptions) -> Backend {
        let rtc_default: Vec<String> = super::rtc::DEFAULT_ICE_SERVERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rtc = if opts.loopback_only {
            RtcHost::loopback_only(rtc_default)
        } else {
            RtcHost::new(rtc_default)
        };
        let clock = opts.clock.clone().unwrap_or_else(|| Arc::new(wall_ms));
        Backend {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    started: false,
                    node: None,
                    node_problem: None,
                    node_url: opts.node_url.clone(),
                    secret: None,
                    ice_given: opts.ice_servers.clone(),
                    links: HashMap::new(),
                    subs: HashMap::new(),
                    dials: HashMap::new(),
                    sessions: HashMap::new(),
                    owners: HashMap::new(),
                    conns: HashMap::new(),
                    chans: HashMap::new(),
                    hold: HashMap::new(),
                    backpressured: HashSet::new(),
                    pinned: HashMap::new(),
                    minted: HashSet::new(),
                    admission: Admission::All(false),
                    refused: 0,
                    next_conn_id: 1,
                    next_dial: 1,
                    next_chan: 1,
                    next_link_uid: 1,
                    out: Vec::new(),
                    writes: Vec::new(),
                    pending_rtc_close: Vec::new(),
                }),
                rtc: Arc::new(rtc),
                clock,
                wake: Notify::new(),
                shutdown: Notify::new(),
                start_lock: tokio::sync::Mutex::new(()),
                subscribers: Mutex::new(Vec::new()),
                task: Mutex::new(None),
                legacy_v1_routes: opts.legacy_v1_routes,
            }),
        }
    }

    /// Whether `other` is this same backend (a clone of it).
    pub fn ptr_eq(&self, other: &Backend) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// A new event stream: every event from now on.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<BackendEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.subscribers.lock().expect("subscribers").push(tx);
        rx
    }

    /// Runs `f` on the state, then emits its events, closes what it closed
    /// and starts its writes.
    ///
    /// The events are emitted before the state lock is released, so every
    /// subscriber sees them in the order the state produced them, whichever
    /// task produced them (K11, `R-12`: a `Backpressure` from the seam's
    /// reader could otherwise overtake the event loop's `Drain` that ends
    /// it). Subscriber channels are unbounded, so emitting never blocks.
    fn with<R>(&self, f: impl FnOnce(&mut State, &RtcHost) -> R) -> R {
        let (r, writes, node, closes) = {
            let mut st = self.inner.state.lock().expect("backend state");
            let r = f(&mut st, &self.inner.rtc);
            let events = st.take_out();
            self.emit(events);
            let writes = std::mem::take(&mut st.writes);
            let closes = std::mem::take(&mut st.pending_rtc_close);
            (r, writes, st.node.clone(), closes)
        };
        self.after(Vec::new(), writes, node, closes);
        r
    }

    /// [`Self::with`]'s effects, outside the lock.
    fn after(
        &self,
        events: Vec<BackendEvent>,
        writes: Vec<Write>,
        node: Option<Shared>,
        closes: Vec<(ConnId, String)>,
    ) {
        for (conn_id, reason) in closes {
            self.inner.rtc.close(conn_id, &reason);
        }
        self.emit(events);
        if let Some(node) = node {
            for w in writes {
                let node = node.clone();
                let me = self.clone();
                tokio::spawn(async move {
                    let n = w.entries.len();
                    if let Err(e) = write(&node, &w).await {
                        me.debug_now(
                            "node:update-error",
                            json!({"entries": n, "message": err_text(&e)}),
                        );
                    }
                });
            }
        }
        self.inner.wake.notify_one();
    }

    /// Emits one debug event (never generic, so a spawned write can report
    /// its failure without instantiating [`Self::with`] again).
    fn debug_now(&self, event: &str, details: Value) {
        let mut st = self.inner.state.lock().expect("backend state");
        st.debug(event, details);
        let events = st.take_out();
        self.emit(events);
    }

    fn emit(&self, events: Vec<BackendEvent>) {
        if events.is_empty() {
            return;
        }
        let mut subs = self.inner.subscribers.lock().expect("subscribers");
        subs.retain(|tx| !tx.is_closed());
        for ev in events {
            for tx in subs.iter() {
                let _ = tx.send(ev.clone());
            }
        }
    }

    // -----------------------------------------------------------------
    // BACKEND_MEMBERS
    // -----------------------------------------------------------------

    /// `describe()`.
    pub fn describe(&self) -> Value {
        json!({
            "id": BACKEND_ID,
            "label": BACKEND_LABEL,
            "interfaceVersion": 1,
            "capabilities": CAPABILITIES,
        })
    }

    /// `FreenetBackend.probe`: whether a node answers at `node_url` (one
    /// WebSocket opened and closed, nothing put or subscribed).
    pub async fn probe(node_url: &str, timeout_ms: u64) -> Value {
        match Shared::connect(node_url, timeout_ms).await {
            Ok((node, _events)) => {
                node.close();
                json!({"state": "available", "detail": null})
            }
            Err(_) => json!({"state": "broken", "detail": no_node_detail(node_url)}),
        }
    }

    /// D-11: the ICE servers every new peer connection gets (`None`: the
    /// RTC half's own list).
    pub fn set_ice_servers(&self, ice_servers: Option<Vec<String>>) {
        self.with(|st, _| st.ice_given = ice_servers);
    }

    /// `start(ctx)`: opens one WebSocket to the node and nothing else, and
    /// starts the event loop. `secret` is the device transport key
    /// (`ctx.keyPair`). A second call on a started backend is a no-op.
    pub async fn start(&self, secret: SigningKey) -> Result<(), Error> {
        let _guard = self.inner.start_lock.lock().await;
        let url = {
            let mut st = self.inner.state.lock().expect("backend state");
            if st.started {
                return Ok(());
            }
            st.secret = Some(secret);
            st.node_url.clone()
        };
        match Shared::connect(&url, node::OPEN_TIMEOUT_MS).await {
            Ok((node, events)) => {
                self.with(|st, _| {
                    st.node = Some(node);
                    st.started = true;
                    st.node_problem = None;
                    st.debug("node:open", json!({"address": url}));
                });
                let me = self.clone();
                let task = tokio::spawn(async move { me.run(events).await });
                *self.inner.task.lock().expect("task") = Some(task);
                Ok(())
            }
            Err(e) => {
                let detail = no_node_detail(&url);
                self.with(|st, _| {
                    st.node_problem = Some(detail.clone());
                    st.debug(
                        "node:unavailable",
                        json!({"address": url, "message": err_text(&e)}),
                    );
                });
                Err(unavailable(
                    format!("The 'freenet' share backend cannot start: {detail}"),
                    detail,
                ))
            }
        }
    }

    /// The event loop: node notifications, RTC events and timers.
    async fn run(self, mut node_events: mpsc::UnboundedReceiver<NodeEvent>) {
        let rtc = self.inner.rtc.clone();
        let mut node_gone = false;
        loop {
            let next = self.next_timer();
            tokio::select! {
                ev = rtc.recv_event() => {
                    let Some(ev) = ev else { break };
                    self.with(|st, rtc| st.on_rtc(rtc, ev));
                }
                ne = node_events.recv(), if !node_gone => match ne {
                    Some(NodeEvent::Notification { id, parts }) => {
                        let clock = self.inner.clock.clone();
                        self.with(|st, rtc| st.on_state(rtc, &clock, &id, &parts));
                    }
                    Some(NodeEvent::Closed) | None => {
                        self.with(|st, _| {
                            if st.node.take().is_some() {
                                let detail = format!("lost the Freenet node at {}", st.node_url);
                                st.node_problem = Some(detail);
                                let url = st.node_url.clone();
                                st.debug("node:closed", json!({"address": url}));
                            }
                        });
                        // Keep serving RTC events for live connections.
                        node_gone = true;
                    }
                },
                () = sleep_until(next) => self.on_timers(),
                () = self.inner.wake.notified() => {}
                () = self.inner.shutdown.notified() => break,
            }
        }
    }

    fn next_timer(&self) -> Option<Instant> {
        let st = self.inner.state.lock().expect("backend state");
        let flush = st
            .sessions
            .values()
            .filter_map(|s| s.out.flush_at)
            .chain(st.dials.values().filter_map(|d| d.out.flush_at));
        let deadlines = st.sessions.values().filter_map(|s| s.deadline_timer);
        flush.chain(deadlines).min()
    }

    fn on_timers(&self) {
        let clock = self.inner.clock.clone();
        self.with(|st, _| {
            let now = Instant::now();
            let sessions: Vec<ConnId> = st
                .sessions
                .iter()
                .filter(|(_, s)| s.out.flush_at.is_some_and(|t| t <= now))
                .map(|(id, _)| *id)
                .collect();
            for id in sessions {
                st.flush_session(id);
            }
            let dials: Vec<u64> = st
                .dials
                .iter()
                .filter(|(_, d)| d.out.flush_at.is_some_and(|t| t <= now))
                .map(|(id, _)| *id)
                .collect();
            for id in dials {
                st.flush_dial(id);
            }
            // S-22: a real timer backs each half-open deadline.
            let due: Vec<(ConnId, String, u64)> = st
                .sessions
                .iter()
                .filter(|(_, s)| !s.surfaced && s.deadline_timer.is_some_and(|t| t <= now))
                .map(|(id, s)| (*id, s.link_id.clone(), s.link_uid))
                .collect();
            for (conn_id, link_id, uid) in due {
                if let Some(s) = st.sessions.get_mut(&conn_id) {
                    s.deadline_timer = None;
                }
                if st.links.get(&link_id).is_some_and(|l| l.uid == uid) {
                    st.expire_half_open(&link_id, clock());
                } else {
                    // Its link was withdrawn: the slot goes all the same.
                    st.refused += 1;
                    st.drop_session(conn_id, "half-open timeout");
                }
                let at = clock();
                if let Some(s) = st.sessions.get_mut(&conn_id)
                    && !s.surfaced
                {
                    let ms = s.deadline.saturating_sub(at).max(1000);
                    s.deadline_timer = Some(now + Duration::from_millis(ms));
                }
            }
        });
    }

    /// `stop()`: cancels every dial, withdraws every link (tombstones, best
    /// effort), closes every peer connection, then the socket. Safe to call
    /// twice.
    pub async fn stop(&self) {
        let _guard = self.inner.start_lock.lock().await;
        let dials: Vec<u64> = self.with(|st, _| st.dials.keys().copied().collect());
        for d in dials {
            self.with(|st, _| {
                st.end_dial(d, Error::new(Code::EHostUnreachable, "Backend stopped"))
            });
        }
        let links: Vec<String> = self.with(|st, _| st.links.keys().cloned().collect());
        for link_id in links {
            self.withdraw_inner(&link_id).await;
        }
        let node = self.with(|st, rtc| {
            let owners: Vec<ConnId> = st.owners.keys().copied().collect();
            for conn_id in owners {
                st.owners.remove(&conn_id);
                rtc.close(conn_id, "stopped");
                st.sessions.remove(&conn_id);
            }
            let live: Vec<ConnId> = st.conns.keys().copied().collect();
            for conn_id in live {
                rtc.close(conn_id, "stopped");
                st.conn_closed(conn_id, "stopped");
            }
            st.sessions.clear();
            st.subs.clear();
            st.pinned.clear();
            st.started = false;
            st.node.take()
        });
        if let Some(node) = node {
            node.close();
        }
        self.inner.shutdown.notify_one();
        let task = self.inner.task.lock().expect("task").take();
        if let Some(task) = task {
            let _ = task.await;
        }
        // A permit left by a stop with no running loop must not end the
        // next start's loop at once.
        let _ = tokio::time::timeout(Duration::ZERO, self.inner.shutdown.notified()).await;
    }

    /// `health()`: `listening` while at least one announced link has a
    /// live subscription; `detail` is `no Freenet node at <address>` after a
    /// failed start (`D-12`).
    pub fn health(&self) -> Value {
        let st = self.inner.state.lock().expect("backend state");
        let listening = st.links.values().any(|l| {
            st.subs
                .get(&l.id)
                .is_some_and(|s| s.subscribed && s.link_uid == Some(l.uid))
        });
        json!({
            "started": st.started,
            "listening": st.started && listening,
            "detail": st.node_problem,
        })
    }

    /// The started backend's shared node connection (K16: the offline
    /// history publisher puts and updates its contract through it).
    /// `E_BACKEND_UNAVAILABLE` before `start` or after `stop`.
    pub fn node(&self) -> Result<Shared, Error> {
        self.inner.state.lock().expect("backend state").usable()
    }

    /// The node URL this backend was given.
    pub fn node_url(&self) -> String {
        self.inner
            .state
            .lock()
            .expect("backend state")
            .node_url
            .clone()
    }

    /// `localPeerKey()`: the 32-byte transport key, or `None` before start.
    pub fn local_peer_key(&self) -> Option<[u8; 32]> {
        let st = self.inner.state.lock().expect("backend state");
        st.secret.as_ref().map(|s| s.verifying_key().to_bytes())
    }

    /// `routeFor(linkId, stored?)`: the stored route, or a freshly minted
    /// one (offline; `route.js::mint`).
    pub fn route_for(&self, link_id: &str, stored: Option<Route>) -> Result<Route, Error> {
        if let Some(r) = stored {
            return Ok(r);
        }
        let bundled = contracts::bundled().map_err(|e| {
            unavailable(
                format!("The 'freenet' share backend has no signalling contract: {e}"),
                "signalling contract missing from this build",
            )
        })?;
        self.with(|st, _| {
            let Some(host) = st.my_hex() else {
                return Err(unavailable(
                    "The 'freenet' share backend has no transport key to mint a route with",
                    "no transport key",
                ));
            };
            // PV-3: a v2 backend mints `pv: 2` routes only.
            let r = if self.inner.legacy_v1_routes {
                route::mint_v1(link_id, &host, &bundled.route)
            } else {
                route::mint(link_id, &host, &bundled.route)
            };
            st.minted.insert(r.sig.clone());
            Ok(r)
        })
    }

    /// `announce(linkId, opts?)`: puts the link's signalling instance with
    /// the empty canonical state (or reads it first for a route this object
    /// did not mint) and its pointer record, and subscribes.
    pub async fn announce(
        &self,
        link_id: &str,
        route_opt: Option<Route>,
        tag: Option<Value>,
    ) -> Result<Announcement, Error> {
        drop(self.inner.start_lock.lock().await);
        let tag = tag.unwrap_or_else(|| json!({}));
        let node = self.with(|st, _| st.usable())?;
        if let Some(known) = self.with(|st, _| st.links.get(link_id).map(|l| l.route.clone())) {
            return Ok(Announcement {
                route: known,
                link_id: link_id.to_string(),
            });
        }
        let r = match route_opt {
            Some(r) => r,
            None => self.route_for(link_id, None)?,
        };
        // PV-3: a v2 host never announces a route without `pv: 2`.
        if !self.inner.legacy_v1_routes {
            route::check_pv(r.params.pv)?;
        }
        let bundled = contracts::bundled().map_err(|e| unavailable(e, "contracts"))?;
        let Some(wasm) = bundled.route.known.get(&r.code) else {
            return Err(Error::with_details(
                Code::EBackendUnsupported,
                "The Freenet route uses a signalling contract this build does not ship",
                "unknown contract code",
            ));
        };
        let (secret, host_hex) = self.with(|st, _| (st.secret.clone(), st.my_hex()));
        let (Some(secret), Some(host_hex)) = (secret, host_hex) else {
            return Err(unavailable("not started", "no transport key"));
        };
        if r.params.host != host_hex {
            return Err(Error::with_details(
                Code::EAuth,
                "The Freenet route belongs to another host",
                "route host is not this device",
            ));
        }
        let started = Instant::now();
        let params = route::params_bytes(&r.params);
        let addr = node::contract_key(wasm, &params);
        let fresh = self.with(|st, _| st.minted.contains(&r.sig));
        let (state, pointer) = tokio::join!(
            ensure_instance(&node, wasm, &params, &addr, EMPTY_STATE, fresh),
            put_pointer(&node, &r, &secret, bundled, fresh)
        );
        if let Err(e) = pointer {
            let mut d = tag.clone();
            merge(&mut d, json!({"linkId": link_id, "message": err_text(&e)}));
            self.with(|st, _| st.debug("host:pointer:error", d));
        }
        let state = state?;
        let uid = self.with(|st, _| {
            let uid = st.next_link_uid;
            st.next_link_uid += 1;
            st.links.insert(
                link_id.to_string(),
                Link {
                    uid,
                    link_id: link_id.to_string(),
                    route: r.clone(),
                    id: addr.id.clone(),
                    key: addr.key,
                    params: params.clone(),
                    payload_key: signal::payload_key(&r.k),
                    ttl_ms: r.params.ttl_ms,
                    tag: tag.clone(),
                    seen: HashMap::new(),
                    sessions: HashMap::new(),
                    answers: VecDeque::new(),
                    refused: 0,
                },
            );
            st.subscription(&addr.id).link_uid = Some(uid);
            uid
        });
        let already = self.with(|st, _| st.subs.get(&addr.id).is_some_and(|s| s.subscribed));
        if !already && let Err(e) = node.subscribe(addr.key.id()).await {
            self.with(|st, _| {
                if st.links.get(link_id).is_some_and(|l| l.uid == uid) {
                    st.links.remove(link_id);
                }
                if let Some(sub) = st.subs.get_mut(&addr.id) {
                    sub.link_uid = None;
                }
                st.release(&addr.id);
            });
            return Err(unavailable(
                format!("The 'freenet' share backend could not subscribe to the link: {e}"),
                "subscribe failed",
            ));
        }
        let clock = self.inner.clock.clone();
        self.with(|st, rtc| {
            if let Some(sub) = st.subs.get_mut(&addr.id) {
                sub.subscribed = true;
            }
            if let Some(state) = state {
                st.on_state(rtc, &clock, &addr.id, &[state]);
            }
            let mut d = tag.clone();
            merge(
                &mut d,
                json!({
                    "linkId": link_id,
                    "instance": addr.id,
                    "fresh": fresh,
                    "ms": started.elapsed().as_millis() as u64,
                }),
            );
            st.debug("host:announce", d);
        });
        Ok(Announcement {
            route: r,
            link_id: link_id.to_string(),
        })
    }

    /// `withdraw(linkId)`: ends discovery, not reachability (`D-04`): no
    /// offer is answered again and the host's own entries are tombstoned;
    /// live connections survive. Idempotent.
    pub async fn withdraw(&self, link_id: &str) {
        self.withdraw_inner(link_id).await;
    }

    async fn withdraw_inner(&self, link_id: &str) {
        let work = self.with(|st, _| {
            let link = st.links.remove(link_id)?;
            if let Some(sub) = st.subs.get_mut(&link.id)
                && sub.link_uid == Some(link.uid)
            {
                sub.link_uid = None;
                st.release(&link.id);
            }
            let mut tombstones = Vec::new();
            let ids: Vec<ConnId> = link.sessions.values().copied().collect();
            for conn_id in ids {
                if let Some(mut out) = st
                    .sessions
                    .get_mut(&conn_id)
                    .map(|s| std::mem::take(&mut s.out))
                {
                    tombstones.extend(st.tombstones(&mut out, &link.params));
                }
            }
            let mut d = link.tag.clone();
            merge(
                &mut d,
                json!({"linkId": link_id, "tombstones": tombstones.len()}),
            );
            st.debug("host:withdraw", d);
            Some((link.key, tombstones, st.node.clone()))
        });
        if let Some((key, tombstones, Some(node))) = work
            && !tombstones.is_empty()
        {
            let w = Write {
                key,
                entries: tombstones,
                timeout_ms: node::TOMBSTONE_TIMEOUT_MS,
            };
            if let Err(e) = write(&node, &w).await {
                self.debug_now(
                    "node:update-error",
                    json!({"entries": w.entries.len(), "message": err_text(&e)}),
                );
            }
        }
    }

    /// `dial(route, expectedPeerKey, opts?)`. The key is pinned at once; a
    /// route naming another host than `expected` never connects (its
    /// `connected` stays pending until cancelled), any other bad route
    /// fails at once.
    pub fn dial(&self, r: Route, expected: [u8; 32], tag: Option<Value>) -> DialHandle {
        let (tx, rx) = oneshot::channel();
        let expected_hex = hex::encode(expected);
        let id = self.with(|st, _| {
            let id = st.next_dial;
            st.next_dial += 1;
            st.pin(&expected_hex);
            st.dials.insert(
                id,
                Dial {
                    expected,
                    expected_hex: expected_hex.clone(),
                    tag: tag.unwrap_or_else(|| json!({})),
                    done: false,
                    reply: Some(tx),
                    conn_id: None,
                    instance: None,
                    key: None,
                    params: Vec::new(),
                    payload_key: [0; 32],
                    cid: String::new(),
                    r: String::new(),
                    host_r: String::new(),
                    ready: false,
                    out: Outbox::default(),
                    seen: HashMap::new(),
                    re: None,
                    answered: false,
                    fingerprint: None,
                    held: Vec::new(),
                    own_held: Vec::new(),
                    conn: None,
                    early: Vec::new(),
                    surfaced: None,
                    started_at: Instant::now(),
                    offer_at: None,
                },
            );
            id
        });
        let me = self.clone();
        tokio::spawn(async move { me.begin_dial(id, r).await });
        DialHandle { id, connected: rx }
    }

    /// `DialHandle.cancel()`: idempotent; never closes a live connection.
    pub fn cancel_dial(&self, id: u64) {
        self.with(|st, _| {
            st.end_dial(id, Error::new(Code::EHostUnreachable, "Dial was cancelled"))
        });
    }

    async fn begin_dial(&self, id: u64, r: Route) {
        drop(self.inner.start_lock.lock().await);
        if let Err(e) = self.with(|st, _| st.usable()) {
            self.with(|st, _| st.end_dial(id, e));
            return;
        }
        let Some((expected_hex, tag)) = self.with(|st, _| {
            st.dials
                .get(&id)
                .map(|d| (d.expected_hex.clone(), d.tag.clone()))
        }) else {
            return;
        };
        let bundled = match contracts::bundled() {
            Ok(b) => b,
            Err(e) => {
                self.with(|st, _| st.end_dial(id, unavailable(e, "contracts")));
                return;
            }
        };
        let verified = if self.inner.legacy_v1_routes {
            route::verify_v1(&r, &expected_hex, &bundled.route)
        } else {
            route::verify(&r, &expected_hex, &bundled.route)
        };
        match verified {
            Ok(checked) => {
                let res = self.start_dial(id, &r, checked).await;
                if let Err(e) = res {
                    self.with(|st, _| st.end_dial(id, e));
                }
            }
            Err(err) => {
                let mut d = tag;
                merge(
                    &mut d,
                    json!({"code": err.code.as_str(), "detail": err.details}),
                );
                self.with(|st, _| st.debug("viewer:route-refused", d));
                if err.code == Code::EAuth {
                    return;
                }
                // PV-2: only an unknown contract code falls back to the
                // pointer record, never a route-version refusal.
                if err.code == Code::EBackendUnsupported
                    && err.details.as_deref() == Some("unknown contract code")
                    && r.ptr.is_some()
                {
                    let res = self.via_pointer(id, &r, err).await;
                    if let Err(e) = res {
                        self.with(|st, _| st.end_dial(id, e));
                    }
                    return;
                }
                self.with(|st, _| st.end_dial(id, err));
            }
        }
    }

    /// `index.js::_viaPointer`: an unknown contract code, looked up through
    /// the route's pointer record.
    async fn via_pointer(&self, id: u64, r: &Route, unsupported: Error) -> Result<(), Error> {
        let bundled = contracts::bundled().map_err(|e| unavailable(e, "contracts"))?;
        let node = self.with(|st, _| st.usable())?;
        let expected = self.with(|st, _| st.dials.get(&id).map(|d| d.expected));
        let Some(expected) = expected else {
            return Ok(());
        };
        let ptr_params = route::pointer_params_bytes(&r.params.host, &r.params.n);
        let addr = node::contract_key(bundled.pointer_wasm, &ptr_params);
        if Some(&addr.id) != r.ptr.as_ref() {
            return Err(unsupported);
        }
        let record = node
            .get(addr.key.id(), node::POINTER_GET_MS)
            .await
            .ok()
            .and_then(|state| serde_json::from_slice::<Value>(&state).ok())
            .and_then(|v| {
                Some(signal::Record {
                    ver: v.get("ver")?.as_u64()?,
                    sig: v.get("sig")?.as_str()?.to_string(),
                    code: v.get("code")?.as_str()?.to_string(),
                    params: v.get("params")?.as_str()?.to_string(),
                    g: v.get("g")?.as_str()?.to_string(),
                })
            })
            .ok_or(unsupported)?;
        if self.with(|st, _| st.dials.get(&id).is_none_or(|d| d.done)) {
            return Ok(());
        }
        let key = VerifyingKey::from_bytes(&expected).map_err(|_| {
            Error::with_details(Code::EAuth, "bad expected key", "bad expected key")
        })?;
        if !signal::verify_record(&key, &ptr_params, &record) {
            return Err(Error::with_details(
                Code::EAuth,
                "The Freenet route's pointer record is not signed by the host",
                "pointer record not signed by the host",
            ));
        }
        let params: Value = serde_json::from_str(&record.params).map_err(|_| {
            Error::with_details(
                Code::ECorrupt,
                "The Freenet route is malformed",
                "malformed route",
            )
        })?;
        // PV-2: a route rebuilt from the pointer record goes through PV-1
        // again (its params carry `pv` when a v2 host wrote the record).
        let rebuilt = json!({
            "sig": record.sig, "code": record.code, "params": params, "k": r.k,
        });
        let next = if self.inner.legacy_v1_routes {
            route_from_json_v1(&rebuilt)?
        } else {
            route_from_json(&rebuilt)?
        };
        self.with(|st, _| {
            let d = json!({"ver": record.ver, "instance": record.sig});
            st.debug("viewer:pointer", d)
        });
        let checked = if self.inner.legacy_v1_routes {
            route::verify_v1(&next, &hex::encode(expected), &bundled.route)?
        } else {
            route::verify(&next, &hex::encode(expected), &bundled.route)?
        };
        self.start_dial(id, &next, checked).await
    }

    /// `index.js::_startDial`.
    async fn start_dial(&self, id: u64, r: &Route, checked: route::Checked) -> Result<(), Error> {
        let addr = node::contract_key(&checked.wasm, &checked.params);
        let node = self.with(|st, rtc| -> Result<Option<Shared>, Error> {
            let node = st.usable()?;
            let Some(my_hex) = st.my_hex() else {
                return Err(unavailable("not started", "no transport key"));
            };
            let conn_id = st.next_conn_id;
            let ice = st.ice();
            let Some(dial) = st.dials.get_mut(&id) else {
                return Ok(None);
            };
            if dial.done {
                return Ok(None);
            }
            st.next_conn_id += 1;
            dial.instance = Some(addr.id.clone());
            dial.key = Some(addr.key);
            dial.params = checked.params.clone();
            dial.payload_key = signal::payload_key(&r.k);
            dial.cid = random_cid_hex();
            dial.r = format!("v:{my_hex}");
            dial.host_r = format!("h:{my_hex}");
            dial.conn_id = Some(conn_id);
            // The peer connection gathers while the instance is fetched.
            rtc.open(conn_id, ice);
            let mut conn = Connection::new(conn_id, dial.expected.to_vec(), true, None);
            conn.open_bootstrap_channel(rtc);
            dial.conn = Some(conn);
            st.owners.insert(conn_id, Owner::Dial(id));
            st.subscription(&addr.id).dials.insert(id);
            Ok(Some(node))
        })?;
        let Some(node) = node else { return Ok(()) };
        let state = loop {
            if self.with(|st, _| st.dials.get(&id).is_none_or(|d| d.done)) {
                return Ok(());
            }
            match node.get(addr.key.id(), node::REQUEST_TIMEOUT_MS).await {
                Ok(state) => break state,
                Err(e) => {
                    let d = json!({"instance": addr.id, "message": err_text(&e)});
                    self.with(|st, _| st.debug("viewer:get-miss", d));
                    tokio::time::sleep(Duration::from_millis(node::DIAL_GET_GAP_MS)).await;
                }
            }
        };
        let already = self.with(|st, _| st.subs.get(&addr.id).is_some_and(|s| s.subscribed));
        if !already && let Err(e) = node.subscribe(addr.key.id()).await {
            return Err(unavailable(
                format!("The 'freenet' share backend could not subscribe to the link: {e}"),
                "subscribe failed",
            ));
        }
        self.with(|st, rtc| {
            if let Some(sub) = st.subs.get_mut(&addr.id) {
                sub.subscribed = true;
            }
            let Some(dial) = st.dials.get_mut(&id) else {
                return;
            };
            if dial.done {
                return;
            }
            dial.ready = true;
            let mut d = dial.tag.clone();
            merge(
                &mut d,
                json!({"instance": addr.id, "ms": dial.started_at.elapsed().as_millis() as u64}),
            );
            if !dial.out.queue.is_empty() {
                dial.out.flush_at = Some(Instant::now());
            }
            st.debug("viewer:subscribed", d);
            st.on_state(rtc, &self.inner.clock, &addr.id, &[state]);
        });
        Ok(())
    }

    /// `setAdmission(policy)`.
    pub fn set_admission(&self, policy: Admission) {
        self.with(|st, _| st.admission = policy);
    }

    /// `serveHistory(conn, store)`: opens (or finds) the connection's
    /// history channel, `zbterm/history 00`, as a raw channel. Idempotent
    /// per connection.
    pub fn serve_history(&self, conn: ConnHandle) -> Result<ChanHandle, Error> {
        self.history_channel(conn)
    }

    /// `attachHistory(conn, store, keys?)`: the same channel as
    /// [`Self::serve_history`]; the keys are the caller's (`history.js`
    /// ignores them too).
    pub fn attach_history(&self, conn: ConnHandle) -> Result<ChanHandle, Error> {
        self.history_channel(conn)
    }

    fn history_channel(&self, conn: ConnHandle) -> Result<ChanHandle, Error> {
        let key = super::channel::label_of(wire::HISTORY_PROTOCOL, &HISTORY_ID);
        let existing =
            self.with(|st, _| st.conns.get(&conn).and_then(|l| l.chans.get(&key)).copied());
        match existing {
            Some(chan) => Ok(chan),
            None => self.open_raw(conn, wire::HISTORY_PROTOCOL, &HISTORY_ID),
        }
    }

    /// `historyRouteFor(store)`: history rides the live connection; there
    /// is no offline route (`D-13`).
    pub fn history_route_for(&self) -> Option<Value> {
        None
    }

    /// `diagnostics()`: JSON-safe; never a route's `k`, never SDP, never an
    /// ICE credential. Always carries `announced`.
    pub fn diagnostics(&self) -> Value {
        let clock = self.inner.clock.clone();
        let mut st = self.inner.state.lock().expect("backend state");
        let now = clock();
        let link_ids: Vec<String> = st.links.keys().cloned().collect();
        let mut links = Vec::new();
        for link_id in link_ids {
            let answered = st.answered_in_window(&link_id, now);
            let link = &st.links[&link_id];
            links.push(json!({
                "linkId": link.link_id,
                "instance": link.id,
                "entries": st.subs.get(&link.id).map(|s| s.entries).unwrap_or(0),
                "answeredLastMinute": answered,
                "halfOpen": st.half_open(link.uid, None),
                "refused": link.refused,
            }));
        }
        let mut conn_ids: Vec<&ConnId> = st.conns.keys().collect();
        conn_ids.sort_unstable();
        let conns: Vec<Value> = conn_ids
            .into_iter()
            .map(|id| {
                let l = &st.conns[id];
                json!({
                    "peer": hex::encode(l.remote),
                    "iceState": l.ice_state,
                    "path": path_str(l.conn.path()),
                    "channels": l.conn.channel_count(),
                })
            })
            .collect();
        let given = st.ice_given.clone();
        json!({
            "backend": BACKEND_ID,
            "started": st.started,
            "announced": st.links.len(),
            "node": {"address": st.node_url, "version": null, "wsRttMs": null},
            "ice": {
                "servers": given.as_ref().map(|g| g.iter().map(|s| redact_ice_server(s)).collect::<Vec<_>>()),
                "hostCandidatesOnly": given.as_ref().is_some_and(Vec::is_empty),
                "relay": false,
            },
            "links": links,
            "conns": conns,
            "refused": st.refused,
        })
    }

    // -----------------------------------------------------------------
    // connections and channels
    // -----------------------------------------------------------------

    /// The remote key, initiator flag and link of a live connection.
    pub fn connection_info(&self, conn: ConnHandle) -> Option<([u8; 32], bool, Option<String>)> {
        let st = self.inner.state.lock().expect("backend state");
        st.conns
            .get(&conn)
            .map(|l| (l.remote, l.initiator, l.link_id.clone()))
    }

    /// `connection.close(reason)`.
    pub fn close_connection(&self, conn: ConnHandle, reason: &str) {
        self.with(|st, rtc| {
            if let Some(l) = st.conns.get_mut(&conn) {
                l.conn.close(rtc, reason);
            }
        });
    }

    /// `connection.openChannel(protocol, id)`: a JSON channel.
    pub fn open_channel(
        &self,
        conn: ConnHandle,
        protocol: &str,
        id: &[u8],
    ) -> Result<ChanHandle, Error> {
        self.open_with(conn, protocol, id, false, false)
    }

    /// A raw ordered byte channel on `conn` (`history.js::HistoryChannel`'s
    /// twin): bytes in, bytes out, never interpreted.
    pub fn open_raw(
        &self,
        conn: ConnHandle,
        protocol: &str,
        id: &[u8],
    ) -> Result<ChanHandle, Error> {
        self.open_with(conn, protocol, id, true, false)
    }

    /// [`Self::open_channel`]/[`Self::open_raw`]; with `hold`, the channel's
    /// events wait for [`Self::release`] (the seam replies with the handle
    /// before any of its data).
    pub fn open_with(
        &self,
        conn: ConnHandle,
        protocol: &str,
        id: &[u8],
        raw: bool,
        hold: bool,
    ) -> Result<ChanHandle, Error> {
        let kind = if raw {
            ChannelKind::Raw
        } else {
            ChannelKind::Json
        };
        self.open_kind(conn, protocol, id, kind, hold)
    }

    /// A binary message channel on `conn` (K13, `protocol.md` §5): part
    /// framed like a JSON channel, but every message is opaque bytes, sent
    /// with [`Self::send_bytes`] (one call, one message) and delivered as
    /// one [`BackendEvent::Bytes`] each, with the same
    /// [`BackendEvent::Backpressure`]/[`BackendEvent::Drain`] signals as a
    /// raw channel.
    pub fn open_binary(
        &self,
        conn: ConnHandle,
        protocol: &str,
        id: &[u8],
    ) -> Result<ChanHandle, Error> {
        self.open_kind(conn, protocol, id, ChannelKind::Binary, false)
    }

    /// [`Self::open_with`] for any [`ChannelKind`].
    pub fn open_kind(
        &self,
        conn: ConnHandle,
        protocol: &str,
        id: &[u8],
        kind: ChannelKind,
        hold: bool,
    ) -> Result<ChanHandle, Error> {
        self.with(|st, rtc| {
            let chan = st.next_chan;
            let Some(live) = st.conns.get_mut(&conn) else {
                return Err(Error::with_details(
                    Code::EHostUnreachable,
                    "Connection is closed",
                    "no such connection",
                ));
            };
            let (key, held) = live
                .conn
                .open_channel_kind(rtc, protocol, id, kind)
                .map_err(|e| Error::new(Code::EInternal, e))?;
            st.next_chan += 1;
            if let Some(live) = st.conns.get_mut(&conn) {
                live.chans.insert(key.clone(), chan);
            }
            st.chans.insert(chan, (conn, key));
            if hold {
                st.hold.insert(chan, Vec::new());
            }
            for ev in held {
                st.map_conn_event(conn, ev);
            }
            Ok(chan)
        })
    }

    /// Emits the events a held channel collected, and every later one.
    pub fn release(&self, chan: ChanHandle) {
        self.with(|st, _| st.release_hold(chan));
    }

    /// `channel.send(message)` on a JSON channel.
    pub fn send(&self, chan: ChanHandle, message: &Value) -> bool {
        self.with(|st, rtc| {
            let Some((conn, key)) = st.chans.get(&chan).cloned() else {
                return false;
            };
            st.conns
                .get_mut(&conn)
                .is_some_and(|l| l.conn.send(rtc, &key, message))
        })
    }

    /// Sends bytes on a raw channel (or, K13, one message on a binary
    /// channel); `false` under back-pressure (a
    /// [`BackendEvent::Backpressure`] is emitted, and a
    /// [`BackendEvent::Drain`] follows) or when closed.
    pub fn send_bytes(&self, chan: ChanHandle, bytes: &[u8]) -> bool {
        self.with(|st, rtc| {
            let Some((conn, key)) = st.chans.get(&chan).cloned() else {
                return false;
            };
            let more = st
                .conns
                .get_mut(&conn)
                .is_some_and(|l| l.conn.send_bytes(rtc, &key, bytes));
            if !more && st.backpressured.insert(chan) {
                st.out.push(BackendEvent::Backpressure { chan });
            }
            more
        })
    }

    /// `channel.close()`.
    pub fn close_channel(&self, chan: ChanHandle) {
        self.with(|st, rtc| {
            let Some((conn, key)) = st.chans.remove(&chan) else {
                return;
            };
            if let Some(l) = st.conns.get_mut(&conn) {
                l.conn.close_channel(rtc, &key);
                l.chans.remove(&key);
            }
            st.out.push(BackendEvent::ChannelClosed { chan });
            st.release_hold(chan);
        });
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

async fn write(node: &Shared, w: &Write) -> Result<(), Error> {
    let delta = serde_json::to_vec(&json!({"e": w.entries})).expect("entries serialize");
    node.update(&w.key, delta, w.timeout_ms).await
}

/// `index.js::_ensureInstance`: the state the node holds, or `None` after a
/// put of `initial`.
async fn ensure_instance(
    node: &Shared,
    wasm: &[u8],
    params: &[u8],
    addr: &node::ContractAddr,
    initial: &[u8],
    fresh: bool,
) -> Result<Option<Vec<u8>>, Error> {
    if !fresh && let Ok(state) = node.get(addr.key.id(), node::ANNOUNCE_GET_MS).await {
        return Ok(Some(state));
    }
    match node
        .put(wasm, params, initial.to_vec(), node::REQUEST_TIMEOUT_MS)
        .await
    {
        Ok(()) => Ok(None),
        Err(err) => match node.get(addr.key.id(), node::ANNOUNCE_GET_MS).await {
            // S-05 b: a put of an instance the node holds is never
            // answered with a PutResponse.
            Ok(state) => Ok(Some(state)),
            Err(_) => Err(unavailable(
                format!(
                    "The 'freenet' share backend could not put the link's contract: {}",
                    err_text(&err)
                ),
                "put failed",
            )),
        },
    }
}

/// `index.js::_putPointer`: the link's pointer record, version 1, naming
/// the link's own signalling instance.
async fn put_pointer(
    node: &Shared,
    r: &Route,
    secret: &SigningKey,
    bundled: &contracts::Bundled,
    fresh: bool,
) -> Result<(), Error> {
    let Some(ptr) = &r.ptr else { return Ok(()) };
    let ptr_params = route::pointer_params_bytes(&r.params.host, &r.params.n);
    let addr = node::contract_key(bundled.pointer_wasm, &ptr_params);
    if addr.id != *ptr {
        return Err(Error::new(
            Code::ECorrupt,
            "the route names another pointer record",
        ));
    }
    let params_text = String::from_utf8(route::params_bytes(&r.params)).expect("utf8 params");
    let record = signal::sign_record(
        secret,
        &ptr_params,
        node::POINTER_VER,
        &r.sig,
        &r.code,
        &params_text,
    );
    // The pointer contract accepts only its canonical encoding: the fields
    // in declaration order (`contracts/src/pointer`'s `Record`), as
    // `JSON.stringify` of `signal.js::signRecord`'s object writes them.
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        ver: u64,
        sig: &'a str,
        code: &'a str,
        params: &'a str,
        g: &'a str,
    }
    let state = serde_json::to_vec(&Canonical {
        ver: record.ver,
        sig: &record.sig,
        code: &record.code,
        params: &record.params,
        g: &record.g,
    })
    .expect("record serializes");
    ensure_instance(
        node,
        bundled.pointer_wasm,
        &ptr_params,
        &addr,
        &state,
        fresh,
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_address_keeps_scheme_host_and_port() {
        assert_eq!(
            node_address("ws://127.0.0.1:7509/v1/contract/command"),
            "ws://127.0.0.1:7509"
        );
        assert_eq!(node_address("WSS://node.example/x"), "WSS://node.example");
        assert_eq!(node_address("not a url"), "not a url");
        assert_eq!(
            no_node_detail(node::DEFAULT_NODE_URL),
            "no Freenet node at ws://127.0.0.1:7509"
        );
    }

    #[test]
    fn redact_ice_server_drops_turn_credentials() {
        assert_eq!(
            redact_ice_server("turn:user:secret@host:3478"),
            "turn:host:3478"
        );
        assert_eq!(redact_ice_server("TURNS:u:p@h:5349"), "TURNS:h:5349");
        assert_eq!(
            redact_ice_server("stun:stun.example:3478"),
            "stun:stun.example:3478"
        );
    }

    #[test]
    fn refusals_carry_the_js_reason_strings() {
        for (r, s) in [
            (Refusal::HalfOpen, "half-open"),
            (Refusal::HalfOpenViewer, "half-open-viewer"),
            (Refusal::Rate, "rate"),
            (Refusal::Admission, "admission"),
        ] {
            assert_eq!(r.as_str(), s);
            assert_eq!(Refusal::parse(s), Some(r));
            let e = r.to_error();
            assert_eq!(e.code, Code::EBackendUnavailable);
            assert_eq!(e.details.as_deref(), Some(s));
        }
        assert_eq!(Refusal::parse("other"), None);
    }

    #[test]
    fn capabilities_match_index_js() {
        // AUTHENTICATED_PEER | MULTIPLEXED_STREAMS | ORDERED_STREAM |
        // EPHEMERAL_DELIVERY | NAT_TRAVERSAL | BROKERED |
        // HISTORY_SPARSE_READ | HISTORY_HEAD_WATCH
        assert_eq!(CAPABILITIES, 1 + 2 + 4 + 8 + 32 + 128 + 512 + 1024);
    }

    #[test]
    fn route_json_round_trips() {
        let r = Route {
            sig: "s".into(),
            code: "c".into(),
            params: RouteParams {
                ttl_ms: 120_000,
                host: "h".into(),
                n: "n".into(),
                pv: Some(2),
            },
            ptr: Some("p".into()),
            k: "k".into(),
        };
        assert_eq!(route_from_json(&route_to_json(&r)).unwrap(), r);
        assert_eq!(route_to_json(&r)["params"]["pv"], 2);
        let mut v1 = r.clone();
        v1.params.pv = None;
        assert!(route_to_json(&v1)["params"].get("pv").is_none());
        assert_eq!(route_from_json_v1(&route_to_json(&v1)).unwrap(), v1);
        let refused = route_from_json(&route_to_json(&v1)).unwrap_err();
        assert_eq!(refused.code, Code::EBackendUnsupported);
        assert_eq!(
            route_from_json(&json!({"sig": 1, "params": {"pv": 2}}))
                .unwrap_err()
                .code,
            Code::ECorrupt
        );
    }
}

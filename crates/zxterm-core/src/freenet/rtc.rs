//! WebRTC peer connections and data channels (K6, spike S2), driving
//! `str0m`'s sans-IO `Rtc` state machine on a `tokio` `UdpSocket`. The
//! public API is shaped like ZBTerm `electron/rtc-host.js::RtcHost`: one
//! [`RtcHost`] opens and drives many connections, each identified by a
//! caller-chosen `conn_id`, and emits every event (`signal`, `state`,
//! `channel`, `data`, `flow`, `close`) with that `conn_id` on one event
//! stream — `super::connection` and `super::dial` consume it exactly as
//! `connection.js`/`index.js` consume `RtcHost`'s `EventEmitter`.
//!
//! `str0m` is sans-IO: it produces `Output::Transmit`/`Output::Timeout`/
//! `Output::Event` values that the caller must act on over its own socket
//! and timer. Each open connection gets its own `tokio` task owning one
//! `Rtc` and one `UdpSocket`; the task loop below (`ConnTask::run`) is the
//! whole of that driving loop — a bug here (a missed timeout tick, wrong
//! handling of a `Transmit`) looks like a `str0m` bug but is this file's.
//!
//! Every call on [`RtcHost`] (`open`, `signal`, `open_channel`,
//! `close_channel`, `send`, `close`, `close_all`) is a plain, synchronous,
//! fire-and-forget push onto that connection's own command queue — the same
//! shape as `RtcHost`'s JS API, and safe here because nothing in this
//! project's `channel.js`/`connection.js` port ever reads `RtcHost.send`'s
//! return value (`channel.js::_pump` and `connection.js::_channelEvent`
//! both discard it); back-pressure is tracked one layer up, in
//! [`super::channel::Channel`], driven by this module's `flow` events.
//! `open` still needs to run inside a `tokio` runtime (to spawn the task),
//! which every caller in this crate already is.
//!
//! **Host-candidate gathering only** (deliberate, matches this phase's own
//! tests: "no ICE servers, loopback host candidates only"). Each
//! connection binds one `127.0.0.1:0` UDP socket and offers its address as
//! a single ICE host candidate. `ice_servers` is accepted (so the API shape
//! matches `RtcHost`'s and a caller can pass `DEFAULT_ICE_SERVERS`) but
//! this phase does not implement STUN/TURN gathering: no server-reflexive
//! or relayed candidate is ever produced. A later phase that needs real NAT
//! traversal (crossing the public internet, D-11's actual deployment case)
//! must add a STUN client here; nothing in this module's shape blocks that
//! — `open`'s `ice_servers` parameter is already threaded through, unused.
//!
//! > 2026-09-29, K10: STUN added (`X-10`, `D-11`). A connection now binds
//! > the loopback interface and, when the default route names one, the
//! > primary interface (`super::stun::primary_ipv4`), offering a host
//! > candidate for each; every `stun:` URL of its ICE list is resolved and
//! > asked for a server-reflexive address (`super::stun`), which is
//! > trickled as a `srflx` candidate. `RtcHost::loopback_only` keeps K6's
//! > loopback-only binding. TURN is still not implemented; `turn:` URLs are
//! > ignored.
//!
//! **`mid` is not tracked.** WebRTC's ICE transport is bundled across the
//! whole session in every peer this project talks to (ZBTerm's
//! `node-datachannel` and this module both never negotiate more than one
//! `m=application` line), so a candidate's `sdpMid` is always the same
//! value; outgoing candidate messages carry `"0"` and an incoming `mid` is
//! accepted but ignored (`str0m::Rtc::add_remote_candidate` takes no `mid`
//! parameter at all — a single ICE agent covers the whole connection).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId as StrChanId;
use str0m::net::{Protocol as NetProtocol, Receive};
use str0m::{Candidate, Event as StrEvent, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as TokioMutex, mpsc};

/// `electron/rtc-host.js::MAX_MESSAGE_SIZE`.
pub const MAX_MESSAGE_SIZE: usize = 65536;
/// `electron/rtc-host.js::HIGH_WATER_MARK`.
pub const HIGH_WATER_MARK: usize = 1024 * 1024;
/// `electron/rtc-host.js::LOW_WATER_MARK`.
pub const LOW_WATER_MARK: usize = 256 * 1024;
/// `electron/rtc-host.js::REMOTE_CHANNEL_BASE`.
pub const REMOTE_CHANNEL_BASE: u32 = 0x8000_0000;
/// `electron/rtc-host.js::DEFAULT_ICE_SERVERS` (`D-11`).
pub const DEFAULT_ICE_SERVERS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
];

pub type ConnId = u64;
pub type ChanId = u32;

/// A signalling message, `rtc-host.js`'s `signal` event body's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalMsg {
    Offer { sdp: String },
    Answer { sdp: String },
    Candidate { candidate: String, mid: String },
}

/// `rtc-host.js`'s `state` event's `state` field (only the values this
/// project's `index.js`/`connection.js` port ever act on: `'connecting'`
/// and `'new'` are not surfaced — see the module doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    Connected,
    Failed,
    Closed,
}

/// `rtc-host.js`'s `channel` event's `op` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelOp {
    Opened,
    Closed,
}

/// One event this `RtcHost` emits, always carrying the `conn_id` it
/// belongs to (`rtc-host.js`'s events, each with `connId`).
#[derive(Debug, Clone)]
pub enum RtcEvent {
    Signal {
        conn_id: ConnId,
        msg: SignalMsg,
    },
    State {
        conn_id: ConnId,
        state: IceState,
        local_fingerprint: Option<String>,
        remote_fingerprint: Option<String>,
        /// `'host'` for every path in this phase (no relay support yet;
        /// see the module doc comment).
        path_kind: Option<String>,
    },
    Channel {
        conn_id: ConnId,
        chan_id: ChanId,
        label: String,
        op: ChannelOp,
    },
    Data {
        conn_id: ConnId,
        chan_id: ChanId,
        data: Vec<u8>,
    },
    Flow {
        conn_id: ConnId,
        chan_id: ChanId,
        paused: bool,
    },
    Close {
        conn_id: ConnId,
        reason: String,
    },
}

enum Cmd {
    /// A resolved `stun:` server (K10): send it a Binding Request.
    Stun(SocketAddr),
    Signal(SignalMsg),
    OpenChannel {
        chan_id: ChanId,
        label: String,
    },
    CloseChannel {
        chan_id: ChanId,
    },
    Send {
        chan_id: ChanId,
        data: Vec<u8>,
    },
    Close {
        reason: String,
    },
}

/// `'<hash_func lowercase> <HEX:UPPERCASE:...>'`, the shape
/// `signal.rs::sdp_fingerprint`/`rtc-host.js::sdpFingerprint` also produce.
fn format_fingerprint(fp: &str0m::crypto::Fingerprint) -> String {
    let hex: Vec<String> = fp.bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("{} {}", fp.hash_func.to_ascii_lowercase(), hex.join(":"))
}

/// One bound UDP socket of a connection and the host candidate it offers.
struct Sock {
    socket: UdpSocket,
    addr: SocketAddr,
}

/// A STUN Binding transaction in flight (K10, `super::stun`).
struct StunTx {
    id: super::stun::TransactionId,
    server: SocketAddr,
    /// Index into `ConnTask::sockets`.
    via: usize,
    next_send: Instant,
    tries: u32,
}

/// How often a Binding Request is sent before the server counts as
/// silent, and the gaps between tries (RFC 8489 §6.2.1's doubling RTO,
/// cut short: ICE trickles, so a late `srflx` candidate is still useful but
/// a silent server must not keep a connection busy).
const STUN_TRIES: u32 = 4;
const STUN_FIRST_RTO_MS: u64 = 250;

/// Drives one `Rtc` peer connection on its own `UdpSocket`s, in its own
/// `tokio` task (`ConnTask::run`).
struct ConnTask {
    conn_id: ConnId,
    rtc: Rtc,
    /// The loopback socket first, then the primary interface's, if any
    /// (K10; K6 had the loopback one only).
    sockets: Vec<Sock>,
    stun: Vec<StunTx>,
    events_tx: mpsc::UnboundedSender<RtcEvent>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    conns: Arc<StdMutex<HashMap<ConnId, mpsc::UnboundedSender<Cmd>>>>,
    pending_offer: Option<SdpPendingOffer>,
    /// str0m's own `ChannelId` <-> this crate's `chan_id`, both directions.
    str0m_to_ours: HashMap<StrChanId, ChanId>,
    ours_to_str0m: HashMap<ChanId, StrChanId>,
    next_remote: u32,
    paused: std::collections::HashSet<StrChanId>,
    /// Parts `handle_send` could not hand to `str0m` yet: `Channel::write`
    /// returns `Ok(false)` (not an error — see `handle_send`'s own doc
    /// comment) when the SCTP association's own send buffer has no room
    /// right now, and a write it does not accept is not queued anywhere
    /// inside `str0m` — it is simply not sent unless *this* code holds
    /// onto it and retries.
    pending_writes: HashMap<StrChanId, std::collections::VecDeque<Vec<u8>>>,
    closed: bool,
}

impl ConnTask {
    async fn run(mut self) {
        // One host candidate per bound socket, gathered up front; `srflx`
        // candidates follow as STUN servers answer (`handle_stun`).
        let addrs: Vec<SocketAddr> = self.sockets.iter().map(|s| s.addr).collect();
        for addr in addrs {
            if let Ok(candidate) = Candidate::host(addr, "udp") {
                self.add_local(candidate);
            }
        }

        let mut buf = vec![0u8; 2048];
        let mut buf2 = vec![0u8; 2048];
        loop {
            let mut timeout_at = self.drain_output(&mut buf).await;
            if self.closed {
                break;
            }
            self.send_stun().await;
            if let Some(next) = self.stun.iter().map(|t| t.next_send).min() {
                timeout_at = timeout_at.min(next);
            }
            let sleep = tokio::time::sleep_until(to_tokio_instant(timeout_at));
            let second = self.sockets.get(1).map(|s| &s.socket);
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Cmd::Close { reason }) => self.close_gracefully(reason).await,
                        Some(c) => self.handle_cmd(c),
                        None => {
                            self.teardown("dropped".to_string());
                        }
                    }
                }
                () = sleep => {
                    let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
                }
                recv = self.sockets[0].socket.recv_from(&mut buf) => {
                    if let Ok((n, source)) = recv {
                        self.receive(0, source, &buf[..n]);
                    }
                }
                recv = recv_on(second, &mut buf2) => {
                    if let Ok((n, source)) = recv {
                        self.receive(1, source, &buf2[..n]);
                    }
                }
            }
            // Retry every channel with anything still queued, on every
            // loop tick — not only on `ChannelBufferedAmountLow`,
            // which fires on *that* threshold (`LOW_WATER_MARK`) being
            // crossed from above and never fires at all if `write()`
            // instead refused a part because `str0m`'s own lower-level
            // SCTP send-window (`Channel::write`'s `available()` check)
            // was briefly exhausted while `buffered_amount()` never
            // reached `LOW_WATER_MARK` to begin with — a real gap this
            // phase hit converting a two-Rust-peer test flaky (a channel
            // opened *after* the connection was already up is not
            // actually writable to for one extra loop tick past its own
            // `ChannelOpen` event, so the very next part written after it
            // can land in exactly this window).
            // K11 (`R-11`): a paused channel is checked on every tick too,
            // so it resumes as soon as its backlog is low, whether or not
            // `str0m` reports `ChannelBufferedAmountLow` for it.
            let mut due: Vec<StrChanId> = self.pending_writes.keys().copied().collect();
            due.extend(
                self.paused
                    .iter()
                    .copied()
                    .filter(|s| !self.pending_writes.contains_key(s)),
            );
            for scid in due {
                self.drain_pending_writes(scid);
            }
            if self.closed {
                break;
            }
        }
        self.conns
            .lock()
            .expect("conns mutex")
            .remove(&self.conn_id);
    }

    /// Drains `poll_output` until `Output::Timeout`, sending every
    /// transmit and translating every event. Returns the next deadline.
    async fn drain_output(&mut self, buf: &mut [u8]) -> Instant {
        loop {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    let via = self.socket_for(t.source, t.destination);
                    let _ = self.sockets[via]
                        .socket
                        .send_to(&t.contents, t.destination)
                        .await;
                }
                Ok(Output::Timeout(t)) => return t,
                Ok(Output::Event(e)) => self.handle_event(e, buf),
                Err(_e) => {
                    self.teardown("error".to_string());
                    return Instant::now();
                }
            }
            if self.closed {
                return Instant::now();
            }
        }
    }

    /// `Rtc::close` (K10): SCTP shutdown and a DTLS `close_notify`, sent
    /// before the task ends, so the remote hears of the close at once
    /// (`Event::Closed` there) instead of when ICE consent runs out.
    async fn close_gracefully(&mut self, reason: String) {
        if self.closed {
            return;
        }
        let _ = self.rtc.close();
        for _ in 0..64 {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    let via = self.socket_for(t.source, t.destination);
                    let _ = self.sockets[via]
                        .socket
                        .send_to(&t.contents, t.destination)
                        .await;
                }
                Ok(Output::Event(_)) => {}
                Ok(Output::Timeout(_)) | Err(_) => break,
            }
            if !self.rtc.is_alive() {
                break;
            }
        }
        self.teardown(reason);
    }

    /// Adds a local candidate to the ICE agent and signals it.
    fn add_local(&mut self, candidate: Candidate) {
        let Some(added) = self.rtc.add_local_candidate(candidate) else {
            return;
        };
        let line = added.to_sdp_string();
        let _ = self.events_tx.send(RtcEvent::Signal {
            conn_id: self.conn_id,
            msg: SignalMsg::Candidate {
                candidate: line,
                mid: "0".to_string(),
            },
        });
    }

    /// The socket a transmit leaves by: the one bound to its `source`, else
    /// the loopback one for a loopback destination and the interface one
    /// for any other.
    fn socket_for(&self, source: SocketAddr, destination: SocketAddr) -> usize {
        if let Some(i) = self.sockets.iter().position(|s| s.addr == source) {
            return i;
        }
        if !destination.ip().is_loopback() && self.sockets.len() > 1 {
            1
        } else {
            0
        }
    }

    /// A datagram on socket `via`: a STUN answer to one of this
    /// connection's own Binding Requests is consumed here; anything else
    /// goes to the ICE agent.
    fn receive(&mut self, via: usize, source: SocketAddr, data: &[u8]) {
        if let Some((_, id)) = super::stun::header(data)
            && let Some(pos) = self
                .stun
                .iter()
                .position(|t| t.id == id && t.server == source)
        {
            let tx = self.stun.remove(pos);
            if let Some(mapped) = super::stun::mapped_address(data, &tx.id) {
                let base = self.sockets[tx.via].addr;
                if mapped != base
                    && mapped.is_ipv4() == base.is_ipv4()
                    && let Ok(c) = Candidate::server_reflexive(mapped, base, "udp")
                {
                    self.add_local(c);
                }
            }
            return;
        }
        let destination = self.sockets[via].addr;
        if let Ok(contents) = data.try_into() {
            let _ = self.rtc.handle_input(Input::Receive(
                Instant::now(),
                Receive {
                    proto: NetProtocol::Udp,
                    source,
                    destination,
                    contents,
                },
            ));
        }
    }

    /// A resolved `stun:` server: one transaction, sent from the loopback
    /// socket for a loopback server and from the interface socket for any
    /// other (skipped when there is none, or for an IPv6 server).
    fn start_stun(&mut self, server: SocketAddr) {
        if !server.is_ipv4() {
            return;
        }
        let via = if server.ip().is_loopback() {
            0
        } else if self.sockets.len() > 1 {
            1
        } else {
            return;
        };
        self.stun.push(StunTx {
            id: super::stun::new_transaction_id(),
            server,
            via,
            next_send: Instant::now(),
            tries: 0,
        });
    }

    /// Sends every Binding Request that is due, dropping transactions that
    /// have used their tries.
    async fn send_stun(&mut self) {
        let now = Instant::now();
        self.stun
            .retain(|t| t.tries < STUN_TRIES || t.next_send > now);
        for i in 0..self.stun.len() {
            if self.stun[i].next_send > now || self.stun[i].tries >= STUN_TRIES {
                continue;
            }
            let tx = &mut self.stun[i];
            let request = super::stun::binding_request(&tx.id);
            let (via, server) = (tx.via, tx.server);
            tx.next_send = now + std::time::Duration::from_millis(STUN_FIRST_RTO_MS << tx.tries);
            tx.tries += 1;
            let _ = self.sockets[via].socket.send_to(&request, server).await;
        }
    }

    fn handle_event(&mut self, event: StrEvent, _buf: &mut [u8]) {
        match event {
            StrEvent::Connected => {
                let local = format_fingerprint(self.rtc.direct_api().local_dtls_fingerprint());
                let remote = self
                    .rtc
                    .direct_api()
                    .remote_dtls_fingerprint()
                    .map(format_fingerprint);
                let _ = self.events_tx.send(RtcEvent::State {
                    conn_id: self.conn_id,
                    state: IceState::Connected,
                    local_fingerprint: Some(local),
                    remote_fingerprint: remote,
                    path_kind: Some("host".to_string()),
                });
            }
            // `str0m`'s ICE agent has no `Failed`/`Closed` connection state
            // (unlike node-datachannel's): trickle ICE never formally ends,
            // so a `Disconnected` reading may still recover. This project's
            // own fingerprint check (`super::dial`) does not depend on the
            // transport failing anyway — see the module doc comment — and
            // a connection that never reaches `Connected` is caught by the
            // caller's own timeout, not by a synthesized failure state
            // here.
            StrEvent::IceConnectionStateChange(_) => {}
            // K10: the remote closed the DTLS connection or SCTP
            // association (`Rtc::close` there, or node-datachannel's
            // `close()`).
            StrEvent::Closed => self.teardown("closed".to_string()),
            StrEvent::ChannelOpen(scid, label) => {
                let chan_id = match self.str0m_to_ours.get(&scid) {
                    Some(id) => *id,
                    None => {
                        let id = self.next_remote;
                        self.next_remote += 1;
                        self.str0m_to_ours.insert(scid, id);
                        self.ours_to_str0m.insert(id, scid);
                        id
                    }
                };
                if let Some(mut ch) = self.rtc.channel(scid) {
                    ch.set_buffered_amount_low_threshold(LOW_WATER_MARK);
                }
                let _ = self.events_tx.send(RtcEvent::Channel {
                    conn_id: self.conn_id,
                    chan_id,
                    label,
                    op: ChannelOp::Opened,
                });
            }
            StrEvent::ChannelData(data) => {
                if let Some(chan_id) = self.str0m_to_ours.get(&data.id).copied() {
                    let _ = self.events_tx.send(RtcEvent::Data {
                        conn_id: self.conn_id,
                        chan_id,
                        data: data.data,
                    });
                }
            }
            StrEvent::ChannelClose(scid) => {
                if let Some(chan_id) = self.str0m_to_ours.remove(&scid) {
                    self.ours_to_str0m.remove(&chan_id);
                    self.paused.remove(&scid);
                    self.pending_writes.remove(&scid);
                    let _ = self.events_tx.send(RtcEvent::Channel {
                        conn_id: self.conn_id,
                        chan_id,
                        label: String::new(),
                        op: ChannelOp::Closed,
                    });
                }
            }
            StrEvent::ChannelBufferedAmountLow(scid) => {
                // The threshold firing means room freed up in the SCTP
                // send buffer: retry whatever `handle_send` could not get
                // `write()` to accept the first time; `drain_pending_writes`
                // tells the caller it may resume (`RtcEvent::Flow { paused:
                // false }`) only once that backlog is low too — otherwise a
                // caller that immediately sends more on hearing "resume"
                // could race ahead of parts still waiting here, or pile
                // them up without bound (`R-11`).
                self.drain_pending_writes(scid);
            }
            _ => {}
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Stun(server) => self.start_stun(server),
            Cmd::Signal(msg) => self.handle_signal(msg),
            Cmd::OpenChannel { chan_id, label } => self.handle_open_channel(chan_id, label),
            Cmd::CloseChannel { chan_id } => self.handle_close_channel(chan_id),
            Cmd::Send { chan_id, data } => self.handle_send(chan_id, data),
            Cmd::Close { reason } => self.teardown(reason),
        }
    }

    fn handle_signal(&mut self, msg: SignalMsg) {
        match msg {
            SignalMsg::Offer { sdp } => {
                let Ok(offer) = SdpOffer::from_sdp_string(&sdp) else {
                    return;
                };
                if let Ok(answer) = self.rtc.sdp_api().accept_offer(offer) {
                    let _ = self.events_tx.send(RtcEvent::Signal {
                        conn_id: self.conn_id,
                        msg: SignalMsg::Answer {
                            sdp: answer.to_sdp_string(),
                        },
                    });
                }
            }
            SignalMsg::Answer { sdp } => {
                let Ok(answer) = SdpAnswer::from_sdp_string(&sdp) else {
                    return;
                };
                if let Some(pending) = self.pending_offer.take() {
                    let _ = self.rtc.sdp_api().accept_answer(pending, answer);
                }
            }
            SignalMsg::Candidate { candidate, .. } => {
                if let Ok(c) = Candidate::from_sdp_string(&candidate) {
                    self.rtc.add_remote_candidate(c);
                }
            }
        }
    }

    fn handle_open_channel(&mut self, chan_id: ChanId, label: String) {
        if self.ours_to_str0m.contains_key(&chan_id) {
            return;
        }
        let mut api = self.rtc.sdp_api();
        let scid = api.add_channel(label);
        self.str0m_to_ours.insert(scid, chan_id);
        self.ours_to_str0m.insert(chan_id, scid);
        if let Some((offer, pending)) = api.apply() {
            self.pending_offer = Some(pending);
            let _ = self.events_tx.send(RtcEvent::Signal {
                conn_id: self.conn_id,
                msg: SignalMsg::Offer {
                    sdp: offer.to_sdp_string(),
                },
            });
        }
    }

    fn handle_close_channel(&mut self, chan_id: ChanId) {
        if let Some(scid) = self.ours_to_str0m.get(&chan_id).copied() {
            let mut api = self.rtc.direct_api();
            api.close_data_channel(scid);
        }
    }

    fn handle_send(&mut self, chan_id: ChanId, data: Vec<u8>) {
        // `channel.rs::PART_BYTES` already caps every part below
        // MAX_MESSAGE_SIZE; a caller that hands this a bigger write has a
        // bug this must not paper over (`electron/rtc-host.js::send`'s own
        // `RangeError`).
        debug_assert!(
            data.len() <= MAX_MESSAGE_SIZE,
            "rtc: a {}-byte write exceeds the {MAX_MESSAGE_SIZE}-byte cap",
            data.len()
        );
        if data.len() > MAX_MESSAGE_SIZE {
            return;
        }
        let Some(scid) = self.ours_to_str0m.get(&chan_id).copied() else {
            return;
        };
        self.pending_writes.entry(scid).or_default().push_back(data);
        self.drain_pending_writes(scid);
    }

    /// Hands as many of `scid`'s queued parts to `str0m` as
    /// `Channel::write` will currently accept, stopping at the first one
    /// it does not (`Ok(false)`) — never on `Ok(true)`/an error alone, and
    /// never dropping a part: `write`'s `Ok(false)` means "not accepted,
    /// try again later" (`str0m::channel::Channel::write`'s own doc
    /// comment: "Returns true or false whether the buffer was accepted or
    /// not"), not a failure, and the part this call could not place stays
    /// at the front of the queue for the next `ChannelBufferedAmountLow`
    /// event or `handle_send` call to retry, in order.
    fn drain_pending_writes(&mut self, scid: StrChanId) {
        // No channel yet: `str0m` can take a loop tick after
        // `add_channel`/`apply()` before `Rtc::channel(scid)` resolves for
        // a channel opened via the "consecutive channel, no SDP
        // renegotiation" path (`handle_open_channel`'s doc comment) — the
        // part stays queued for the next tick's retry (`ConnTask::run`'s
        // own per-tick drain), not lost.
        let Some(mut ch) = self.rtc.channel(scid) else {
            return;
        };
        let mut pending = 0;
        if let Some(queue) = self.pending_writes.get_mut(&scid) {
            while let Some(part) = queue.front() {
                match ch.write(true, part) {
                    Ok(true) => {
                        queue.pop_front();
                    }
                    Ok(false) | Err(_) => break,
                }
            }
            pending = queue.iter().map(Vec::len).sum::<usize>();
            if queue.is_empty() {
                self.pending_writes.remove(&scid);
            }
        }
        // The channel's backlog is what `str0m` buffers plus what it has
        // not accepted yet. `str0m` refuses writes (`Ok(false)`) long
        // before its own buffer reaches HIGH_WATER_MARK, so a mark on
        // `buffered_amount()` alone never paused a sender and the parts
        // waiting here grew without bound (K11, `R-11`).
        let backlog = ch.buffered_amount() + pending;
        let Some(chan_id) = self.str0m_to_ours.get(&scid).copied() else {
            return;
        };
        let flow = if backlog > HIGH_WATER_MARK && self.paused.insert(scid) {
            Some(true)
        } else if backlog <= LOW_WATER_MARK && self.paused.remove(&scid) {
            Some(false)
        } else {
            None
        };
        if let Some(paused) = flow {
            let _ = self.events_tx.send(RtcEvent::Flow {
                conn_id: self.conn_id,
                chan_id,
                paused,
            });
        }
    }

    fn teardown(&mut self, reason: String) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.events_tx.send(RtcEvent::Close {
            conn_id: self.conn_id,
            reason,
        });
    }
}

/// `socket.recv_from`, or never when there is no such socket.
async fn recv_on(
    socket: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Binds one UDP socket on `ip`, port chosen by the OS.
fn bind_udp(ip: std::net::IpAddr) -> Option<Sock> {
    let socket = std::net::UdpSocket::bind((ip, 0)).ok()?;
    socket.set_nonblocking(true).ok()?;
    let socket = UdpSocket::from_std(socket).ok()?;
    let addr = socket.local_addr().ok()?;
    Some(Sock { socket, addr })
}

fn to_tokio_instant(i: Instant) -> tokio::time::Instant {
    let now_std = Instant::now();
    let now_tokio = tokio::time::Instant::now();
    if i <= now_std {
        now_tokio
    } else {
        now_tokio + (i - now_std)
    }
}

/// Wraps `str0m`'s sans-IO WebRTC state machine on `tokio` `UdpSocket`s, one
/// per connection, with an API and event stream shaped like
/// `electron/rtc-host.js::RtcHost` (see the module doc comment).
pub struct RtcHost {
    default_ice_servers: Vec<String>,
    /// Whether connections also bind the primary interface (K10); off,
    /// they bind loopback only, as K6's did.
    interfaces: bool,
    events_tx: mpsc::UnboundedSender<RtcEvent>,
    events_rx: TokioMutex<mpsc::UnboundedReceiver<RtcEvent>>,
    conns: Arc<StdMutex<HashMap<ConnId, mpsc::UnboundedSender<Cmd>>>>,
}

impl RtcHost {
    pub fn new(default_ice_servers: Vec<String>) -> RtcHost {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        RtcHost {
            default_ice_servers,
            interfaces: true,
            events_tx,
            events_rx: TokioMutex::new(events_rx),
            conns: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// An `RtcHost` whose connections bind the loopback interface only
    /// (K6's behaviour): host candidates on 127.0.0.1, and `srflx` ones
    /// from a loopback STUN server only.
    pub fn loopback_only(default_ice_servers: Vec<String>) -> RtcHost {
        let mut host = RtcHost::new(default_ice_servers);
        host.interfaces = false;
        host
    }

    /// The next event, awaiting one if none is queued yet. `None` once
    /// every sender (every connection task, plus this `RtcHost`'s own) has
    /// gone away.
    pub async fn recv_event(&self) -> Option<RtcEvent> {
        self.events_rx.lock().await.recv().await
    }

    /// Opens connection `conn_id`: binds its own UDP sockets (loopback,
    /// and the primary interface's when there is one), offers one host
    /// candidate per socket, and spawns the task that drives it. `false` if
    /// `conn_id` is already open, or no socket could be bound.
    /// `ice_servers` overrides this host's default list for this connection
    /// (`D-11`): every `stun:` URL in it is resolved and asked for this
    /// connection's server-reflexive address (`super::stun`); `turn:` URLs
    /// are ignored (no TURN client).
    pub fn open(&self, conn_id: ConnId, ice_servers: Option<Vec<String>>) -> bool {
        let mut conns = self.conns.lock().expect("conns mutex");
        if conns.contains_key(&conn_id) {
            return false;
        }
        let ice_servers = ice_servers.unwrap_or_else(|| self.default_ice_servers.clone());
        let Some(loopback) = bind_udp(std::net::Ipv4Addr::LOCALHOST.into()) else {
            return false;
        };
        let mut sockets = vec![loopback];
        if self.interfaces
            && let Some(ip) = super::stun::primary_ipv4()
            && let Some(sock) = bind_udp(ip.into())
        {
            sockets.push(sock);
        }
        let rtc = Rtc::builder().build(Instant::now());
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let task = ConnTask {
            conn_id,
            rtc,
            sockets,
            stun: Vec::new(),
            events_tx: self.events_tx.clone(),
            cmd_rx,
            conns: self.conns.clone(),
            pending_offer: None,
            str0m_to_ours: HashMap::new(),
            ours_to_str0m: HashMap::new(),
            next_remote: REMOTE_CHANNEL_BASE,
            paused: std::collections::HashSet::new(),
            pending_writes: HashMap::new(),
            closed: false,
        };
        // Every `stun:` server is resolved off the connection's task and
        // handed to it as `Cmd::Stun` (a slow resolver never stalls ICE).
        for url in &ice_servers {
            let Some((host, port)) = super::stun::stun_target(url) else {
                continue;
            };
            let tx = cmd_tx.clone();
            tokio::spawn(async move {
                if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), port)).await
                    && let Some(addr) = addrs.into_iter().find(SocketAddr::is_ipv4)
                {
                    let _ = tx.send(Cmd::Stun(addr));
                }
            });
        }
        conns.insert(conn_id, cmd_tx);
        drop(conns);
        tokio::spawn(task.run());
        true
    }

    fn send_cmd(&self, conn_id: ConnId, cmd: Cmd) {
        let conns = self.conns.lock().expect("conns mutex");
        if let Some(tx) = conns.get(&conn_id) {
            let _ = tx.send(cmd);
        }
    }

    pub fn signal(&self, conn_id: ConnId, msg: SignalMsg) {
        self.send_cmd(conn_id, Cmd::Signal(msg));
    }

    /// `chan_id` must be below [`REMOTE_CHANNEL_BASE`] (a channel this side
    /// opens); the caller (`super::connection`) owns that invariant.
    pub fn open_channel(&self, conn_id: ConnId, chan_id: ChanId, label: &str) {
        self.send_cmd(
            conn_id,
            Cmd::OpenChannel {
                chan_id,
                label: label.to_string(),
            },
        );
    }

    pub fn close_channel(&self, conn_id: ConnId, chan_id: ChanId) {
        self.send_cmd(conn_id, Cmd::CloseChannel { chan_id });
    }

    /// Fire-and-forget, like `RtcHost.send` (see the module doc comment for
    /// why its return value is never needed here).
    pub fn send(&self, conn_id: ConnId, chan_id: ChanId, data: Vec<u8>) {
        self.send_cmd(conn_id, Cmd::Send { chan_id, data });
    }

    pub fn close(&self, conn_id: ConnId, reason: &str) {
        self.send_cmd(
            conn_id,
            Cmd::Close {
                reason: reason.to_string(),
            },
        );
    }

    pub fn close_all(&self, reason: &str) {
        let ids: Vec<ConnId> = self
            .conns
            .lock()
            .expect("conns mutex")
            .keys()
            .copied()
            .collect();
        for id in ids {
            self.close(id, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn wait_for<F: Fn(&RtcEvent) -> bool>(host: &RtcHost, pred: F, what: &str) -> RtcEvent {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let ev = host.recv_event().await.expect("event stream ended");
                if pred(&ev) {
                    return ev;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    /// A Rust str0m peer dialing another Rust str0m peer, entirely within
    /// this process: the fast, JS-independent sanity check for the driving
    /// loop, before `tests/rtc_parity.rs` attempts interop with ZBTerm's
    /// `node-datachannel`.
    #[tokio::test]
    async fn two_rtc_hosts_connect_and_exchange_a_message() {
        let dialer = RtcHost::new(vec![]);
        let host = RtcHost::new(vec![]);
        assert!(dialer.open(1, Some(vec![])));
        assert!(host.open(1, Some(vec![])));

        // Gather each side's one host candidate.
        let d_cand = wait_for(
            &dialer,
            |e| {
                matches!(
                    e,
                    RtcEvent::Signal {
                        msg: SignalMsg::Candidate { .. },
                        ..
                    }
                )
            },
            "dialer candidate",
        )
        .await;
        let h_cand = wait_for(
            &host,
            |e| {
                matches!(
                    e,
                    RtcEvent::Signal {
                        msg: SignalMsg::Candidate { .. },
                        ..
                    }
                )
            },
            "host candidate",
        )
        .await;

        // The dialer opens the bootstrap channel, producing the offer.
        dialer.open_channel(1, 0, "zbterm/fnet-bootstrap");
        let offer = wait_for(
            &dialer,
            |e| {
                matches!(
                    e,
                    RtcEvent::Signal {
                        msg: SignalMsg::Offer { .. },
                        ..
                    }
                )
            },
            "offer",
        )
        .await;
        let RtcEvent::Signal {
            msg: SignalMsg::Offer { sdp: offer_sdp },
            ..
        } = offer
        else {
            unreachable!()
        };

        host.signal(1, SignalMsg::Offer { sdp: offer_sdp });
        let answer = wait_for(
            &host,
            |e| {
                matches!(
                    e,
                    RtcEvent::Signal {
                        msg: SignalMsg::Answer { .. },
                        ..
                    }
                )
            },
            "answer",
        )
        .await;
        let RtcEvent::Signal {
            msg: SignalMsg::Answer { sdp: answer_sdp },
            ..
        } = answer
        else {
            unreachable!()
        };
        dialer.signal(1, SignalMsg::Answer { sdp: answer_sdp });

        if let RtcEvent::Signal {
            msg: SignalMsg::Candidate { candidate, mid },
            ..
        } = d_cand
        {
            host.signal(1, SignalMsg::Candidate { candidate, mid });
        }
        if let RtcEvent::Signal {
            msg: SignalMsg::Candidate { candidate, mid },
            ..
        } = h_cand
        {
            dialer.signal(1, SignalMsg::Candidate { candidate, mid });
        }

        wait_for(
            &dialer,
            |e| {
                matches!(
                    e,
                    RtcEvent::State {
                        state: IceState::Connected,
                        ..
                    }
                )
            },
            "dialer connected",
        )
        .await;
        wait_for(
            &host,
            |e| {
                matches!(
                    e,
                    RtcEvent::State {
                        state: IceState::Connected,
                        ..
                    }
                )
            },
            "host connected",
        )
        .await;

        wait_for(
            &dialer,
            |e| {
                matches!(
                    e,
                    RtcEvent::Channel {
                        chan_id: 0,
                        op: ChannelOp::Opened,
                        ..
                    }
                )
            },
            "dialer channel open",
        )
        .await;
        let host_chan = wait_for(
            &host,
            |e| {
                matches!(
                    e,
                    RtcEvent::Channel {
                        op: ChannelOp::Opened,
                        ..
                    }
                )
            },
            "host channel open",
        )
        .await;
        let RtcEvent::Channel {
            chan_id: host_chan_id,
            label,
            ..
        } = host_chan
        else {
            unreachable!()
        };
        assert_eq!(label, "zbterm/fnet-bootstrap");
        assert!(host_chan_id >= REMOTE_CHANNEL_BASE);

        dialer.send(1, 0, b"hello".to_vec());
        let data = wait_for(&host, |e| matches!(e, RtcEvent::Data { .. }), "data").await;
        let RtcEvent::Data { data, chan_id, .. } = data else {
            unreachable!()
        };
        assert_eq!(chan_id, host_chan_id);
        assert_eq!(data, b"hello");

        dialer.close_all("test done");
        host.close_all("test done");
    }

    /// K6 debug: a second data channel, opened *after* the connection is
    /// already up (the "no SDP renegotiation" consecutive-channel path,
    /// `RtcHost::open_channel`'s doc comment) — does the receiving side
    /// ever see it reported as two separate channels for one `add_channel`
    /// call? Str0m-to-str0m only, no JS involved, to tell a bug in this
    /// crate's own bootstrap/channel bookkeeping apart from a str0m (or
    /// str0m-vs-node-datachannel interop) issue in the consecutive-channel
    /// path itself.
    #[tokio::test]
    async fn second_channel_after_connect_is_reported_exactly_once() {
        for attempt in 0..10 {
            let dialer = RtcHost::new(vec![]);
            let host = RtcHost::new(vec![]);
            assert!(dialer.open(1, Some(vec![])));
            assert!(host.open(1, Some(vec![])));

            let d_cand = wait_for(
                &dialer,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Signal {
                            msg: SignalMsg::Candidate { .. },
                            ..
                        }
                    )
                },
                "dialer candidate",
            )
            .await;
            let h_cand = wait_for(
                &host,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Signal {
                            msg: SignalMsg::Candidate { .. },
                            ..
                        }
                    )
                },
                "host candidate",
            )
            .await;

            dialer.open_channel(1, 0, "zbterm/fnet-bootstrap");
            let offer = wait_for(
                &dialer,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Signal {
                            msg: SignalMsg::Offer { .. },
                            ..
                        }
                    )
                },
                "offer",
            )
            .await;
            let RtcEvent::Signal {
                msg: SignalMsg::Offer { sdp: offer_sdp },
                ..
            } = offer
            else {
                unreachable!()
            };
            host.signal(1, SignalMsg::Offer { sdp: offer_sdp });
            let answer = wait_for(
                &host,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Signal {
                            msg: SignalMsg::Answer { .. },
                            ..
                        }
                    )
                },
                "answer",
            )
            .await;
            let RtcEvent::Signal {
                msg: SignalMsg::Answer { sdp: answer_sdp },
                ..
            } = answer
            else {
                unreachable!()
            };
            dialer.signal(1, SignalMsg::Answer { sdp: answer_sdp });
            if let RtcEvent::Signal {
                msg: SignalMsg::Candidate { candidate, mid },
                ..
            } = d_cand
            {
                host.signal(1, SignalMsg::Candidate { candidate, mid });
            }
            if let RtcEvent::Signal {
                msg: SignalMsg::Candidate { candidate, mid },
                ..
            } = h_cand
            {
                dialer.signal(1, SignalMsg::Candidate { candidate, mid });
            }
            wait_for(
                &dialer,
                |e| {
                    matches!(
                        e,
                        RtcEvent::State {
                            state: IceState::Connected,
                            ..
                        }
                    )
                },
                "dialer connected",
            )
            .await;
            wait_for(
                &host,
                |e| {
                    matches!(
                        e,
                        RtcEvent::State {
                            state: IceState::Connected,
                            ..
                        }
                    )
                },
                "host connected",
            )
            .await;
            wait_for(
                &dialer,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Channel {
                            chan_id: 0,
                            op: ChannelOp::Opened,
                            ..
                        }
                    )
                },
                "dialer bootstrap open",
            )
            .await;
            wait_for(
                &host,
                |e| {
                    matches!(
                        e,
                        RtcEvent::Channel {
                            op: ChannelOp::Opened,
                            ..
                        }
                    )
                },
                "host bootstrap open",
            )
            .await;

            // The second channel, opened after the connection is already up.
            dialer.open_channel(1, 1, "zxterm/second");
            let mut host_opens = 0;
            let mut host_chan_id = None;
            let host_open = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match host.recv_event().await.unwrap() {
                        RtcEvent::Channel {
                            chan_id,
                            op: ChannelOp::Opened,
                            label,
                            ..
                        } if label == "zxterm/second" => {
                            host_opens += 1;
                            host_chan_id = Some(chan_id);
                            // Give a straggler duplicate a moment to arrive
                            // before deciding there is only one.
                            if tokio::time::timeout(Duration::from_millis(300), async {
                                loop {
                                    if let RtcEvent::Channel {
                                        label,
                                        op: ChannelOp::Opened,
                                        ..
                                    } = host.recv_event().await.unwrap()
                                        && label == "zxterm/second"
                                    {
                                        return;
                                    }
                                }
                            })
                            .await
                            .is_ok()
                            {
                                host_opens += 1;
                            }
                            return;
                        }
                        _ => {}
                    }
                }
            })
            .await;
            assert!(
                host_open.is_ok(),
                "attempt {attempt}: timed out waiting for the second channel to open"
            );
            assert_eq!(
                host_opens, 1,
                "attempt {attempt}: the second channel reported opened more than once"
            );

            let host_chan_id = host_chan_id.unwrap();
            let big = "w".repeat(crate::freenet::channel::PART_BYTES * 2 + 111);
            let msg = serde_json::json!({ "body": big });
            for part in crate::freenet::channel::cut(&msg) {
                dialer.send(1, 1, part);
            }
            let mut received: Vec<u8> = Vec::new();
            let mut last = false;
            let assembled = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let RtcEvent::Data { chan_id, data, .. } = host.recv_event().await.unwrap()
                        && chan_id == host_chan_id
                    {
                        last = data[0] & 1 != 0;
                        received.extend_from_slice(&data[5..]);
                        if last {
                            return;
                        }
                    }
                }
            })
            .await;
            assert!(
                assembled.is_ok(),
                "attempt {attempt}: timed out reassembling the second channel's message"
            );
            assert_eq!(
                String::from_utf8(received).unwrap(),
                msg.to_string(),
                "attempt {attempt}: byte-identical reassembly"
            );

            dialer.close_all("test done");
            host.close_all("test done");
        }
    }

    /// K10: a `stun:` server in the ICE list yields a `srflx` candidate
    /// with the address it maps this connection to. The server is a local
    /// responder (never a public one) that answers every Binding Request
    /// with a fixed documentation address (RFC 5737 TEST-NET-3), as a NAT
    /// would map the socket.
    #[tokio::test]
    async fn a_stun_server_yields_a_server_reflexive_candidate() {
        let responder = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let port = responder.local_addr().unwrap().port();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served2 = served.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = responder.recv_from(&mut buf).await {
                if let Some((kind, id)) = crate::freenet::stun::header(&buf[..n])
                    && kind == crate::freenet::stun::BINDING_REQUEST
                {
                    served2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let reply = crate::freenet::stun::binding_success(&id, mapped);
                    let _ = responder.send_to(&reply, from).await;
                }
            }
        });

        let host = RtcHost::loopback_only(vec![]);
        assert!(host.open(1, Some(vec![format!("stun:127.0.0.1:{port}")])));
        let mut kinds = Vec::new();
        let srflx = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let RtcEvent::Signal {
                    msg: SignalMsg::Candidate { candidate, .. },
                    ..
                } = host.recv_event().await.expect("event stream")
                {
                    let c = Candidate::from_sdp_string(&candidate).expect("parses");
                    kinds.push(c.kind());
                    if c.kind() == str0m::CandidateKind::ServerReflexive {
                        return c;
                    }
                }
            }
        })
        .await
        .expect("a srflx candidate within 5 s");
        assert_eq!(srflx.addr(), mapped, "the address the server mapped");
        assert_eq!(
            kinds[0],
            str0m::CandidateKind::Host,
            "the host candidate comes first"
        );
        assert!(served.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        host.close_all("test done");
    }

    /// K10: with a STUN server in both ICE lists, two peers still connect
    /// (the extra candidates do not disturb the host-candidate pair).
    #[tokio::test]
    async fn two_peers_with_a_stun_server_connect() {
        let responder = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = responder.recv_from(&mut buf).await {
                if let Some((_, id)) = crate::freenet::stun::header(&buf[..n]) {
                    let reply = crate::freenet::stun::binding_success(&id, from);
                    let _ = responder.send_to(&reply, from).await;
                }
            }
        });
        let ice = vec![format!("stun:127.0.0.1:{port}")];
        let dialer = RtcHost::new(ice.clone());
        let host = RtcHost::new(ice);
        assert!(dialer.open(1, None));
        assert!(host.open(1, None));
        dialer.open_channel(1, 0, "zbterm/fnet-bootstrap");
        let offer = wait_for(
            &dialer,
            |e| {
                matches!(
                    e,
                    RtcEvent::Signal {
                        msg: SignalMsg::Offer { .. },
                        ..
                    }
                )
            },
            "offer",
        )
        .await;
        let RtcEvent::Signal { msg, .. } = offer else {
            unreachable!()
        };
        host.signal(1, msg);
        // Relay every candidate and the answer both ways until both sides
        // report connected.
        let mut connected = (false, false);
        tokio::time::timeout(Duration::from_secs(10), async {
            while !(connected.0 && connected.1) {
                tokio::select! {
                    Some(ev) = dialer.recv_event() => match ev {
                        RtcEvent::Signal { msg, .. } => host.signal(1, msg),
                        RtcEvent::State { state: IceState::Connected, .. } => connected.0 = true,
                        _ => {}
                    },
                    Some(ev) = host.recv_event() => match ev {
                        RtcEvent::Signal { msg, .. } => dialer.signal(1, msg),
                        RtcEvent::State { state: IceState::Connected, .. } => connected.1 = true,
                        _ => {}
                    },
                }
            }
        })
        .await
        .expect("both sides connected within 10 s");
        dialer.close_all("test done");
        host.close_all("test done");
    }
}

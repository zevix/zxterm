//! One authenticated Freenet peer connection (K6, spike S2), the Rust twin
//! of ZBTerm `engine/backends/freenet/connection.js`: the bootstrap gate
//! (`S-26`), channel pairing (opener vs. taker, and the both-opened-at-once
//! race), and `path()`.
//!
//! Unlike `connection.js::FreenetConnection`, which holds a live
//! `rtcHost`/`connId` and calls back into it whenever it likes, this
//! `Connection` is pure state: [`Connection::handle_rtc_event`] takes
//! whatever [`super::rtc::RtcEvent`] arrived (already filtered to this
//! connection's `conn_id` by the caller — `super::dial`) and the
//! `&super::rtc::RtcHost` to act on, and returns the [`ConnEvent`]s a
//! caller should react to. This mirrors the same ownership adaptation
//! `super::channel` documents: the module boundary moves from "channel
//! calls back into its owner" to "the owner drives the channel/connection
//! by value," which Rust's borrow rules make far simpler than a JS-style
//! `EventEmitter` web of back-references.
//!
//! The bootstrap channel (`chanId = 0`, label `crate::wire::BOOTSTRAP_LABEL`)
//! is opened only by a dial, never by a host session (`super::dial` owns
//! that distinction); every other channel this side opens is deferred
//! (`Connection::deferred`) until the bootstrap channel itself reports
//! `opened` — the `S-26` fix, reproduced here as a plain ordering
//! guarantee regardless of whether `str0m`'s specific behaviour has the
//! node-datachannel race it was built to fix (see `super::rtc`'s own doc
//! comment on this point).

use std::collections::HashMap;

use super::channel::{self, Channel, Received};
use super::rtc::{ChanId, ChannelOp, ConnId, RtcEvent, RtcHost};

/// `connection.js`'s `pathOf`: the local candidate type, or `Relay` when
/// either end is a TURN relay. This phase never configures TURN (no
/// STUN/TURN gathering at all — see `super::rtc`'s doc comment), so `path()`
/// is always `Direct` in practice; the enum stays faithful to the design's
/// three-way split (`Broker` never applies to a Freenet peer connection
/// either: the contract brokers only the handshake, never the data).
///
/// > 2026-09-29, K10: STUN (server-reflexive candidates) now exists
/// > (`super::stun`); TURN still does not, so `Relay` still never occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relay,
}

fn path_of(path_kind: Option<&str>) -> Path {
    if path_kind == Some("relay") {
        Path::Relay
    } else {
        Path::Direct
    }
}

/// One outcome of [`Connection::handle_rtc_event`] the caller should react
/// to (`connection.js`'s `onChannel` callback and each `FreenetChannel`'s
/// `onmessage`/`onclose`, flattened into one return value since this
/// `Connection` has no callback fields of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnEvent {
    /// A channel *this* side asked to open (`open_channel`) is now open and
    /// usable (`send`/`receive`d messages will start flowing).
    ChannelOpened {
        key: String,
    },
    /// The remote opened a new `(protocol, id)` channel this side has not
    /// taken yet; call [`Connection::open_channel`] with the same
    /// `protocol`/`id` to take it (or ignore it).
    IncomingChannel {
        protocol: String,
        id: Vec<u8>,
    },
    /// A complete message reassembled on channel `key`.
    Message {
        key: String,
        value: serde_json::Value,
    },
    ChannelClosed {
        key: String,
    },
    /// One data-channel message on raw channel `key` (K10), uninterpreted.
    Bytes {
        key: String,
        bytes: Vec<u8>,
    },
    /// Raw channel `key` was over its back-pressure mark (a
    /// [`Connection::send_bytes`] returned `false`) and takes more again
    /// (`history.js::HistoryChannel`'s `ondrain`).
    Drain {
        key: String,
    },
    /// The whole connection closed.
    Closed {
        reason: String,
    },
}

struct Pending {
    chan_id: ChanId,
    /// Raw parts that arrived before this side called `open_channel` for
    /// this key (a legitimate case, unlike `channel.js`'s JS-callback-
    /// timing-specific `_held` — see the module doc comment and
    /// `super::channel`'s).
    data: Vec<Vec<u8>>,
}

/// One authenticated Freenet peer connection (`connection.js::FreenetConnection`).
pub struct Connection {
    conn_id: ConnId,
    pub remote_peer_key: Vec<u8>,
    pub initiator: bool,
    pub closed: bool,
    path: Path,
    /// label -> this side's channel object.
    channels: HashMap<String, Channel>,
    /// label -> the `chan_id` that channel sends on (the one `Channel`
    /// itself was told about via `send_on`); tracked here too so `pump`
    /// does not have to guess it out of `by_chan`, which for the
    /// both-opened-at-once case holds more than one `chan_id` per label.
    send_targets: HashMap<String, ChanId>,
    /// RTC `chan_id` -> the label it belongs to (an owned channel, or a
    /// pending remote one).
    by_chan: HashMap<ChanId, String>,
    /// label -> a remote-opened channel this side has not taken yet.
    pending: HashMap<String, Pending>,
    next_chan_id: ChanId,
    bootstrap_open: bool,
    /// `chan_id -> label`: channels this side opened before the bootstrap
    /// channel itself reported `opened` (`S-26`).
    deferred: HashMap<ChanId, String>,
    /// Every RTC channel-open event's label, in the order it arrived —
    /// the structural evidence the S2 gate checks the bootstrap-before-
    /// other-channels ordering against (`Connection::open_order`).
    open_order: Vec<String>,
    /// Raw channels whose last `send_bytes` reported back-pressure; each
    /// gets one [`ConnEvent::Drain`] once it takes more again.
    blocked: std::collections::HashSet<String>,
}

impl Connection {
    pub fn new(
        conn_id: ConnId,
        remote_peer_key: Vec<u8>,
        initiator: bool,
        path_kind: Option<String>,
    ) -> Connection {
        Connection {
            conn_id,
            remote_peer_key,
            initiator,
            closed: false,
            path: path_of(path_kind.as_deref()),
            channels: HashMap::new(),
            send_targets: HashMap::new(),
            by_chan: HashMap::new(),
            pending: HashMap::new(),
            // chan_id 0 is the dial's bootstrap channel; every other
            // channel this side opens is numbered from 1 (`index.js::_nextChanId`).
            next_chan_id: 1,
            bootstrap_open: false,
            deferred: HashMap::new(),
            open_order: Vec::new(),
            blocked: std::collections::HashSet::new(),
        }
    }

    pub fn path(&self) -> Path {
        self.path
    }

    /// The label of every RTC channel-open event seen so far, in arrival
    /// order (index 0 is always the bootstrap channel in a correct run).
    pub fn open_order(&self) -> &[String] {
        &self.open_order
    }

    pub fn bootstrap_is_open(&self) -> bool {
        self.bootstrap_open
    }

    /// `connection.js::openChannel`. `Err` if the connection is closed or
    /// this side already has `(protocol, id)` open. A message the remote
    /// sent before this call is dropped here; [`Self::open_channel_with`]
    /// hands it back instead.
    pub fn open_channel(
        &mut self,
        rtc: &RtcHost,
        protocol: &str,
        id: &[u8],
    ) -> Result<String, &'static str> {
        self.open_channel_with(rtc, protocol, id, false)
            .map(|(key, _held)| key)
    }

    /// `connection.js::_openChannel` with the channel kind to make: a JSON
    /// channel, or with `raw` a raw ordered byte channel
    /// ([`Channel::new_raw`], `history.js::HistoryChannel`'s twin). Returns
    /// the channel's key and the [`ConnEvent`]s of whatever the remote sent
    /// on it before this side took it (`connection.js`'s pending `data`).
    pub fn open_channel_with(
        &mut self,
        rtc: &RtcHost,
        protocol: &str,
        id: &[u8],
        raw: bool,
    ) -> Result<(String, Vec<ConnEvent>), &'static str> {
        let kind = if raw {
            channel::ChannelKind::Raw
        } else {
            channel::ChannelKind::Json
        };
        self.open_channel_kind(rtc, protocol, id, kind)
    }

    /// [`Self::open_channel_with`] for any [`channel::ChannelKind`] (K13 adds
    /// the binary message channel).
    pub fn open_channel_kind(
        &mut self,
        rtc: &RtcHost,
        protocol: &str,
        id: &[u8],
        kind: channel::ChannelKind,
    ) -> Result<(String, Vec<ConnEvent>), &'static str> {
        if self.closed {
            return Err("connection is closed");
        }
        let key = channel::label_of(protocol, id);
        if self.channels.contains_key(&key) {
            return Err("channel already open on this connection");
        }
        let mut ch = Channel::of_kind(kind, protocol, id);
        if let Some(p) = self.pending.remove(&key) {
            // The remote opened it first: send and read on its data channel.
            self.by_chan.insert(p.chan_id, key.clone());
            self.send_targets.insert(key.clone(), p.chan_id);
            ch.send_on(p.chan_id, true, false);
            let mut held = Vec::new();
            for part in &p.data {
                if let Some(ev) = self.feed(&mut ch, &key, part, p.chan_id) {
                    let malformed = matches!(ev, ConnEvent::ChannelClosed { .. });
                    held.push(ev);
                    if malformed {
                        for id in ch.shut() {
                            rtc.close_channel(self.conn_id, id);
                            self.by_chan.remove(&id);
                        }
                        self.send_targets.remove(&key);
                        return Ok((key, held));
                    }
                }
            }
            self.channels.insert(key.clone(), ch);
            return Ok((key, held));
        }
        let chan_id = self.next_chan_id;
        self.next_chan_id += 1;
        self.by_chan.insert(chan_id, key.clone());
        self.send_targets.insert(key.clone(), chan_id);
        ch.send_on(chan_id, false, true);
        self.channels.insert(key.clone(), ch);
        if self.bootstrap_open {
            rtc.open_channel(self.conn_id, chan_id, &key);
        } else {
            self.deferred.insert(chan_id, key.clone());
        }
        Ok((key, Vec::new()))
    }

    /// `history.js::HistoryChannel::send` on raw channel `key`: queues
    /// `bytes` and writes every part currently allowed out. `false` under
    /// back-pressure or once closed (a later [`ConnEvent::Drain`] says it
    /// takes more again), or when `key` is not an open raw channel.
    pub fn send_bytes(&mut self, rtc: &RtcHost, key: &str, bytes: &[u8]) -> bool {
        let Some(ch) = self.channels.get_mut(key) else {
            return false;
        };
        if ch.is_raw() {
            ch.send_bytes(bytes);
        } else if ch.is_binary() {
            ch.send_message_bytes(bytes);
        } else {
            return false;
        }
        self.pump(rtc, key);
        let more = self.channels.get(key).is_some_and(Channel::takes_more);
        if !more {
            self.blocked.insert(key.to_string());
        }
        more
    }

    /// `channel.js::close`: shuts channel `key` and closes every data
    /// channel it used. `false` if no such channel is open.
    pub fn close_channel(&mut self, rtc: &RtcHost, key: &str) -> bool {
        let Some(mut ch) = self.channels.remove(key) else {
            return false;
        };
        for id in ch.shut() {
            if !self.closed {
                rtc.close_channel(self.conn_id, id);
            }
            self.by_chan.remove(&id);
            self.deferred.remove(&id);
        }
        self.send_targets.remove(key);
        self.blocked.remove(key);
        true
    }

    /// `connection.js::close`: closes the peer connection (the RTC half
    /// reports `Close`, which [`Self::handle_rtc_event`] turns into
    /// [`ConnEvent::Closed`]).
    pub fn close(&mut self, rtc: &RtcHost, reason: &str) {
        if !self.closed {
            rtc.close(self.conn_id, reason);
        }
    }

    /// This connection's RTC id.
    pub fn conn_id(&self) -> ConnId {
        self.conn_id
    }

    /// Open channels, the bootstrap channel included (`connection.js`'s
    /// `_channels.size`, for diagnostics).
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Whether channel `key` is open on this side.
    pub fn has_channel(&self, key: &str) -> bool {
        self.channels.contains_key(key)
    }

    /// One [`ConnEvent::Drain`] for every blocked raw channel that takes
    /// more again.
    fn drains(&mut self) -> Vec<ConnEvent> {
        let ready: Vec<String> = self
            .blocked
            .iter()
            .filter(|k| self.channels.get(*k).is_some_and(Channel::takes_more))
            .cloned()
            .collect();
        ready
            .into_iter()
            .map(|key| {
                self.blocked.remove(&key);
                ConnEvent::Drain { key }
            })
            .collect()
    }

    /// `connection.js`'s dial-only bootstrap channel open, `chanId = 0`,
    /// never deferred (it is the gate every other channel waits on).
    pub fn open_bootstrap_channel(&mut self, rtc: &RtcHost) {
        let key = crate::wire::BOOTSTRAP_LABEL.to_string();
        let mut ch = Channel::new("bootstrap", &[]);
        ch.send_on(0, false, true);
        self.by_chan.insert(0, key.clone());
        self.send_targets.insert(key.clone(), 0);
        self.channels.insert(key, ch);
        rtc.open_channel(self.conn_id, 0, crate::wire::BOOTSTRAP_LABEL);
    }

    /// `channel.js::send` plus `_pump`: queues `message` on channel `key`
    /// and writes every part currently allowed out to the RTC layer.
    pub fn send(&mut self, rtc: &RtcHost, key: &str, message: &serde_json::Value) -> bool {
        let Some(ch) = self.channels.get_mut(key) else {
            return false;
        };
        let ok = ch.send(message);
        self.pump(rtc, key);
        ok
    }

    fn pump(&mut self, rtc: &RtcHost, key: &str) {
        let Some(send_chan_id) = self.send_targets.get(key).copied() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(key) else {
            return;
        };
        while let Some(part) = ch.pop_sendable() {
            rtc.send(self.conn_id, send_chan_id, part);
        }
    }

    fn feed(
        &mut self,
        ch: &mut Channel,
        key: &str,
        data: &[u8],
        chan_id: ChanId,
    ) -> Option<ConnEvent> {
        match ch.receive(data, chan_id) {
            Received::Message(value) => Some(ConnEvent::Message {
                key: key.to_string(),
                value,
            }),
            Received::Bytes(bytes) => Some(ConnEvent::Bytes {
                key: key.to_string(),
                bytes,
            }),
            Received::Malformed => Some(ConnEvent::ChannelClosed {
                key: key.to_string(),
            }),
            _ => None,
        }
    }

    /// Feeds one [`RtcEvent`] already known to belong to this connection
    /// (the caller, `super::dial`, filters by `conn_id`) and returns every
    /// [`ConnEvent`] it produced.
    pub fn handle_rtc_event(&mut self, rtc: &RtcHost, ev: &RtcEvent) -> Vec<ConnEvent> {
        let mut out = Vec::new();
        match ev {
            RtcEvent::Channel {
                chan_id,
                label,
                op: ChannelOp::Opened,
                ..
            } => {
                self.open_order.push(label.clone());
                if label == crate::wire::BOOTSTRAP_LABEL {
                    self.bootstrap_opened(rtc);
                }
                if let Some(key) = self.by_chan.get(chan_id).cloned() {
                    // A channel this side already knows: either it just
                    // opened for real (this side created it), or — for
                    // the bootstrap channel specifically — nothing more
                    // to do (it never surfaces as a `ConnEvent`, matching
                    // `channel.js::parseLabel`'s treatment of it).
                    if let Some(ch) = self.channels.get_mut(&key) {
                        ch.opened(*chan_id);
                        self.pump(rtc, &key);
                        if label != crate::wire::BOOTSTRAP_LABEL {
                            out.push(ConnEvent::ChannelOpened { key });
                        }
                    }
                    return out;
                }
                let Some((protocol, id)) = channel::parse_label(label) else {
                    // The bootstrap label, or anything else this side did
                    // not construct via `label_of`: opaque, ignored
                    // (`connection.js::_channelEvent`'s own rule).
                    return out;
                };
                let key = label.clone();
                if let Some(ch) = self.channels.get_mut(&key) {
                    // Both sides opened the same key at once: read from
                    // the remote's data channel too, each still sending
                    // on its own.
                    self.by_chan.insert(*chan_id, key.clone());
                    ch.also_read_from(*chan_id);
                    rtc.send(self.conn_id, *chan_id, channel::READY_PART.to_vec());
                    return out;
                }
                if self.pending.contains_key(&key) {
                    // An unexpected second open for a key already pending:
                    // refuse it.
                    rtc.close_channel(self.conn_id, *chan_id);
                    return out;
                }
                // The host half has wired it: the opener may now send
                // (channel.js's READY rule, S-27).
                rtc.send(self.conn_id, *chan_id, channel::READY_PART.to_vec());
                self.by_chan.insert(*chan_id, key.clone());
                self.pending.insert(
                    key.clone(),
                    Pending {
                        chan_id: *chan_id,
                        data: Vec::new(),
                    },
                );
                out.push(ConnEvent::IncomingChannel { protocol, id });
            }
            RtcEvent::Channel {
                chan_id,
                op: ChannelOp::Closed,
                ..
            } => {
                if let Some(key) = self.by_chan.remove(chan_id) {
                    self.deferred.remove(chan_id);
                    if let Some(mut ch) = self.channels.remove(&key) {
                        let remaining = ch.shut();
                        for other in remaining {
                            if other != *chan_id {
                                rtc.close_channel(self.conn_id, other);
                                self.by_chan.remove(&other);
                            }
                        }
                        self.send_targets.remove(&key);
                        self.blocked.remove(&key);
                        out.push(ConnEvent::ChannelClosed { key });
                    } else if let Some(p) = self.pending.get(&key)
                        && p.chan_id == *chan_id
                    {
                        self.pending.remove(&key);
                    }
                }
            }
            RtcEvent::Data { chan_id, data, .. } => {
                if let Some(key) = self.by_chan.get(chan_id).cloned() {
                    if let Some(mut ch) = self.channels.remove(&key) {
                        if let Some(ev) = self.feed(&mut ch, &key, data, *chan_id) {
                            if let ConnEvent::ChannelClosed { .. } = &ev {
                                let ids = ch.shut();
                                for id in ids {
                                    rtc.close_channel(self.conn_id, id);
                                    self.by_chan.remove(&id);
                                }
                                self.send_targets.remove(&key);
                                self.blocked.remove(&key);
                            } else {
                                self.channels.insert(key.clone(), ch);
                            }
                            out.push(ev);
                        } else {
                            // A `Ready` transition may have made it
                            // writable: pump before putting it back.
                            self.channels.insert(key.clone(), ch);
                            self.pump(rtc, &key);
                            out.extend(self.drains());
                        }
                    } else if let Some(p) = self.pending.get_mut(&key) {
                        p.data.push(data.clone());
                    }
                }
            }
            RtcEvent::Flow {
                chan_id, paused, ..
            } => {
                if let Some(key) = self.by_chan.get(chan_id).cloned()
                    && let Some(ch) = self.channels.get_mut(&key)
                {
                    ch.flow(*chan_id, *paused);
                    if !*paused {
                        self.pump(rtc, &key);
                        out.extend(self.drains());
                    }
                }
            }
            RtcEvent::Close { reason, .. } => {
                self.closed = true;
                out.push(ConnEvent::Closed {
                    reason: reason.clone(),
                });
            }
            RtcEvent::State { .. } | RtcEvent::Signal { .. } => {
                // Pre-connect handshake events: `super::dial` consumes
                // these directly and never routes them here.
            }
        }
        out
    }

    fn bootstrap_opened(&mut self, rtc: &RtcHost) {
        if self.bootstrap_open {
            return;
        }
        self.bootstrap_open = true;
        let deferred: Vec<(ChanId, String)> = self.deferred.drain().collect();
        for (chan_id, key) in deferred {
            if self.by_chan.get(&chan_id) == Some(&key) {
                rtc.open_channel(self.conn_id, chan_id, &key);
            }
        }
    }
}

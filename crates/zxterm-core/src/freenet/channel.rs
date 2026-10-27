//! One Freenet channel (K6, spike S2): the framing/back-pressure layer over
//! a WebRTC data channel, byte-identical to ZBTerm `engine/backends/
//! freenet/channel.js`.
//!
//! A message is JSON, then UTF-8, cut into parts of at most
//! [`MAX_MESSAGE_SIZE`] bytes each; every part starts with a 5-byte header
//! `[flags u8][index u32 LE]` (`flags` bit 0 marks the last part, `index`
//! counts parts of one message from 0). `flags` bit 1 marks [`READY_PART`],
//! which carries no message: the first thing the side that did NOT open a
//! data channel sends on it, once its RTC half reports the channel opened
//! (the `S-27` rule); the opener sends nothing before it. A channel is
//! ordered and reliable (a WebRTC data channel's own guarantee), so parts
//! of one message arrive consecutively in order.
//!
//! This module is pure state: it has no socket and no async I/O of its own.
//! `Channel::pop_sendable` hands the caller (`super::connection`) the next
//! part to actually write to the RTC layer, and `Channel::receive` turns a
//! raw part into a [`Received`] outcome. Unlike `channel.js::FreenetChannel`
//! this struct never holds a callback/connection back-reference: the
//! module boundary here is that `connection.rs` drives every `Channel` by
//! value, passing whatever the RTC layer needs as plain arguments, rather
//! than each channel calling back into its owner — an adaptation to Rust's
//! ownership rules, not a behavioural difference.
//!
//! One further simplification, safe in this crate's single-task-per-
//! connection design (never true of `channel.js`'s Node/node-datachannel
//! callback timing): `channel.js::_hold`/`_held` replays messages that
//! arrived before the *opener* had received its `FreenetChannel` object
//! back from `openChannel` — a race specific to node-datachannel's message
//! callback firing from a different turn of the event loop than the
//! `openChannel` call that set it up. `super::connection` wires a `Channel`
//! and its owning `(protocol, id)` key synchronously, in the same step that
//! creates it, so a `ChannelData` event for a not-yet-`openChannel`'d key
//! cannot arrive first; there is nothing here for a held-buffer to replay.

//!
//! > 2026-09-30, K13: a third kind, the binary message channel
//! > ([`Channel::new_binary`], [`ChannelKind::Binary`]), carries the v2
//! > session channels (`protocol.md` §5): the same part framing and
//! > `READY_PART` rule as a JSON channel, but a message is opaque bytes (a
//! > `postcard` value) instead of JSON text.

use std::collections::{HashSet, VecDeque};

/// What a channel carries (K13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// `channel.js`: JSON messages in parts.
    Json,
    /// `history.js::HistoryChannel`: raw bytes, no parts.
    Raw,
    /// Opaque byte messages in parts (the v2 session channels).
    Binary,
}

/// `channel.js::MAX_MESSAGE_SIZE`: one data-channel message at most.
pub const MAX_MESSAGE_SIZE: usize = 65536;
/// `channel.js::HEADER_BYTES`.
pub const HEADER_BYTES: usize = 5;
/// `channel.js::PART_BYTES = MAX_MESSAGE_SIZE - HEADER_BYTES`.
pub const PART_BYTES: usize = MAX_MESSAGE_SIZE - HEADER_BYTES;
/// `channel.js`'s `flags` bit 0.
pub const LAST: u8 = 1;
/// `channel.js`'s `flags` bit 1.
pub const READY: u8 = 2;
/// `channel.js::QUEUE_HIGH_WATER`.
pub const QUEUE_HIGH_WATER: usize = 256 * 1024;

/// `channel.js::READY_PART`: 5 bytes exactly, `flags = READY`, index field
/// zero, no body.
pub const READY_PART: [u8; 5] = [READY, 0, 0, 0, 0];

/// `channel.js::labelOf`.
pub fn label_of(protocol: &str, id: &[u8]) -> String {
    format!("{protocol} {}", hex::encode(id))
}

/// `channel.js::parseLabel`: `None` for a label this side did not construct
/// via `label_of` (the dial's bootstrap channel, or anything else without
/// this exact `"<protocol> <hex>"` shape).
pub fn parse_label(label: &str) -> Option<(String, Vec<u8>)> {
    let at = label.rfind(' ')?;
    if at == 0 {
        return None;
    }
    let id_hex = &label[at + 1..];
    if !id_hex.len().is_multiple_of(2)
        || !id_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let id = hex::decode(id_hex).ok()?;
    Some((label[..at].to_string(), id))
}

/// `channel.js::cut`: `message` as the parts that carry it. `None` if
/// `message` does not serialize to JSON (mirrors `JSON.stringify`
/// returning `undefined` for e.g. a bare function — never the case for a
/// `serde_json::Value`, but kept as a `Result` for parity with the JS
/// `TypeError` path and so a future caller building `Value` from something
/// odd is not tempted to `unwrap` blindly).
pub fn cut(message: &serde_json::Value) -> Vec<Vec<u8>> {
    cut_bytes(message.to_string().as_bytes())
}

/// `channel.js::cut`'s part framing over any message body (K13: a binary
/// message channel's bodies are opaque bytes).
pub fn cut_bytes(body: &[u8]) -> Vec<Vec<u8>> {
    let count = std::cmp::max(1, body.len().div_ceil(PART_BYTES));
    let mut parts = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * PART_BYTES;
        let end = std::cmp::min(start + PART_BYTES, body.len());
        let chunk = &body[start..end];
        let mut part = Vec::with_capacity(HEADER_BYTES + chunk.len());
        part.push(if index == count - 1 { LAST } else { 0 });
        part.extend_from_slice(&(index as u32).to_le_bytes());
        part.extend_from_slice(chunk);
        parts.push(part);
    }
    parts
}

/// The outcome of feeding one raw part to [`Channel::receive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Not the last part of a message yet; more are expected.
    Pending,
    /// The other side's `READY_PART` arrived and was consumed: this side
    /// may now send.
    Ready,
    /// A complete message reassembled byte-identical to its JSON body.
    Message(serde_json::Value),
    /// One data-channel message of a raw channel ([`Channel::new_raw`]),
    /// handed over as it arrived; or (K13) one whole reassembled message of
    /// a binary channel ([`Channel::new_binary`]).
    Bytes(Vec<u8>),
    /// A malformed part or `READY_PART`, or JSON that failed to parse.
    /// The caller shuts the channel (`channel:malformed`), same as
    /// `channel.js`'s `this._shut(true)` on every one of these paths.
    Malformed,
    /// The channel is already closed; the part is ignored.
    Closed,
}

/// One Freenet channel's framing/back-pressure state
/// (`channel.js::FreenetChannel`).
pub struct Channel {
    pub protocol: String,
    pub id: Vec<u8>,
    pub label: String,
    send_chan_id: Option<u32>,
    writable: bool,
    open: bool,
    await_ready: bool,
    paused: bool,
    chan_ids: HashSet<u32>,
    queue: VecDeque<Vec<u8>>,
    queued: usize,
    queued_high: usize,
    parts: Vec<Vec<u8>>,
    closed: bool,
    /// A raw ordered byte channel (K10): no part header, no JSON; see
    /// [`Channel::new_raw`].
    raw: bool,
    /// A binary message channel (K13): parts, but no JSON; see
    /// [`Channel::new_binary`].
    binary: bool,
}

impl Channel {
    pub fn new(protocol: &str, id: &[u8]) -> Channel {
        Channel {
            protocol: protocol.to_string(),
            id: id.to_vec(),
            label: label_of(protocol, id),
            send_chan_id: None,
            writable: false,
            open: false,
            await_ready: false,
            paused: false,
            chan_ids: HashSet::new(),
            queue: VecDeque::new(),
            queued: 0,
            queued_high: 0,
            parts: Vec::new(),
            closed: false,
            raw: false,
            binary: false,
        }
    }

    /// A binary message channel (K13, `protocol.md` §5): framed exactly as
    /// a JSON channel ([`cut_bytes`], `READY_PART`), but a message is
    /// opaque bytes; [`Self::send_message_bytes`] sends one and
    /// [`Self::receive`] hands a whole reassembled one over as
    /// [`Received::Bytes`].
    pub fn new_binary(protocol: &str, id: &[u8]) -> Channel {
        let mut ch = Channel::new(protocol, id);
        ch.binary = true;
        ch
    }

    /// A channel of `kind`.
    pub fn of_kind(kind: ChannelKind, protocol: &str, id: &[u8]) -> Channel {
        match kind {
            ChannelKind::Json => Channel::new(protocol, id),
            ChannelKind::Raw => Channel::new_raw(protocol, id),
            ChannelKind::Binary => Channel::new_binary(protocol, id),
        }
    }

    /// Whether this is a binary message channel ([`Self::new_binary`]).
    pub fn is_binary(&self) -> bool {
        self.binary
    }

    /// Queues one binary message as parts ([`cut_bytes`]). Returns
    /// [`Self::takes_more`].
    pub fn send_message_bytes(&mut self, body: &[u8]) -> bool {
        if self.closed {
            return false;
        }
        for part in cut_bytes(body) {
            self.queued += part.len();
            self.queue.push_back(part);
        }
        if self.queued > self.queued_high {
            self.queued_high = self.queued;
        }
        self.takes_more()
    }

    /// A raw ordered byte channel (K10), the Rust twin of ZBTerm
    /// `history.js::HistoryChannel`: the same label, pairing, `READY_PART`
    /// rule, queue and back-pressure as a JSON channel, but [`Self::send_bytes`]
    /// cuts the bytes into data-channel messages of at most
    /// [`MAX_MESSAGE_SIZE`] with no header, and every data-channel message
    /// that arrives is handed over as [`Received::Bytes`], uninterpreted.
    /// A send of at most `MAX_MESSAGE_SIZE` bytes stays one data-channel
    /// message, so a caller that frames its own messages (ZBTerm's
    /// `channel.js` parts, `history.js`'s u32 frames) keeps its boundaries.
    pub fn new_raw(protocol: &str, id: &[u8]) -> Channel {
        let mut ch = Channel::new(protocol, id);
        ch.raw = true;
        ch
    }

    /// Whether this is a raw byte channel ([`Self::new_raw`]).
    pub fn is_raw(&self) -> bool {
        self.raw
    }

    /// `history.js::HistoryChannel::send`: queues `bytes` as parts of at
    /// most [`MAX_MESSAGE_SIZE`] bytes, no header. Returns
    /// [`Self::takes_more`].
    pub fn send_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.closed {
            return false;
        }
        for part in bytes.chunks(MAX_MESSAGE_SIZE) {
            self.queued += part.len();
            self.queue.push_back(part.to_vec());
        }
        if self.queued > self.queued_high {
            self.queued_high = self.queued;
        }
        self.takes_more()
    }

    /// `history.js::HistoryChannel::_takesMore`: open, not paused, and
    /// less than [`QUEUE_HIGH_WATER`] queued.
    pub fn takes_more(&self) -> bool {
        !self.closed && !self.paused && self.queued < QUEUE_HIGH_WATER
    }

    /// Bytes queued and not yet handed to the RTC layer.
    pub fn queued(&self) -> usize {
        self.queued
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The data channel `chan_id` is this endpoint's to send on
    /// (`channel.js::_sendOn`); `await_ready` when this side created it
    /// (the opener), so it waits for [`READY_PART`] before sending.
    pub fn send_on(&mut self, chan_id: u32, open: bool, await_ready: bool) {
        self.send_chan_id = Some(chan_id);
        self.chan_ids.insert(chan_id);
        self.await_ready = await_ready;
        if open {
            self.opened(chan_id);
        }
    }

    /// The channel `both sides opened the key at once` case
    /// (`connection.js::_channelEvent`): this endpoint also reads from the
    /// remote's data channel.
    pub fn also_read_from(&mut self, chan_id: u32) {
        self.chan_ids.insert(chan_id);
    }

    /// `channel.js::_opened`.
    pub fn opened(&mut self, chan_id: u32) {
        if Some(chan_id) != self.send_chan_id || self.open {
            return;
        }
        self.open = true;
        self.become_writable();
    }

    fn become_writable(&mut self) {
        if self.writable || !self.open || self.await_ready {
            return;
        }
        self.writable = true;
    }

    /// `channel.js::_flow`: back-pressure from the RTC half for the data
    /// channel this endpoint sends on.
    pub fn flow(&mut self, chan_id: u32, paused: bool) {
        if Some(chan_id) != self.send_chan_id {
            return;
        }
        self.paused = paused;
    }

    /// `channel.js::send`: cuts `message` into parts and queues them.
    /// Returns the same back-pressure signal `send()` returns: `false`
    /// once closed, paused, or [`QUEUE_HIGH_WATER`] or more is queued.
    pub fn send(&mut self, message: &serde_json::Value) -> bool {
        if self.closed {
            return false;
        }
        for part in cut(message) {
            self.queued += part.len();
            self.queue.push_back(part);
        }
        if self.queued > self.queued_high {
            self.queued_high = self.queued;
        }
        !self.closed && !self.paused && self.queued < QUEUE_HIGH_WATER
    }

    /// Pops the next queued part to actually write to the RTC layer, or
    /// `None` if nothing is currently allowed to go out (not writable,
    /// paused, closed, or the queue is empty) — `channel.js::_pump`, with
    /// the RTC `send` call itself left to the caller.
    pub fn pop_sendable(&mut self) -> Option<Vec<u8>> {
        if self.closed || !self.writable || self.paused {
            return None;
        }
        let part = self.queue.pop_front()?;
        self.queued -= part.len();
        Some(part)
    }

    /// Whether `pop_sendable` has anything to hand out right now.
    pub fn has_sendable(&self) -> bool {
        !self.closed && self.writable && !self.paused && !self.queue.is_empty()
    }

    /// `channel.js::_data`/`_readyPart`: feeds one raw part received on
    /// `chan_id` to this channel's reassembly state machine.
    pub fn receive(&mut self, data: &[u8], chan_id: u32) -> Received {
        if self.closed {
            return Received::Closed;
        }
        if self.await_ready && Some(chan_id) == self.send_chan_id {
            if data.len() != READY_PART.len() || data != READY_PART {
                return Received::Malformed;
            }
            self.await_ready = false;
            self.become_writable();
            return Received::Ready;
        }
        if self.raw {
            return Received::Bytes(data.to_vec());
        }
        if data.len() < HEADER_BYTES {
            return Received::Malformed;
        }
        let index = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if index != self.parts.len() {
            return Received::Malformed;
        }
        self.parts.push(data[HEADER_BYTES..].to_vec());
        if data[0] & LAST == 0 {
            return Received::Pending;
        }
        let body: Vec<u8> = self.parts.concat();
        self.parts.clear();
        if self.binary {
            return Received::Bytes(body);
        }
        match std::str::from_utf8(&body)
            .ok()
            .and_then(|s| serde_json::from_str(s).ok())
        {
            Some(value) => Received::Message(value),
            None => Received::Malformed,
        }
    }

    /// `channel.js::_shut`: closes every data channel of this endpoint
    /// (unless the connection is gone) and marks the channel closed.
    /// Returns the `chan_id`s this channel was reading from, so the caller
    /// (`connection.rs`) can close them on the RTC half if `close_data_channels`.
    pub fn shut(&mut self) -> Vec<u32> {
        if self.closed {
            return Vec::new();
        }
        self.closed = true;
        self.queue.clear();
        self.queued = 0;
        self.parts.clear();
        self.chan_ids.drain().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn binary_messages_are_parts_reassembled_to_bytes() {
        let mut a = Channel::new_binary("zxterm/ctl", &[1; 16]);
        a.send_on(1, true, false);
        let body: Vec<u8> = (0..(PART_BYTES * 2 + 7)).map(|i| i as u8).collect();
        assert!(a.send_message_bytes(&body));
        let mut b = Channel::new_binary("zxterm/ctl", &[1; 16]);
        b.send_on(2, true, false);
        let mut got = None;
        while let Some(part) = a.pop_sendable() {
            assert!(part.len() <= MAX_MESSAGE_SIZE);
            match b.receive(&part, 1) {
                Received::Bytes(m) => got = Some(m),
                Received::Pending => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, Some(body));
        // An empty message is one part with no body.
        assert_eq!(cut_bytes(&[]), vec![vec![LAST, 0, 0, 0, 0]]);
    }

    #[test]
    fn label_of_matches_protocol_space_hex() {
        assert_eq!(
            label_of("zbterm/history", &[0xAB, 0xCD]),
            "zbterm/history abcd"
        );
        assert_eq!(label_of("p", &[]), "p ");
    }

    #[test]
    fn parse_label_round_trips_label_of() {
        let label = label_of("zbterm/ctl", &[1, 2, 3]);
        let (protocol, id) = parse_label(&label).expect("parses");
        assert_eq!(protocol, "zbterm/ctl");
        assert_eq!(id, vec![1, 2, 3]);
    }

    #[test]
    fn parse_label_rejects_the_bootstrap_label() {
        // BOOTSTRAP_LABEL has no trailing hex id in this shape.
        assert_eq!(parse_label(crate::wire::BOOTSTRAP_LABEL), None);
    }

    #[test]
    fn parse_label_rejects_uppercase_hex_and_odd_length() {
        assert_eq!(parse_label("p ABCD"), None);
        assert_eq!(parse_label("p abc"), None);
        assert_eq!(parse_label("noSpaceAtAll"), None);
        assert_eq!(parse_label(" abcd"), None); // at == 0
    }

    #[test]
    fn cut_produces_one_part_for_a_short_message() {
        let msg = json!({"a": 1});
        let parts = cut(&msg);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0][0], LAST);
        assert_eq!(&parts[0][1..5], &0u32.to_le_bytes());
        let body = &parts[0][HEADER_BYTES..];
        assert_eq!(std::str::from_utf8(body).unwrap(), msg.to_string());
    }

    #[test]
    fn cut_splits_a_large_message_into_parts_at_most_max_message_size() {
        let big = "x".repeat(PART_BYTES * 3 + 10);
        let msg = json!({"body": big});
        let parts = cut(&msg);
        assert!(parts.len() > 1, "must split");
        for (i, part) in parts.iter().enumerate() {
            assert!(
                part.len() <= MAX_MESSAGE_SIZE,
                "part {i} exceeds MAX_MESSAGE_SIZE"
            );
            let is_last = i == parts.len() - 1;
            assert_eq!(part[0] & LAST != 0, is_last);
            let index = u32::from_le_bytes([part[1], part[2], part[3], part[4]]) as usize;
            assert_eq!(index, i);
        }
        // Reassemble and compare byte-identical to the original JSON text.
        let reassembled: Vec<u8> = parts
            .iter()
            .flat_map(|p| p[HEADER_BYTES..].to_vec())
            .collect();
        assert_eq!(String::from_utf8(reassembled).unwrap(), msg.to_string());
    }

    #[test]
    fn round_trip_send_and_receive_reassembles_multi_part_message() {
        // `sender` is the *taker* (did not open the channel): it may send
        // immediately, but the real `READY_PART` handshake is
        // `connection.rs`'s job, not `Channel::send`'s — this test injects
        // it by hand, exactly as `connection.rs::_channelEvent` would.
        let mut sender = Channel::new("zbterm/history", &[9]);
        sender.send_on(1, true, false);
        let big = "y".repeat(PART_BYTES * 2 + 5);
        let msg = json!({"payload": big});
        assert!(sender.send(&msg));

        let mut receiver = Channel::new("zbterm/history", &[9]);
        // The receiver is the *opener*: it awaits READY (S-27) and is not
        // writable until it gets it.
        receiver.send_on(1, true, true);
        assert_eq!(receiver.receive(&READY_PART, 1), Received::Ready);

        let mut result = None;
        while let Some(part) = sender.pop_sendable() {
            match receiver.receive(&part, 1) {
                Received::Message(v) => result = Some(v),
                Received::Pending => {}
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(result, Some(msg));
    }

    #[test]
    fn opener_is_not_writable_until_ready_part_arrives() {
        let mut opener = Channel::new("p", &[1]);
        opener.send_on(1, true, true);
        assert!(!opener.has_sendable());
        assert!(opener.send(&json!({"x": 1})));
        assert!(!opener.has_sendable(), "must not send before READY_PART");
        assert_eq!(opener.receive(&READY_PART, 1), Received::Ready);
        assert!(opener.has_sendable(), "now writable");
    }

    #[test]
    fn taker_sends_ready_immediately_since_it_never_awaits() {
        let mut taker = Channel::new("p", &[1]);
        taker.send_on(1, true, false);
        assert!(taker.send(&json!({"x": 1})));
        assert!(taker.has_sendable());
    }

    #[test]
    fn a_malformed_ready_part_is_refused() {
        let mut opener = Channel::new("p", &[1]);
        opener.send_on(1, true, true);
        assert_eq!(opener.receive(&[9, 9, 9, 9, 9], 1), Received::Malformed);
    }

    #[test]
    fn out_of_order_index_is_malformed() {
        let mut receiver = Channel::new("p", &[1]);
        receiver.send_on(1, true, false);
        let mut part = vec![0u8; HEADER_BYTES];
        part[1..5].copy_from_slice(&1u32.to_le_bytes()); // expected 0, got 1
        assert_eq!(receiver.receive(&part, 1), Received::Malformed);
    }

    #[test]
    fn invalid_json_body_is_malformed() {
        let mut receiver = Channel::new("p", &[1]);
        receiver.send_on(1, true, false);
        let mut part = vec![LAST, 0, 0, 0, 0];
        part.extend_from_slice(b"{not json");
        assert_eq!(receiver.receive(&part, 1), Received::Malformed);
    }

    #[test]
    fn shut_is_idempotent_and_clears_queue() {
        let mut ch = Channel::new("p", &[1]);
        ch.send_on(1, true, false);
        ch.send(&json!({"a": 1}));
        let chan_ids = ch.shut();
        assert_eq!(chan_ids, vec![1]);
        assert!(ch.is_closed());
        assert!(!ch.send(&json!({"b": 2})));
        assert_eq!(ch.shut(), Vec::<u32>::new(), "idempotent");
    }

    #[test]
    fn back_pressure_reports_false_at_queue_high_water() {
        let mut ch = Channel::new("p", &[1]);
        ch.send_on(1, true, false);
        // Never opened for real send in this test; queue keeps growing.
        ch.paused = false;
        let big = "z".repeat(QUEUE_HIGH_WATER);
        let ok = ch.send(&json!({"b": big}));
        assert!(!ok, "queued >= QUEUE_HIGH_WATER must report back-pressure");
    }

    #[test]
    fn both_sides_opened_at_once_reads_from_both_chan_ids() {
        let mut ch = Channel::new("p", &[1]);
        ch.send_on(1, true, true); // this side's own, awaiting ready
        ch.also_read_from(2); // the remote's, discovered via the pairing race
        // Data on the *other* chan_id is not subject to the await-ready gate.
        let mut part = vec![LAST, 0, 0, 0, 0];
        part.extend_from_slice(b"{}");
        assert_eq!(ch.receive(&part, 2), Received::Message(json!({})));
    }
}

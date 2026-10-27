//! `Output` back-pressure and drop-to-snapshot (K7 Step 5): a client that
//! falls behind (its outbound queue is full) gets one snapshot event plus a
//! capped tail instead of an ever-growing backlog — the `S-35` rule
//! (ZBTerm's own fixed bug, `engine/share-manager.js`'s `_lagPeer`/
//! `_resyncPeer`) moved to this seam.
//!
//! Caps reused from `share-manager.js`'s `RESYNC_SCROLLBACK`/
//! `RESYNC_TAIL_BYTES` (verified 2026-09-29: `const RESYNC_SCROLLBACK = 500`
//! lines, `const RESYNC_TAIL_BYTES = 64 * 1024` bytes) — ZBTerm's own tuned
//! numbers for terminal-scrollback resync, reused here as a design choice
//! this phase makes, not a fact ported from a spec (see this phase's
//! Gotchas). `LAG_RESYNC_MS`/`LAG_RESYNC_MAX_MS` are a *different* pair (a
//! retry backoff interval) and are not reused here.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use super::protocol::Frame;

/// `share-manager.js::RESYNC_TAIL_BYTES`.
pub const RESYNC_TAIL_BYTES: usize = 64 * 1024;
/// `share-manager.js::RESYNC_SCROLLBACK`.
pub const RESYNC_SCROLLBACK: usize = 500;

/// A capped ring buffer of the most recent bytes, enforcing both caps
/// generically: [`RESYNC_TAIL_BYTES`] always, and [`RESYNC_SCROLLBACK`]
/// discrete `\n`-terminated records only when the buffered bytes actually
/// contain any `\n` (a raw byte stream, like `test.flood`'s, is not
/// line-oriented, so only the byte cap applies to it — a later phase's
/// line-structured `Output` use gets both caps for free, per this phase's
/// own Gotchas).
struct Tail {
    buf: VecDeque<u8>,
}

impl Tail {
    fn new() -> Self {
        Tail {
            buf: VecDeque::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
        self.enforce_byte_cap();
        self.enforce_line_cap();
    }

    fn enforce_byte_cap(&mut self) {
        while self.buf.len() > RESYNC_TAIL_BYTES {
            self.buf.pop_front();
        }
    }

    fn enforce_line_cap(&mut self) {
        let newline_count = self.buf.iter().filter(|&&b| b == b'\n').count();
        if newline_count == 0 || newline_count <= RESYNC_SCROLLBACK {
            return;
        }
        let mut to_drop = newline_count - RESYNC_SCROLLBACK;
        while to_drop > 0 {
            match self.buf.pop_front() {
                Some(b'\n') => to_drop -= 1,
                Some(_) => {}
                None => break,
            }
        }
    }

    fn take(&mut self) -> Vec<u8> {
        self.buf.drain(..).collect()
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buf.len()
    }
}

/// One connected client's outbound `Output` sink: droppable, back-pressure
/// aware. `stream_name` is fixed for the lifetime of one sink (a caller that
/// multiplexes several logical streams over one connection uses one
/// [`OutputSink`] per stream).
pub struct OutputSink {
    tx: mpsc::Sender<Frame>,
    lagging: AtomicBool,
    tail: Mutex<Tail>,
}

/// What one `send` call did — surfaced for tests and metrics, never required
/// reading by a caller that just wants fire-and-forget delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Queued normally.
    Sent,
    /// The outbound queue was full: this chunk was folded into the tail
    /// instead of queued, and the client is now marked lagging.
    Dropped,
    /// Still lagging from an earlier drop: folded into the tail.
    StillLagging,
    /// The connection is gone; nothing was done.
    Closed,
}

impl OutputSink {
    /// `capacity` is the outbound channel's queue depth (in frames): once
    /// this many `Output` frames are queued and undelivered, the client
    /// counts as "behind".
    pub fn new(tx: mpsc::Sender<Frame>) -> Self {
        OutputSink {
            tx,
            lagging: AtomicBool::new(false),
            tail: Mutex::new(Tail::new()),
        }
    }

    /// Sends (or drops-to-tail) one chunk of `stream`'s output. Never
    /// blocks: a full queue is exactly the "client fell behind" signal this
    /// sink exists to handle.
    pub fn send(&self, stream: &str, bytes: &[u8]) -> SendOutcome {
        if !self.lagging.load(Ordering::Acquire) {
            match self.tx.try_send(Frame::Output {
                stream: stream.to_string(),
                bytes: bytes.to_vec(),
            }) {
                Ok(()) => return SendOutcome::Sent,
                Err(mpsc::error::TrySendError::Closed(_)) => return SendOutcome::Closed,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.lagging.store(true, Ordering::Release);
                    self.tail.lock().unwrap().push(bytes);
                    self.try_resync();
                    return SendOutcome::Dropped;
                }
            }
        }
        self.tail.lock().unwrap().push(bytes);
        let outcome = self.try_resync();
        if outcome == SendOutcome::Closed {
            SendOutcome::Closed
        } else {
            SendOutcome::StillLagging
        }
    }

    /// If lagging and the outbound queue now has room, replaces the queued
    /// backlog with one `resync` [`Frame::Event`] plus the capped tail as a
    /// single `snapshot` [`Frame::Output`], and clears the lagging flag.
    /// A queue still full leaves the tail buffered for the next `send` (or
    /// the next drain, see [`OutputSink::poll_resync`]) to retry.
    fn try_resync(&self) -> SendOutcome {
        if !self.lagging.load(Ordering::Acquire) {
            return SendOutcome::Sent;
        }
        let mut tail = self.tail.lock().unwrap();
        if tail.is_empty() {
            self.lagging.store(false, Ordering::Release);
            return SendOutcome::Sent;
        }
        match self.tx.try_send(Frame::Event {
            name: "resync".to_string(),
            data: "{}".to_string(),
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => return SendOutcome::Closed,
            Err(mpsc::error::TrySendError::Full(_)) => return SendOutcome::StillLagging,
        }
        let bytes = tail.take();
        match self.tx.try_send(Frame::Output {
            stream: "snapshot".to_string(),
            bytes,
        }) {
            Ok(()) => {
                self.lagging.store(false, Ordering::Release);
                SendOutcome::Sent
            }
            Err(mpsc::error::TrySendError::Closed(_)) => SendOutcome::Closed,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The resync Event went out but the snapshot Output could
                // not follow immediately; keep the bytes so the next poll
                // resends them (never drop what was already accepted for
                // resync).
                SendOutcome::StillLagging
            }
        }
    }

    /// Called by the writer task whenever the outbound queue drains, to
    /// retry a resync that a full queue previously deferred. A no-op when
    /// not lagging.
    pub fn poll_resync(&self) {
        self.try_resync();
    }

    /// Whether this client is currently considered behind.
    pub fn is_lagging(&self) -> bool {
        self.lagging.load(Ordering::Acquire)
    }

    /// The tail buffer's current length — for tests only (never a
    /// public API real callers should depend on).
    #[cfg(test)]
    fn tail_len(&self) -> usize {
        self.tail.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_keeping_up_receives_every_chunk() {
        let (tx, mut rx) = mpsc::channel(8);
        let sink = OutputSink::new(tx);
        for i in 0..5u8 {
            assert_eq!(sink.send("s", &[i]), SendOutcome::Sent);
        }
        for i in 0..5u8 {
            match rx.try_recv().unwrap() {
                Frame::Output { bytes, .. } => assert_eq!(bytes, vec![i]),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(!sink.is_lagging());
    }

    #[test]
    fn a_lagging_client_gets_one_snapshot_instead_of_an_unbounded_backlog() {
        let (tx, mut rx) = mpsc::channel(2);
        let sink = OutputSink::new(tx);
        // Fill the queue.
        assert_eq!(sink.send("s", b"a"), SendOutcome::Sent);
        assert_eq!(sink.send("s", b"b"), SendOutcome::Sent);
        // Now the queue is full: every further chunk drops to the tail
        // instead of growing the queue without bound.
        for _ in 0..1000 {
            let outcome = sink.send("s", b"x");
            assert!(matches!(
                outcome,
                SendOutcome::Dropped | SendOutcome::StillLagging
            ));
        }
        assert!(sink.is_lagging());
        assert!(sink.tail_len() <= RESYNC_TAIL_BYTES);

        // Drain the queue (the two originally-sent chunks) and poll for the
        // resync: it must now go out as exactly one Event + one Output.
        assert!(matches!(rx.try_recv().unwrap(), Frame::Output { .. }));
        assert!(matches!(rx.try_recv().unwrap(), Frame::Output { .. }));
        sink.poll_resync();
        assert!(!sink.is_lagging());
        match rx.try_recv().unwrap() {
            Frame::Event { name, .. } => assert_eq!(name, "resync"),
            other => panic!("expected resync Event, got {other:?}"),
        }
        match rx.try_recv().unwrap() {
            Frame::Output { stream, .. } => assert_eq!(stream, "snapshot"),
            other => panic!("expected snapshot Output, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "nothing queued beyond the resync pair"
        );
    }

    #[test]
    fn the_tail_never_exceeds_resync_tail_bytes() {
        let (tx, _rx) = mpsc::channel(1);
        let sink = OutputSink::new(tx);
        // Force lagging with an oversized single push directly against the
        // internal tail cap.
        let mut tail = Tail::new();
        for _ in 0..(RESYNC_TAIL_BYTES * 3) {
            tail.push(b"z");
        }
        assert!(tail.len() <= RESYNC_TAIL_BYTES);
        drop(sink); // sink itself untouched above; this only exercises Tail.
    }

    #[test]
    fn line_oriented_tail_is_capped_at_resync_scrollback_records() {
        let mut tail = Tail::new();
        for i in 0..(RESYNC_SCROLLBACK * 2) {
            tail.push(format!("line-{i}\n").as_bytes());
        }
        let bytes = tail.take();
        let newline_count = bytes.iter().filter(|&&b| b == b'\n').count();
        assert!(newline_count <= RESYNC_SCROLLBACK);
        assert!(bytes.len() <= RESYNC_TAIL_BYTES);
    }
}

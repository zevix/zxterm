//! Serving history on the `history` channel (`protocol.md` §5,
//! [`crate::session::messages::HistoryMsg`]).
//!
//! A viewer sends `RangeRequest {request_id, start, end, credit}`; the host
//! answers with up to [`crate::history::MAX_SEGMENTS_PER_REQUEST`] closed
//! segments as `Segment {request_id, start, data}` messages, then
//! `Done {request_id, next}` (`next`: the first sequence number not served;
//! `start` when nothing was, e.g. the range lies in the still-open segment,
//! which the live channel carries). Each `Segment` costs one credit; the
//! host sends only while it holds credit and waits, never drops, when it
//! has none; the viewer adds credit with `Credit`. The host caps the credit
//! it will hold at [`crate::history::MAX_HISTORY_CREDIT`] whatever the
//! viewer asks, so a request never has more than that many segments
//! (about 64 KiB each) in flight, and at most
//! [`crate::history::MAX_REQUESTS_PER_PEER`] requests run per peer.
//!
//! `Segment.data` is a [`SegmentData`] (`postcard`): the segment record
//! (`super::segment`), its index in the file, and, on the request's first
//! segment, the [`RangeProof`] that lets the viewer check every segment of
//! the request against the signed head before trusting it
//! (`super::fetch::RangeVerifier`). Nothing local (snapshots, the index) is
//! ever part of a reply.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::Error;

use super::MAX_HISTORY_CREDIT;
use super::head::RangeProof;
use super::segment::SegmentHeader;
use super::store::SegmentFile;

/// The wire form of one served segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentData {
    /// Index of the segment in the file (its place in the chain).
    pub index: u64,
    pub record: Vec<u8>,
    /// Present on the first segment of a request.
    pub proof: Option<RangeProof>,
}

impl SegmentData {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("segment data always encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<SegmentData, Error> {
        postcard::from_bytes(bytes)
            .map_err(|_| Error::new(crate::error::Code::ECorrupt, "Segment reply is malformed"))
    }
}

/// What a source answers a range with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangePlan {
    pub first_index: u64,
    pub count: u64,
    /// The first sequence number not served.
    pub next: u64,
    pub proof: RangeProof,
}

/// Where the host's `history` channel gets its segments.
pub trait HistorySource: Send + Sync + std::fmt::Debug {
    /// The segments answering `[start, end)`, or `None` when no closed
    /// segment holds any of it.
    fn plan(&self, start: u64, end: u64) -> Result<Option<RangePlan>, Error>;
    /// The record of segment `index`, checked against the chain.
    fn record(&self, index: u64) -> Result<Vec<u8>, Error>;
}

/// A [`SegmentFile`] shared between its writer (the caller appending
/// output) and the service serving it.
#[derive(Clone)]
pub struct SharedHistory(pub Arc<Mutex<SegmentFile>>);

impl std::fmt::Debug for SharedHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedHistory")
    }
}

impl SharedHistory {
    pub fn new(file: SegmentFile) -> SharedHistory {
        SharedHistory(Arc::new(Mutex::new(file)))
    }
}

impl HistorySource for SharedHistory {
    fn plan(&self, start: u64, end: u64) -> Result<Option<RangePlan>, Error> {
        Ok(self.0.lock().expect("history").plan_range(start, end))
    }

    fn record(&self, index: u64) -> Result<Vec<u8>, Error> {
        self.0.lock().expect("history").record(index)
    }
}

/// The sources the service serves from, by session id.
#[derive(Debug, Clone, Default)]
pub struct HistoryRegistry {
    sources: Arc<Mutex<HashMap<String, Arc<dyn HistorySource>>>>,
}

impl HistoryRegistry {
    pub fn new() -> HistoryRegistry {
        HistoryRegistry::default()
    }

    pub fn insert(&self, session_id: &str, source: Arc<dyn HistorySource>) {
        self.sources
            .lock()
            .expect("history registry")
            .insert(session_id.to_string(), source);
    }

    pub fn remove(&self, session_id: &str) {
        self.sources
            .lock()
            .expect("history registry")
            .remove(session_id);
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<dyn HistorySource>> {
        self.sources
            .lock()
            .expect("history registry")
            .get(session_id)
            .cloned()
    }
}

/// What a request emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeOut {
    /// A `Segment` message: its `start` and `data` ([`SegmentData`]).
    Segment { start: u64, data: Vec<u8> },
    /// The `Done` message's `next`; the request is finished.
    Done { next: u64 },
}

/// One request being served: the credit-gated cursor over its plan.
#[derive(Debug)]
pub struct ServeRequest {
    source: Arc<dyn HistorySource>,
    plan: RangePlan,
    sent: u64,
    credit: u64,
    served_end: u64,
    proof_sent: bool,
    finished: bool,
}

impl ServeRequest {
    /// A request for `[start, end)` with the viewer's initial `credit`;
    /// `Ok(Err(next))`-style: `None` plan means nothing to serve, answered
    /// by the caller with `Done {next: start}`.
    pub fn start(
        source: Arc<dyn HistorySource>,
        start: u64,
        end: u64,
        credit: u32,
    ) -> Result<Option<ServeRequest>, Error> {
        let Some(plan) = source.plan(start, end)? else {
            return Ok(None);
        };
        Ok(Some(ServeRequest {
            source,
            plan,
            sent: 0,
            credit: (credit as u64).min(MAX_HISTORY_CREDIT as u64),
            served_end: start,
            proof_sent: false,
            finished: false,
        }))
    }

    /// The viewer's `Credit`: added, never above
    /// [`MAX_HISTORY_CREDIT`] held.
    pub fn add_credit(&mut self, credit: u32) {
        self.credit = (self.credit + credit as u64).min(MAX_HISTORY_CREDIT as u64);
    }

    /// Segments the request could send now.
    pub fn credit(&self) -> u64 {
        self.credit
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Everything the current credit allows, then `Done` once every
    /// planned segment is out. A source error ends the request early with
    /// `Done {next}` for what was served.
    pub fn pump(&mut self) -> Vec<ServeOut> {
        let mut out = Vec::new();
        while !self.finished && self.sent < self.plan.count && self.credit > 0 {
            let record = match self.source.record(self.plan.first_index + self.sent) {
                Ok(r) => r,
                Err(_) => {
                    self.finished = true;
                    out.push(ServeOut::Done {
                        next: self.served_end,
                    });
                    return out;
                }
            };
            let Ok(header) = SegmentHeader::decode(&record) else {
                self.finished = true;
                out.push(ServeOut::Done {
                    next: self.served_end,
                });
                return out;
            };
            let data = SegmentData {
                index: self.plan.first_index + self.sent,
                record,
                proof: (!self.proof_sent).then(|| self.plan.proof.clone()),
            };
            self.proof_sent = true;
            self.served_end = header.end_seq();
            self.sent += 1;
            self.credit -= 1;
            out.push(ServeOut::Segment {
                start: header.first_seq,
                data: data.encode(),
            });
        }
        if !self.finished && self.sent == self.plan.count {
            self.finished = true;
            out.push(ServeOut::Done {
                next: self.plan.next,
            });
        }
        out
    }
}

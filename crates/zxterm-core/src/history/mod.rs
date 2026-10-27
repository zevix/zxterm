//! C3 segments and live history (design §4.5, K15): one session's
//! append-only file of zstd-compressed, AEAD-sealed segments, a signed
//! tamper-evident head, a local seek index with `vt100` snapshots, a signed
//! metadata record, live range reads on the `history` channel, and a
//! one-shot import of a session's existing packets. K16 adds the offline half:
//! `segment-v1` (`contracts/src/segment`), published to while a session is
//! shared and read by a viewer with the host offline.
//!
//! - [`packet`]: the plaintext packet (`schema.js::PlainPacket`).
//! - [`segment`]: the record and frame format, the seal.
//! - [`head`]: the BLAKE3 chain root, the signed head, range proofs.
//! - [`index`]: the local `seq -> ts` index and snapshot files.
//! - [`metadata`]: the signed metadata record (no envelopes for a
//!   sensitive session).
//! - [`store`]: [`SegmentFile`], which owns them all.
//! - [`serve`]/[`fetch`]: the `history` channel's host and viewer halves.
//! - [`import`]: the one-shot import.
//! - [`contract`]: `segment-v1`'s state codec, signing and the viewer's
//!   verification of a state read from it (K16, `X-26`).
//! - [`publish`]: the host's publisher and the viewer's offline read.
//!
//! Every number below is pinned by `X-24` and by a test that names it.

pub mod contract;
pub mod fetch;
pub mod head;
pub mod import;
pub mod index;
pub mod metadata;
pub mod packet;
pub mod publish;
pub mod segment;
pub mod serve;
pub mod store;

pub use packet::PlainPacket;
pub use store::{HistoryConfig, Screen, SegmentFile};

/// The flush rule's byte target: a segment closes as soon as its packets'
/// `postcard` bytes reach this many (design §4.5: "about 64 KiB of output
/// packets each"). A segment therefore holds the target plus at most one
/// packet, and is smaller after compression (measured by
/// `tests/history_format.rs::segment_sizes_under_bursty_output`).
pub const SEGMENT_TARGET_BYTES: usize = 64 * 1024;

/// The flush rule's size ceiling: a packet that would take a segment that
/// already holds packets past this many bytes closes it first and starts
/// the next one. Together with [`SEGMENT_TARGET_BYTES`]: a segment of more
/// than one packet is between the target and this ceiling (or holds fewer
/// bytes when it closed by age, an epoch change or a flush), and only a
/// single packet larger than the ceiling makes a larger segment.
pub const SEGMENT_MAX_BYTES: usize = 128 * 1024;

/// The flush rule's time bound: a segment also closes when the next packet
/// is this much newer (by `PlainPacket::ts_ms`) than its first, so a slow
/// session's history reaches its viewers without waiting for 64 KiB.
pub const SEGMENT_MAX_AGE_MS: u64 = 10_000;

/// A `vt100` snapshot is taken every this many closed segments (`X-24`),
/// about every 512 KiB of output at the target size.
pub const SNAPSHOT_EVERY_SEGMENTS: u64 = 8;

/// The most segments one range request is answered with (a request for
/// more is answered in pieces, `Done {next}` says where to continue). It
/// bounds the proof a request carries (`R-22`).
pub const MAX_SEGMENTS_PER_REQUEST: usize = 256;

/// The most credit the host holds for one request: at most this many
/// segments (about 64 KiB each, so about 256 KiB) are ever in flight,
/// whatever the viewer asks for. Tuned by the concurrent test
/// (`tests/history_format.rs::range_fetch_while_live_output_continues`):
/// with 16, two runs of nine held a burst that made the association
/// retransmit after about a second and stalled `live` with it (`R-23`);
/// with 4, none of eight did, at the same history throughput.
pub const MAX_HISTORY_CREDIT: u32 = 4;

/// The most range requests the host runs per peer at once; a further one is
/// answered `Done {next: start}` at once.
pub const MAX_REQUESTS_PER_PEER: usize = 4;

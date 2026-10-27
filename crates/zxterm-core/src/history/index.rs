//! The local seek index (design §4.5): `seq → ts` per segment and a `vt100`
//! screen snapshot every [`crate::history::SNAPSHOT_EVERY_SEGMENTS`]
//! closed segments. **Local only**: neither file is ever served on the
//! `history` channel, sent over the seam or written to a contract.
//!
//! - `index.zxi`: `INDEX_MAGIC` then one fixed 48-byte [`SegmentEntry`] per
//!   closed segment, appended as the segment closes. It holds positions and
//!   times only and can always be rebuilt from the segment file with the
//!   history keys.
//! - `snapshots.zxv`: frames of `u64le(segments) ‖ u64le(next_seq) ‖
//!   u32le(sealed length) ‖ sealed`, where `sealed` is the [`Snapshot`]
//!   (`postcard`) sealed under the local snapshot key
//!   (`crate::session::epoch::derive_snapshot_key`): a screen is terminal
//!   content, so it is not left in the clear on disk. A snapshot is a seek
//!   aid, never a precondition of a read (`crate::history::SegmentFile`
//!   replays from segment 0 when there is none).

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error};

/// The first bytes of `index.zxi`.
pub const INDEX_MAGIC: &[u8; 8] = b"ZXHIDX1\0";
/// Bytes of one encoded [`SegmentEntry`].
pub const ENTRY_BYTES: usize = 48;

/// One closed segment, as the local index knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentEntry {
    /// Offset of the frame in the segment file.
    pub offset: u64,
    /// Length of the record.
    pub len: u32,
    pub epoch: u32,
    pub first_seq: u64,
    pub count: u32,
    /// Bytes of the segment's plaintext (before compression).
    pub plain_len: u32,
    pub first_ts: u64,
    pub last_ts: u64,
}

impl SegmentEntry {
    pub fn end_seq(&self) -> u64 {
        self.first_seq + self.count as u64
    }

    pub fn encode(&self) -> [u8; ENTRY_BYTES] {
        let mut b = [0u8; ENTRY_BYTES];
        b[0..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.len.to_le_bytes());
        b[12..16].copy_from_slice(&self.epoch.to_le_bytes());
        b[16..24].copy_from_slice(&self.first_seq.to_le_bytes());
        b[24..28].copy_from_slice(&self.count.to_le_bytes());
        b[28..32].copy_from_slice(&self.plain_len.to_le_bytes());
        b[32..40].copy_from_slice(&self.first_ts.to_le_bytes());
        b[40..48].copy_from_slice(&self.last_ts.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> SegmentEntry {
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().expect("4 bytes"));
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
        SegmentEntry {
            offset: u64_at(0),
            len: u32_at(8),
            epoch: u32_at(12),
            first_seq: u64_at(16),
            count: u32_at(24),
            plain_len: u32_at(28),
            first_ts: u64_at(32),
            last_ts: u64_at(40),
        }
    }
}

/// Parses `index.zxi`'s bytes (a partial last entry is dropped).
pub fn decode_index(bytes: &[u8]) -> Result<Vec<SegmentEntry>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < INDEX_MAGIC.len() || &bytes[..INDEX_MAGIC.len()] != INDEX_MAGIC {
        return Err(Error::new(Code::ECorrupt, "Index file has no known header"));
    }
    Ok(bytes[INDEX_MAGIC.len()..]
        .chunks_exact(ENTRY_BYTES)
        .map(SegmentEntry::decode)
        .collect())
}

/// The position of the segment holding `seq` among `entries` (sorted, as
/// they are written).
pub fn segment_for_seq(entries: &[SegmentEntry], seq: u64) -> Option<usize> {
    let i = entries.partition_point(|e| e.end_seq() <= seq);
    (i < entries.len() && entries[i].first_seq <= seq).then_some(i)
}

/// The first sequence number whose segment ends at or after `ts_ms`
/// (`seq → ts` read the other way: where to start reading to see what
/// happened at `ts_ms`). `None` when every segment ends earlier.
pub fn first_seq_at_or_after(entries: &[SegmentEntry], ts_ms: u64) -> Option<u64> {
    let i = entries.partition_point(|e| e.last_ts < ts_ms);
    entries.get(i).map(|e| e.first_seq)
}

/// A `vt100` screen at a segment boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub cols: u16,
    pub rows: u16,
    /// `vt100::Screen::contents_formatted`.
    pub formatted: Vec<u8>,
}

/// Where a snapshot sits in `snapshots.zxv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Closed segments the screen covers.
    pub segments: u64,
    /// The sequence number after the last packet it covers.
    pub next_seq: u64,
    /// Offset of the sealed bytes.
    pub offset: u64,
    pub len: u32,
}

/// Bytes before a snapshot's sealed bytes.
pub const SNAPSHOT_PREFIX_BYTES: usize = 8 + 8 + 4;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(first_seq: u64, count: u32, first_ts: u64, last_ts: u64) -> SegmentEntry {
        SegmentEntry {
            offset: first_seq * 100,
            len: 90,
            epoch: 1,
            first_seq,
            count,
            plain_len: 500,
            first_ts,
            last_ts,
        }
    }

    #[test]
    fn entries_round_trip_and_seek() {
        let entries = vec![
            entry(0, 10, 100, 190),
            entry(10, 5, 200, 240),
            entry(15, 20, 300, 400),
        ];
        let mut file = INDEX_MAGIC.to_vec();
        for e in &entries {
            file.extend(e.encode());
        }
        file.extend_from_slice(&[1, 2, 3]);
        assert_eq!(decode_index(&file).unwrap(), entries);
        assert_eq!(segment_for_seq(&entries, 0), Some(0));
        assert_eq!(segment_for_seq(&entries, 9), Some(0));
        assert_eq!(segment_for_seq(&entries, 10), Some(1));
        assert_eq!(segment_for_seq(&entries, 34), Some(2));
        assert_eq!(segment_for_seq(&entries, 35), None);
        assert_eq!(first_seq_at_or_after(&entries, 0), Some(0));
        assert_eq!(first_seq_at_or_after(&entries, 191), Some(10));
        assert_eq!(first_seq_at_or_after(&entries, 400), Some(15));
        assert_eq!(first_seq_at_or_after(&entries, 401), None);
        assert!(decode_index(b"nope nope nope").is_err());
    }
}

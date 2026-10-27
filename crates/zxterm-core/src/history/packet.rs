//! The plaintext packet a segment carries: ZBTerm `engine/schema.js`'s
//! `PlainPacket` field for field (`version`, `tsMs`, `kind`, `flags`,
//! `cols?`, `rows?`, `payload?`), `postcard`-encoded instead of
//! compact-encoded. Only the outer envelope differs from ZBTerm's
//! `StoredPacket`: a segment seals a whole run of packets at once
//! (`crate::history::segment`), and a packet's `seq` is its position in the
//! log, not a field of the packet.

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error};

/// `schema.js::VERSION`.
pub const VERSION: u32 = 2;

/// `PacketKind.DATA`.
pub const KIND_DATA: u8 = 0;
/// `PacketKind.RESIZE`.
pub const KIND_RESIZE: u8 = 1;
/// `PacketKind.MARKER`.
pub const KIND_MARKER: u8 = 2;

/// `PacketFlags.COLS`.
pub const FLAG_COLS: u8 = 1;
/// `PacketFlags.ROWS`.
pub const FLAG_ROWS: u8 = 2;
/// `PacketFlags.PAYLOAD`.
pub const FLAG_PAYLOAD: u8 = 4;
/// `PacketFlags.HD`.
pub const FLAG_HD: u8 = 8;

/// The largest payload one packet may carry. PTY reads are far smaller;
/// the bound keeps one packet from making a segment unbounded.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// `schema.js::PlainPacket`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainPacket {
    pub version: u32,
    pub ts_ms: u64,
    pub kind: u8,
    pub flags: u8,
    pub cols: Option<u32>,
    pub rows: Option<u32>,
    pub payload: Option<Vec<u8>>,
}

fn corrupt(msg: &str) -> Error {
    Error::new(Code::ECorrupt, msg.to_string())
}

impl PlainPacket {
    /// A `DATA` packet.
    pub fn data(ts_ms: u64, payload: Vec<u8>, hd: bool) -> PlainPacket {
        PlainPacket {
            version: VERSION,
            ts_ms,
            kind: KIND_DATA,
            flags: FLAG_PAYLOAD | if hd { FLAG_HD } else { 0 },
            cols: None,
            rows: None,
            payload: Some(payload),
        }
    }

    /// A `RESIZE` packet.
    pub fn resize(ts_ms: u64, cols: u32, rows: u32) -> PlainPacket {
        PlainPacket {
            version: VERSION,
            ts_ms,
            kind: KIND_RESIZE,
            flags: FLAG_COLS | FLAG_ROWS,
            cols: Some(cols),
            rows: Some(rows),
            payload: None,
        }
    }

    /// A `MARKER` packet (no payload).
    pub fn marker(ts_ms: u64) -> PlainPacket {
        PlainPacket {
            version: VERSION,
            ts_ms,
            kind: KIND_MARKER,
            flags: 0,
            cols: None,
            rows: None,
            payload: None,
        }
    }

    /// The packet's flags and fields agree, its version and kind are
    /// known and its payload is within [`MAX_PAYLOAD_BYTES`].
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(corrupt("Unsupported packet version"));
        }
        if self.kind > KIND_MARKER {
            return Err(corrupt("Unknown packet kind"));
        }
        if self.flags & !(FLAG_COLS | FLAG_ROWS | FLAG_PAYLOAD | FLAG_HD) != 0 {
            return Err(corrupt("Unknown packet flags"));
        }
        let has = |flag: u8, present: bool| (self.flags & flag != 0) == present;
        if !has(FLAG_COLS, self.cols.is_some())
            || !has(FLAG_ROWS, self.rows.is_some())
            || !has(FLAG_PAYLOAD, self.payload.is_some())
        {
            return Err(corrupt("Packet flags do not match its fields"));
        }
        if self
            .payload
            .as_ref()
            .is_some_and(|p| p.len() > MAX_PAYLOAD_BYTES)
        {
            return Err(corrupt("Packet payload is too large"));
        }
        Ok(())
    }

    /// The packet's `postcard` bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a packet always encodes")
    }

    /// The `postcard` length of the packet.
    pub fn encoded_len(&self) -> usize {
        postcard::experimental::serialized_size(self).expect("a packet always encodes")
    }

    /// Decodes a run of packets back to back (a segment's plaintext).
    pub fn decode_all(mut bytes: &[u8]) -> Result<Vec<PlainPacket>, Error> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (p, rest) = postcard::take_from_bytes::<PlainPacket>(bytes)
                .map_err(|_| corrupt("Segment holds a malformed packet"))?;
            p.validate()?;
            out.push(p);
            bytes = rest;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_of_packets_round_trips() {
        let run = vec![
            PlainPacket::data(1, b"hello".to_vec(), false),
            PlainPacket::resize(2, 100, 30),
            PlainPacket::marker(3),
            PlainPacket::data(4, vec![0; 300], true),
        ];
        let mut bytes = Vec::new();
        for p in &run {
            let e = p.encode();
            assert_eq!(e.len(), p.encoded_len());
            bytes.extend(e);
        }
        assert_eq!(PlainPacket::decode_all(&bytes).unwrap(), run);
    }

    #[test]
    fn inconsistent_flags_are_refused() {
        let mut p = PlainPacket::data(1, vec![1], false);
        p.flags = 0;
        assert_eq!(p.validate().unwrap_err().code, Code::ECorrupt);
        let mut q = PlainPacket::marker(1);
        q.kind = 9;
        assert!(q.validate().is_err());
    }
}

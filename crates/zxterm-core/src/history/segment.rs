//! One segment record and its file framing (design §4.5).
//!
//! A segment file is a sequence of frames:
//!
//! ```text
//! frame  = u32le(record length) ‖ record
//! record = header (17 bytes) ‖ AEAD-seal(zstd(packet ‖ packet ‖ …))
//! header = u8(FORMAT) ‖ u32le(epoch) ‖ u64le(first_seq) ‖ u32le(count)
//! ```
//!
//! The packets are [`super::packet::PlainPacket`]s in `postcard`, back to
//! back. The seal is `crate::session::packet::encrypt` (the same
//! XChaCha20-Poly1305 as live frames and ZBTerm's stored packets) under the
//! epoch's history key (`crate::session::epoch::derive_history_key`), with
//! `seq = first_seq`, so a `(key, first_seq)` pair never repeats: a
//! segment's first sequence number is strictly greater than every earlier
//! one under the same key. The associated data is
//! `crate::session::packet::associated_data(session_id, epoch, first_seq,
//! signer_key ‖ u32le(count))`: a segment cannot be moved to another
//! session, epoch, position or count, and it is bound to the host's
//! signing key. The header is plaintext (it is the AEAD's
//! associated data) and the chain hash (`super::head`) covers the whole
//! record, header included.

use std::io::Read;

use crate::error::{Code, Error};
use crate::session::packet as aead;

use super::packet::PlainPacket;

/// The record format byte.
pub const FORMAT: u8 = 1;
/// Bytes of a record's plaintext header.
pub const HEADER_BYTES: usize = 17;
/// Bytes of a frame's length prefix.
pub const FRAME_PREFIX_BYTES: usize = 4;
/// The zstd level (`zstd::DEFAULT_COMPRESSION_LEVEL`).
pub const ZSTD_LEVEL: i32 = 3;
/// A record longer than this is corrupt (the compressed segment of one
/// full flush plus its overshoot is far smaller;
/// [`super::contract::MAX_SEGMENT_BYTES`] is the contract's own bound).
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// A segment's plaintext (before compression) may not be larger than this.
pub const MAX_PLAIN_BYTES: usize = 16 * 1024 * 1024;

/// A record's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub epoch: u32,
    /// The log sequence number of the segment's first packet.
    pub first_seq: u64,
    /// Packets in the segment.
    pub count: u32,
}

fn corrupt(msg: &str) -> Error {
    Error::new(Code::ECorrupt, msg.to_string())
}

impl SegmentHeader {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut h = [0u8; HEADER_BYTES];
        h[0] = FORMAT;
        h[1..5].copy_from_slice(&self.epoch.to_le_bytes());
        h[5..13].copy_from_slice(&self.first_seq.to_le_bytes());
        h[13..17].copy_from_slice(&self.count.to_le_bytes());
        h
    }

    /// The header of `record` (`E_CORRUPT` for a short or unknown record).
    pub fn decode(record: &[u8]) -> Result<SegmentHeader, Error> {
        if record.len() < HEADER_BYTES + aead::TAG_BYTES {
            return Err(corrupt("Segment record is too short"));
        }
        if record[0] != FORMAT {
            return Err(corrupt("Unknown segment format"));
        }
        Ok(SegmentHeader {
            epoch: u32::from_le_bytes(record[1..5].try_into().expect("4 bytes")),
            first_seq: u64::from_le_bytes(record[5..13].try_into().expect("8 bytes")),
            count: u32::from_le_bytes(record[13..17].try_into().expect("4 bytes")),
        })
    }

    /// The sequence number after the segment's last packet.
    pub fn end_seq(&self) -> u64 {
        self.first_seq + self.count as u64
    }
}

fn device_ad(signer: &[u8; 32], count: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(36);
    d.extend_from_slice(signer);
    d.extend_from_slice(&count.to_le_bytes());
    d
}

/// The plaintext of `packets`: their `postcard` bytes back to back.
pub fn plain_bytes(packets: &[PlainPacket]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        out.extend(p.encode());
    }
    out
}

/// Seals `packets` as one record. `signer` is the host's signing public
/// key (bound in as associated data).
pub fn seal(
    key: &[u8; 32],
    session_id: &str,
    signer: &[u8; 32],
    header: &SegmentHeader,
    packets: &[PlainPacket],
) -> Result<Vec<u8>, Error> {
    if packets.len() != header.count as usize {
        return Err(Error::new(Code::EInternal, "segment count mismatch"));
    }
    let plain = plain_bytes(packets);
    if plain.len() > MAX_PLAIN_BYTES {
        return Err(Error::new(Code::EInternal, "segment is too large"));
    }
    let compressed = zstd::bulk::compress(&plain, ZSTD_LEVEL)
        .map_err(|e| Error::new(Code::EInternal, format!("zstd: {e}")))?;
    let sealed = aead::encrypt(
        key,
        session_id,
        header.epoch,
        header.first_seq,
        &device_ad(signer, header.count),
        &compressed,
    );
    let mut record = Vec::with_capacity(HEADER_BYTES + sealed.len());
    record.extend_from_slice(&header.encode());
    record.extend_from_slice(&sealed);
    Ok(record)
}

/// Opens a record: the AEAD first (`E_CORRUPT 'Encrypted data failed
/// authentication'` on any change), then the decompression and the
/// packets, whose count must be the header's.
pub fn open(
    key: &[u8; 32],
    session_id: &str,
    signer: &[u8; 32],
    record: &[u8],
) -> Result<(SegmentHeader, Vec<PlainPacket>), Error> {
    let header = SegmentHeader::decode(record)?;
    let compressed = aead::decrypt(
        key,
        session_id,
        header.epoch,
        header.first_seq,
        &device_ad(signer, header.count),
        &record[HEADER_BYTES..],
    )?;
    let plain = zstd::bulk::decompress(&compressed, MAX_PLAIN_BYTES)
        .map_err(|_| corrupt("Segment failed to decompress"))?;
    let packets = PlainPacket::decode_all(&plain)?;
    if packets.len() != header.count as usize {
        return Err(corrupt("Segment packet count does not match its header"));
    }
    Ok((header, packets))
}

/// The frame of `record`.
pub fn frame(record: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_PREFIX_BYTES + record.len());
    f.extend_from_slice(&(record.len() as u32).to_le_bytes());
    f.extend_from_slice(record);
    f
}

/// One frame found by [`scan_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpan {
    /// Offset of the frame's length prefix.
    pub offset: u64,
    /// Length of the record.
    pub len: u32,
}

/// Reads every whole frame of `reader`, calling `each` with the record;
/// a frame cut short at the end is reported as `torn_bytes`, a frame
/// longer than [`MAX_RECORD_BYTES`] is `E_CORRUPT`.
pub fn scan_with(
    mut reader: impl Read,
    mut each: impl FnMut(FrameSpan, Vec<u8>) -> Result<(), Error>,
) -> Result<u64, Error> {
    let io = |e: std::io::Error| Error::new(Code::EInternal, format!("segment file: {e}"));
    let mut offset = 0u64;
    loop {
        let mut prefix = [0u8; FRAME_PREFIX_BYTES];
        let got = read_full(&mut reader, &mut prefix).map_err(io)?;
        if got == 0 {
            return Ok(0);
        }
        if got < FRAME_PREFIX_BYTES {
            return Ok(got as u64);
        }
        let len = u32::from_le_bytes(prefix) as usize;
        if len > MAX_RECORD_BYTES {
            return Err(corrupt("Segment frame is too long"));
        }
        let mut record = vec![0u8; len];
        let got = read_full(&mut reader, &mut record).map_err(io)?;
        if got < len {
            return Ok((FRAME_PREFIX_BYTES + got) as u64);
        }
        each(
            FrameSpan {
                offset,
                len: len as u32,
            },
            record,
        )?;
        offset += (FRAME_PREFIX_BYTES + len) as u64;
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets() -> Vec<PlainPacket> {
        (0..5)
            .map(|i| PlainPacket::data(i, format!("line {i}\r\n").into_bytes(), false))
            .collect()
    }

    #[test]
    fn seal_open_round_trip_and_every_bound_field_matters() {
        let key = [3u8; 32];
        let sid = "ab".repeat(32);
        let signer = [9u8; 32];
        let h = SegmentHeader {
            epoch: 2,
            first_seq: 40,
            count: 5,
        };
        let record = seal(&key, &sid, &signer, &h, &packets()).unwrap();
        let (h2, back) = open(&key, &sid, &signer, &record).unwrap();
        assert_eq!(h2, h);
        assert_eq!(back, packets());
        assert!(open(&[4u8; 32], &sid, &signer, &record).is_err());
        assert!(open(&key, &"cd".repeat(32), &signer, &record).is_err());
        assert!(open(&key, &sid, &[8u8; 32], &record).is_err());
        // The header is authenticated: a lied-about count or position fails.
        for byte in [1usize, 5, 13] {
            let mut bad = record.clone();
            bad[byte] ^= 1;
            assert_eq!(
                open(&key, &sid, &signer, &bad).unwrap_err().code,
                Code::ECorrupt
            );
        }
    }

    #[test]
    fn scan_reports_a_torn_tail() {
        let r1 = vec![1u8; 40];
        let r2 = vec![2u8; 50];
        let mut file = frame(&r1);
        file.extend(frame(&r2));
        let whole = file.len();
        file.extend_from_slice(&[9, 0, 0, 0, 1, 2]);
        let mut seen = Vec::new();
        let torn = scan_with(&file[..], |span, rec| {
            seen.push((span, rec.len()));
            Ok(())
        })
        .unwrap();
        assert_eq!(torn, 6);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].0.offset as usize, 4 + 40);
        assert_eq!(whole, 4 + 40 + 4 + 50);
    }
}

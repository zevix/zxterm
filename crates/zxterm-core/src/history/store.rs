//! [`SegmentFile`]: one session's append-only segment file with its signed
//! head, local index, local screen snapshots and signed metadata record.
//!
//! Files in a session's history directory:
//!
//! | file | holds | replicated |
//! |---|---|---|
//! | `segments.zxs` | the frames of `super::segment` | yes (live and K16) |
//! | `head.zxh` | the encoded `super::head::SignedHead` | yes |
//! | `metadata.zxm` | the encoded `super::metadata::SignedMetadata` | yes |
//! | `index.zxi` | `super::index::SegmentEntry` per segment | never |
//! | `snapshots.zxv` | sealed `vt100` screens | never |
//!
//! Writes: [`SegmentFile::append`] buffers packets; a segment closes when
//! [`crate::history::SEGMENT_TARGET_BYTES`] of packet bytes are buffered,
//! when the next packet would take it past
//! [`crate::history::SEGMENT_MAX_BYTES`], when the next packet is [`crate::history::SEGMENT_MAX_AGE_MS`] newer
//! than the segment's first, when the epoch changes
//! ([`SegmentFile::set_epoch`]) or on [`SegmentFile::flush`]. Closing seals
//! and appends the frame, appends the index entry, extends the chain,
//! re-signs and atomically replaces `head.zxh`, and every
//! [`crate::history::SNAPSHOT_EVERY_SEGMENTS`]th segment also appends a
//! snapshot. Nothing is `fsync`ed: a crash of the process loses at most the
//! open segment's packets, a crash of the machine may lose more.
//!
//! [`SegmentFile::open`] recovers what a crash can leave: a torn last
//! frame is cut off, a head one or more segments behind the file is
//! re-signed (the host holds the key), a missing or short index is rebuilt
//! from the segments. It refuses (`E_AUTH`/`E_CORRUPT`) a head whose
//! signature is wrong or whose chain root is not the file's.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::{Code, Error};
use crate::session::packet as aead;

use super::head::{self, ROOT_0, RangeProof, SignedHead};
use super::index::{
    self, INDEX_MAGIC, SNAPSHOT_PREFIX_BYTES, SegmentEntry, Snapshot, SnapshotEntry,
};
use super::metadata::{MetadataBody, SignedMetadata};
use super::packet::{KIND_DATA, KIND_RESIZE, PlainPacket};
use super::segment::{self, FRAME_PREFIX_BYTES, SegmentHeader};
use super::serve::RangePlan;
use super::{
    MAX_SEGMENTS_PER_REQUEST, SEGMENT_MAX_AGE_MS, SEGMENT_MAX_BYTES, SEGMENT_TARGET_BYTES,
    SNAPSHOT_EVERY_SEGMENTS,
};

const SEGMENTS: &str = "segments.zxs";
const HEAD: &str = "head.zxh";
const METADATA: &str = "metadata.zxm";
const INDEX: &str = "index.zxi";
const SNAPSHOTS: &str = "snapshots.zxv";

/// What a [`SegmentFile`] needs to know about its session.
#[derive(Clone)]
pub struct HistoryConfig {
    pub dir: PathBuf,
    /// 64 lowercase hex chars.
    pub session_id: String,
    /// The host's device key: signs the head and the metadata record; its
    /// public half is bound into every segment's associated data.
    pub signer: SigningKey,
    /// Seals the local snapshots (`crate::session::epoch::derive_snapshot_key`).
    pub snapshot_key: [u8; 32],
    /// The terminal size before any `RESIZE` packet.
    pub cols: u16,
    pub rows: u16,
    /// The history key of each epoch the file holds or will hold.
    pub epoch_keys: BTreeMap<u32, [u8; 32]>,
    /// The sequence number of a new file's first packet.
    pub first_seq: u64,
}

impl std::fmt::Debug for HistoryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryConfig")
            .field("dir", &self.dir)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// A `vt100` screen (local; see [`SegmentFile::screen_at`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    pub cols: u16,
    pub rows: u16,
    /// `vt100::Screen::contents`: the visible text.
    pub text: String,
    /// `vt100::Screen::contents_formatted`.
    pub formatted: Vec<u8>,
}

/// One session's segment file. See the module documentation.
pub struct SegmentFile {
    cfg: HistoryConfig,
    signer_key: [u8; 32],
    seg: File,
    idx: File,
    snaps: File,
    seg_len: u64,
    snaps_len: u64,
    entries: Vec<SegmentEntry>,
    hashes: Vec<[u8; 32]>,
    /// `roots[k]` is the chain root after `k` segments.
    roots: Vec<[u8; 32]>,
    head: SignedHead,
    snapshots: Vec<SnapshotEntry>,
    epoch: Option<u32>,
    next_seq: u64,
    open: Vec<PlainPacket>,
    open_bytes: usize,
    parser: Option<vt100::Parser>,
    torn_bytes: u64,
    /// Called with the segment count each time a segment closes (K16).
    on_close: Option<CloseHook>,
}

/// What [`SegmentFile::set_close_hook`] takes.
pub type CloseHook = Box<dyn Fn(u64) + Send + Sync>;

/// One closed segment as the offline contract stores it (K16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSegment {
    pub index: u32,
    /// `root_index`: the chain root before this segment.
    pub prev_root: [u8; 32],
    /// The sealed record, header included.
    pub record: Vec<u8>,
}

/// A run of closed segments and the chain state at the file's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportBatch {
    pub segments: Vec<ExportedSegment>,
    /// Closed segments in the file (the head's length).
    pub length: u64,
    /// `root_length`.
    pub root: [u8; 32],
}

fn io_err(what: &str, e: std::io::Error) -> Error {
    Error::new(Code::EInternal, format!("history {what}: {e}"))
}

fn corrupt(msg: &str) -> Error {
    Error::new(Code::ECorrupt, msg.to_string())
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = File::create(&tmp).map_err(|e| io_err(name, e))?;
    f.write_all(bytes).map_err(|e| io_err(name, e))?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| io_err(name, e))
}

fn feed(parser: &mut vt100::Parser, p: &PlainPacket) {
    match p.kind {
        KIND_DATA => {
            if let Some(payload) = &p.payload {
                parser.process(payload);
            }
        }
        KIND_RESIZE => {
            if let (Some(c), Some(r)) = (p.cols, p.rows) {
                parser.screen_mut().set_size(
                    r.clamp(1, u16::MAX as u32) as u16,
                    c.clamp(1, u16::MAX as u32) as u16,
                );
            }
        }
        _ => {}
    }
}

fn screen_of(parser: &vt100::Parser) -> Screen {
    let s = parser.screen();
    let (rows, cols) = s.size();
    Screen {
        cols,
        rows,
        text: s.contents(),
        formatted: s.contents_formatted(),
    }
}

impl SegmentFile {
    /// Makes a new, empty history in `cfg.dir` (created if needed); an
    /// existing one is refused.
    pub fn create(cfg: HistoryConfig) -> Result<SegmentFile, Error> {
        std::fs::create_dir_all(&cfg.dir).map_err(|e| io_err("dir", e))?;
        let seg_path = cfg.dir.join(SEGMENTS);
        if seg_path.exists() || cfg.dir.join(HEAD).exists() {
            return Err(Error::new(
                Code::EInternal,
                "history already exists in this directory",
            ));
        }
        File::create(&seg_path).map_err(|e| io_err("segments", e))?;
        let mut idx = INDEX_MAGIC.to_vec();
        idx.truncate(INDEX_MAGIC.len());
        std::fs::write(cfg.dir.join(INDEX), &idx).map_err(|e| io_err("index", e))?;
        File::create(cfg.dir.join(SNAPSHOTS)).map_err(|e| io_err("snapshots", e))?;
        let head = SignedHead::sign(&cfg.session_id, 0, ROOT_0, &cfg.signer);
        write_atomic(&cfg.dir, HEAD, &head.encode())?;
        SegmentFile::open(cfg)
    }

    /// Opens an existing history: cold, from its files alone (plus the
    /// keys in `cfg`).
    pub fn open(cfg: HistoryConfig) -> Result<SegmentFile, Error> {
        let dir = cfg.dir.clone();
        let signer_key = cfg.signer.verifying_key().to_bytes();
        let seg = OpenOptions::new()
            .read(true)
            .append(true)
            .open(dir.join(SEGMENTS))
            .map_err(|e| io_err("segments", e))?;

        // Pass 1: the chain, from the bytes on disk.
        let mut spans = Vec::new();
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        let mut headers: Vec<SegmentHeader> = Vec::new();
        let torn = segment::scan_with(
            BufReader::new(File::open(dir.join(SEGMENTS)).map_err(|e| io_err("segments", e))?),
            |span, record| {
                let h = SegmentHeader::decode(&record)?;
                if let Some(prev) = headers.last()
                    && prev.end_seq() != h.first_seq
                {
                    return Err(corrupt("Segments are not contiguous"));
                }
                hashes.push(head::record_hash(&record));
                headers.push(h);
                spans.push(span);
                Ok(())
            },
        )?;
        let mut seg_len = seg.metadata().map_err(|e| io_err("segments", e))?.len();
        if torn > 0 {
            seg_len -= torn;
            seg.set_len(seg_len).map_err(|e| io_err("segments", e))?;
        }
        let mut roots = vec![ROOT_0];
        for h in &hashes {
            roots.push(head::chain_step(roots.last().expect("root_0"), h));
        }

        // The head: signature first, then the chain.
        let head_bytes = std::fs::read(dir.join(HEAD)).map_err(|e| io_err("head", e))?;
        let mut head = SignedHead::decode(&head_bytes)?;
        head.verify(&cfg.session_id, &cfg.signer.verifying_key())?;
        if head.length > hashes.len() as u64 {
            return Err(corrupt(
                "History head names more segments than the file holds",
            ));
        }
        if roots[head.length as usize] != head.chain_root {
            return Err(corrupt("History chain root does not match the signed head"));
        }
        if (head.length as usize) < hashes.len() {
            // A crash between the frame and the head: the host signs what
            // it wrote.
            head = SignedHead::sign(
                &cfg.session_id,
                hashes.len() as u64,
                *roots.last().expect("root"),
                &cfg.signer,
            );
            write_atomic(&dir, HEAD, &head.encode())?;
        }

        // The local index, rebuilt from where it disagrees with the file.
        let idx_bytes = std::fs::read(dir.join(INDEX)).unwrap_or_default();
        let mut entries = index::decode_index(&idx_bytes).unwrap_or_default();
        let agrees = |e: &SegmentEntry, span: &segment::FrameSpan, h: &SegmentHeader| {
            e.offset == span.offset
                && e.len == span.len
                && e.epoch == h.epoch
                && e.first_seq == h.first_seq
                && e.count == h.count
        };
        let mut keep = 0;
        while keep < entries.len()
            && keep < spans.len()
            && agrees(&entries[keep], &spans[keep], &headers[keep])
        {
            keep += 1;
        }
        entries.truncate(keep);
        if keep < spans.len() {
            let mut rd = File::open(dir.join(SEGMENTS)).map_err(|e| io_err("segments", e))?;
            for i in keep..spans.len() {
                let record = read_record_at(&mut rd, &spans[i])?;
                let key = cfg
                    .epoch_keys
                    .get(&headers[i].epoch)
                    .ok_or_else(|| missing_key(headers[i].epoch))?;
                let (_, packets) = segment::open(key, &cfg.session_id, &signer_key, &record)?;
                entries.push(entry_of(&spans[i], &headers[i], &packets));
            }
            let mut fresh = INDEX_MAGIC.to_vec();
            for e in &entries {
                fresh.extend(e.encode());
            }
            std::fs::write(dir.join(INDEX), &fresh).map_err(|e| io_err("index", e))?;
        } else if idx_bytes.len() != INDEX_MAGIC.len() + entries.len() * index::ENTRY_BYTES {
            let mut fresh = INDEX_MAGIC.to_vec();
            for e in &entries {
                fresh.extend(e.encode());
            }
            std::fs::write(dir.join(INDEX), &fresh).map_err(|e| io_err("index", e))?;
        }
        let idx = OpenOptions::new()
            .append(true)
            .open(dir.join(INDEX))
            .map_err(|e| io_err("index", e))?;

        // The snapshots (each frame's prefix is plaintext).
        let snaps = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(dir.join(SNAPSHOTS))
            .map_err(|e| io_err("snapshots", e))?;
        let (snapshots, snaps_len) = load_snapshots(&dir, entries.len() as u64, &snaps)?;

        let next_seq = entries.last().map_or(cfg.first_seq, |e| e.end_seq());
        let epoch = entries.last().map(|e| e.epoch);
        Ok(SegmentFile {
            signer_key,
            seg,
            idx,
            snaps,
            seg_len,
            snaps_len,
            entries,
            hashes,
            roots,
            head,
            snapshots,
            epoch,
            next_seq,
            open: Vec::new(),
            open_bytes: 0,
            parser: None,
            torn_bytes: torn,
            on_close: None,
            cfg,
        })
    }

    /// The verifying half of the host's signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.cfg.signer.verifying_key()
    }

    pub fn session_id(&self) -> &str {
        &self.cfg.session_id
    }

    /// The host's device signing key (K16: it also signs the offline
    /// contract's records, `zxterm_core::history::contract`).
    pub fn signing_key(&self) -> &SigningKey {
        &self.cfg.signer
    }

    /// Calls `hook` with the new segment count every time a segment
    /// closes, after the head is written (K16: the offline publisher's
    /// wake-up). The hook must not block or lock this file.
    pub fn set_close_hook(&mut self, hook: CloseHook) {
        self.on_close = Some(hook);
    }

    /// The closed segments `from..` (at most `max_bytes` of records, but
    /// always one when any is left) with the chain root before each, and
    /// the file's length and chain root now.
    pub fn export(&mut self, from: u64, max_bytes: usize) -> Result<ExportBatch, Error> {
        let mut segments = Vec::new();
        let mut bytes = 0usize;
        let mut i = from as usize;
        while i < self.entries.len() {
            let len = self.entries[i].len as usize;
            if !segments.is_empty() && bytes + len > max_bytes {
                break;
            }
            let record = self.record(i as u64)?;
            bytes += record.len();
            segments.push(ExportedSegment {
                index: i as u32,
                prev_root: self.roots[i],
                record,
            });
            i += 1;
        }
        Ok(ExportBatch {
            segments,
            length: self.entries.len() as u64,
            root: *self.roots.last().expect("root_0"),
        })
    }

    /// Bytes of a torn last frame the last [`SegmentFile::open`] cut off.
    pub fn torn_bytes(&self) -> u64 {
        self.torn_bytes
    }

    /// The signed head over the closed segments.
    pub fn head(&self) -> &SignedHead {
        &self.head
    }

    /// Closed segments.
    pub fn segment_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The local index entries of the closed segments.
    pub fn entries(&self) -> &[SegmentEntry] {
        &self.entries
    }

    /// The sequence number the next appended packet gets.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The sequence number after the last packet of a closed segment.
    pub fn closed_end_seq(&self) -> u64 {
        self.entries
            .last()
            .map_or(self.cfg.first_seq, |e| e.end_seq())
    }

    /// Registers the history key of `epoch`.
    pub fn add_epoch_key(&mut self, epoch: u32, key: [u8; 32]) {
        self.cfg.epoch_keys.insert(epoch, key);
    }

    /// Sets the epoch new packets are sealed under, closing the open
    /// segment first when it is another epoch's.
    pub fn set_epoch(&mut self, epoch: u32) -> Result<(), Error> {
        if !self.cfg.epoch_keys.contains_key(&epoch) {
            return Err(missing_key(epoch));
        }
        if self.epoch.is_some_and(|e| e != epoch) {
            self.close_open()?;
        }
        self.epoch = Some(epoch);
        Ok(())
    }

    fn ensure_parser(&mut self) -> Result<(), Error> {
        if self.parser.is_some() {
            return Ok(());
        }
        // Restored like `screen_at` does it: from the latest snapshot and
        // the closed segments after it (the open segment is empty here).
        let end = self.closed_end_seq();
        let parser = self.replay_to(end)?;
        self.parser = Some(parser);
        Ok(())
    }

    /// Appends a packet; its sequence number. Closes the segment it
    /// completes (see the module documentation for the rule).
    pub fn append(&mut self, packet: PlainPacket) -> Result<u64, Error> {
        packet.validate()?;
        if self.epoch.is_none() {
            return Err(Error::new(Code::EInternal, "no epoch set for history"));
        }
        self.ensure_parser()?;
        let len = packet.encoded_len();
        if let Some(first) = self.open.first()
            && (packet.ts_ms.saturating_sub(first.ts_ms) >= SEGMENT_MAX_AGE_MS
                || self.open_bytes + len > SEGMENT_MAX_BYTES)
        {
            self.close_open()?;
        }
        feed(self.parser.as_mut().expect("parser"), &packet);
        self.open_bytes += len;
        self.open.push(packet);
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.open_bytes >= SEGMENT_TARGET_BYTES {
            self.close_open()?;
        }
        Ok(seq)
    }

    /// Closes the open segment (if any): the packets are sealed, chained
    /// and signed into the head.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.close_open()
    }

    fn close_open(&mut self) -> Result<(), Error> {
        if self.open.is_empty() {
            return Ok(());
        }
        let epoch = self.epoch.expect("append checked the epoch");
        let key = *self
            .cfg
            .epoch_keys
            .get(&epoch)
            .ok_or_else(|| missing_key(epoch))?;
        let count = self.open.len() as u32;
        let header = SegmentHeader {
            epoch,
            first_seq: self.next_seq - count as u64,
            count,
        };
        let record = segment::seal(
            &key,
            &self.cfg.session_id,
            &self.signer_key,
            &header,
            &self.open,
        )?;
        let frame = segment::frame(&record);
        let span = segment::FrameSpan {
            offset: self.seg_len,
            len: record.len() as u32,
        };
        self.seg
            .write_all(&frame)
            .map_err(|e| io_err("segments", e))?;
        let entry = SegmentEntry {
            plain_len: self.open_bytes as u32,
            ..entry_of(&span, &header, &self.open)
        };
        self.idx
            .write_all(&entry.encode())
            .map_err(|e| io_err("index", e))?;
        self.seg_len += frame.len() as u64;
        let h = head::record_hash(&record);
        let root = head::chain_step(self.roots.last().expect("root_0"), &h);
        self.hashes.push(h);
        self.roots.push(root);
        self.entries.push(entry);
        self.open.clear();
        self.open_bytes = 0;
        self.head = SignedHead::sign(
            &self.cfg.session_id,
            self.entries.len() as u64,
            root,
            &self.cfg.signer,
        );
        write_atomic(&self.cfg.dir, HEAD, &self.head.encode())?;
        if (self.entries.len() as u64).is_multiple_of(SNAPSHOT_EVERY_SEGMENTS) {
            self.write_snapshot()?;
        }
        if let Some(hook) = &self.on_close {
            hook(self.entries.len() as u64);
        }
        Ok(())
    }

    fn write_snapshot(&mut self) -> Result<(), Error> {
        let parser = self.parser.as_ref().expect("a closed segment had a parser");
        let s = parser.screen();
        let (rows, cols) = s.size();
        let snap = Snapshot {
            cols,
            rows,
            formatted: s.contents_formatted(),
        };
        let segments = self.entries.len() as u64;
        let next_seq = self.closed_end_seq();
        let plain = postcard::to_allocvec(&snap).expect("a snapshot always encodes");
        let sealed = aead::encrypt(
            &self.cfg.snapshot_key,
            &self.cfg.session_id,
            0,
            next_seq,
            SNAPSHOT_AD,
            &plain,
        );
        let mut frame = Vec::with_capacity(SNAPSHOT_PREFIX_BYTES + sealed.len());
        frame.extend_from_slice(&segments.to_le_bytes());
        frame.extend_from_slice(&next_seq.to_le_bytes());
        frame.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&sealed);
        self.snaps
            .write_all(&frame)
            .map_err(|e| io_err("snapshots", e))?;
        self.snapshots.push(SnapshotEntry {
            segments,
            next_seq,
            offset: self.snaps_len + SNAPSHOT_PREFIX_BYTES as u64,
            len: sealed.len() as u32,
        });
        self.snaps_len += frame.len() as u64;
        Ok(())
    }

    fn read_raw(&mut self, i: usize) -> Result<Vec<u8>, Error> {
        let e = self
            .entries
            .get(i)
            .ok_or_else(|| Error::new(Code::EInternal, "no such segment"))?;
        let span = segment::FrameSpan {
            offset: e.offset,
            len: e.len,
        };
        read_record_at(&mut self.seg, &span)
    }

    /// The raw record of segment `i`, checked against the chain (a
    /// segment changed on disk since the file was opened is `E_CORRUPT`).
    pub fn record(&mut self, i: u64) -> Result<Vec<u8>, Error> {
        let i = i as usize;
        let record = self.read_raw(i)?;
        if head::record_hash(&record) != self.hashes[i] {
            return Err(corrupt("Segment no longer matches the chain"));
        }
        Ok(record)
    }

    /// Segment `i` opened: the AEAD first, then the chain.
    fn read_segment(&mut self, i: usize) -> Result<(SegmentHeader, Vec<PlainPacket>), Error> {
        let record = self.read_raw(i)?;
        let epoch = SegmentHeader::decode(&record)?.epoch;
        let key = self
            .cfg
            .epoch_keys
            .get(&epoch)
            .ok_or_else(|| missing_key(epoch))?;
        let opened = segment::open(key, &self.cfg.session_id, &self.signer_key, &record)?;
        if head::record_hash(&record) != self.hashes[i] {
            return Err(corrupt("Segment no longer matches the chain"));
        }
        Ok(opened)
    }

    /// The packets with sequence numbers in `[start, end)` that are
    /// closed or still buffered, with their sequence numbers.
    pub fn read(&mut self, start: u64, end: u64) -> Result<Vec<(u64, PlainPacket)>, Error> {
        let mut out = Vec::new();
        if start >= end {
            return Ok(out);
        }
        let mut i = self.entries.partition_point(|e| e.end_seq() <= start);
        while i < self.entries.len() && self.entries[i].first_seq < end {
            let (h, packets) = self.read_segment(i)?;
            for (k, p) in packets.into_iter().enumerate() {
                let seq = h.first_seq + k as u64;
                if (start..end).contains(&seq) {
                    out.push((seq, p));
                }
            }
            i += 1;
        }
        let base = self.closed_end_seq();
        for (k, p) in self.open.iter().enumerate() {
            let seq = base + k as u64;
            if (start..end).contains(&seq) {
                out.push((seq, p.clone()));
            }
        }
        Ok(out)
    }

    fn read_snapshot(&mut self, s: SnapshotEntry) -> Result<Snapshot, Error> {
        let mut sealed = vec![0u8; s.len as usize];
        self.snaps
            .seek(SeekFrom::Start(s.offset))
            .and_then(|_| self.snaps.read_exact(&mut sealed))
            .map_err(|e| io_err("snapshots", e))?;
        let plain = aead::decrypt(
            &self.cfg.snapshot_key,
            &self.cfg.session_id,
            0,
            s.next_seq,
            SNAPSHOT_AD,
            &sealed,
        )?;
        postcard::from_bytes(&plain).map_err(|_| corrupt("Snapshot is malformed"))
    }

    /// The parser after every packet with a sequence number below `seq`:
    /// from the latest snapshot at or before `seq` when there is one, else
    /// from the start of the file. A snapshot only saves work.
    fn replay_to(&mut self, seq: u64) -> Result<vt100::Parser, Error> {
        let snap = self
            .snapshots
            .iter()
            .rev()
            .find(|s| s.next_seq <= seq)
            .copied();
        let (mut parser, from) = match snap {
            Some(s) => {
                let snap = self.read_snapshot(s)?;
                let mut p = vt100::Parser::new(snap.rows, snap.cols, 0);
                p.process(&snap.formatted);
                (p, s.segments as usize)
            }
            None => (
                vt100::Parser::new(self.cfg.rows.max(1), self.cfg.cols.max(1), 0),
                0,
            ),
        };
        let mut i = from;
        while i < self.entries.len() && self.entries[i].first_seq < seq {
            let (h, packets) = self.read_segment(i)?;
            for (k, p) in packets.iter().enumerate() {
                if h.first_seq + (k as u64) < seq {
                    feed(&mut parser, p);
                }
            }
            i += 1;
        }
        let base = self.closed_end_seq();
        for (k, p) in self.open.iter().enumerate() {
            if base + (k as u64) < seq {
                feed(&mut parser, p);
            }
        }
        Ok(parser)
    }

    /// The screen after every packet with a sequence number below `seq`.
    /// Local only: no channel, message or contract carries it.
    pub fn screen_at(&mut self, seq: u64) -> Result<Screen, Error> {
        let seq = seq.min(self.next_seq);
        Ok(screen_of(&self.replay_to(seq)?))
    }

    /// Where a reader should start to see what happened at `ts_ms`.
    pub fn first_seq_at_or_after(&self, ts_ms: u64) -> Option<u64> {
        index::first_seq_at_or_after(&self.entries, ts_ms)
    }

    /// Snapshots written so far, as `(closed segments covered, next_seq)`.
    pub fn snapshot_positions(&self) -> Vec<(u64, u64)> {
        self.snapshots
            .iter()
            .map(|s| (s.segments, s.next_seq))
            .collect()
    }

    /// The closed segments a request for `[start, end)` is answered from,
    /// with the proof that checks them against the head. `None` when no
    /// closed segment holds a packet of the range. At most
    /// [`MAX_SEGMENTS_PER_REQUEST`] segments; `next` says where to
    /// continue.
    pub fn plan_range(&self, start: u64, end: u64) -> Option<RangePlan> {
        if start >= end || start >= self.closed_end_seq() {
            return None;
        }
        let first = self.entries.partition_point(|e| e.end_seq() <= start);
        if first >= self.entries.len() {
            return None;
        }
        let mut last = first;
        while last + 1 < self.entries.len()
            && self.entries[last].end_seq() < end
            && last + 1 - first < MAX_SEGMENTS_PER_REQUEST
        {
            last += 1;
        }
        Some(RangePlan {
            first_index: first as u64,
            count: (last - first + 1) as u64,
            next: self.entries[last].end_seq(),
            proof: RangeProof {
                head: self.head.encode().to_vec(),
                first_index: first as u64,
                prev_root: self.roots[first],
                hashes: self.hashes[first..=last].to_vec(),
                after: self.hashes[last + 1..].to_vec(),
            },
        })
    }

    /// Replaces the metadata record with `body`, signed.
    pub fn set_metadata(&mut self, body: &MetadataBody) -> Result<(), Error> {
        let signed = SignedMetadata::sign(body, &self.cfg.signer)?;
        write_atomic(&self.cfg.dir, METADATA, &signed.encode())
    }

    /// The stored metadata record, if any, verified.
    pub fn metadata(&self) -> Result<Option<MetadataBody>, Error> {
        match std::fs::read(self.cfg.dir.join(METADATA)) {
            Ok(bytes) => SignedMetadata::decode(&bytes)?
                .verify(&self.cfg.signer.verifying_key())
                .map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("metadata", e)),
        }
    }
}

const SNAPSHOT_AD: &[u8] = b"zxterm/history-snapshot";

fn missing_key(epoch: u32) -> Error {
    Error::new(Code::ENoKey, format!("No history key for epoch {epoch}"))
}

fn entry_of(span: &segment::FrameSpan, h: &SegmentHeader, packets: &[PlainPacket]) -> SegmentEntry {
    SegmentEntry {
        offset: span.offset,
        len: span.len,
        epoch: h.epoch,
        first_seq: h.first_seq,
        count: h.count,
        plain_len: packets.iter().map(PlainPacket::encoded_len).sum::<usize>() as u32,
        first_ts: packets.first().map_or(0, |p| p.ts_ms),
        last_ts: packets.last().map_or(0, |p| p.ts_ms),
    }
}

fn read_record_at(f: &mut File, span: &segment::FrameSpan) -> Result<Vec<u8>, Error> {
    let mut record = vec![0u8; span.len as usize];
    f.seek(SeekFrom::Start(span.offset + FRAME_PREFIX_BYTES as u64))
        .and_then(|_| f.read_exact(&mut record))
        .map_err(|e| io_err("segments", e))?;
    Ok(record)
}

fn load_snapshots(
    dir: &Path,
    segments: u64,
    file: &File,
) -> Result<(Vec<SnapshotEntry>, u64), Error> {
    let bytes = std::fs::read(dir.join(SNAPSHOTS)).map_err(|e| io_err("snapshots", e))?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + SNAPSHOT_PREFIX_BYTES <= bytes.len() {
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("8"));
        let len = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().expect("4")) as usize;
        if at + SNAPSHOT_PREFIX_BYTES + len > bytes.len() {
            break;
        }
        out.push(SnapshotEntry {
            segments: u64_at(at),
            next_seq: u64_at(at + 8),
            offset: (at + SNAPSHOT_PREFIX_BYTES) as u64,
            len: len as u32,
        });
        at += SNAPSHOT_PREFIX_BYTES + len;
    }
    if at < bytes.len() {
        file.set_len(at as u64)
            .map_err(|e| io_err("snapshots", e))?;
    }
    // A snapshot beyond the segments that survived is stale.
    out.retain(|s| s.segments <= segments);
    Ok((out, at as u64))
}

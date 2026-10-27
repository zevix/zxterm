//! K15 C3 segments and live history (design §4.5, `X-24`): the local
//! format (`zxterm_core::history`), its three tamper levels, the seek index
//! and snapshots, the metadata record, the 16 MiB import, credit-gated
//! serving and, over a throwaway `LocalNode` (never the owner's node,
//! loopback only, no ICE servers), a range fetch that runs while `live`
//! output continues. Run with `--nocapture` for the measured numbers.
//!
//! The concurrent tests need `freenet` on `PATH` and skip with a printed
//! reason otherwise.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto_box::aead::OsRng;
use crypto_box::aead::rand_core::RngCore;
use ed25519_dalek::SigningKey;
use tokio::sync::mpsc::UnboundedReceiver;

use zxterm_core::Code;
use zxterm_core::freenet::backend::{Admission, Backend, BackendOptions};
use zxterm_core::freenet::route::Route;
use zxterm_core::history::fetch::RangeVerifier;
use zxterm_core::history::head::SignedHead;
use zxterm_core::history::import::import;
use zxterm_core::history::metadata::{
    EnvelopeEntry, EpochEntry, InfoEntry, LinkEntry, MemberEntry, MetadataBody,
};
use zxterm_core::history::segment::{self, HEADER_BYTES};
use zxterm_core::history::serve::{
    HistoryRegistry, HistorySource, SegmentData, ServeOut, ServeRequest, SharedHistory,
};
use zxterm_core::history::{
    HistoryConfig, MAX_HISTORY_CREDIT, PlainPacket, SEGMENT_MAX_BYTES, SEGMENT_TARGET_BYTES,
    SNAPSHOT_EVERY_SEGMENTS, SegmentFile,
};
use zxterm_core::idkey::IdentityKey;
use zxterm_core::session::LocalIdentity;
use zxterm_core::session::caps::{READ_HISTORY, VIEW_LIVE};
use zxterm_core::session::envelope;
use zxterm_core::session::epoch::{derive_history_key, derive_snapshot_key};
use zxterm_core::session::host::{LinkKind, LinkSpec};
use zxterm_core::session::messages::{InputMode, SessionInfo};
use zxterm_core::session::service::{
    HostOpen, JoinSpec, JoinStatus, ServiceOptions, SessionEvent, SessionService,
};
use zxterm_testkit::ScratchHome;
use zxterm_testkit::local_node::{LocalNode, freenet_available};

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// xorshift64*, so every run writes the same bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// About `len` bytes of colourised terminal lines with random hex in
/// them (compresses to roughly half).
fn terminal_text(rng: &mut Rng, len: usize, line_no: &mut u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 128);
    while out.len() < len {
        let colour = 31 + (rng.next() % 7);
        let tail: String = (0..24)
            .map(|_| format!("{:x}", rng.next() % 16))
            .collect::<String>();
        out.extend_from_slice(
            format!("\x1b[{colour}mline {line_no:06}\x1b[0m {tail}{tail}\r\n").as_bytes(),
        );
        *line_no += 1;
    }
    out.truncate(len.max(1));
    out
}

fn packets(n: usize, payload: usize, seed: u64, ts0: u64, ts_step: u64) -> Vec<PlainPacket> {
    let mut rng = Rng(seed);
    let mut line = 0;
    (0..n)
        .map(|i| {
            PlainPacket::data(
                ts0 + i as u64 * ts_step,
                terminal_text(&mut rng, payload, &mut line),
                i % 97 == 0,
            )
        })
        .collect()
}

/// Packets of random printable bytes (they compress to about 3/4).
fn noisy_packets(n: usize, payload: usize, seed: u64, ts0: u64) -> Vec<PlainPacket> {
    let mut rng = Rng(seed);
    (0..n)
        .map(|i| {
            let bytes = (0..payload)
                .map(|_| b'!' + (rng.next() % 90) as u8)
                .collect();
            PlainPacket::data(ts0 + i as u64 * 3, bytes, false)
        })
        .collect()
}

struct Store {
    _home: ScratchHome,
    dir: PathBuf,
    sid: String,
    signer: SigningKey,
    keys: BTreeMap<u32, [u8; 32]>,
    snapshot_key: [u8; 32],
}

impl Store {
    fn new(epochs: &[u32]) -> Store {
        let home = ScratchHome::new().expect("scratch home");
        let dir = home.tmp().join("history");
        let keys = epochs
            .iter()
            .map(|e| (*e, derive_history_key(&random::<32>())))
            .collect();
        Store {
            dir,
            _home: home,
            sid: hex::encode(random::<32>()),
            signer: SigningKey::from_bytes(&random::<32>()),
            keys,
            snapshot_key: derive_snapshot_key(&random::<32>()),
        }
    }

    fn cfg(&self) -> HistoryConfig {
        HistoryConfig {
            dir: self.dir.clone(),
            session_id: self.sid.clone(),
            signer: self.signer.clone(),
            snapshot_key: self.snapshot_key,
            cols: 80,
            rows: 24,
            epoch_keys: self.keys.clone(),
            first_seq: 0,
        }
    }

    fn create(&self) -> SegmentFile {
        SegmentFile::create(self.cfg()).expect("create")
    }

    fn open(&self) -> Result<SegmentFile, zxterm_core::Error> {
        SegmentFile::open(self.cfg())
    }

    fn seg_path(&self) -> PathBuf {
        self.dir.join("segments.zxs")
    }

    fn verifier(&self) -> RangeVerifier {
        RangeVerifier::new(&self.sid, self.signer.verifying_key(), self.keys.clone())
    }
}

/// Writes `packets` in epoch 1 (and `later` in epoch 2 when the store has
/// it), flushes, and returns everything written in order.
fn write_all(store: &Store, first: &[PlainPacket], later: &[PlainPacket]) -> SegmentFile {
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    for p in first {
        f.append(p.clone()).unwrap();
    }
    if !later.is_empty() {
        f.set_epoch(2).unwrap();
        for p in later {
            f.append(p.clone()).unwrap();
        }
    }
    f.flush().unwrap();
    f
}

fn all_records(f: &mut SegmentFile) -> Vec<Vec<u8>> {
    (0..f.segment_count())
        .map(|i| f.record(i).unwrap())
        .collect()
}

/// Serves `[start, end)` fully, verifying each segment.
fn fetch(f: &mut SegmentFile, store: &Store, start: u64, end: u64) -> Vec<(u64, PlainPacket)> {
    let plan = f.plan_range(start, end).expect("a plan");
    let mut v = store.verifier();
    let mut out = Vec::new();
    for k in 0..plan.count {
        let record = f.record(plan.first_index + k).unwrap();
        let data = SegmentData {
            index: plan.first_index + k,
            record,
            proof: (k == 0).then(|| plan.proof.clone()),
        };
        out.extend(v.accept(&data.encode()).unwrap().packets);
    }
    v.finish(plan.next, start).unwrap();
    out
}

// ---------------------------------------------------------------------------
// format
// ---------------------------------------------------------------------------

#[test]
fn format_round_trip_cold_reopen_byte_identical() {
    let store = Store::new(&[1, 2]);
    let first = packets(300, 700, 1, 1_000, 5);
    let later = packets(200, 900, 2, 10_000, 5);
    let expected: Vec<PlainPacket> = first.iter().chain(later.iter()).cloned().collect();
    let f = write_all(&store, &first, &later);
    let segs = f.segment_count();
    let head = *f.head();
    assert!(segs >= 4, "{segs} segments");
    assert_eq!(head.length, segs);
    drop(f);

    // Cold: a new value from the files alone.
    let mut g = store.open().expect("reopen");
    assert_eq!(g.segment_count(), segs);
    assert_eq!(*g.head(), head);
    assert_eq!(g.torn_bytes(), 0);
    head.verify(&store.sid, &store.signer.verifying_key())
        .expect("the head verifies");
    let read = g.read(0, expected.len() as u64).unwrap();
    assert_eq!(read.len(), expected.len());
    for (i, (seq, p)) in read.iter().enumerate() {
        assert_eq!(*seq, i as u64);
        assert_eq!(*p, expected[i], "packet {i}");
        assert_eq!(p.encode(), expected[i].encode(), "packet {i} bytes");
    }
    // A viewer reads the same through the served path, every packet
    // checked against the head.
    let fetched = fetch(&mut g, &store, 0, expected.len() as u64);
    assert_eq!(fetched, read);
    // Two epochs, so the key of each was needed.
    assert!(g.entries().iter().any(|e| e.epoch == 1));
    assert!(g.entries().iter().any(|e| e.epoch == 2));
    // Appending after a cold reopen continues the sequence.
    g.set_epoch(2).unwrap();
    let seq = g
        .append(PlainPacket::data(99_000, b"more".to_vec(), false))
        .unwrap();
    assert_eq!(seq, expected.len() as u64);
    g.flush().unwrap();
    let mut h = store.open().unwrap();
    assert_eq!(
        h.read(seq, seq + 1).unwrap()[0].1.payload.as_deref(),
        Some(&b"more"[..])
    );
    println!(
        "format: {} packets in {} segments over 2 epochs, cold reopen identical, head length {}",
        expected.len(),
        segs,
        head.length
    );
}

#[test]
fn tamper_1_a_flipped_segment_byte_fails_the_aead() {
    let store = Store::new(&[1]);
    let mut f = write_all(&store, &packets(400, 800, 3, 0, 3), &[]);
    let entries = f.entries().to_vec();
    assert!(entries.len() >= 4);
    // Flip one ciphertext byte of segment 2 (an earlier one, not the last).
    let victim = 2usize;
    let at = entries[victim].offset + 4 + HEADER_BYTES as u64 + 5;
    let mut raw = std::fs::read(store.seg_path()).unwrap();
    raw[at as usize] ^= 0x01;
    std::fs::write(store.seg_path(), &raw).unwrap();

    // The open handle reads the changed bytes: the AEAD refuses them.
    let e = f
        .read(entries[victim].first_seq, entries[victim].end_seq())
        .unwrap_err();
    assert_eq!(e.code, Code::ECorrupt);
    assert_eq!(e.message, "Encrypted data failed authentication");
    // The same record, on its own.
    let record =
        raw[entries[victim].offset as usize + 4..][..entries[victim].len as usize].to_vec();
    let e = segment::open(
        &store.keys[&1],
        &store.sid,
        &store.signer.verifying_key().to_bytes(),
        &record,
    )
    .unwrap_err();
    assert_eq!(e.message, "Encrypted data failed authentication");
    // A viewer served that record refuses it the same way.
    let plan = f.plan_range(entries[victim].first_seq, entries[victim].end_seq());
    let plan = plan.unwrap();
    let mut v = store.verifier();
    let data = SegmentData {
        index: plan.first_index,
        record,
        proof: Some(plan.proof),
    };
    let e = v.accept(&data.encode()).unwrap_err();
    assert_eq!(e.message, "Encrypted data failed authentication");
    // And a cold reopen refuses the file.
    assert_eq!(store.open().err().unwrap().code, Code::ECorrupt);
    println!(
        "tamper 1: flipped byte in segment {victim} of {} -> AEAD failure",
        entries.len()
    );
}

#[test]
fn tamper_2_a_flipped_head_byte_fails_the_signature() {
    let store = Store::new(&[1]);
    let f = write_all(&store, &packets(200, 800, 4, 0, 3), &[]);
    let n = f.segment_count();
    drop(f);
    let head_path = store.dir.join("head.zxh");
    let clean = std::fs::read(&head_path).unwrap();
    // One byte inside the length, the chain root and the signature.
    for at in [1usize, 20, 60] {
        let mut bad = clean.clone();
        bad[at] ^= 0x01;
        std::fs::write(&head_path, &bad).unwrap();
        let e = store.open().err().expect("a tampered head is refused");
        assert_eq!(e.code, Code::EAuth, "byte {at}");
        assert_eq!(e.message, "History head signature is invalid");
    }
    // A viewer given a proof with a tampered head refuses it too.
    std::fs::write(&head_path, &clean).unwrap();
    let mut f = store.open().unwrap();
    let mut plan = f.plan_range(0, 10).unwrap();
    plan.proof.head[9] ^= 0x01;
    let data = SegmentData {
        index: plan.first_index,
        record: f.record(plan.first_index).unwrap(),
        proof: Some(plan.proof),
    };
    let e = store.verifier().accept(&data.encode()).unwrap_err();
    assert_eq!(e.code, Code::EAuth);
    // A head from another key is refused.
    let other = SigningKey::from_bytes(&random::<32>());
    let forged = SignedHead::sign(&store.sid, n, f.head().chain_root, &other);
    std::fs::write(&head_path, forged.encode()).unwrap();
    assert_eq!(store.open().err().unwrap().code, Code::EAuth);
    println!("tamper 2: flipped head byte (length, root, signature) -> signature check fails");
}

#[test]
fn tamper_3_an_earlier_segment_replaced_after_later_ones_closed_breaks_the_chain() {
    let store = Store::new(&[1]);
    let mut f = write_all(&store, &packets(500, 800, 5, 0, 3), &[]);
    let n = f.segment_count() as usize;
    assert!(n >= 5, "{n} segments");
    let mut records = all_records(&mut f);
    let entries = f.entries().to_vec();
    let plan = f.plan_range(0, entries[3].end_seq()).unwrap();
    drop(f);

    // Whoever holds the history key (any member with READ_HISTORY) can
    // seal a segment that authenticates: replace segment 1 with one that
    // says something else, same header. It is not the last segment.
    let key = store.keys[&1];
    let signer = store.signer.verifying_key().to_bytes();
    let (header, mut ps) = segment::open(&key, &store.sid, &signer, &records[1]).unwrap();
    ps[0] = PlainPacket::data(ps[0].ts_ms, b"\x1b[2J forged history".to_vec(), false);
    let forged = segment::seal(&key, &store.sid, &signer, &header, &ps).unwrap();
    // Its own AEAD verifies: this is what the chain is for.
    segment::open(&key, &store.sid, &signer, &forged).expect("the forged segment authenticates");
    records[1] = forged.clone();
    let mut file = Vec::new();
    for r in &records {
        file.extend(segment::frame(r));
    }
    std::fs::write(store.seg_path(), &file).unwrap();

    // The file is refused: the recomputed chain root is not the head's,
    // and no AEAD failed on the way.
    let e = store.open().err().expect("the forged file is refused");
    assert_eq!(e.code, Code::ECorrupt);
    assert_eq!(
        e.message,
        "History chain root does not match the signed head"
    );

    // A viewer served the forged segment (a host, or a relay, with the
    // honest proof) refuses it although its AEAD passes.
    let mut v = store.verifier();
    let mut refused = None;
    for k in 0..plan.count {
        let data = SegmentData {
            index: plan.first_index + k,
            record: records[(plan.first_index + k) as usize].clone(),
            proof: (k == 0).then(|| plan.proof.clone()),
        };
        match v.accept(&data.encode()) {
            Ok(_) => assert_ne!(k, 1, "the forged segment was accepted"),
            Err(e) => {
                refused = Some((k, e));
                break;
            }
        }
    }
    let (k, e) = refused.expect("the viewer refused the forgery");
    assert_eq!(k, 1);
    assert_eq!(e.code, Code::ECorrupt);
    assert_eq!(e.message, "Segment is not the one the signed head covers");

    // Dropping, duplicating and reordering segments are caught the same way.
    for variant in 0..3 {
        let mut r = all_records_from(&file);
        match variant {
            0 => {
                r.remove(2);
            }
            1 => r.insert(2, r[1].clone()),
            _ => r.swap(1, 3),
        }
        let mut bytes = Vec::new();
        for x in &r {
            bytes.extend(segment::frame(x));
        }
        std::fs::write(store.seg_path(), &bytes).unwrap();
        assert!(store.open().is_err(), "variant {variant}");
    }
    println!(
        "tamper 3: segment 1 of {n} replaced by an AEAD-valid forgery -> chain root mismatch (file) and 'not the one the signed head covers' (viewer); drop/duplicate/reorder refused"
    );
}

fn all_records_from(file: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    segment::scan_with(file, |_, r| {
        out.push(r);
        Ok(())
    })
    .unwrap();
    out
}

#[test]
fn a_viewer_refuses_a_rolled_back_head_and_an_unknown_epoch() {
    let store = Store::new(&[1]);
    let mut f = write_all(&store, &packets(300, 800, 6, 0, 3), &[]);
    let plan = f.plan_range(0, 10).unwrap();
    let data = SegmentData {
        index: plan.first_index,
        record: f.record(0).unwrap(),
        proof: Some(plan.proof.clone()),
    };
    let head_len = f.head().length;
    let e = store
        .verifier()
        .with_min_head_length(head_len + 1)
        .accept(&data.encode())
        .unwrap_err();
    assert_eq!(e.message, "History head is shorter than one already seen");
    let no_key = RangeVerifier::new(&store.sid, store.signer.verifying_key(), BTreeMap::new())
        .accept(&data.encode())
        .unwrap_err();
    assert_eq!(no_key.code, Code::ENoKey);
    let other = RangeVerifier::new(
        &store.sid,
        SigningKey::from_bytes(&random::<32>()).verifying_key(),
        store.keys.clone(),
    )
    .accept(&data.encode())
    .unwrap_err();
    assert_eq!(other.code, Code::EAuth);
    // A first segment without a proof is refused.
    let bare = SegmentData {
        proof: None,
        ..SegmentData::decode(&data.encode()).unwrap()
    };
    assert!(store.verifier().accept(&bare.encode()).is_err());
}

#[test]
fn a_torn_tail_and_a_stale_head_are_recovered() {
    let store = Store::new(&[1]);
    let mut f = write_all(&store, &packets(300, 800, 7, 0, 3), &[]);
    let n = f.segment_count();
    let head_before = *f.head();
    let expected = f.read(0, f.closed_end_seq()).unwrap();
    drop(f);
    // A crash mid-frame: half of a frame at the end.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(store.seg_path())
        .unwrap();
    file.write_all(&[200, 0, 0, 0, 1, 2, 3]).unwrap();
    drop(file);
    let mut g = store.open().expect("a torn tail does not stop the open");
    assert_eq!(g.torn_bytes(), 7);
    assert_eq!(g.segment_count(), n);
    assert_eq!(*g.head(), head_before);
    assert_eq!(g.read(0, g.closed_end_seq()).unwrap(), expected);
    // A crash between a frame and its head: the head is one behind.
    g.set_epoch(1).unwrap();
    for p in packets(120, 800, 8, 50_000, 1) {
        g.append(p).unwrap();
    }
    g.flush().unwrap();
    let m = g.segment_count();
    assert!(m > n);
    drop(g);
    let stale = SignedHead::sign(&store.sid, n, head_before.chain_root, &store.signer);
    std::fs::write(store.dir.join("head.zxh"), stale.encode()).unwrap();
    let h = store.open().expect("a head behind the file is re-signed");
    assert_eq!(h.head().length, m);
    h.head()
        .verify(&store.sid, &store.signer.verifying_key())
        .unwrap();
    assert_eq!(store.open().unwrap().head().length, m);
}

// ---------------------------------------------------------------------------
// index, snapshots
// ---------------------------------------------------------------------------

fn reference_screen(ps: &[(u64, PlainPacket)], upto: u64) -> String {
    let mut p = vt100::Parser::new(24, 80, 0);
    for (seq, packet) in ps {
        if *seq >= upto {
            break;
        }
        match packet.kind {
            0 => p.process(packet.payload.as_deref().unwrap_or(&[])),
            1 => p
                .screen_mut()
                .set_size(packet.rows.unwrap() as u16, packet.cols.unwrap() as u16),
            _ => {}
        }
    }
    p.screen().contents()
}

#[test]
fn the_index_seeks_and_a_snapshot_is_a_seek_aid_not_a_precondition() {
    let store = Store::new(&[1]);
    let mut all = packets(2500, 600, 9, 1_000, 7);
    // A resize in the middle, and a screen clear now and then.
    all.insert(1200, PlainPacket::resize(9_000, 100, 30));
    all.insert(
        1800,
        PlainPacket::data(9_500, b"\x1b[2J\x1b[Hafter clear\r\n".to_vec(), false),
    );
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    for p in &all {
        f.append(p.clone()).unwrap();
    }
    f.flush().unwrap();
    let n = f.segment_count();
    assert!(n >= 2 * SNAPSHOT_EVERY_SEGMENTS, "{n} segments");
    let snaps = f.snapshot_positions();
    assert_eq!(snaps.len() as u64, n / SNAPSHOT_EVERY_SEGMENTS);
    assert_eq!(snaps[0].0, SNAPSHOT_EVERY_SEGMENTS);
    let indexed: Vec<(u64, PlainPacket)> = all
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, p)| (i as u64, p))
        .collect();
    // Screens at seqs before, at and after snapshots, with and without one.
    let probe: Vec<u64> = vec![
        0,
        1,
        snaps[0].1 - 1,
        snaps[0].1,
        snaps[0].1 + 3,
        1199,
        1201,
        snaps[1].1 + 17,
        1799,
        1801,
        all.len() as u64,
    ];
    for &seq in &probe {
        let s = f.screen_at(seq).unwrap();
        assert_eq!(s.text, reference_screen(&indexed, seq), "screen at {seq}");
    }
    // seq -> ts and ts -> seq.
    let e = f.entries()[3];
    assert_eq!(
        f.read(e.first_seq, e.first_seq + 1).unwrap()[0].1.ts_ms,
        e.first_ts
    );
    assert_eq!(f.first_seq_at_or_after(e.first_ts), Some(e.first_seq));
    assert_eq!(f.first_seq_at_or_after(u64::MAX), None);
    drop(f);

    // Delete both local files: reads and screens still answer (replay from
    // the start), and the index is rebuilt from the segments.
    std::fs::remove_file(store.dir.join("snapshots.zxv")).unwrap();
    std::fs::remove_file(store.dir.join("index.zxi")).unwrap();
    let mut g = store.open().expect("no index, no snapshots");
    assert!(g.snapshot_positions().is_empty());
    assert_eq!(g.segment_count(), n);
    for &seq in &probe {
        let s = g.screen_at(seq).unwrap();
        assert_eq!(
            s.text,
            reference_screen(&indexed, seq),
            "no snapshot, screen at {seq}"
        );
    }
    // Reads need no snapshot and no fresh index either.
    assert_eq!(g.read(2000, 2003).unwrap().len(), 3);
    let same = g.entries().to_vec();
    drop(g);
    let h = store.open().unwrap();
    assert_eq!(h.entries(), &same[..]);
    // Snapshots are local: nothing served names one, and the file is not
    // plaintext (a screen is terminal content).
    let raw = std::fs::read(store.dir.join("segments.zxs")).unwrap();
    assert!(!raw.windows(11).any(|w| w == b"after clear"));
    println!(
        "index: {n} segments, snapshots at {:?}; screens equal a full replay with and without snapshots",
        snaps.iter().map(|s| s.0).collect::<Vec<_>>()
    );
}

#[test]
fn the_snapshot_file_is_sealed_and_never_served() {
    let store = Store::new(&[1]);
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    let marker = b"SECRET-SCREEN-TEXT";
    for i in 0..3000u64 {
        let mut payload = format!("row {i} ").into_bytes();
        payload.extend_from_slice(marker);
        payload.extend_from_slice(b"\r\n");
        payload.resize(500, b'.');
        f.append(PlainPacket::data(i, payload, false)).unwrap();
    }
    f.flush().unwrap();
    assert!(!f.snapshot_positions().is_empty());
    let snaps = std::fs::read(store.dir.join("snapshots.zxv")).unwrap();
    assert!(snaps.len() > 100);
    assert!(!snaps.windows(marker.len()).any(|w| w == marker));
    // A served plan and its records hold no snapshot bytes: the reply type
    // carries a record and a proof only.
    let plan = f.plan_range(0, f.closed_end_seq()).unwrap();
    assert_eq!(plan.proof.hashes.len() as u64, plan.count);
    for i in 0..plan.count.min(3) {
        let d = SegmentData {
            index: i,
            record: f.record(i).unwrap(),
            proof: None,
        };
        let wire = d.encode();
        assert!(!wire.windows(marker.len()).any(|w| w == marker));
    }
}

// ---------------------------------------------------------------------------
// metadata
// ---------------------------------------------------------------------------

#[test]
fn the_metadata_record_is_signed_and_a_sensitive_session_stores_no_envelope() {
    let sealed = b"an-envelope-sealed-to-a-member-device".to_vec();
    let body = |sensitive: bool| {
        MetadataBody::new(
            "unused",
            InfoEntry {
                name: "meta".into(),
                created_at: 1,
                sensitive,
                cols: 80,
                rows: 24,
            },
            vec![EpochEntry {
                epoch: 1,
                first_seq: 0,
            }],
            vec![EnvelopeEntry {
                epoch: 1,
                device_key: [4; 32],
                sealed: sealed.clone(),
            }],
            vec![MemberEntry {
                identity_key: [1; 32],
                device_key: [4; 32],
                device_name: "d".into(),
                caps: 3,
                link_id: [2; 16],
                revoked: false,
            }],
            vec![LinkEntry {
                link_id: [2; 16],
                group: false,
                max_viewers: 1,
                auto_join: true,
                caps: None,
                revoked: false,
            }],
        )
    };
    let contains = |path: &Path| {
        let raw = std::fs::read(path).unwrap();
        raw.windows(sealed.len()).any(|w| w == &sealed[..])
    };
    let store = Store::new(&[1]);
    let mut f = store.create();
    assert!(f.metadata().unwrap().is_none());
    f.set_metadata(&body(false)).unwrap();
    assert_eq!(f.metadata().unwrap().unwrap(), body(false));
    assert!(contains(&store.dir.join("metadata.zxm")));
    // Sensitive: the constructor already dropped the envelope, and the
    // stored file never holds its bytes.
    let store2 = Store::new(&[1]);
    let mut g = store2.create();
    g.set_metadata(&body(true)).unwrap();
    let back = g.metadata().unwrap().unwrap();
    assert!(back.envelopes.is_empty());
    assert!(!contains(&store2.dir.join("metadata.zxm")));
    // A flipped byte makes the record fail its signature.
    let path = store.dir.join("metadata.zxm");
    let mut raw = std::fs::read(&path).unwrap();
    raw[12] ^= 1;
    std::fs::write(&path, raw).unwrap();
    assert!(f.metadata().is_err());
}

// ---------------------------------------------------------------------------
// segment sizes under bursty output
// ---------------------------------------------------------------------------

fn bursty(store: &Store, max_read: usize, label: &str) {
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    let mut rng = Rng(77);
    let mut line = 0;
    let mut ts = 0u64;
    let mut written = 0usize;
    // Keystrokes (1-40 B), screenfuls (1-8 KiB) and dumps (up to
    // `max_read`), and 30 seconds of quiet now and then.
    while written < 24 * 1024 * 1024 {
        let (len, gap) = match rng.next() % 100 {
            0..=59 => (1 + (rng.next() % 40) as usize, 20),
            60..=94 => (1024 + (rng.next() % 7168) as usize, 5),
            95..=98 => (
                (max_read / 4 + (rng.next() as usize % (max_read * 3 / 4))).max(1),
                1,
            ),
            _ => (200, 30_000),
        };
        ts += gap;
        let payload = terminal_text(&mut rng, len, &mut line);
        written += payload.len();
        f.append(PlainPacket::data(ts, payload, false)).unwrap();
    }
    f.flush().unwrap();
    let entries = f.entries().to_vec();
    let mut plain: Vec<u32> = entries.iter().map(|e| e.plain_len).collect();
    let mut rec: Vec<u32> = entries.iter().map(|e| e.len).collect();
    let by_size = entries
        .iter()
        .filter(|e| e.plain_len as usize >= SEGMENT_TARGET_BYTES)
        .count();
    plain.sort_unstable();
    rec.sort_unstable();
    let pct = |v: &[u32], p: usize| v[(v.len() - 1) * p / 100];
    let mean = |v: &[u32]| v.iter().map(|x| *x as u64).sum::<u64>() / v.len() as u64;
    println!(
        "segments ({label}, reads up to {} KiB): n={} at or over the target {} closed early (age, ceiling, flush) {}; plaintext bytes min {} p10 {} p50 {} p90 {} max {} mean {}; sealed bytes min {} p50 {} p90 {} max {} mean {}",
        max_read / 1024,
        entries.len(),
        by_size,
        entries.len() - by_size,
        plain[0],
        pct(&plain, 10),
        pct(&plain, 50),
        pct(&plain, 90),
        plain[plain.len() - 1],
        mean(&plain),
        rec[0],
        pct(&rec, 50),
        pct(&rec, 90),
        rec[rec.len() - 1],
        mean(&rec),
    );
    // The rule: a segment of several packets is within the ceiling, only
    // one packet bigger than it makes a bigger segment, and every sealed
    // segment is far below the record bound.
    for e in &entries {
        assert!(
            e.count == 1 || e.plain_len as usize <= SEGMENT_MAX_BYTES,
            "segment of {} packets holds {} bytes",
            e.count,
            e.plain_len
        );
    }
    assert!(
        rec.iter()
            .all(|r| (*r as usize) < segment::MAX_RECORD_BYTES / 4)
    );
    // Sealed segments compress: the median is below the target.
    assert!((pct(&rec, 50) as usize) < SEGMENT_TARGET_BYTES);
}

#[test]
fn segment_sizes_under_bursty_output() {
    // PTY reads are at most 64 KiB (`node-pty`, the sidecar's `share.push`
    // joins up to 64 KiB); dumps of 400 KiB are the stress case.
    bursty(&Store::new(&[1]), 64 * 1024, "pty-sized reads");
    bursty(&Store::new(&[1]), 400 * 1024, "stress dumps");
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

#[test]
fn import_of_16_mib_round_trips_through_a_fresh_read() {
    let store = Store::new(&[3]);
    let per = 1024;
    let n = 16 * 1024 * 1024 / per;
    let source = packets(n, per, 11, 1_000, 2);
    let total: usize = source
        .iter()
        .map(|p| p.payload.as_ref().unwrap().len())
        .sum();
    assert_eq!(total, 16 * 1024 * 1024);
    let t = Instant::now();
    let f = import(store.cfg(), source.iter().cloned(), 3, store.keys[&3]).unwrap();
    let took = t.elapsed();
    let segs = f.segment_count();
    let on_disk = std::fs::metadata(store.seg_path()).unwrap().len();
    drop(f);
    println!(
        "import: {} MiB in {} packets -> {} segments, {} bytes on disk, {:.2} s, {:.1} MiB/s",
        total / (1024 * 1024),
        n,
        segs,
        on_disk,
        took.as_secs_f64(),
        total as f64 / (1024.0 * 1024.0) / took.as_secs_f64()
    );
    // A fresh read, from the files alone, byte for byte.
    let t = Instant::now();
    let mut g = store.open().unwrap();
    let opened = t.elapsed();
    g.head()
        .verify(&store.sid, &store.signer.verifying_key())
        .unwrap();
    let t = Instant::now();
    let read = g.read(0, n as u64).unwrap();
    let read_took = t.elapsed();
    assert_eq!(read.len(), n);
    for (i, (seq, p)) in read.iter().enumerate() {
        assert_eq!(*seq, i as u64);
        assert_eq!(p, &source[i], "packet {i}");
    }
    println!(
        "import readback: open {:.0} ms (chain of {} segments), read {:.2} s, {:.1} MiB/s, identical",
        opened.as_secs_f64() * 1000.0,
        g.segment_count(),
        read_took.as_secs_f64(),
        total as f64 / (1024.0 * 1024.0) / read_took.as_secs_f64()
    );
    // Sequence numbers are preserved with a non-zero first_seq.
    let store2 = Store::new(&[3]);
    let mut cfg = store2.cfg();
    cfg.first_seq = 1_000;
    let mut h = import(cfg, source.iter().take(50).cloned(), 3, store2.keys[&3]).unwrap();
    assert_eq!(h.next_seq(), 1_050);
    let r = h.read(1_010, 1_012).unwrap();
    assert_eq!(r[0].0, 1_010);
    assert_eq!(r[0].1, source[10]);
    assert!(
        import(
            store2.cfg(),
            source.iter().take(1).cloned(),
            3,
            store2.keys[&3]
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// serving: credit
// ---------------------------------------------------------------------------

#[test]
fn a_request_waits_for_credit_and_never_holds_more_than_the_cap() {
    let store = Store::new(&[1]);
    let f = write_all(&store, &packets(3000, 800, 12, 0, 1), &[]);
    let n = f.segment_count();
    assert!(n > 20, "{n}");
    let end = f.closed_end_seq();
    let source: Arc<dyn HistorySource> = Arc::new(SharedHistory::new(f));
    let mut req = ServeRequest::start(source.clone(), 0, end, 2)
        .unwrap()
        .unwrap();
    let out = req.pump();
    assert_eq!(out.len(), 2, "two credits, two segments");
    assert!(
        req.pump().is_empty(),
        "no credit: it waits, it does not drop"
    );
    assert!(!req.is_finished());
    req.add_credit(1_000_000);
    assert_eq!(req.credit(), MAX_HISTORY_CREDIT as u64, "credit is capped");
    let out = req.pump();
    assert_eq!(out.len() as u32, MAX_HISTORY_CREDIT);
    // Feed credit until done; the segments arrive in order and complete.
    let mut segs = 2 + out.len() as u64;
    let mut last = None;
    while !req.is_finished() {
        req.add_credit(4);
        for o in req.pump() {
            match o {
                ServeOut::Segment { .. } => segs += 1,
                ServeOut::Done { next } => last = Some(next),
            }
        }
    }
    assert_eq!(segs, n);
    assert_eq!(last, Some(end));
    // A range that lies in the open segment is not planned.
    assert!(
        ServeRequest::start(source, end, end + 10, 4)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_long_range_is_answered_in_pieces() {
    let store = Store::new(&[1]);
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    // Many tiny segments: a marker per segment via flush.
    for i in 0..300u64 {
        f.append(PlainPacket::data(i, vec![b'x'; 10], false))
            .unwrap();
        f.flush().unwrap();
    }
    let plan = f.plan_range(0, 300).unwrap();
    assert_eq!(
        plan.count as usize,
        zxterm_core::history::MAX_SEGMENTS_PER_REQUEST
    );
    assert_eq!(plan.next, plan.count);
    let rest = f.plan_range(plan.next, 300).unwrap();
    assert_eq!(rest.first_index, plan.count);
    assert_eq!(rest.next, 300);
    // The proof of the first piece still spans the whole head.
    let head = plan
        .proof
        .verify(&store.sid, &store.signer.verifying_key())
        .unwrap();
    assert_eq!(head.length, 300);
}

// ---------------------------------------------------------------------------
// live: a range fetch while output continues
// ---------------------------------------------------------------------------

struct Peer {
    svc: SessionService,
    rx: UnboundedReceiver<SessionEvent>,
    key: SigningKey,
    boots: u64,
}

impl Peer {
    async fn start(url: &str, opts: ServiceOptions) -> Peer {
        let backend = Backend::new(BackendOptions {
            node_url: url.to_string(),
            ice_servers: Some(vec![]),
            clock: None,
            loopback_only: true,
            legacy_v1_routes: false,
        });
        let key = SigningKey::from_bytes(&random::<32>());
        let (svc, rx) = SessionService::new(backend.clone(), opts);
        let mut tries = 0;
        while let Err(e) = backend.start(key.clone()).await {
            tries += 1;
            assert!(tries < 3, "start: {e:?}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Peer {
            svc,
            rx,
            key,
            boots: 0,
        }
    }

    /// Handles one event; a host answers `BootstrapNeeded` at once.
    fn take(&mut self, ev: &SessionEvent) {
        if let SessionEvent::BootstrapNeeded {
            session_id,
            request_id,
            ..
        } = ev
        {
            self.boots += 1;
            let doc = serde_json::json!({"boot": self.boots});
            let _ = self
                .svc
                .provide_bootstrap(session_id, *request_id, doc.to_string().as_bytes());
        }
    }

    async fn wait(&mut self, what: &str, mut pred: impl FnMut(&SessionEvent) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let ev = tokio::time::timeout(left, self.rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
                .expect("event stream");
            self.take(&ev);
            if pred(&ev) {
                return;
            }
        }
    }
}

fn identity(name: &str) -> LocalIdentity {
    let (device_pk, device_sk) = envelope::generate_device_key();
    let id = IdentityKey::from_seed(random::<64>().to_vec());
    LocalIdentity {
        device_secret_key: device_sk,
        identity_key: id.identity_public_key(),
        identity_proof: id.bootstrap(device_pk, now_ms()),
        device_name: name.to_string(),
        claim: None,
        auth_secret_key: None,
    }
}

struct Session {
    sid: String,
    route: Route,
    link: LinkSpec,
}

async fn host_with_history(
    h: &mut Peer,
    source: Arc<dyn HistorySource>,
    reg: &HistoryRegistry,
) -> Session {
    let sid = hex::encode(random::<32>());
    h.svc
        .host_open(HostOpen {
            session_id: sid.clone(),
            info: SessionInfo {
                name: "history".into(),
                created_at: now_ms(),
                sensitive: false,
                quick_catchup_kb: 0,
                cols: 80,
                rows: 24,
            },
            input_mode: InputMode::Host,
            log_key: random::<32>(),
            meta_key: random::<32>(),
            local: identity("host"),
            first_epoch: 1,
        })
        .expect("host_open");
    reg.insert(&sid, source);
    h.svc.backend().set_admission(Admission::All(true));
    let link = LinkSpec {
        link_id: random::<16>(),
        kind: LinkKind::Group,
        max_viewers: 99,
        auto_join: true,
        caps: Some(VIEW_LIVE | READ_HISTORY),
    };
    let ann = h
        .svc
        .backend()
        .announce(&hex::encode(link.link_id), None, None)
        .await
        .expect("announce");
    h.svc.add_link(&sid, link.clone()).expect("add_link");
    Session {
        sid,
        route: ann.route,
        link,
    }
}

const LIVE_PAYLOAD: usize = 512;
const LIVE_INTERVAL_MS: u64 = 4;

fn live_marker(n: u64) -> Vec<u8> {
    let mut v = format!("L{n:08}:{:016}:", now_us()).into_bytes();
    v.resize(LIVE_PAYLOAD, b'x');
    v
}

fn parse_marker(data: &[u8]) -> Option<(u64, u64)> {
    let s = std::str::from_utf8(data.get(..27)?).ok()?;
    let n = s.strip_prefix('L')?.get(..8)?.parse().ok()?;
    let t = s.get(10..26)?.parse().ok()?;
    Some((n, t))
}

/// The host: pushes a marked live packet every few milliseconds until
/// `stop`, answering any `BootstrapNeeded`; returns how many it pushed.
async fn host_live(
    mut h: Peer,
    sid: String,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> (Peer, u64) {
    let mut n = 0u64;
    let mut tick = tokio::time::interval(Duration::from_millis(LIVE_INTERVAL_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if h.svc.push(&sid, &live_marker(n), false).is_ok() {
                    n += 1;
                }
            }
            Some(ev) = h.rx.recv() => h.take(&ev),
            _ = stop.changed() => break,
        }
    }
    (h, n)
}

#[derive(Default, Clone)]
struct Live {
    /// `(arrival µs, latency µs)` per marked output.
    arrivals: Vec<(u64, u64)>,
    seqs: Vec<u64>,
}

impl Live {
    fn latencies_ms(&self) -> Vec<f64> {
        let mut v: Vec<f64> = self.arrivals.iter().map(|a| a.1 as f64 / 1000.0).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    }

    fn max_gap_ms(&self) -> f64 {
        self.arrivals
            .windows(2)
            .map(|w| (w[1].0 - w[0].0) as f64 / 1000.0)
            .fold(0.0, f64::max)
    }
}

fn pct(v: &[f64], p: usize) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v[(v.len() - 1) * p / 100]
}

/// The viewer's event stream: stamps every event on arrival (so the live
/// latency does not include the fetch's own verification work), records
/// the live output and forwards the rest.
fn spawn_stamper(
    mut rx: UnboundedReceiver<SessionEvent>,
) -> (
    UnboundedReceiver<SessionEvent>,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<Live>,
) {
    let (tx, out) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut live = Live::default();
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    let arrived = now_us();
                    if let SessionEvent::Output { data, .. } = &ev
                        && let Some((n, sent)) = parse_marker(data)
                    {
                        live.arrivals.push((arrived, arrived.saturating_sub(sent)));
                        live.seqs.push(n);
                        continue;
                    }
                    let _ = tx.send(ev);
                }
                _ = stop_rx.changed() => break,
            }
        }
        live
    });
    (out, stop_tx, task)
}

struct Fetched {
    packets: Vec<(u64, PlainPacket)>,
    bytes: usize,
    took: Duration,
    segments: u64,
    /// The longest wait between two segments (or the request and its
    /// first), in ms.
    max_gap_ms: f64,
}

/// Fetches `[0, end)` with credit replenished as segments are consumed
/// (one credit back per segment verified), in as many requests as the
/// host's per-request bound needs.
async fn fetch_all(
    v: &SessionService,
    rx: &mut UnboundedReceiver<SessionEvent>,
    store: &Store,
    sid: &str,
    end: u64,
) -> Fetched {
    let t = Instant::now();
    let mut out = Fetched {
        packets: Vec::new(),
        bytes: 0,
        took: Duration::ZERO,
        segments: 0,
        max_gap_ms: 0.0,
    };
    let mut last = Instant::now();
    let mut start = 0u64;
    while start < end {
        let req = v
            .request_history(sid, start, end, MAX_HISTORY_CREDIT)
            .unwrap();
        let mut verifier = store.verifier();
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .expect("history event")
                .expect("event stream");
            match ev {
                SessionEvent::HistorySegment {
                    request_id, data, ..
                } if request_id == req => {
                    out.max_gap_ms = out.max_gap_ms.max(last.elapsed().as_secs_f64() * 1000.0);
                    last = Instant::now();
                    out.bytes += data.len();
                    let seg = verifier.accept(&data).expect("segment verifies");
                    out.packets.extend(seg.packets);
                    out.segments += 1;
                    v.history_credit(sid, req, 1).unwrap();
                }
                SessionEvent::HistoryDone {
                    request_id, next, ..
                } if request_id == req => {
                    verifier
                        .finish(next, start)
                        .expect("done follows the last segment");
                    assert!(next > start, "a request made progress");
                    start = next;
                    break;
                }
                _ => {}
            }
        }
    }
    out.took = t.elapsed();
    out
}

/// A host serving `source` and a viewer joined to it (`VIEW_LIVE |
/// READ_HISTORY`), both at rest.
async fn connect_pair(
    url: &str,
    source: Arc<dyn HistorySource>,
    reg: &HistoryRegistry,
) -> (Peer, Peer, Session) {
    let mut h = Peer::start(
        url,
        ServiceOptions {
            history: Some(reg.clone()),
            ..Default::default()
        },
    )
    .await;
    let mut v = Peer::start(url, ServiceOptions::default()).await;
    let session = host_with_history(&mut h, source, reg).await;
    let join_id = v
        .svc
        .join(JoinSpec {
            route: session.route.clone(),
            expected_peer_key: h.key.verifying_key().to_bytes(),
            link_id: session.link.link_id,
            local: identity("viewer"),
        })
        .expect("join");
    // The host answers the grant's bootstrap request while the viewer waits.
    let hid = join_id.clone();
    let (h, ()) = tokio::join!(
        async {
            h.wait("the grant's bootstrap request", |e| {
                matches!(e, SessionEvent::BootstrapNeeded { .. })
            })
            .await;
            h
        },
        v.wait("joined", |e| matches!(
            e,
            SessionEvent::JoinChanged { join_id, status: JoinStatus::Joined, .. } if *join_id == hid
        ))
    );
    (h, v, session)
}

async fn wait_done(v: &mut Peer, want: u32) -> u64 {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(10), v.rx.recv())
            .await
            .expect("an answer")
            .expect("event stream");
        if let SessionEvent::HistoryDone {
            request_id, next, ..
        } = ev
            && request_id == want
        {
            return next;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_in_the_open_segment_and_a_fifth_request_are_answered_done() {
    if !freenet_available() {
        println!(
            "SKIP a_range_in_the_open_segment_and_a_fifth_request_are_answered_done: freenet binary not on PATH"
        );
        return;
    }
    let node = LocalNode::start().expect("start a LocalNode");
    let store = Store::new(&[1]);
    // Segments, then packets still in the open segment.
    let mut f = store.create();
    f.set_epoch(1).unwrap();
    for p in packets(400, 800, 31, 0, 1) {
        f.append(p).unwrap();
    }
    let closed = f.closed_end_seq();
    let total = f.next_seq();
    assert!(closed > 0 && total > closed, "{closed} closed of {total}");
    let reg = HistoryRegistry::new();
    let (_h, mut v, session) = connect_pair(&node.url, Arc::new(SharedHistory::new(f)), &reg).await;
    // Only the open segment: nothing to serve, `next` is where it began.
    let id = v
        .svc
        .request_history(&session.sid, closed, total, 4)
        .unwrap();
    assert_eq!(wait_done(&mut v, id).await, closed);
    // Four requests with no credit wait; the fifth is answered at once.
    let waiting: Vec<u32> = (0..4)
        .map(|_| v.svc.request_history(&session.sid, 0, closed, 0).unwrap())
        .collect();
    let fifth = v.svc.request_history(&session.sid, 0, closed, 4).unwrap();
    assert_eq!(wait_done(&mut v, fifth).await, 0);
    // Credit releases a waiting one: its segments arrive, then its Done.
    v.svc.history_credit(&session.sid, waiting[0], 4).unwrap();
    let mut segments = 0;
    let next = loop {
        let ev = tokio::time::timeout(Duration::from_secs(10), v.rx.recv())
            .await
            .expect("history event")
            .expect("event stream");
        match ev {
            SessionEvent::HistorySegment { request_id, .. } if request_id == waiting[0] => {
                segments += 1;
                v.svc.history_credit(&session.sid, waiting[0], 1).unwrap();
            }
            SessionEvent::HistoryDone {
                request_id, next, ..
            } if request_id == waiting[0] => break next,
            SessionEvent::HistorySegment { request_id, .. } => {
                panic!("request {request_id} sent a segment without credit")
            }
            _ => {}
        }
    };
    assert!(segments >= 1);
    assert_eq!(next, closed);
    println!(
        "history: open-segment range and a fifth request answered Done; a credited request served {segments} segments"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn range_fetch_while_live_output_continues() {
    if !freenet_available() {
        println!("SKIP range_fetch_while_live_output_continues: freenet binary not on PATH");
        return;
    }
    let node = LocalNode::start().expect("start a LocalNode");
    let store = Arc::new(Store::new(&[1]));
    // 8 MiB of history on the host.
    let source_packets = noisy_packets(8192, 1024, 21, 5_000);
    let file = {
        let store = store.clone();
        let src = source_packets.clone();
        tokio::task::spawn_blocking(move || write_all(&store, &src, &[]))
            .await
            .unwrap()
    };
    let end = file.closed_end_seq();
    let segs = file.segment_count();
    let shared = SharedHistory::new(file);
    let reg = HistoryRegistry::new();
    let (h, v, session) = connect_pair(&node.url, Arc::new(shared), &reg).await;
    let (mut vrx, vstop, vtask) = spawn_stamper(v.rx);
    let vsvc = v.svc.clone();

    // Phase A: live alone, 3 s.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let host_a = tokio::spawn(host_live(h, session.sid.clone(), stop_rx));
    tokio::time::sleep(Duration::from_secs(3)).await;
    stop_tx.send(true).unwrap();
    let (h, pushed_a) = host_a.await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase B: history alone.
    let alone = fetch_all(&vsvc, &mut vrx, &store, &session.sid, end).await;
    assert_eq!(alone.packets.len() as u64, end);

    // Phase C: the same fetch while live output continues.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let host_c = tokio::spawn(host_live(h, session.sid.clone(), stop_rx));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mark_from = now_us();
    let concurrent = fetch_all(&vsvc, &mut vrx, &store, &session.sid, end).await;
    let mark_to = now_us();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop_tx.send(true).unwrap();
    let (_h, pushed_total) = host_c.await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    vstop.send(true).unwrap();
    let live = vtask.await.unwrap();

    // Correctness: the fetched history is what the host wrote, packet for
    // packet, both times.
    assert_eq!(concurrent.packets.len(), source_packets.len());
    for (i, (seq, p)) in concurrent.packets.iter().enumerate() {
        assert_eq!(*seq, i as u64);
        assert_eq!(*p, source_packets[i], "packet {i}");
    }
    assert_eq!(alone.packets, concurrent.packets);

    // Live during the fetch window, and alone.
    let during: Vec<(u64, u64)> = live
        .arrivals
        .iter()
        .copied()
        .filter(|a| a.0 >= mark_from && a.0 <= mark_to)
        .collect();
    let during_live = Live {
        arrivals: during.clone(),
        seqs: Vec::new(),
    };
    let alone_live = Live {
        arrivals: live
            .arrivals
            .iter()
            .copied()
            .take_while(|a| a.0 < mark_from)
            .take(pushed_a as usize)
            .collect(),
        seqs: Vec::new(),
    };
    let lat_alone = alone_live.latencies_ms();
    let lat_during = during_live.latencies_ms();
    let window_s = (mark_to - mark_from) as f64 / 1e6;
    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
    println!(
        "history: {segs} segments, {:.2} MiB of segment data on the wire",
        mib(concurrent.bytes)
    );
    println!(
        "live alone: {} of {} pushed arrived, latency p50 {:.1} p95 {:.1} p99 {:.1} max {:.1} ms, {:.0} msg/s",
        alone_live.arrivals.len(),
        pushed_a,
        pct(&lat_alone, 50),
        pct(&lat_alone, 95),
        pct(&lat_alone, 99),
        lat_alone.last().copied().unwrap_or(f64::NAN),
        alone_live.arrivals.len() as f64 / 3.0
    );
    println!(
        "history alone: {:.2} MiB/s ({} segments in {:.2} s), longest wait between segments {:.0} ms",
        mib(alone.bytes) / alone.took.as_secs_f64(),
        alone.segments,
        alone.took.as_secs_f64(),
        alone.max_gap_ms
    );
    println!(
        "CONCURRENT history: {:.2} MiB/s ({} segments in {:.2} s), longest wait between segments {:.0} ms",
        mib(concurrent.bytes) / concurrent.took.as_secs_f64(),
        concurrent.segments,
        concurrent.took.as_secs_f64(),
        concurrent.max_gap_ms
    );
    println!(
        "CONCURRENT live: {} arrived in the {:.2} s fetch window ({:.0} msg/s), latency p50 {:.1} p95 {:.1} p99 {:.1} max {:.1} ms, longest gap {:.1} ms; {} pushed in all, {} arrived in all",
        during.len(),
        window_s,
        during.len() as f64 / window_s,
        pct(&lat_during, 50),
        pct(&lat_during, 95),
        pct(&lat_during, 99),
        lat_during.last().copied().unwrap_or(f64::NAN),
        during_live.max_gap_ms(),
        pushed_total + pushed_a,
        live.arrivals.len()
    );

    // Neither channel starves. The bounds are for a loopback node on this
    // machine's debug build, and sit far below the one-second stall a
    // burst of history used to cause (`R-23`, credit 16): live keeps
    // arriving (>= 80% of the rate it had alone), its p99 latency stays
    // within 250 ms, no live message waits more than 500 ms or goes
    // unheard for more than 500 ms, and the fetch keeps at least a quarter
    // of its solo speed.
    let live_rate_alone = alone_live.arrivals.len() as f64 / 3.0;
    let live_rate_during = during.len() as f64 / window_s;
    assert!(
        live_rate_during >= 0.8 * live_rate_alone,
        "live rate {live_rate_during:.0}/s during the fetch vs {live_rate_alone:.0}/s alone"
    );
    assert!(
        pct(&lat_during, 99) <= 250.0,
        "live p99 latency {:.1} ms during the fetch",
        pct(&lat_during, 99)
    );
    assert!(
        lat_during.last().copied().unwrap_or(0.0) <= 500.0,
        "live max latency during the fetch"
    );
    assert!(during_live.max_gap_ms() <= 500.0, "live went quiet");
    assert!(
        mib(concurrent.bytes) / concurrent.took.as_secs_f64()
            >= 0.25 * (mib(alone.bytes) / alone.took.as_secs_f64()),
        "history starved by live"
    );
}

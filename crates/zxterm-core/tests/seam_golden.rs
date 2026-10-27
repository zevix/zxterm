//! Writes one fixed value of each seam [`Frame`](zxterm_core::seam::Frame)
//! kind to `tests/seam-golden/*.bin` (K7 Step 7) — checked into the repo as
//! test fixtures, not regenerated on every run. ZBTerm's `codec.js` test
//! reads these exact files and asserts it decodes them to the same logical
//! values (and, for round-trip, re-encodes to the same bytes).
//!
//! Regenerate deliberately (re-run this test with `ZX_SEAM_GOLDEN_WRITE=1`)
//! if the wire format changes, and note the change in that phase's Handoff
//! notes — `postcard`'s wire format depends on struct field order, so a
//! Rust-side change here must never drift from the checked-in files (this
//! phase's own Gotchas).

use std::fs;
use std::path::PathBuf;

use zxterm_core::seam::{Frame, WireError, encode};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/seam-golden")
}

fn fixtures() -> Vec<(&'static str, Frame)> {
    vec![
        (
            "request",
            Frame::Request {
                id: "1".into(),
                method: "core.version".into(),
                args: "{}".into(),
            },
        ),
        (
            "reply-ok",
            Frame::Reply {
                id: "1".into(),
                ok: Ok("{\"version\":\"0.1.0\"}".into()),
            },
        ),
        (
            "reply-err",
            Frame::Reply {
                id: "2".into(),
                ok: Err(WireError {
                    code: "E_AUTH".into(),
                    message: "bad signature".into(),
                }),
            },
        ),
        (
            "event",
            Frame::Event {
                name: "resync".into(),
                data: "{}".into(),
            },
        ),
        (
            "output",
            Frame::Output {
                stream: "test-flood".into(),
                bytes: vec![1, 2, 3, 4, 5],
            },
        ),
        // K10: the raw-channel frame, variant 4 (the four above keep their
        // bytes).
        (
            "chan",
            Frame::Chan {
                chan: 300,
                bytes: vec![0, 1, 2, 253, 254, 255],
            },
        ),
    ]
}

/// Writes (or, by default, only checks) the golden fixtures. This is a
/// `#[test]` (not a `fn main`/example) so `cargo test` always exercises
/// encoding these exact values, catching an accidental `postcard`-breaking
/// change to `Frame` even when nobody remembers to set
/// `ZX_SEAM_GOLDEN_WRITE`.
#[test]
fn golden_fixtures_encode_and_match_the_checked_in_files() {
    let dir = golden_dir();
    let write = std::env::var("ZX_SEAM_GOLDEN_WRITE").is_ok();
    if write {
        fs::create_dir_all(&dir).expect("create tests/seam-golden");
    }

    for (name, frame) in fixtures() {
        let bytes = encode(&frame).expect("encode fixture");
        let path = dir.join(format!("{name}.bin"));
        if write {
            fs::write(&path, &bytes).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
        }
        let checked_in = fs::read(&path).unwrap_or_else(|e| {
            panic!("{path:?} is missing (run with ZX_SEAM_GOLDEN_WRITE=1 to generate it): {e}")
        });
        assert_eq!(
            bytes, checked_in,
            "{name}.bin has drifted from Frame's current postcard encoding — \
             regenerate deliberately (ZX_SEAM_GOLDEN_WRITE=1) and note the wire-format \
             change in this phase's Handoff notes, per this phase's own Gotchas"
        );

        // Round-trip: the checked-in bytes decode back to the exact value
        // that produced them.
        let decoded = zxterm_core::seam::decode(&checked_in).expect("decode checked-in fixture");
        assert_eq!(
            decoded, frame,
            "{name}.bin does not decode back to its source value"
        );
    }
}

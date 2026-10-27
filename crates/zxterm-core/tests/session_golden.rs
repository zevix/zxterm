//! Golden `postcard` bytes of the session protocol v2's messages (K13 step
//! 11): one fixed instance of every variant of `protocol.md` §7's
//! [`CtlMsg`], [`LiveMsg`] and [`HistoryMsg`], and a [`SealedInput`], checked
//! into `tests/session-golden/*.bin`. The mapping table of `protocol.md`
//! §6.2 names 14 JS message types; each has its Rust variant and file here
//! (`MAPPING`), and the new `history` channel's four.
//!
//! The test encodes each value and compares it with its file, and decodes
//! the file back to the value. Variant and field order are the wire and are
//! append-only (§7): a drift fails here. Regenerate only deliberately, with
//! `ZX_SESSION_GOLDEN_WRITE=1`, and note the wire change in the phase's
//! handoff notes.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use zxterm_core::session::messages::{
    self, CtlMsg, ErrorCode, Exit, HistoryMsg, InputMode, JoinReason, LiveMsg, Role, SealedFrame,
    SealedInput, SessionInfo, WireClaim,
};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/session-golden")
}

/// `protocol.md` §6.2: JS `type` string -> the fixture of its v2 message.
const MAPPING: &[(&str, &str)] = &[
    ("join-request", "ctl-0-join-request"),
    ("identity-challenge", "ctl-1-identity-challenge"),
    ("identity-response", "ctl-2-identity-response"),
    ("approval-pending", "ctl-3-approval-pending"),
    ("confirm", "ctl-4-confirm"),
    ("bootstrap", "live-1-bootstrap"),
    ("data", "live-0-data"),
    ("snapshot", "live-2-snapshot"),
    ("timeline", "live-3-timeline"),
    ("rekey", "live-4-rekey"),
    ("input", "ctl-5-input"),
    ("end", "ctl-6-end"),
    ("info", "ctl-7-info"),
    ("error", "ctl-8-error"),
];

fn ctl_name(m: &CtlMsg) -> &'static str {
    match m {
        CtlMsg::JoinRequest { .. } => "ctl-0-join-request",
        CtlMsg::IdentityChallenge { .. } => "ctl-1-identity-challenge",
        CtlMsg::IdentityResponse { .. } => "ctl-2-identity-response",
        CtlMsg::ApprovalPending => "ctl-3-approval-pending",
        CtlMsg::Confirm { .. } => "ctl-4-confirm",
        CtlMsg::Input { .. } => "ctl-5-input",
        CtlMsg::End { .. } => "ctl-6-end",
        CtlMsg::Info { .. } => "ctl-7-info",
        CtlMsg::Error { .. } => "ctl-8-error",
    }
}

fn live_name(m: &LiveMsg) -> &'static str {
    match m {
        LiveMsg::Data { .. } => "live-0-data",
        LiveMsg::Bootstrap { .. } => "live-1-bootstrap",
        LiveMsg::Snapshot { .. } => "live-2-snapshot",
        LiveMsg::Timeline { .. } => "live-3-timeline",
        LiveMsg::Rekey { .. } => "live-4-rekey",
    }
}

fn history_name(m: &HistoryMsg) -> &'static str {
    match m {
        HistoryMsg::RangeRequest { .. } => "history-0-range-request",
        HistoryMsg::Credit { .. } => "history-1-credit",
        HistoryMsg::Segment { .. } => "history-2-segment",
        HistoryMsg::Done { .. } => "history-3-done",
    }
}

fn claim() -> WireClaim {
    WireClaim {
        provider: Some("github".into()),
        subject: Some("octocat".into()),
        identity_key: Some("11".repeat(32)),
        auth_key: Some("22".repeat(32)),
        ssh_fingerprint: Some("SHA256:abc".into()),
        issued_at: Some(1_759_000_000_000),
        nonce: Some("33".repeat(16)),
        signature: Some("-----BEGIN SSH SIGNATURE-----\nAA==\n-----END SSH SIGNATURE-----".into()),
        ssh_public_key: None,
    }
}

fn frame(seq: u64) -> SealedFrame {
    SealedFrame {
        epoch: 3,
        seq,
        device_key: [0x44; 32],
        ciphertext: vec![0xC0, 0xFF, 0xEE, 0x00, 0x01],
    }
}

fn ctl() -> Vec<CtlMsg> {
    vec![
        CtlMsg::JoinRequest {
            link_id: [0x0A; 16],
            device_key: [0x01; 32],
            identity_key: [0x02; 32],
            identity_proof: vec![1, 2, 3, 4],
            device_name: "viewer".into(),
            identity_claim: Some(claim()),
            auth_key: Some([0x03; 32]),
            app_version: "1".into(),
        },
        CtlMsg::IdentityChallenge {
            challenge_id: "0f".repeat(16),
            nonce: "1e".repeat(32),
            session_id: "2d".repeat(32),
            role: Role::Viewer,
        },
        CtlMsg::IdentityResponse {
            challenge_id: "0f".repeat(16),
            signature: [0x5A; 64],
        },
        CtlMsg::ApprovalPending,
        CtlMsg::Confirm {
            session_id: "2d".repeat(32),
            info: SessionInfo {
                name: "build".into(),
                created_at: 1_759_000_000_000,
                sensitive: false,
                quick_catchup_kb: 256,
                cols: 120,
                rows: 40,
            },
            input_mode: InputMode::All,
            log_key: [0x06; 32],
            meta_key: [0x07; 32],
            host_device_key: [0x08; 32],
            envelope: vec![9; 48],
            host_identity_claim: None,
            host_auth_key: None,
        },
        CtlMsg::Input {
            sealed: vec![0xAB; 60],
        },
        CtlMsg::End {
            session_id: "2d".repeat(32),
            exit: Some(Exit {
                code: Some(-1),
                signal: Some("SIGHUP".into()),
            }),
        },
        CtlMsg::Info {
            session_id: "2d".repeat(32),
            name: None,
            input_mode: Some(InputMode::Host),
        },
        CtlMsg::Error {
            code: ErrorCode::EAuth,
            message: "Invite is no longer valid".into(),
            reason: Some(JoinReason::Revoked),
        },
    ]
}

fn live() -> Vec<LiveMsg> {
    vec![
        LiveMsg::Data {
            frame: frame(1),
            hd: true,
        },
        LiveMsg::Bootstrap { frame: frame(2) },
        LiveMsg::Snapshot { frame: frame(3) },
        LiveMsg::Timeline { frame: frame(4) },
        LiveMsg::Rekey {
            epoch: 4,
            envelope: vec![0xEE; 48],
        },
    ]
}

fn history() -> Vec<HistoryMsg> {
    vec![
        HistoryMsg::RangeRequest {
            request_id: 1,
            start: 0,
            end: 300,
            credit: 16,
        },
        HistoryMsg::Credit {
            request_id: 1,
            credit: 8,
        },
        HistoryMsg::Segment {
            request_id: 1,
            start: 128,
            data: vec![7; 5],
        },
        HistoryMsg::Done {
            request_id: 1,
            next: 300,
        },
    ]
}

fn sealed_input() -> SealedInput {
    SealedInput {
        session_id: "2d".repeat(32),
        epoch: 3,
        input_ctr: 7,
        device_key: [0x01; 32],
        identity_key: [0x02; 32],
        identity_proof: vec![1, 2, 3, 4],
        data: b"ls -la\r".to_vec(),
    }
}

fn check(name: &str, bytes: &[u8], write: bool) -> Vec<u8> {
    let path = golden_dir().join(format!("{name}.bin"));
    if write {
        fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
    }
    let checked_in = fs::read(&path).unwrap_or_else(|e| {
        panic!("{path:?} is missing (run with ZX_SESSION_GOLDEN_WRITE=1 to generate it): {e}")
    });
    assert_eq!(
        bytes, checked_in,
        "{name}.bin has drifted from the message's postcard encoding: the variant/field order \
         is the wire and append-only (protocol.md §7)"
    );
    checked_in
}

#[test]
fn every_message_matches_its_golden_bytes_and_round_trips() {
    let write = std::env::var("ZX_SESSION_GOLDEN_WRITE").is_ok();
    if write {
        fs::create_dir_all(golden_dir()).expect("create tests/session-golden");
    }
    let mut names = BTreeSet::new();
    for m in ctl() {
        let name = ctl_name(&m);
        let file = check(name, &messages::encode(&m), write);
        assert_eq!(messages::decode::<CtlMsg>(&file).unwrap(), m, "{name}");
        assert!(names.insert(name));
    }
    for m in live() {
        let name = live_name(&m);
        let file = check(name, &messages::encode(&m), write);
        assert_eq!(messages::decode::<LiveMsg>(&file).unwrap(), m, "{name}");
        assert!(names.insert(name));
    }
    for m in history() {
        let name = history_name(&m);
        let file = check(name, &messages::encode(&m), write);
        assert_eq!(messages::decode::<HistoryMsg>(&file).unwrap(), m, "{name}");
        assert!(names.insert(name));
    }
    let si = sealed_input();
    let file = check("sealed-input", &messages::encode(&si), write);
    assert_eq!(messages::decode::<SealedInput>(&file).unwrap(), si);
    names.insert("sealed-input");

    // Every variant once: 9 + 5 + 4, plus the sealed input.
    assert_eq!(names.len(), 9 + 5 + 4 + 1);
    // Every row of protocol.md §6.2's mapping table has its fixture.
    assert_eq!(MAPPING.len(), 14);
    for (js, fixture) in MAPPING {
        assert!(names.contains(fixture), "{js} -> {fixture} has no fixture");
    }
    // No stray file in the directory.
    let on_disk: BTreeSet<String> = fs::read_dir(golden_dir())
        .unwrap()
        .map(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".bin")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = names.iter().map(|s| s.to_string()).collect();
    assert_eq!(on_disk, expected);
}

/// The layout, spelled out for two messages (protocol.md §7: an enum is its
/// variant index varint, then its fields in order; `[u8; N]` is N raw
/// bytes; `Option` is 0/1 then the value; `u64` a varint).
#[test]
fn the_layout_is_postcards() {
    let pending = messages::encode(&CtlMsg::ApprovalPending);
    assert_eq!(pending, [3]);
    let done = messages::encode(&HistoryMsg::Done {
        request_id: 1,
        next: 300,
    });
    assert_eq!(done, [3, 1, 0xAC, 0x02]);
    let rekey = messages::encode(&LiveMsg::Rekey {
        epoch: 4,
        envelope: vec![0xEE; 2],
    });
    assert_eq!(rekey, [4, 4, 2, 0xEE, 0xEE]);
    let err = messages::encode(&CtlMsg::Error {
        code: ErrorCode::EAuth,
        message: "x".into(),
        reason: Some(JoinReason::Revoked),
    });
    assert_eq!(err, [8, 1, 1, b'x', 1, 1]);
}

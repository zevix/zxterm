//! K16: the contract's own checks, run natively against the same code the WASM is built from
//! (`cargo test` in this crate), and the generator of `states/`.
//!
//! `states/*.json` are the `fdev verify-merge` corpus. Ed25519 signatures are deterministic, so
//! this file rebuilds every fixture byte for byte and fails when a committed one differs; run
//! with `ZX_WRITE_FIXTURES=1` to (re)write them.
use ed25519_compact::{KeyPair, Seed};
use freenet_stdlib::prelude::*;
use zxterm_segment::{
    head_bytes, segment_bytes, Head, Segment, SegmentRecord, Wire, DOMAIN, MAX_SEGMENTS,
    MAX_SEGMENT_BYTES, MAX_TOTAL_BYTES,
};

fn pair(seed: u8) -> KeyPair {
    KeyPair::from_seed(Seed::new([seed; 32]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn params(host: &KeyPair) -> Vec<u8> {
    format!(
        r#"{{"host":"{}","session":"zxterm-k16-verify-merge"}}"#,
        hex(host.pk.as_ref())
    )
    .into_bytes()
}

fn content(i: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|k| (i as usize * 31 + k) as u8 ^ 0x5a)
        .collect()
}

fn root(i: u64) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&i.to_le_bytes());
    r[8] = 0xc3;
    r
}

fn segment_of(key: &KeyPair, params: &[u8], i: u32, len: usize) -> SegmentRecord {
    let mut rec = SegmentRecord {
        i,
        p: root(i as u64),
        c: content(i, len),
        g: [0u8; 64],
    };
    rec.g = *key.sk.sign(segment_bytes(params, &rec), None);
    rec
}

fn head_of(key: &KeyPair, params: &[u8], n: u64) -> Head {
    let mut head = Head {
        n,
        r: root(n),
        g: [0u8; 64],
    };
    head.g = *key.sk.sign(head_bytes(params, &head), None);
    head
}

fn state(head: Option<Head>, segs: Vec<SegmentRecord>) -> Vec<u8> {
    serde_json::to_vec(&Wire { h: head, s: segs }).unwrap()
}

fn run_params(p: &[u8]) -> Parameters<'static> {
    Parameters::from(p.to_vec())
}

fn validate(p: &[u8], s: &[u8]) -> ValidateResult {
    Segment::validate_state(
        run_params(p),
        State::from(s.to_vec()),
        RelatedContracts::default(),
    )
    .unwrap()
}

fn update(p: &[u8], s: &[u8], deltas: Vec<Vec<u8>>) -> Result<Vec<u8>, ContractError> {
    let data = deltas
        .into_iter()
        .map(|d| UpdateData::Delta(StateDelta::from(d)))
        .collect();
    Segment::update_state(run_params(p), State::from(s.to_vec()), data)
        .map(|m| m.unwrap_valid().as_ref().to_vec())
}

fn parsed(bytes: &[u8]) -> Wire {
    serde_json::from_slice(bytes).unwrap()
}

/// The fixture corpus: name and bytes.
fn fixtures() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let host = pair(7);
    let other = pair(9);
    let p = params(&host);
    let seg = |i: u32| segment_of(&host, &p, i, 40 + (i as usize % 7));
    let range = |a: u32, b: u32| (a..b).map(seg).collect::<Vec<_>>();
    let mut out: Vec<(String, Vec<u8>)> = vec![
        // empty
        ("s0".into(), state(None, vec![])),
        // partial segments, no head yet
        ("s1".into(), state(None, range(0, 3))),
        // segments and the head that covers them
        ("s2".into(), state(Some(head_of(&host, &p, 3)), range(0, 3))),
        // a later run, the head moved on
        ("s3".into(), state(Some(head_of(&host, &p, 6)), range(3, 6))),
        // overlapping the two above, no head
        ("s4".into(), state(None, range(2, 5))),
        // a head alone
        ("s5".into(), state(Some(head_of(&host, &p, 1)), vec![])),
        // a hole in the indices (a partial replica)
        (
            "s6".into(),
            state(
                Some(head_of(&host, &p, 9)),
                vec![seg(0), seg(1), seg(5), seg(8)],
            ),
        ),
    ];
    // A non-owner write: every record signed by another key. Not a valid state, and a merge that
    // meets it is refused; verify-merge must find no violation in refusing.
    let forged: Vec<SegmentRecord> = (0..2).map(|i| segment_of(&other, &p, i, 40)).collect();
    out.push(("s7".into(), state(Some(head_of(&other, &p, 2)), forged)));
    // A record whose index is written again with other bytes (a forged overwrite).
    let mut over = seg(1);
    over.c = content(1, 41);
    over.g = *host.sk.sign(segment_bytes(&p, &over), None);
    out.push(("s8".into(), state(None, vec![seg(1), over])));
    // An over-bound merge: s9 holds MAX_SEGMENTS - 4 records from 0, s10 the same number from
    // 256; their union has more than MAX_SEGMENTS, so the oldest indices are dropped.
    let big = |a: u32, b: u32| {
        (a..b)
            .map(|i| segment_of(&host, &p, i, 1))
            .collect::<Vec<_>>()
    };
    let n = (MAX_SEGMENTS - 4) as u32;
    out.push((
        "s9".into(),
        state(Some(head_of(&host, &p, n as u64)), big(0, n)),
    ));
    out.push((
        "s10".into(),
        state(Some(head_of(&host, &p, 256 + n as u64)), big(256, 256 + n)),
    ));
    (p, out)
}

#[test]
fn the_fixtures_are_what_the_generator_writes() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("states");
    let (p, all) = fixtures();
    let write = std::env::var("ZX_WRITE_FIXTURES").is_ok();
    if write {
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("params.json"),
            &p,
        )
        .unwrap();
    }
    let on_disk =
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("params.json"))
            .unwrap_or_default();
    assert_eq!(on_disk, p, "params.json is the generator's");
    for (name, bytes) in &all {
        let path = dir.join(format!("{name}.json"));
        if write {
            std::fs::write(&path, bytes).unwrap();
        }
        assert_eq!(
            &std::fs::read(&path).unwrap(),
            bytes,
            "{name}.json is the generator's"
        );
    }
    // Which of them are valid states.
    let valid: Vec<&str> = all
        .iter()
        .filter(|(_, b)| matches!(validate(&p, b), ValidateResult::Valid))
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(
        valid,
        ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s9", "s10"]
    );
}

#[test]
fn the_domain_is_pinned() {
    assert_eq!(DOMAIN, b"zxterm/segment/1");
    let host = pair(7);
    let p = params(&host);
    let rec = segment_of(&host, &p, 5, 3);
    let bytes = segment_bytes(&p, &rec);
    assert_eq!(&bytes[..16], b"zxterm/segment/1");
    assert_eq!(bytes[16], 1);
    let head = head_of(&host, &p, 5);
    let bytes = head_bytes(&p, &head);
    assert_eq!(bytes[16], 2);
    assert_eq!(bytes.len(), 16 + 1 + 4 + p.len() + 8 + 32);
}

#[test]
fn a_non_owner_write_is_refused_by_validate_and_by_update() {
    let host = pair(7);
    let other = pair(9);
    let p = params(&host);
    let good = state(
        Some(head_of(&host, &p, 2)),
        (0..2).map(|i| segment_of(&host, &p, i, 40)).collect(),
    );
    assert!(matches!(validate(&p, &good), ValidateResult::Valid));
    // A state signed by another key, a segment alone, a head alone.
    let forged_seg = segment_of(&other, &p, 2, 40);
    let forged_head = head_of(&other, &p, 3);
    let cases = [
        state(None, vec![forged_seg.clone()]),
        state(Some(forged_head.clone()), vec![]),
    ];
    for bad in &cases {
        assert!(matches!(validate(&p, bad), ValidateResult::Invalid));
        assert!(
            update(&p, &good, vec![bad.clone()]).is_err(),
            "update refuses a non-owner write"
        );
    }
    // The host's own signature under another session's parameters is a non-owner write too.
    let elsewhere = format!(
        r#"{{"host":"{}","session":"another"}}"#,
        hex(host.pk.as_ref())
    )
    .into_bytes();
    let moved = state(None, vec![segment_of(&host, &elsewhere, 2, 40)]);
    assert!(update(&p, &good, vec![moved]).is_err());
    // A flipped byte of a signed record.
    let mut tampered = segment_of(&host, &p, 2, 40);
    tampered.c[0] ^= 1;
    assert!(update(&p, &good, vec![state(None, vec![tampered])]).is_err());
    // A segment signed as a head (the tag keeps them apart).
    let mut swapped = segment_of(&host, &p, 2, 40);
    swapped.g = *host.sk.sign(head_bytes(&p, &head_of(&host, &p, 2)), None);
    assert!(update(&p, &good, vec![state(None, vec![swapped])]).is_err());
    // The state is untouched by the refusals.
    assert!(matches!(validate(&p, &good), ValidateResult::Valid));
}

#[test]
fn an_index_is_write_once() {
    let host = pair(7);
    let p = params(&host);
    let s0 = segment_of(&host, &p, 0, 40);
    let base = state(None, vec![s0.clone()]);
    let mut other = s0.clone();
    other.c = content(0, 41);
    other.g = *host.sk.sign(segment_bytes(&p, &other), None);
    // Validly signed by the host, but not what the index holds: refused, not merged.
    let err = update(&p, &base, vec![state(None, vec![other.clone()])]).unwrap_err();
    assert!(format!("{err}").contains("already holds"), "{err}");
    // The same bytes again are a no-op, and a delta of both is refused whichever comes first.
    assert_eq!(
        update(&p, &base, vec![state(None, vec![s0.clone()])]).unwrap(),
        base
    );
    assert!(update(
        &p,
        &state(None, vec![]),
        vec![
            state(None, vec![s0.clone()]),
            state(None, vec![other.clone()])
        ]
    )
    .is_err());
    assert!(update(
        &p,
        &state(None, vec![]),
        vec![state(None, vec![other]), state(None, vec![s0])]
    )
    .is_err());
}

#[test]
fn the_head_only_grows_and_the_merge_is_a_union() {
    let host = pair(7);
    let p = params(&host);
    let seg = |i| segment_of(&host, &p, i, 40);
    let a = state(Some(head_of(&host, &p, 2)), vec![seg(0), seg(1)]);
    let b = state(Some(head_of(&host, &p, 4)), vec![seg(2), seg(3)]);
    let ab = update(&p, &a, vec![b.clone()]).unwrap();
    let ba = update(&p, &b, vec![a.clone()]).unwrap();
    assert_eq!(ab, ba);
    let merged = parsed(&ab);
    assert_eq!(merged.h.unwrap().n, 4);
    assert_eq!(
        merged.s.iter().map(|r| r.i).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(
        update(&p, &ab, vec![a]).unwrap(),
        ab,
        "an older head never takes the head back"
    );
    assert!(matches!(validate(&p, &ab), ValidateResult::Valid));
}

#[test]
fn an_over_bound_merge_evicts_the_oldest_indices() {
    let host = pair(7);
    let p = params(&host);
    let seg = |i: u32| segment_of(&host, &p, i, 1);
    let first: Vec<_> = (0..MAX_SEGMENTS as u32).map(seg).collect();
    let base = state(Some(head_of(&host, &p, MAX_SEGMENTS as u64)), first);
    assert!(matches!(validate(&p, &base), ValidateResult::Valid));
    let more: Vec<_> = (MAX_SEGMENTS as u32..MAX_SEGMENTS as u32 + 5)
        .map(seg)
        .collect();
    let next = update(
        &p,
        &base,
        vec![state(
            Some(head_of(&host, &p, MAX_SEGMENTS as u64 + 5)),
            more.clone(),
        )],
    )
    .unwrap();
    let kept = parsed(&next);
    assert_eq!(kept.s.len(), MAX_SEGMENTS);
    assert_eq!(kept.s.first().unwrap().i, 5, "the five oldest went");
    assert_eq!(kept.s.last().unwrap().i, MAX_SEGMENTS as u32 + 4);
    assert_eq!(
        kept.h.unwrap().n,
        MAX_SEGMENTS as u64 + 5,
        "the head is not evicted"
    );
    assert!(matches!(validate(&p, &next), ValidateResult::Valid));
    // A stale replica resurrecting the evicted prefix loses it again: order independence.
    let stale = update(&p, &next, vec![base.clone()]).unwrap();
    assert_eq!(stale, next);
    let other_way = update(&p, &base, vec![state(None, more), next.clone()]).unwrap();
    assert_eq!(other_way, next);
    // A state over the count bound is not a valid state.
    let over: Vec<_> = (0..MAX_SEGMENTS as u32 + 1).map(seg).collect();
    assert!(matches!(
        validate(&p, &state(None, over)),
        ValidateResult::Invalid
    ));
}

#[test]
fn the_byte_bounds_hold() {
    let host = pair(7);
    let p = params(&host);
    let big = |i: u32, len: usize| segment_of(&host, &p, i, len);
    // One record over MAX_SEGMENT_BYTES is refused.
    assert!(update(
        &p,
        &state(None, vec![]),
        vec![state(None, vec![big(0, MAX_SEGMENT_BYTES + 1)])]
    )
    .is_err());
    assert!(update(&p, &state(None, vec![]), vec![state(None, vec![big(0, 0)])]).is_err());
    let ok = update(
        &p,
        &state(None, vec![]),
        vec![state(None, vec![big(0, MAX_SEGMENT_BYTES)])],
    )
    .unwrap();
    assert!(matches!(validate(&p, &ok), ValidateResult::Valid));
    // Fill MAX_TOTAL_BYTES with maximal records; one more evicts the oldest.
    let fit = MAX_TOTAL_BYTES / MAX_SEGMENT_BYTES;
    let all: Vec<_> = (0..fit as u32).map(|i| big(i, MAX_SEGMENT_BYTES)).collect();
    let s = update(&p, &state(None, vec![]), vec![state(None, all)]).unwrap();
    assert_eq!(parsed(&s).s.len(), fit);
    let s = update(
        &p,
        &s,
        vec![state(None, vec![big(fit as u32, MAX_SEGMENT_BYTES)])],
    )
    .unwrap();
    let kept = parsed(&s);
    assert_eq!(kept.s.len(), fit, "one in, the oldest out");
    assert_eq!(kept.s.first().unwrap().i, 1);
    assert!(kept.s.iter().map(|r| r.c.len()).sum::<usize>() <= MAX_TOTAL_BYTES);
}

#[test]
fn summary_and_delta_carry_what_the_other_side_lacks() {
    let host = pair(7);
    let p = params(&host);
    let seg = |i| segment_of(&host, &p, i, 40);
    let full = state(Some(head_of(&host, &p, 4)), (0..4).map(seg).collect());
    let partial = state(Some(head_of(&host, &p, 2)), vec![seg(0), seg(1), seg(3)]);
    let summary = Segment::summarize_state(run_params(&p), State::from(partial.clone())).unwrap();
    assert_eq!(
        std::str::from_utf8(summary.as_ref()).unwrap(),
        r#"{"n":2,"r":[[0,2],[3,4]]}"#
    );
    let delta =
        Segment::get_state_delta(run_params(&p), State::from(full.clone()), summary).unwrap();
    let d = parsed(delta.as_ref());
    assert_eq!(d.s.iter().map(|r| r.i).collect::<Vec<_>>(), [2]);
    assert_eq!(d.h.unwrap().n, 4);
    assert_eq!(
        update(&p, &partial, vec![delta.as_ref().to_vec()]).unwrap(),
        full
    );
    // Nothing to send when the other side has it all.
    let all = Segment::summarize_state(run_params(&p), State::from(full.clone())).unwrap();
    let none = Segment::get_state_delta(run_params(&p), State::from(full), all).unwrap();
    assert!(none.as_ref().is_empty());
}

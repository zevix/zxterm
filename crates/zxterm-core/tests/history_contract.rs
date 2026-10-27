//! K16: `segment-v1`, the offline-history contract, end to end on throwaway
//! `LocalNode`s (never the owner's node) and against the contract's own
//! code.
//!
//! - a host process shares and publishes, is killed, and a viewer process
//!   reads the full history from the contract (`history.readContract`);
//! - the contract itself refuses a non-host write (asserted on the reason
//!   the contract gives, and on the state staying as it was), a
//!   conflicting overwrite of an index and a forged `Put`;
//! - an over-bound merge evicts the oldest segments and the head and
//!   the chain still verify for the retained ones;
//! - a restarted publisher resumes after what the contract holds;
//! - the contract crate's own tests (`contracts/src/segment/tests`) pass,
//!   which call `validate_state`/`update_state` directly;
//! - the core's bounds and signed-bytes prefix are the contract's.
//!
//! Needs `freenet` on `PATH` for the node tests; each skips with a printed
//! reason otherwise.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use zxterm_core::freenet::backend::{Backend, BackendOptions};
use zxterm_core::freenet::contracts::SEGMENT_V1;
use zxterm_core::freenet::node;
use zxterm_core::history::contract::{
    self, ContractState, MAX_SEGMENT_BYTES, MAX_SEGMENTS, MAX_TOTAL_BYTES, encode_parts,
    params_bytes, sign_head, sign_segment,
};
use zxterm_core::history::packet::PlainPacket;
use zxterm_core::history::publish::{self, SegmentPublisher};
use zxterm_core::history::serve::SharedHistory;
use zxterm_core::history::{HistoryConfig, SegmentFile};
use zxterm_testkit::ScratchHome;
use zxterm_testkit::local_node::{LocalNode, freenet_available};

fn node_or_skip(test: &str) -> Option<LocalNode> {
    if !freenet_available() {
        println!("SKIP {test}: freenet binary not on PATH");
        return None;
    }
    Some(LocalNode::start().expect("start a LocalNode"))
}

fn host_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn sid(n: u8) -> String {
    hex::encode([n; 32])
}

async fn started_backend(url: &str, label: u8) -> Backend {
    let backend = Backend::new(BackendOptions {
        node_url: url.to_string(),
        ice_servers: Some(vec![]),
        clock: None,
        loopback_only: true,
        legacy_v1_routes: false,
    });
    let key = SigningKey::from_bytes(&[label; 32]);
    let mut tries = 0;
    while let Err(e) = backend.start(key.clone()).await {
        tries += 1;
        assert!(tries < 3, "start: {e:?}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    backend
}

fn config(home: &ScratchHome, name: &str, sid: &str) -> HistoryConfig {
    HistoryConfig {
        dir: home.tmp().join(name),
        session_id: sid.to_string(),
        signer: host_key(),
        snapshot_key: [5u8; 32],
        cols: 80,
        rows: 24,
        epoch_keys: BTreeMap::from([(1u32, [9u8; 32])]),
        first_seq: 0,
    }
}

fn keys() -> BTreeMap<u32, [u8; 32]> {
    BTreeMap::from([(1u32, [9u8; 32])])
}

fn payload(i: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    blake3::Hasher::new()
        .update(&i.to_le_bytes())
        .finalize_xof()
        .fill(&mut b);
    b
}

// ---------------------------------------------------------------------
// the contract's bounds and prefix are the core's
// ---------------------------------------------------------------------

fn contract_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/src/segment/src/lib.rs");
    std::fs::read_to_string(path).expect("read the contract source")
}

fn const_of(source: &str, name: &str) -> String {
    let line = source
        .lines()
        .find(|l| l.starts_with(&format!("pub const {name}:")))
        .unwrap_or_else(|| panic!("{name} is not in the contract"));
    line.split('=')
        .nth(1)
        .expect("a value")
        .trim()
        .trim_end_matches(';')
        .to_string()
}

#[test]
fn the_core_holds_the_contracts_bounds_and_domain() {
    let src = contract_source();
    assert_eq!(const_of(&src, "MAX_SEGMENTS"), MAX_SEGMENTS.to_string());
    assert_eq!(MAX_SEGMENTS, 512);
    assert_eq!(
        const_of(&src, "MAX_SEGMENT_BYTES"),
        "1_048_576 + 4096",
        "the contract's record bound"
    );
    assert_eq!(MAX_SEGMENT_BYTES, 1_048_576 + 4096);
    assert_eq!(
        const_of(&src, "MAX_TOTAL_BYTES"),
        "16 * 1024 * 1024",
        "the contract's size bound"
    );
    assert_eq!(MAX_TOTAL_BYTES, 16 * 1024 * 1024);
    assert_eq!(
        const_of(&src, "DOMAIN"),
        format!("b\"{}\"", zxterm_core::wire::SEGMENT_CONTRACT_DOMAIN)
    );
    assert_eq!(
        zxterm_core::wire::SEGMENT_CONTRACT_DOMAIN,
        "zxterm/segment/1"
    );
}

/// `MAX_SEGMENT_BYTES` (`X-26`) holds the largest record the flush rule
/// can seal (K15's numbers): a multi-packet segment of up to
/// `SEGMENT_MAX_BYTES` of packets and a single packet of up to
/// `MAX_PAYLOAD_BYTES`, both incompressible.
#[test]
fn the_largest_sealed_record_fits_the_contracts_record_bound() {
    use zxterm_core::history::packet::MAX_PAYLOAD_BYTES;
    use zxterm_core::history::segment::{self, SegmentHeader};
    use zxterm_core::history::{SEGMENT_MAX_BYTES, SEGMENT_TARGET_BYTES};
    let signer = host_key().verifying_key().to_bytes();
    let seal = |packets: Vec<PlainPacket>| {
        let header = SegmentHeader {
            epoch: 1,
            first_seq: 0,
            count: packets.len() as u32,
        };
        segment::seal(&[9u8; 32], &sid(1), &signer, &header, &packets)
            .unwrap()
            .len()
    };
    let single = seal(vec![PlainPacket::data(
        0,
        payload(0, MAX_PAYLOAD_BYTES),
        true,
    )]);
    let many: Vec<PlainPacket> = (0..8)
        .map(|i| PlainPacket::data(i, payload(i, SEGMENT_MAX_BYTES / 8 - 64), false))
        .collect();
    assert!(many.iter().map(PlainPacket::encoded_len).sum::<usize>() <= SEGMENT_MAX_BYTES);
    let multi = seal(many);
    println!(
        "largest sealed records: single 1 MiB packet {single} B, 128 KiB multi-packet {multi} B, \
         bound {MAX_SEGMENT_BYTES} B (target {SEGMENT_TARGET_BYTES})"
    );
    assert!(single > MAX_PAYLOAD_BYTES && single <= MAX_SEGMENT_BYTES);
    assert!(multi <= MAX_SEGMENT_BYTES);
}

/// The contract's own tests call `validate_state`, `update_state`,
/// `summarize_state` and `get_state_delta` on the code the WASM is built
/// from (a non-owner write, a conflicting overwrite, the bounds, the
/// merge laws) and check its `states/` fixtures are what its generator
/// writes.
#[test]
fn the_contract_crate_passes_its_own_tests() {
    let manifest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/src/segment/Cargo.toml");
    let target =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/contract-segment-tests");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["test", "--release", "--manifest-path"])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUSTFLAGS")
        .output()
        .expect("run cargo test in the contract crate");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the contract's tests failed:\n{text}");
    assert!(text.contains("test result: ok. 8 passed"), "{text}");
}

// ---------------------------------------------------------------------
// the contract refuses what is not the host's
// ---------------------------------------------------------------------

fn record(key: &SigningKey, params: &[u8], i: u32, len: usize) -> contract::SegmentRecord {
    sign_segment(key, params, i, [i as u8; 32], payload(u64::from(i), len))
}

fn refusal(r: Result<(), zxterm_core::Error>) -> String {
    let e = r.expect_err("the contract must refuse this write");
    e.details.unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_contract_refuses_a_non_host_write_an_overwrite_and_a_forged_put() {
    let Some(node) = node_or_skip("the_contract_refuses_a_non_host_write") else {
        return;
    };
    let host = host_key();
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let params = params_bytes(&host.verifying_key().to_bytes(), &sid(3));
    let addr = node::contract_key(SEGMENT_V1, &params);
    let mut c = node::Client::connect(&node.url).await.unwrap();

    // A valid state is accepted: the host's records, its head.
    let good: Vec<_> = (0..2).map(|i| record(&host, &params, i, 100)).collect();
    let head = sign_head(&host, &params, 2, [2u8; 32]);
    let state = encode_parts(Some(&head), &good);
    c.put(SEGMENT_V1, &params, state.clone()).await.unwrap();
    let held = c.get(addr.key.id(), 5_000).await.unwrap();
    assert_eq!(held, state, "the node holds the core's canonical encoding");

    // Non-owner writes: a segment, a head; each refused with the
    // contract's own reason, the state as it was.
    let forged_seg = encode_parts(None, &[record(&other, &params, 2, 100)]);
    let why = refusal(c.update(&addr.key, forged_seg, 5_000).await);
    println!("non-host segment: {why}");
    assert!(why.contains("bad segment signature"), "{why}");
    let forged_head = encode_parts(Some(&sign_head(&other, &params, 3, [3u8; 32])), &[]);
    let why = refusal(c.update(&addr.key, forged_head, 5_000).await);
    println!("non-host head: {why}");
    assert!(why.contains("bad head signature"), "{why}");
    assert_eq!(c.get(addr.key.id(), 5_000).await.unwrap(), state);

    // The host's own key cannot rewrite an index it already wrote.
    let mut again = record(&host, &params, 1, 100);
    again.record = payload(99, 100);
    let again = sign_segment(&host, &params, 1, again.prev_root, again.record);
    let why = refusal(
        c.update(&addr.key, encode_parts(None, &[again]), 5_000)
            .await,
    );
    println!("overwrite: {why}");
    assert!(why.contains("already holds other bytes"), "{why}");
    assert_eq!(c.get(addr.key.id(), 5_000).await.unwrap(), state);

    // The host's signature for another session's parameters is a
    // non-owner write here.
    let elsewhere = params_bytes(&host.verifying_key().to_bytes(), &sid(4));
    let moved = encode_parts(None, &[record(&host, &elsewhere, 2, 100)]);
    let why = refusal(c.update(&addr.key, moved, 5_000).await);
    assert!(why.contains("bad segment signature"), "{why}");

    // A forged Put (the parameters name the host, the records another
    // key) is not a valid state: no instance appears.
    let forged_params = params_bytes(&host.verifying_key().to_bytes(), &sid(5));
    let forged_state = encode_parts(None, &[record(&other, &forged_params, 0, 100)]);
    let r = c.put(SEGMENT_V1, &forged_params, forged_state).await;
    let why = refusal(r);
    println!("forged put: {why}");
    assert!(why.contains("not valid"), "{why}");
    let forged_addr = node::contract_key(SEGMENT_V1, &forged_params);
    assert!(c.get(forged_addr.key.id(), 2_000).await.is_err());

    // The node is fine and the host still writes.
    let next = encode_parts(
        Some(&sign_head(&host, &params, 3, [3u8; 32])),
        &[record(&host, &params, 2, 100)],
    );
    c.update(&addr.key, next, 5_000).await.unwrap();
    let st = ContractState::decode(&c.get(addr.key.id(), 5_000).await.unwrap()).unwrap();
    assert_eq!(st.segments.len(), 3);
    assert_eq!(st.head.unwrap().length, 3);
}

// ---------------------------------------------------------------------
// publish, kill the host, read offline
// ---------------------------------------------------------------------

fn zxterm_core_bin() -> &'static str {
    env!("CARGO_BIN_EXE_zxterm-core")
}

/// A sidecar this test spawned; killed by its own `Child` handle only.
struct Sidecar {
    child: Child,
    profile: PathBuf,
    _home: ScratchHome,
}

impl Sidecar {
    fn spawn() -> Sidecar {
        let home = ScratchHome::new().expect("scratch home");
        let profile = home.path().join("p");
        std::fs::create_dir_all(&profile).unwrap();
        let child = Command::new(zxterm_core_bin())
            .args(["sidecar", "--profile"])
            .arg(&profile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zxterm-core sidecar");
        let socket = zxterm_core::seam::socket_path(&profile);
        let start = Instant::now();
        while !socket.exists() {
            assert!(start.elapsed() < Duration::from_secs(10), "no socket");
            std::thread::sleep(Duration::from_millis(20));
        }
        Sidecar {
            child,
            profile,
            _home: home,
        }
    }

    fn ctl(&self, method: &str, args: Value) -> Value {
        let out = Command::new(zxterm_core_bin())
            .args(["ctl", "--profile"])
            .arg(&self.profile)
            .args([method, &args.to_string()])
            .output()
            .expect("run ctl");
        assert!(
            out.status.success(),
            "{method}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
    }

    fn ctl_err(&self, method: &str, args: Value) -> String {
        let out = Command::new(zxterm_core_bin())
            .args(["ctl", "--profile"])
            .arg(&self.profile)
            .args([method, &args.to_string()])
            .output()
            .expect("run ctl");
        assert!(!out.status.success(), "{method} should fail");
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }

    /// Kills the process (SIGKILL by its own handle) and waits for it.
    fn kill(&mut self) {
        self.child.kill().expect("kill the sidecar");
        let status = self.child.wait().expect("wait for the sidecar");
        assert!(!status.success(), "the host was killed, not stopped");
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_host_that_is_killed_leaves_its_full_history_readable_from_the_contract() {
    let Some(node) = node_or_skip("a_host_that_is_killed_leaves_its_full_history") else {
        return;
    };
    let mut host = Sidecar::spawn();
    let session = sid(6);
    let signing = hex::encode([7u8; 32]);
    let hist_key = hex::encode([9u8; 32]);
    host.ctl(
        "freenet.start",
        json!({"secretKey": "11".repeat(32), "nodeUrl": node.url, "iceServers": []}),
    );
    let dir = host._home.tmp().join("h");
    host.ctl(
        "history.open",
        json!({"sessionId": session, "dir": dir, "signingKey": signing,
            "snapshotKey": hex::encode([5u8; 32]), "cols": 80, "rows": 24,
            "epochKeys": {"1": hist_key}, "create": true, "epoch": 1, "publish": true}),
    );
    // Long lines, so segments close at 64 KiB and by age, in three epochs of
    // output; the argument size stays under the OS limit per call.
    let mut sent: Vec<(u64, String)> = Vec::new();
    for batch in 0..5u64 {
        let mut packets = Vec::new();
        for k in 0..10u64 {
            let i = batch * 10 + k;
            let text = format!("row {i:03} {}\r\n", "x".repeat(7000));
            packets.push(json!({"tsMs": 1000 + i * 4000, "kind": 0, "payload": B64.encode(&text)}));
            sent.push((i, text));
        }
        host.ctl(
            "history.append",
            json!({"sessionId": session, "packets": packets}),
        );
    }
    let flushed = host.ctl("history.flush", json!({"sessionId": session}));
    let segments = flushed["segments"].as_u64().unwrap();
    assert!(segments >= 5, "{segments} segments");
    let status = host.ctl(
        "history.publishStatus",
        json!({"sessionId": session, "waitLength": segments, "timeoutMs": 20000}),
    );
    println!("published: {status}");
    assert_eq!(status["headLength"], json!(segments));
    assert_eq!(status["errors"], json!(0));
    let head = host.ctl("history.head", json!({"sessionId": session}));
    let verifying = head["verifyingKey"].as_str().unwrap().to_string();

    // The host process is killed, not disconnected.
    host.kill();
    drop(host);

    // A viewer process that never spoke to the host reads everything.
    let viewer = Sidecar::spawn();
    viewer.ctl(
        "freenet.start",
        json!({"secretKey": "22".repeat(32), "nodeUrl": node.url, "iceServers": []}),
    );
    let read = viewer.ctl(
        "history.readContract",
        json!({"sessionId": session, "verifyingKey": verifying,
            "epochKeys": {"1": hist_key}, "from": 0, "count": 200}),
    );
    assert_eq!(read["headLength"], json!(segments));
    assert_eq!(read["firstIndex"], json!(0));
    assert_eq!(read["held"], json!(segments));
    assert_eq!(read["beyondHead"], json!(0));
    assert_eq!(
        read["chainRoot"], head["chainRoot"],
        "the signed head's root"
    );
    let mut got: Vec<(u64, String)> = Vec::new();
    for (n, seg) in read["segments"].as_array().unwrap().iter().enumerate() {
        assert_eq!(seg["index"], json!(n));
        for p in seg["packets"].as_array().unwrap() {
            let text =
                String::from_utf8(B64.decode(p["payload"].as_str().unwrap()).unwrap()).unwrap();
            got.push((p["seq"].as_u64().unwrap(), text));
        }
    }
    assert_eq!(got, sent, "every packet, in order, decrypted");

    // Pieces, and a replayed shorter head, and a wrong key.
    let piece = viewer.ctl(
        "history.readContract",
        json!({"sessionId": session, "verifyingKey": verifying,
            "epochKeys": {"1": hist_key}, "from": 2, "count": 2}),
    );
    assert_eq!(piece["segments"].as_array().unwrap().len(), 2);
    assert_eq!(piece["segments"][0]["index"], json!(2));
    let stale = viewer.ctl_err(
        "history.readContract",
        json!({"sessionId": session, "verifyingKey": verifying,
            "epochKeys": {"1": hist_key}, "minHeadLength": segments + 1}),
    );
    assert!(stale.contains("shorter"), "{stale}");
    let wrong_key = viewer.ctl_err(
        "history.readContract",
        json!({"sessionId": session, "verifyingKey": verifying,
            "epochKeys": {"1": hex::encode([1u8; 32])}, "from": 0, "count": 1}),
    );
    assert!(wrong_key.contains("authentication"), "{wrong_key}");
    let other_host = hex::encode(
        SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    // Another host key names another instance: nothing is there.
    assert!(
        !viewer
            .ctl_err(
                "history.readContract",
                json!({"sessionId": session, "verifyingKey": other_host,
                    "epochKeys": {"1": hist_key}}),
            )
            .is_empty()
    );
}

// ---------------------------------------------------------------------
// an over-bound merge, a resumed publisher
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_over_bound_merge_evicts_the_oldest_and_the_rest_still_verifies() {
    let Some(node) = node_or_skip("an_over_bound_merge_evicts_the_oldest") else {
        return;
    };
    let home = ScratchHome::new().unwrap();
    let backend = started_backend(&node.url, 1).await;
    let session = sid(7);
    let file = SegmentFile::create(config(&home, "big", &session)).unwrap();
    let history = SharedHistory::new(file);
    history.0.lock().unwrap().set_epoch(1).unwrap();
    let publisher = SegmentPublisher::start(backend.clone(), history.clone());

    // 1 MiB of incompressible output per segment: a record is a little
    // over 1 MiB, so MAX_TOTAL_BYTES holds 15 of them and the 17th merge
    // pushes the two oldest out.
    let total = 17u64;
    let mut sent = Vec::new();
    for i in 0..total {
        let data = payload(i, 1024 * 1024);
        history
            .0
            .lock()
            .unwrap()
            .append(PlainPacket::data(1000 + i, data.clone(), false))
            .unwrap();
        sent.push((i, data));
    }
    history.0.lock().unwrap().flush().unwrap();
    let started = Instant::now();
    publisher
        .wait_published(total, Duration::from_secs(120))
        .await
        .expect("published");
    let status = publisher.status();
    println!(
        "17 x 1 MiB segments published in {:?}: {} updates, {} errors",
        started.elapsed(),
        status.updates,
        status.errors
    );
    let host = history.0.lock().unwrap().verifying_key();
    let record_len = history.0.lock().unwrap().entries()[0].len as usize;
    let fit = MAX_TOTAL_BYTES / record_len;
    assert_eq!(fit, 15, "records of {record_len} B");

    let view = publish::read_offline(&backend, &host, &session, 0)
        .await
        .expect("the state verifies");
    assert_eq!(view.head_length, total);
    assert_eq!(view.len() as usize, fit, "the bound retains what fits");
    assert_eq!(
        view.first_index,
        total - fit as u64,
        "the oldest went first"
    );
    assert!(view.first_index >= 1);
    let segs = view.open_range(0, 100, &keys()).unwrap();
    assert_eq!(segs.len(), fit);
    for seg in &segs {
        let (seq, packet) = &seg.packets[0];
        assert_eq!(*seq, seg.index);
        assert_eq!(
            packet.payload.as_ref().unwrap(),
            &sent[seg.index as usize].1
        );
    }
    // What the contract holds is its canonical encoding of what the core
    // wrote, and the state is under its size bound.
    let state = publish::read_state(&backend, &host, &session)
        .await
        .unwrap();
    let decoded = ContractState::decode(&state).unwrap();
    assert_eq!(decoded.encode(), state);
    assert!(decoded.record_bytes() <= MAX_TOTAL_BYTES);
    publisher.stop();
    backend.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_publisher_sends_only_what_the_contract_lacks() {
    let Some(node) = node_or_skip("a_restarted_publisher_sends_only_what_the_contract_lacks")
    else {
        return;
    };
    let home = ScratchHome::new().unwrap();
    let backend = started_backend(&node.url, 2).await;
    let session = sid(8);
    let file = SegmentFile::create(config(&home, "resume", &session)).unwrap();
    let history = SharedHistory::new(file);
    history.0.lock().unwrap().set_epoch(1).unwrap();
    let close = |from: u64, to: u64| {
        let mut f = history.0.lock().unwrap();
        for i in from..to {
            f.append(PlainPacket::data(
                1000 + i,
                format!("segment {i}\r\n").into_bytes(),
                false,
            ))
            .unwrap();
            f.flush().unwrap();
        }
    };

    close(0, 5);
    let first = SegmentPublisher::start(backend.clone(), history.clone());
    first
        .wait_published(5, Duration::from_secs(60))
        .await
        .expect("first publisher");
    first.stop();
    let a = first.status();
    assert_eq!((a.next_index, a.head_length), (5, 5));

    // The host restarts with three more segments closed meanwhile.
    close(5, 8);
    let second = SegmentPublisher::start(backend.clone(), history.clone());
    second
        .wait_published(8, Duration::from_secs(60))
        .await
        .expect("second publisher");
    let b = second.status();
    assert_eq!(b.next_index, 8);
    assert_eq!(
        b.updates, 1,
        "one update carried the three missing segments"
    );
    assert_eq!(b.errors, 0);

    // A segment that closes while it runs is one more update.
    close(8, 9);
    second
        .wait_published(9, Duration::from_secs(60))
        .await
        .expect("live close");
    assert_eq!(second.status().updates, 2);
    second.stop();

    let host = history.0.lock().unwrap().verifying_key();
    let view = publish::read_offline(&backend, &host, &session, 9)
        .await
        .unwrap();
    assert_eq!((view.first_index, view.len()), (0, 9));
    let segs = view.open_range(0, 100, &keys()).unwrap();
    let texts: Vec<String> = segs
        .iter()
        .map(|s| String::from_utf8(s.packets[0].1.payload.clone().unwrap()).unwrap())
        .collect();
    let expected: Vec<String> = (0..9).map(|i| format!("segment {i}\r\n")).collect();
    assert_eq!(texts, expected);
    backend.stop().await;
}

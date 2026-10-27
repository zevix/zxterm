//! K15: the `history.*` seam methods (`crate::seam::history_methods`),
//! driven through `Dispatcher::dispatch_full` as a seam client would:
//! open, append, seal, read, seek, import, metadata and the viewer's
//! verification of a served segment.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use zxterm_core::history::head::SignedHead;
use zxterm_core::history::serve::SegmentData;
use zxterm_core::history::{HistoryConfig, SegmentFile};
use zxterm_core::seam::{ConnCtx, Dispatcher};
use zxterm_testkit::ScratchHome;

struct Client {
    d: Dispatcher,
    ctx: ConnCtx,
    _gone: watch::Sender<bool>,
    _out: mpsc::Receiver<zxterm_core::seam::Frame>,
    _ev: mpsc::Receiver<zxterm_core::seam::Frame>,
}

impl Client {
    fn new(home: &ScratchHome) -> Client {
        let profile = home.path().join("p");
        std::fs::create_dir_all(&profile).unwrap();
        let (o, out) = mpsc::channel(8);
        let (e, ev) = mpsc::channel(8);
        let (g, gone) = watch::channel(false);
        Client {
            d: Dispatcher::new(profile),
            ctx: ConnCtx::new(o, e, gone),
            _gone: g,
            _out: out,
            _ev: ev,
        }
    }

    async fn call(&self, method: &str, args: Value) -> Result<Value, zxterm_core::Error> {
        let (res, _) = self
            .d
            .dispatch_full(method, &args.to_string(), &self.ctx)
            .await;
        res.map(|s| serde_json::from_str(&s).unwrap())
    }

    async fn ok(&self, method: &str, args: Value) -> Value {
        self.call(method, args)
            .await
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }
}

fn packet(i: u64, payload: &str) -> Value {
    json!({"tsMs": 1000 + i, "kind": 0, "payload": B64.encode(payload)})
}

#[tokio::test]
async fn open_append_read_seek_and_metadata_over_the_seam() {
    let home = ScratchHome::new().unwrap();
    let c = Client::new(&home);
    let dir = home.tmp().join("h1");
    let sid = "ab".repeat(32);
    let signing = hex::encode([7u8; 32]);
    let hist_key = hex::encode([9u8; 32]);
    let base = json!({"sessionId": sid, "dir": dir, "signingKey": signing,
        "snapshotKey": hex::encode([5u8; 32]), "cols": 40, "rows": 10,
        "epochKeys": {"1": hist_key}});
    // Nothing is open yet.
    assert!(
        c.call("history.head", json!({"sessionId": sid}))
            .await
            .is_err()
    );
    let mut open = base.clone();
    open["create"] = json!(true);
    open["epoch"] = json!(1);
    let r = c.ok("history.open", open.clone()).await;
    assert_eq!(r, json!({"segments": 0, "nextSeq": 0}));
    assert!(c.call("history.open", open).await.is_err(), "already open");
    let mut packets = Vec::new();
    for i in 0..40u64 {
        // Three short lines first, so the screen at seq 2 is legible; then
        // long ones that fill several segments.
        let text = if i < 3 {
            format!("row {i:03}\r\n")
        } else {
            format!("row {i:03} {}\r\n", "x".repeat(6000))
        };
        packets.push(packet(i, &text));
    }
    packets.push(json!({"tsMs": 5000, "kind": 1, "cols": 20, "rows": 5}));
    let r = c
        .ok(
            "history.append",
            json!({"sessionId": sid, "packets": packets}),
        )
        .await;
    assert_eq!(r, json!({"firstSeq": 0, "nextSeq": 41}));
    let r = c.ok("history.flush", json!({"sessionId": sid})).await;
    let segments = r["segments"].as_u64().unwrap();
    assert!(segments >= 3, "{segments}");
    let head = c.ok("history.head", json!({"sessionId": sid})).await;
    assert_eq!(head["length"], json!(segments));
    assert_eq!(head["closedEndSeq"], json!(41));

    // The head is signed by the key the caller gave.
    let vk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    assert_eq!(head["verifyingKey"], json!(hex::encode(vk.to_bytes())));
    let mut enc = Vec::new();
    enc.extend_from_slice(&head["length"].as_u64().unwrap().to_le_bytes());
    enc.extend(hex::decode(head["chainRoot"].as_str().unwrap()).unwrap());
    enc.extend(hex::decode(head["signature"].as_str().unwrap()).unwrap());
    SignedHead::decode(&enc).unwrap().verify(&sid, &vk).unwrap();

    // read, screenAt.
    let r = c
        .ok(
            "history.read",
            json!({"sessionId": sid, "start": 3, "end": 5}),
        )
        .await;
    let ps = r["packets"].as_array().unwrap();
    assert_eq!(ps.len(), 2);
    assert_eq!(ps[0]["seq"], json!(3));
    let text = String::from_utf8(B64.decode(ps[0]["payload"].as_str().unwrap()).unwrap()).unwrap();
    assert!(text.contains("row 003 "));
    let s = c
        .ok("history.screenAt", json!({"sessionId": sid, "seq": 2}))
        .await;
    assert_eq!(
        (s["cols"].as_u64(), s["rows"].as_u64()),
        (Some(40), Some(10))
    );
    assert!(s["text"].as_str().unwrap().contains("row 001"));
    let s = c
        .ok("history.screenAt", json!({"sessionId": sid, "seq": 41}))
        .await;
    assert_eq!(
        (s["cols"].as_u64(), s["rows"].as_u64()),
        (Some(20), Some(5))
    );

    // metadata: a sensitive session's envelope never reaches the record.
    let meta = |sensitive: bool| {
        json!({"info": {"name": "n", "createdAt": 1, "sensitive": sensitive, "cols": 40, "rows": 10},
               "epochs": [{"epoch": 1, "firstSeq": 0}],
               "envelopes": [{"epoch": 1, "deviceKey": hex::encode([3u8; 32]), "sealed": B64.encode("SEALED-ENVELOPE-BYTES")}],
               "members": [], "links": []})
    };
    c.ok(
        "history.setMetadata",
        json!({"sessionId": sid, "metadata": meta(true)}),
    )
    .await;
    let r = c.ok("history.metadata", json!({"sessionId": sid})).await;
    assert_eq!(r["metadata"]["envelopes"], json!([]));
    let raw = std::fs::read(dir.join("metadata.zxm")).unwrap();
    assert!(!raw.windows(21).any(|w| w == b"SEALED-ENVELOPE-BYTES"));
    c.ok(
        "history.setMetadata",
        json!({"sessionId": sid, "metadata": meta(false)}),
    )
    .await;
    let r = c.ok("history.metadata", json!({"sessionId": sid})).await;
    assert_eq!(r["metadata"]["envelopes"].as_array().unwrap().len(), 1);

    // The viewer's side: verify the segments a host would serve.
    c.ok("history.close", json!({"sessionId": sid})).await;
    let mut cfg = HistoryConfig {
        dir: dir.clone(),
        session_id: sid.clone(),
        signer: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        snapshot_key: [5u8; 32],
        cols: 40,
        rows: 10,
        epoch_keys: Default::default(),
        first_seq: 0,
    };
    cfg.epoch_keys.insert(1, [9u8; 32]);
    let mut f = SegmentFile::open(cfg).unwrap();
    let plan = f.plan_range(0, 41).unwrap();
    let verify_args = |data: &SegmentData| {
        json!({"sessionId": "cd".repeat(32), "requestId": 1, "verifyingKey": hex::encode(vk.to_bytes()),
               "epochKeys": {"1": hist_key}, "data": B64.encode(data.encode())})
    };
    let mut got = 0;
    {
        // Another session id: the head does not verify.
        let data = SegmentData {
            index: plan.first_index,
            record: f.record(plan.first_index).unwrap(),
            proof: Some(plan.proof.clone()),
        };
        let e = c
            .call("history.verify", verify_args(&data))
            .await
            .unwrap_err();
        assert_eq!(e.code, zxterm_core::Code::EAuth);
    }
    for k in 0..plan.count {
        let data = SegmentData {
            index: plan.first_index + k,
            record: f.record(plan.first_index + k).unwrap(),
            proof: (k == 0).then(|| plan.proof.clone()),
        };
        let mut args = verify_args(&data);
        args["sessionId"] = json!(sid);
        let r = c.ok("history.verify", args).await;
        got += r["packets"].as_array().unwrap().len();
    }
    assert_eq!(got, 41);
    c.ok(
        "history.verifyDone",
        json!({"sessionId": sid, "requestId": 1, "start": 0, "next": plan.next}),
    )
    .await;
    // Done for a request that served nothing must say `start`.
    assert!(
        c.call(
            "history.verifyDone",
            json!({"sessionId": sid, "requestId": 2, "start": 0, "next": 9})
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn import_over_the_seam_registers_a_history_and_refuses_a_second_open() {
    let home = ScratchHome::new().unwrap();
    let c = Client::new(&home);
    let dir = home.tmp().join("h2");
    let sid = "ef".repeat(32);
    let packets: Vec<Value> = (0..30u64)
        .map(|i| packet(i, &format!("imported {i}\r\n")))
        .collect();
    let r = c
        .ok(
            "history.import",
            json!({"sessionId": sid, "dir": dir, "signingKey": hex::encode([1u8; 32]),
                   "snapshotKey": hex::encode([2u8; 32]), "cols": 80, "rows": 24,
                   "epoch": 4, "historyKey": hex::encode([3u8; 32]), "firstSeq": 100,
                   "packets": packets}),
        )
        .await;
    assert_eq!(r["nextSeq"], json!(130));
    assert_eq!(r["segments"], json!(1));
    let r = c
        .ok(
            "history.read",
            json!({"sessionId": sid, "start": 128, "end": 130}),
        )
        .await;
    let ps = r["packets"].as_array().unwrap();
    assert_eq!(ps[0]["seq"], json!(128));
    assert_eq!(
        B64.decode(ps[1]["payload"].as_str().unwrap()).unwrap(),
        b"imported 29\r\n"
    );
    // A second import into the same directory is refused.
    let again = c
        .call(
            "history.import",
            json!({"sessionId": "01".repeat(32), "dir": dir, "signingKey": hex::encode([1u8; 32]),
                   "snapshotKey": hex::encode([2u8; 32]), "cols": 80, "rows": 24,
                   "epoch": 4, "historyKey": hex::encode([3u8; 32]), "packets": []}),
        )
        .await;
    assert!(again.is_err());
    assert!(c.call("history.nope", json!({})).await.is_err());
}

/// K16: the offline-history methods refuse cleanly without a started
/// Freenet backend or a published history (`X-26`); the node-backed
/// round trip is `tests/history_contract.rs`.
#[tokio::test]
async fn offline_history_methods_need_a_backend_and_a_published_history() {
    let home = ScratchHome::new().unwrap();
    let c = Client::new(&home);
    let sid = "ab".repeat(32);
    let base = json!({"sessionId": sid, "dir": home.tmp().join("h2"),
        "signingKey": hex::encode([7u8; 32]), "snapshotKey": hex::encode([5u8; 32]),
        "cols": 40, "rows": 10, "epochKeys": {"1": hex::encode([9u8; 32])},
        "create": true, "epoch": 1});
    // `publish: true` without a started backend refuses, the history is open.
    let mut with_publish = base.clone();
    with_publish["publish"] = json!(true);
    let err = c.call("history.open", with_publish).await.unwrap_err();
    assert_eq!(err.code, zxterm_core::Code::EBackendUnavailable);
    assert!(
        c.call("history.head", json!({"sessionId": sid}))
            .await
            .is_ok()
    );
    let err = c
        .call("history.publish", json!({"sessionId": sid}))
        .await
        .unwrap_err();
    assert_eq!(err.code, zxterm_core::Code::EBackendUnavailable);
    let err = c
        .call("history.publishStatus", json!({"sessionId": sid}))
        .await
        .unwrap_err();
    assert_eq!(err.code, zxterm_core::Code::EAuth);
    c.ok("history.unpublish", json!({"sessionId": sid})).await;
    let err = c
        .call(
            "history.readContract",
            json!({"sessionId": sid, "verifyingKey": hex::encode([1u8; 32]),
                "epochKeys": {"1": hex::encode([9u8; 32])}}),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, zxterm_core::Code::EBackendUnavailable);
    c.ok("history.close", json!({"sessionId": sid})).await;
}

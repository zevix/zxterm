//! K10 core-to-ZBTerm: the Rust `freenet::backend::Backend` and ZBTerm's
//! current JS `engine/backends/freenet/index.js::FreenetBackend` (with a
//! real `electron/rtc-host.js::RtcHost`, `js/freenet_backend_peer.js`) on
//! one throwaway `LocalNode`, in both directions (Rust announces and JS
//! dials; JS announces and Rust dials), with a JSON channel
//! (`channel.js` framing, a message larger than one part) and a raw
//! channel paired with JS's `history.js::HistoryChannel` both ways; and the
//! Hypercore replication smoke test: `js/freenet_hypercore_smoke.js`
//! replicates real Hypercore blocks from a JS host over a raw channel the
//! core provides through the seam, driven from a Node process.
//!
//! Needs `freenet` and `node` on `PATH` and the ZBTerm tree; skips with a
//! printed reason otherwise. Never the owner's node.
//!
//! > 2026-09-29, K11: ZBTerm's live tree no longer holds this JS (its Freenet
//! > backend is a proxy to this core, ZBTerm `D-34`); the helper scripts run
//! > against its JS reference revision (`zxterm_testkit::js::reference_root`),
//! > with that revision's own `node_modules`, prepared by
//! > `scripts/prepare-js-reference.sh` (`X-20`); the test skips, naming the
//! > script, only while it is not prepared
//! > (`zxterm_testkit::js::freenet_reference_skip`).
//!
//! > 2026-09-30, K13: the JS reference backend is a **v1** peer; a default
//! > Rust backend is v2 (`protocol.md` §12). The two interop tests run the
//! > Rust side with `BackendOptions::legacy_v1_routes`, so they still pin the
//! > v1 transport both ways; the new
//! > `a_v2_core_and_the_v1_js_backend_refuse_each_others_routes` pins the
//! > cross-version refusal in both directions (§12.4: the v1 JS verifier
//! > refuses a v2 route at check 3; the v2 core refuses a v1 route at PV-1,
//! > offline). The Hypercore smoke test now has a sidecar on both ends.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use zxterm_core::Code;
use zxterm_core::freenet::backend::{
    Admission, Backend, BackendEvent, BackendOptions, route_from_json, route_from_json_v1,
    route_to_json,
};
use zxterm_core::freenet::route;
use zxterm_testkit::js::LineChild;
use zxterm_testkit::local_node::{LocalNode, freenet_available};
use zxterm_testkit::scratch_home::ScratchHome;

const T: Duration = Duration::from_secs(30);

fn skip_reason() -> Option<String> {
    if !freenet_available() {
        return Some("freenet binary not on PATH".into());
    }
    // K11: the JS side is ZBTerm's former JS Freenet backend, run from its
    // JS reference revision (`zxterm_testkit::js::FREENET_REFERENCE_SCRIPTS`).
    zxterm_testkit::js::freenet_reference_skip()
}

fn key(label: &str) -> SigningKey {
    let seed = blake3::hash(format!("{label}/{:?}", std::time::SystemTime::now()).as_bytes());
    SigningKey::from_bytes(seed.as_bytes())
}

struct JsPeer {
    child: LineChild,
    events: VecDeque<Value>,
}

impl JsPeer {
    fn spawn(home: &ScratchHome) -> JsPeer {
        JsPeer {
            child: LineChild::spawn("freenet_backend_peer.js", &[], home)
                .expect("spawn the JS peer"),
            events: VecDeque::new(),
        }
    }

    fn call(&mut self, cmd: Value) -> Value {
        self.child.send_json(&cmd).expect("send to the JS peer");
        tokio::task::block_in_place(|| {
            loop {
                let v = self.child.recv_json(T).unwrap_or_else(|| {
                    panic!(
                        "JS peer: no reply to {cmd}; stderr: {}",
                        self.child.stderr_text()
                    )
                });
                if v.get("ok").is_some() {
                    assert_eq!(v["ok"], true, "JS peer: {cmd} failed: {v}");
                    return v;
                }
                self.events.push_back(v);
            }
        })
    }

    fn wait(&mut self, what: &str, mut pred: impl FnMut(&Value) -> bool) -> Value {
        tokio::task::block_in_place(|| {
            let deadline = Instant::now() + T;
            loop {
                if let Some(pos) = self.events.iter().position(&mut pred) {
                    return self.events.remove(pos).unwrap();
                }
                let left = deadline.saturating_duration_since(Instant::now());
                let v = self.child.recv_json(left).unwrap_or_else(|| {
                    panic!(
                        "JS peer: no {what}; queued {:?}; stderr: {}",
                        self.events,
                        self.child.stderr_text()
                    )
                });
                self.events.push_back(v);
            }
        })
    }
}

struct RustPeer {
    backend: Backend,
    events: UnboundedReceiver<BackendEvent>,
    seen: Vec<BackendEvent>,
    key: SigningKey,
}

impl RustPeer {
    /// `legacy`: a v1 backend (`BackendOptions::legacy_v1_routes`), to
    /// talk to the v1 JS reference.
    async fn start(url: &str, legacy: bool) -> RustPeer {
        let backend = Backend::new(BackendOptions {
            node_url: url.to_string(),
            ice_servers: Some(vec![]),
            clock: None,
            loopback_only: false,
            legacy_v1_routes: legacy,
        });
        let events = backend.subscribe();
        let key = key("rust");
        // A node still starting under a loaded test run may not open its
        // WebSocket within `node::OPEN_TIMEOUT_MS`: try three times.
        let mut tries = 0;
        while let Err(e) = backend.start(key.clone()).await {
            tries += 1;
            assert!(tries < 3, "start: {e:?}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        RustPeer {
            backend,
            events,
            seen: Vec::new(),
            key,
        }
    }

    async fn wait(
        &mut self,
        what: &str,
        mut pred: impl FnMut(&BackendEvent) -> bool,
    ) -> BackendEvent {
        if let Some(pos) = self.seen.iter().position(&mut pred) {
            return self.seen.remove(pos);
        }
        let deadline = Instant::now() + T;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let ev = tokio::time::timeout(left, self.events.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}; seen {:?}", self.seen))
                .expect("events");
            if pred(&ev) {
                return ev;
            }
            self.seen.push(ev);
        }
    }
}

/// The JSON and raw channel exchange on one connection, whichever side
/// dialed: JS opens a JSON channel and a raw one, Rust takes both; then
/// Rust opens its own of each and JS takes them.
async fn exchange(rust: &mut RustPeer, rconn: u64, js: &mut JsPeer, jh: u64) {
    // JS -> Rust, a JSON channel.
    let big = json!({"type": "hello", "body": "j".repeat(140_000)});
    let label = js.call(json!({"cmd": "openChannel", "handle": jh, "protocol": "zbterm/ctl", "idHex": "0a", "raw": false}))["label"]
        .as_str()
        .unwrap()
        .to_string();
    rust.wait("incoming ctl", |e| matches!(e, BackendEvent::IncomingChannel { conn, protocol, id } if *conn == rconn && protocol == "zbterm/ctl" && id == &vec![0x0a]))
        .await;
    let rctl = rust
        .backend
        .open_channel(rconn, "zbterm/ctl", &[0x0a])
        .expect("take ctl");
    js.call(json!({"cmd": "send", "handle": jh, "label": label, "message": big}));
    match rust
        .wait(
            "ctl message",
            |e| matches!(e, BackendEvent::Message { chan, .. } if *chan == rctl),
        )
        .await
    {
        BackendEvent::Message { value, .. } => {
            assert_eq!(value, big, "a multi-part JSON message, JS -> Rust")
        }
        _ => unreachable!(),
    }
    let reply = json!({"type": "welcome", "body": "r".repeat(100_000)});
    assert!(rust.backend.send(rctl, &reply));
    let got = js.wait("ctl reply", |v| {
        v["event"] == "message" && v["label"] == label
    });
    assert_eq!(got["value"], reply, "a multi-part JSON message, Rust -> JS");

    // JS -> Rust, a raw channel (HistoryChannel on the JS side).
    let rlabel = js.call(json!({"cmd": "openChannel", "handle": jh, "protocol": "zbterm/history", "idHex": "00", "raw": true}))["label"]
        .as_str()
        .unwrap()
        .to_string();
    rust.wait("incoming history", |e| matches!(e, BackendEvent::IncomingChannel { conn, protocol, .. } if *conn == rconn && protocol == "zbterm/history"))
        .await;
    let rh = rust.backend.attach_history(rconn).expect("attachHistory");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    js.call(json!({"cmd": "sendRaw", "handle": jh, "label": rlabel, "b64": B64.encode(&payload)}));
    let mut got = Vec::new();
    while got.len() < payload.len() {
        match rust
            .wait(
                "raw bytes",
                |e| matches!(e, BackendEvent::Bytes { chan, .. } if *chan == rh),
            )
            .await
        {
            BackendEvent::Bytes { bytes, .. } => {
                assert!(bytes.len() <= 65_536);
                got.extend(bytes);
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(got, payload, "raw bytes JS -> Rust unchanged");
    let back: Vec<u8> = (0..90_000u32).map(|i| (i % 13) as u8).collect();
    assert!(rust.backend.send_bytes(rh, &back));
    let mut got = Vec::new();
    while got.len() < back.len() {
        let v = js.wait("raw bytes back", |v| {
            v["event"] == "bytes" && v["label"] == rlabel
        });
        got.extend(B64.decode(v["b64"].as_str().unwrap()).unwrap());
    }
    assert_eq!(got, back, "raw bytes Rust -> JS unchanged");

    // Rust -> JS: a JSON channel the Rust side opens.
    js.call(json!({"cmd": "onChannel", "handle": jh, "protocol": "zbterm/term"}));
    let rterm = rust
        .backend
        .open_channel(rconn, "zbterm/term", &[1, 2])
        .expect("open term");
    js.wait("incoming term", |v| {
        v["event"] == "incomingChannel" && v["protocol"] == "zbterm/term" && v["idHex"] == "0102"
    });
    let tlabel = js.call(json!({"cmd": "openChannel", "handle": jh, "protocol": "zbterm/term", "idHex": "0102", "raw": false}))["label"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(rust.backend.send(rterm, &json!({"n": 1})));
    let got = js.wait("term message", |v| {
        v["event"] == "message" && v["label"] == tlabel
    });
    assert_eq!(got["value"], json!({"n": 1}));
    js.call(json!({"cmd": "send", "handle": jh, "label": tlabel, "message": {"n": 2}}));
    match rust
        .wait(
            "term reply",
            |e| matches!(e, BackendEvent::Message { chan, .. } if *chan == rterm),
        )
        .await
    {
        BackendEvent::Message { value, .. } => assert_eq!(value, json!({"n": 2})),
        _ => unreachable!(),
    }

    // Closing a channel on the JS side closes it on the Rust side.
    js.call(json!({"cmd": "closeChannel", "handle": jh, "label": label}));
    rust.wait(
        "ctl closed",
        |e| matches!(e, BackendEvent::ChannelClosed { chan } if *chan == rctl),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_announces_and_the_js_backend_dials() {
    if let Some(r) = skip_reason() {
        println!("SKIP rust_announces_and_the_js_backend_dials: {r}");
        return;
    }
    let node = LocalNode::start().expect("LocalNode");
    let home = ScratchHome::new().expect("scratch home");
    let mut rust = RustPeer::start(&node.url, true).await;
    let mut js = JsPeer::spawn(&home);
    let js_key = js.call(json!({"cmd": "start", "nodeUrl": node.url}))["publicKeyHex"]
        .as_str()
        .unwrap()
        .to_string();

    rust.backend.set_admission(Admission::All(true));
    let ann = rust
        .backend
        .announce("link-rj", None, None)
        .await
        .expect("announce");
    js.call(json!({"cmd": "dial", "route": route_to_json(&ann.route), "expectedPeerKeyHex": hex::encode(rust.key.verifying_key().to_bytes())}));
    let dialed = js.wait("dialConnected", |v| {
        v["event"] == "dialConnected" || v["event"] == "dialError"
    });
    assert_eq!(dialed["event"], "dialConnected", "{dialed}");
    let jh = dialed["handle"].as_u64().unwrap();
    let rconn = match rust
        .wait(
            "the JS viewer's connection",
            |e| matches!(e, BackendEvent::Connection { link_id: Some(l), .. } if l == "link-rj"),
        )
        .await
    {
        BackendEvent::Connection {
            conn,
            remote_peer_key,
            initiator,
            ..
        } => {
            assert_eq!(hex::encode(remote_peer_key), js_key);
            assert!(!initiator);
            conn
        }
        _ => unreachable!(),
    };
    exchange(&mut rust, rconn, &mut js, jh).await;

    // withdraw keeps the connection.
    rust.backend.withdraw("link-rj").await;
    assert_eq!(rust.backend.diagnostics()["announced"], 0);
    assert_eq!(
        rust.backend.diagnostics()["conns"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A connection the Rust side closes ends on the JS side.
    rust.backend.close_connection(rconn, "done");
    js.wait("JS connection closed", |v| {
        v["event"] == "connectionClosed" && v["handle"] == jh
    });
    js.call(json!({"cmd": "stop"}));
    rust.backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_js_backend_announces_and_rust_dials() {
    if let Some(r) = skip_reason() {
        println!("SKIP the_js_backend_announces_and_rust_dials: {r}");
        return;
    }
    let node = LocalNode::start().expect("LocalNode");
    let home = ScratchHome::new().expect("scratch home");
    let mut rust = RustPeer::start(&node.url, true).await;
    let mut js = JsPeer::spawn(&home);
    let js_key = js.call(json!({"cmd": "start", "nodeUrl": node.url}))["publicKeyHex"]
        .as_str()
        .unwrap()
        .to_string();
    js.call(json!({"cmd": "setAdmission", "policy": true}));
    let route =
        route_from_json_v1(&js.call(json!({"cmd": "announce", "linkId": "link-jr"}))["route"])
            .expect("a JS route");
    let expected: [u8; 32] = hex::decode(&js_key).unwrap().try_into().unwrap();
    let handle = rust.backend.dial(route, expected, None);
    let rconn = tokio::time::timeout(T, handle.connected)
        .await
        .expect("dial within 30 s")
        .unwrap()
        .expect("connected to the JS host");
    let conn_ev = js.wait("the Rust viewer's connection", |v| {
        v["event"] == "connection" && v["linkId"] == "link-jr"
    });
    assert_eq!(
        conn_ev["remoteKeyHex"],
        hex::encode(rust.key.verifying_key().to_bytes())
    );
    assert_eq!(conn_ev["initiator"], false);
    let jh = conn_ev["handle"].as_u64().unwrap();
    exchange(&mut rust, rconn, &mut js, jh).await;

    // The JS host's diagnostics count the answered offer.
    let d = js.call(json!({"cmd": "diagnostics"}))["diagnostics"].clone();
    assert_eq!(d["links"][0]["answeredLastMinute"], 1);
    assert_eq!(d["announced"], 1);

    // A JS-side stop ends the connection on the Rust side.
    js.call(json!({"cmd": "stop"}));
    rust.wait(
        "connection closed by JS",
        |e| matches!(e, BackendEvent::ConnectionClosed { conn, .. } if *conn == rconn),
    )
    .await;
    rust.backend.stop().await;
}

/// `protocol.md` §12.4 against the real v1 JS reference: a v2 core's route
/// is refused by the v1 JS backend at check 3 (`E_CORRUPT`, "does not match
/// its contract code and parameters"), and a v1 JS route is refused by the
/// v2 core at PV-1 (`E_BACKEND_UNSUPPORTED` naming the upgrade), offline and
/// without a pointer lookup (PV-2). Neither side half-connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_v2_core_and_the_v1_js_backend_refuse_each_others_routes() {
    if let Some(r) = skip_reason() {
        println!("SKIP a_v2_core_and_the_v1_js_backend_refuse_each_others_routes: {r}");
        return;
    }
    let node = LocalNode::start().expect("LocalNode");
    let home = ScratchHome::new().expect("scratch home");
    let mut rust = RustPeer::start(&node.url, false).await;
    let mut js = JsPeer::spawn(&home);
    let js_key = js.call(json!({"cmd": "start", "nodeUrl": node.url}))["publicKeyHex"]
        .as_str()
        .unwrap()
        .to_string();
    rust.backend.set_admission(Admission::All(true));
    js.call(json!({"cmd": "setAdmission", "policy": true}));

    // v2 host, v1 viewer: check 3.
    let ann = rust
        .backend
        .announce("link-v2", None, None)
        .await
        .expect("announce");
    assert_eq!(ann.route.params.pv, Some(route::PROTOCOL_VERSION));
    js.call(json!({"cmd": "dial", "route": route_to_json(&ann.route), "expectedPeerKeyHex": hex::encode(rust.key.verifying_key().to_bytes())}));
    let refused = js.wait("the JS dial's end", |v| {
        v["event"] == "dialConnected" || v["event"] == "dialError"
    });
    assert_eq!(refused["event"], "dialError", "{refused}");
    assert_eq!(refused["code"], "E_CORRUPT", "{refused}");
    assert_eq!(
        refused["message"],
        "The Freenet route does not match its contract code and parameters"
    );

    // v1 host, v2 viewer: PV-1, before any field is read and offline.
    let js_route = js.call(json!({"cmd": "announce", "linkId": "link-v1"}))["route"].clone();
    assert!(js_route["params"].get("pv").is_none());
    let err = route_from_json(&js_route).unwrap_err();
    assert_eq!(err.code, Code::EBackendUnsupported);
    assert_eq!(err.message, route::OLDER_PROTOCOL_MESSAGE);
    // The same route handed to the dial as a struct: refused by the dial's
    // verifier, with no pointer lookup (`viewer:pointer` never fires).
    let v1 = route_from_json_v1(&js_route).expect("a well-formed v1 route");
    let expected: [u8; 32] = hex::decode(&js_key).unwrap().try_into().unwrap();
    let handle = rust.backend.dial(v1, expected, None);
    let dial_err = tokio::time::timeout(T, handle.connected)
        .await
        .expect("settles")
        .unwrap()
        .expect_err("refused");
    assert_eq!(dial_err.code, Code::EBackendUnsupported);
    assert!(
        dial_err.message.contains("protocol") && dial_err.message.contains("upgrade"),
        "{dial_err:?}"
    );
    while let Ok(ev) = rust.events.try_recv() {
        rust.seen.push(ev);
    }
    assert!(
        rust.seen.iter().any(
            |e| matches!(e, BackendEvent::Debug { event, .. } if event == "viewer:route-refused")
        ),
        "the dial's verifier refused it"
    );
    assert!(
        !rust
            .seen
            .iter()
            .any(|e| matches!(e, BackendEvent::Debug { event, .. } if event == "viewer:pointer")),
        "no pointer fallback"
    );
    assert!(
        !rust
            .seen
            .iter()
            .any(|e| matches!(e, BackendEvent::Connection { .. })),
        "never half-connected"
    );
    js.call(json!({"cmd": "stop"}));
    rust.backend.stop().await;
}

/// Hypercore replication over a raw channel the core provides, driven from
/// Node: the JS host serves a session's Hypercores with
/// `history.js::serveHistory`; the Node process dials it through a
/// `zxterm-core sidecar` over the seam (`freenet.dial`,
/// `freenet.attachHistory`) and replicates them into its own cores through
/// `Chan` frames (a `history.js::historyStream`-shaped duplex, Noise on
/// top).
///
/// > 2026-09-30, K13: the host is a second sidecar now (`freenet.announce`,
/// > `freenet.serveHistory`), because a v2 core dials only `pv: 2` routes
/// > and the reference JS backend mints v1 ones.
#[test]
fn hypercore_replicates_over_a_core_raw_channel_driven_from_node() {
    if let Some(r) = skip_reason() {
        println!("SKIP hypercore_replicates_over_a_core_raw_channel_driven_from_node: {r}");
        return;
    }
    let node = LocalNode::start().expect("LocalNode");
    let home = ScratchHome::new().expect("scratch home");
    let bin = env!("CARGO_BIN_EXE_zxterm-core");
    let mut cmd = zxterm_testkit::js::command("freenet_hypercore_smoke.js", &[&node.url, bin]);
    zxterm_testkit::scratch_home::apply_env(&mut cmd, &home.env());
    let started = Instant::now();
    let out = cmd.output().expect("run the smoke test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status
    );
    let result: Value = stdout
        .lines()
        .rev()
        .find_map(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .filter(|v| v.get("result").is_some())
        })
        .unwrap_or_else(|| panic!("no result line\nstdout: {stdout}\nstderr: {stderr}"))["result"]
        .clone();
    println!(
        "hypercore smoke (reported, not gated): {result} in {:?}",
        started.elapsed()
    );
    assert_eq!(result["ok"], true, "{result}");
    assert!(result["blocks"].as_u64().unwrap() >= 1);
    assert_eq!(result["intact"], true);
    assert_eq!(result["meta"], true, "the second core came along");
    assert!(
        result["chanFrames"].as_u64().unwrap() > 0,
        "bytes crossed as Chan frames"
    );
}

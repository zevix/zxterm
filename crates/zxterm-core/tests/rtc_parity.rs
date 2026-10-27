//! K6 acceptance gate (WebRTC and channels, spike S2): a Rust-hosted peer
//! dialed by ZBTerm's real `FreenetBackend` + `electron/rtc-host.js::RtcHost`
//! (crates/zxterm-testkit/js/rtc_peer.js), the reverse (Rust dials the JS
//! peer), the bootstrap-before-other-channels ordering (`S-26`), a
//! multi-part message round trip in both directions, the fingerprint-tamper
//! negative gate (design §6 step 5), and offer→connected / throughput
//! measurements against a real local Freenet node.
//!
//! Needs both `freenet` and `node` on `PATH`; skips with a printed reason
//! naming whichever is missing. Never dials the owner's node
//! (`zxterm_testkit::local_node::LocalNode` refuses port 7509 outright).
//!
//! > 2026-09-29, K11: ZBTerm's live tree no longer holds this JS (its Freenet
//! > backend is a proxy to this core, ZBTerm `D-34`); the helper scripts run
//! > against its JS reference revision (`zxterm_testkit::js::reference_root`),
//! > with that revision's own `node_modules`, prepared by
//! > `scripts/prepare-js-reference.sh` (`X-20`); the test skips, naming the
//! > script, only while it is not prepared
//! > (`zxterm_testkit::js::freenet_reference_skip`).

//!
//! > 2026-09-30, K13: `rtc_peer.js` is a v1 peer, so the routes exchanged
//! > with it are v1 ones: the Rust side verifies a JS route with
//! > `route::verify_v1` and mints the route a JS peer dials with
//! > `route::mint_v1` (a v2 route is refused by v1 JS at check 3, and a v1
//! > route by the v2 `route::verify` at PV-1, `protocol.md` §12).
use std::future::Future;
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use zxterm_core::Code;
use zxterm_core::freenet::channel::PART_BYTES;
use zxterm_core::freenet::connection::Connection;
use zxterm_core::freenet::dial::{self, AcceptArgs, DialArgs};
use zxterm_core::freenet::node::{self, Client};
use zxterm_core::freenet::route::{self, Contracts as RouteContracts, Route, RouteParams};
use zxterm_core::freenet::rtc::{self, RtcHost};
use zxterm_core::freenet::signal;
use zxterm_core::wire;
use zxterm_testkit::local_node::{LocalNode, freenet_available};
use zxterm_testkit::scratch_home::ScratchHome;

fn route_contracts(c: &zxterm_testkit::contracts::Contracts) -> RouteContracts {
    RouteContracts {
        known: c.known.clone(),
        current: c.current.clone(),
        pointer_code: c.pointer.code.clone(),
    }
}

/// The JSON `route` object `FreenetBackend::announce`/`rtc_peer.js` hands
/// back, parsed into this crate's `route::Route`.
fn route_from_json(v: &Value) -> Route {
    let params = v.get("params").expect("route.params");
    Route {
        sig: v
            .get("sig")
            .and_then(Value::as_str)
            .expect("route.sig")
            .to_string(),
        code: v
            .get("code")
            .and_then(Value::as_str)
            .expect("route.code")
            .to_string(),
        params: RouteParams {
            ttl_ms: params
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .expect("params.ttl_ms"),
            host: params
                .get("host")
                .and_then(Value::as_str)
                .expect("params.host")
                .to_string(),
            n: params
                .get("n")
                .and_then(Value::as_str)
                .expect("params.n")
                .to_string(),
            pv: None,
        },
        ptr: v.get("ptr").and_then(Value::as_str).map(str::to_string),
        k: v.get("k")
            .and_then(Value::as_str)
            .expect("route.k")
            .to_string(),
    }
}

fn route_to_json(r: &Route) -> Value {
    json!({
        "sig": r.sig,
        "code": r.code,
        "params": {"ttl_ms": r.params.ttl_ms, "host": r.params.host, "n": r.params.n},
        "ptr": r.ptr,
        "k": r.k,
    })
}

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(fut)
}

fn keys_from_seed(seed: u8) -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// A newline-JSON `rtc_peer.js` child, plus the queue `call`/`wait_event`
/// need to tell "a reply to my last command" apart from an async event on
/// the same stdout stream.
struct JsPeer {
    child: zxterm_testkit::js::LineChild,
    events: std::collections::VecDeque<Value>,
}

impl JsPeer {
    fn spawn(home: &ScratchHome) -> JsPeer {
        let child = zxterm_testkit::js::LineChild::spawn("rtc_peer.js", &[], home)
            .expect("spawn rtc_peer.js");
        JsPeer {
            child,
            events: std::collections::VecDeque::new(),
        }
    }

    /// Blocking (its own `LineChild::recv_json` waits on a plain
    /// `std::sync::mpsc::Receiver`, not a `tokio` one) — always run inside
    /// `tokio::task::block_in_place` (this fn's own `call`/`wait_event`
    /// callers all run under `block_on`'s multi-threaded runtime, which
    /// `block_in_place` requires) so blocking here for up to tens of
    /// seconds never ties up a worker thread another task on the *same*
    /// runtime — this `JsPeer`'s own background `ConnDriver` pump among
    /// them — needs to make progress; that starvation was intermittent,
    /// not structural, which is exactly what made it look like a protocol
    /// bug at first.
    fn call(&mut self, cmd: Value) -> Value {
        self.child
            .send_json(&cmd)
            .expect("send command to rtc_peer.js");
        tokio::task::block_in_place(|| {
            loop {
                let v = self
                    .child
                    .recv_json(Duration::from_secs(20))
                    .unwrap_or_else(|| {
                        panic!(
                            "rtc_peer.js: no reply; stderr: {}",
                            self.child.stderr_text()
                        )
                    });
                if v.get("ok").is_some() {
                    return v;
                }
                self.events.push_back(v);
            }
        })
    }

    fn wait_event(&mut self, timeout: Duration, mut pred: impl FnMut(&Value) -> bool) -> Value {
        tokio::task::block_in_place(|| {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(pos) = self.events.iter().position(&mut pred) {
                    return self.events.remove(pos).expect("position found it");
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    panic!(
                        "rtc_peer.js: timed out waiting for an event; stderr: {}",
                        self.child.stderr_text()
                    );
                }
                let Some(v) = self.child.recv_json(remaining) else {
                    panic!(
                        "rtc_peer.js: no event within timeout; queued so far: {:?}; try_wait: {:?}; stderr: {}",
                        self.events,
                        self.child.try_wait(),
                        self.child.stderr_text()
                    );
                };
                self.events.push_back(v);
            }
        })
    }
}

/// Drives one [`Connection`] for its whole life: a background task
/// continuously pumps `rtc.recv_event()` into `conn.handle_rtc_event` (the
/// same thing a real caller must run forever, mirroring
/// `connection.js`'s always-live `EventEmitter` wiring — a test that only
/// drained events at specific checkpoints deadlocked here in development:
/// a channel this side opens after the bootstrap channel's own
/// `ChannelOpen` event arrives stays deferred until *something* processes
/// that event, and nothing else ever does). `open_channel`/`send` lock the
/// same `Connection` briefly to call through to it; `wait_for` polls the
/// `ConnEvent`s the background task has collected so far.
struct ConnDriver {
    inner: std::sync::Arc<
        tokio::sync::Mutex<(Connection, Vec<zxterm_core::freenet::connection::ConnEvent>)>,
    >,
    notify: std::sync::Arc<tokio::sync::Notify>,
    rtc: std::sync::Arc<RtcHost>,
}

impl ConnDriver {
    fn spawn(rtc: std::sync::Arc<RtcHost>, conn: Connection) -> ConnDriver {
        let inner = std::sync::Arc::new(tokio::sync::Mutex::new((conn, Vec::new())));
        let notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let (inner2, notify2, rtc2) = (inner.clone(), notify.clone(), rtc.clone());
        tokio::spawn(async move {
            loop {
                let Some(ev) = rtc2.recv_event().await else {
                    break;
                };
                let mut guard = inner2.lock().await;
                let ces = guard.0.handle_rtc_event(&rtc2, &ev);
                if !ces.is_empty() {
                    guard.1.extend(ces);
                    drop(guard);
                    notify2.notify_waiters();
                }
            }
        });
        ConnDriver { inner, notify, rtc }
    }

    async fn open_channel(&self, protocol: &str, id: &[u8]) -> String {
        self.inner
            .lock()
            .await
            .0
            .open_channel(&self.rtc, protocol, id)
            .expect("open the test channel")
    }

    async fn send(&self, key: &str, message: &Value) -> bool {
        self.inner.lock().await.0.send(&self.rtc, key, message)
    }

    async fn open_order(&self) -> Vec<String> {
        self.inner.lock().await.0.open_order().to_vec()
    }

    /// Waits for a [`ConnEvent`](zxterm_core::freenet::connection::ConnEvent)
    /// the background task already collected (or collects while waiting)
    /// that matches `pred`, removing it from the queue.
    async fn wait_for(
        &self,
        timeout: Duration,
        mut pred: impl FnMut(&zxterm_core::freenet::connection::ConnEvent) -> bool,
    ) -> zxterm_core::freenet::connection::ConnEvent {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut guard = self.inner.lock().await;
                if let Some(pos) = guard.1.iter().position(&mut pred) {
                    return guard.1.remove(pos);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for the expected ConnEvent"
            );
            // Bounded per-iteration wait: `notify_waiters` only wakes
            // *currently registered* waiters, so a notification that
            // lands between the check above and registering this wait
            // would otherwise be lost until the next one — capping the
            // wait re-checks the queue at least this often regardless.
            let _ = tokio::time::timeout(
                remaining.min(Duration::from_millis(50)),
                self.notify.notified(),
            )
            .await;
        }
    }
}

fn big_message(tag: &str, len: usize) -> Value {
    json!({"tag": tag, "body": "z".repeat(len)})
}

#[test]
fn rtc_and_channel_s2_gate() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP rtc_and_channel_s2_gate: {reason}");
        return;
    }
    if !freenet_available() {
        println!("SKIP rtc_and_channel_s2_gate: freenet binary not on PATH");
        return;
    }

    let contracts = zxterm_testkit::contracts::load();
    let rc = route_contracts(&contracts);
    let node = LocalNode::start().expect("start a local freenet node");

    block_on(async {
        rust_dials_js_host(&node, &rc).await;
        js_dials_rust_host(&node, &rc).await;
        fingerprint_tamper_js_lying_host_rust_dials(&node, &rc).await;
        fingerprint_tamper_js_lying_dialer_rust_hosts(&node, &rc).await;
        fingerprint_tamper_rust_dialer_lies_to_itself(&node, &rc).await;
        fingerprint_tamper_rust_host_lies_to_itself(&node, &rc).await;
    });

    measure_offer_to_connected_and_throughput();
}

/// Direction 1: a JS-hosted peer (real `FreenetBackend` + `RtcHost` on the
/// shared `LocalNode`) is announced; a Rust `dial::dial` connects to it.
/// Asserts the bootstrap-before-other-channels ordering on both sides and a
/// multi-part message round trip in both directions.
async fn rust_dials_js_host(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut host = JsPeer::spawn(&home);
    let started = host.call(json!({"cmd": "start", "nodeUrl": node.url}));
    assert_eq!(started["ok"], true, "host start: {started:?}");
    let host_pub_hex = started["publicKeyHex"]
        .as_str()
        .expect("publicKeyHex")
        .to_string();

    let announced = host.call(json!({"cmd": "announce", "linkId": "k6-a"}));
    assert_eq!(announced["ok"], true, "announce: {announced:?}");
    let route = route_from_json(&announced["route"]);

    let (my_secret, my_public) = keys_from_seed(0xA1);
    let host_public = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(hex::decode(&host_pub_hex).expect("hex")).expect("32 bytes"),
    )
    .expect("host public key");
    let checked = route::verify_v1(&route, &host_pub_hex, rc).expect("route verifies");

    let rtc_host = std::sync::Arc::new(RtcHost::new(vec![]));
    let mut client = Client::connect(&node.url)
        .await
        .expect("connect node client");

    let started_at = Instant::now();
    let conn = dial::dial(
        &mut client,
        &rtc_host,
        1,
        DialArgs {
            checked: &checked,
            route_k: &route.k,
            expected_peer_key: &host_public,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: None,
        },
    )
    .await
    .expect("rust dial must connect to the JS host");
    println!(
        "rust dials JS host: connected in {:?}",
        started_at.elapsed()
    );
    assert!(conn.initiator);
    assert_eq!(conn.remote_peer_key, host_public.to_bytes().to_vec());
    let driver = ConnDriver::spawn(rtc_host.clone(), conn);

    let host_conn = host.wait_event(Duration::from_secs(20), |v| v["event"] == "connection");
    let host_handle = host_conn["handle"].as_i64().expect("handle");
    assert_eq!(
        host_conn["remoteKeyHex"].as_str().unwrap(),
        hex::encode(my_public.to_bytes()),
        "the JS host sees the Rust dialer's own key"
    );

    // Bootstrap-before-other-channels, checked structurally on both sides.
    let key = driver.open_channel("zbterm/history", &[7]).await;
    host.call(json!({"cmd": "onChannel", "handle": host_handle, "protocol": "zbterm/history"}));
    let incoming = host.wait_event(Duration::from_secs(15), |v| v["event"] == "incomingChannel");
    assert_eq!(incoming["idHex"].as_str().unwrap(), "07");
    let opened = host.call(json!({
        "cmd": "openChannel", "handle": host_handle, "protocol": "zbterm/history", "idHex": "07"
    }));
    assert_eq!(opened["ok"], true);
    let host_label = opened["label"].as_str().unwrap().to_string();

    driver
        .wait_for(Duration::from_secs(10), |ce| {
            matches!(ce, zxterm_core::freenet::connection::ConnEvent::ChannelOpened { key: k } if k == &key)
        })
        .await;

    let order = driver.open_order().await;
    assert_eq!(
        order.first().map(String::as_str),
        Some(wire::BOOTSTRAP_LABEL),
        "rust: bootstrap first, order={order:?}"
    );
    assert!(
        order.contains(&key),
        "rust: the test channel also opened, order={order:?}"
    );

    let host_order = host.call(json!({"cmd": "openOrder"}));
    let host_order_list: Vec<String> = host_order["order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        host_order_list.first().map(String::as_str),
        Some(wire::BOOTSTRAP_LABEL),
        "js host: bootstrap first, order={host_order_list:?}"
    );
    assert!(
        host_order_list.contains(&host_label),
        "js host: the test channel also opened"
    );

    // Multi-part round trip, both directions: > PART_BYTES so `cut`/`_data`
    // (channel.rs) actually reassembles more than one part.
    let big_len = PART_BYTES * 2 + 777;
    let from_rust = big_message("rust->js", big_len);
    assert!(driver.send(&key, &from_rust).await);
    let got = host.wait_event(Duration::from_secs(15), |v| v["event"] == "message");
    assert_eq!(
        &got["value"], &from_rust,
        "js host received the rust->js message byte-identical"
    );

    let from_js = big_message("js->rust", big_len);
    let sent = host.call(
        json!({"cmd": "send", "handle": host_handle, "label": host_label, "message": from_js}),
    );
    assert_eq!(sent["result"], true);
    let msg_ev = driver
        .wait_for(Duration::from_secs(15), |ce| {
            matches!(ce, zxterm_core::freenet::connection::ConnEvent::Message { key: k, .. } if k == &key)
        })
        .await;
    if let zxterm_core::freenet::connection::ConnEvent::Message { value, .. } = msg_ev {
        assert_eq!(
            value, from_js,
            "rust received the js->rust message byte-identical"
        );
    }

    host.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// Direction 2: Rust announces (put + subscribe the signalling instance
/// itself) and accepts one offer (`dial::accept_one`); a JS peer
/// (`FreenetBackend::dial`) connects to it.
async fn js_dials_rust_host(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut viewer = JsPeer::spawn(&home);
    let started = viewer.call(json!({"cmd": "start", "nodeUrl": node.url}));
    assert_eq!(started["ok"], true);
    let viewer_pub_hex = started["publicKeyHex"].as_str().unwrap().to_string();

    let (my_secret, my_public) = keys_from_seed(0xB2);
    let my_hex = hex::encode(my_public.to_bytes());
    let route = route::mint_v1("k6-b", &my_hex, rc);
    let params = route::params_bytes(&route.params);
    let wasm = rc.known.get(&route.code).expect("current signalling wasm");
    let addr = node::contract_key(wasm, &params);
    let payload_key = signal::payload_key(&route.k);

    // One connection for both announce (put + subscribe) and the later
    // recv_notification/update calls in `accept_one`: a subscription
    // belongs to the WebSocket connection that made it, so a *second*
    // `Client` (a separate connection) never sees this instance's
    // notifications at all, however long it waits.
    let mut host_client = Client::connect(&node.url).await.expect("host client");
    host_client
        .put(wasm, &params, b"{\"e\":[]}".to_vec())
        .await
        .expect("put the signalling instance");
    host_client
        .subscribe(addr.key.id())
        .await
        .expect("subscribe");

    let rtc_host = std::sync::Arc::new(RtcHost::new(vec![]));

    let dial_started = viewer.call(json!({
        "cmd": "dial", "route": route_to_json(&route), "expectedPeerKeyHex": my_hex
    }));
    assert_eq!(dial_started["ok"], true);

    let started_at = Instant::now();
    let conn = dial::accept_one(
        &mut host_client,
        &rtc_host,
        1,
        AcceptArgs {
            link_params: &params,
            contract_key: &addr.key,
            payload_key: &payload_key,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: None,
        },
    )
    .await
    .expect("rust host must accept the JS viewer's dial");
    println!(
        "js dials rust host: connected in {:?}",
        started_at.elapsed()
    );
    assert!(!conn.initiator);
    let viewer_public = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(hex::decode(&viewer_pub_hex).expect("hex")).expect("32 bytes"),
    )
    .expect("viewer public key");
    assert_eq!(conn.remote_peer_key, viewer_public.to_bytes().to_vec());
    let driver = ConnDriver::spawn(rtc_host.clone(), conn);

    let viewer_conn = viewer.wait_event(Duration::from_secs(20), |v| v["event"] == "dialConnected");
    let viewer_handle = viewer_conn["handle"].as_i64().expect("handle");

    let key = driver.open_channel("zbterm/history", &[9]).await;
    viewer.call(json!({"cmd": "onChannel", "handle": viewer_handle, "protocol": "zbterm/history"}));
    let incoming = viewer.wait_event(Duration::from_secs(15), |v| v["event"] == "incomingChannel");
    assert_eq!(incoming["idHex"].as_str().unwrap(), "09");
    let opened = viewer.call(json!({
        "cmd": "openChannel", "handle": viewer_handle, "protocol": "zbterm/history", "idHex": "09"
    }));
    assert_eq!(opened["ok"], true);
    let viewer_label = opened["label"].as_str().unwrap().to_string();

    driver
        .wait_for(Duration::from_secs(10), |ce| {
            matches!(ce, zxterm_core::freenet::connection::ConnEvent::ChannelOpened { key: k } if k == &key)
        })
        .await;

    let order = driver.open_order().await;
    assert_eq!(
        order.first().map(String::as_str),
        Some(wire::BOOTSTRAP_LABEL),
        "rust host: bootstrap first, order={order:?}"
    );

    let big_len = PART_BYTES * 2 + 555;
    let from_rust = big_message("rust->js", big_len);
    assert!(driver.send(&key, &from_rust).await);
    let got = viewer.wait_event(Duration::from_secs(15), |v| v["event"] == "message");
    assert_eq!(
        &got["value"], &from_rust,
        "js viewer received the rust->js message byte-identical"
    );

    let from_js = big_message("js->rust", big_len);
    let sent = viewer.call(
        json!({"cmd": "send", "handle": viewer_handle, "label": viewer_label, "message": from_js}),
    );
    assert_eq!(sent["result"], true);
    let msg_ev = driver
        .wait_for(Duration::from_secs(15), |ce| {
            matches!(ce, zxterm_core::freenet::connection::ConnEvent::Message { key: k, .. } if k == &key)
        })
        .await;
    if let zxterm_core::freenet::connection::ConnEvent::Message { value, .. } = msg_ev {
        assert_eq!(
            value, from_js,
            "rust host received the js->rust message byte-identical"
        );
    }

    viewer.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// The `S6` conformance negative (i), JS-host direction: a JS host whose
/// own fingerprint check is fed a corrupted `remoteFingerprint`
/// (`rtc_peer.js`'s `lieAboutFingerprint`, the exact mechanism
/// `test/backends/freenet-backend.test.js`'s own "our fingerprint check"
/// negative uses) refuses a *real* Rust dialer's connection —
/// `host:fingerprint-mismatch`. The Rust dialer's own outcome is not
/// asserted here: since the lie is the JS host's own internal bookkeeping
/// (never sent over the wire), the honest Rust side may briefly reach its
/// own `Connected`+match before the JS host tears the connection down, or
/// see the teardown first — both are correct depending on timing, and only
/// the JS host's detection is deterministic.
async fn fingerprint_tamper_js_lying_host_rust_dials(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut host = JsPeer::spawn(&home);
    let started =
        host.call(json!({"cmd": "start", "nodeUrl": node.url, "lieAboutFingerprint": true}));
    assert_eq!(started["ok"], true);
    let host_pub_hex = started["publicKeyHex"].as_str().unwrap().to_string();
    let announced = host.call(json!({"cmd": "announce", "linkId": "k6-fp-a"}));
    let route = route_from_json(&announced["route"]);

    let (my_secret, _my_public) = keys_from_seed(0xC3);
    let host_public = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(hex::decode(&host_pub_hex).expect("hex")).expect("32 bytes"),
    )
    .expect("host public key");
    let checked = route::verify_v1(&route, &host_pub_hex, rc).expect("route verifies");

    let rtc_host = RtcHost::new(vec![]);
    let mut client = Client::connect(&node.url)
        .await
        .expect("connect node client");

    let dial_result = dial::dial(
        &mut client,
        &rtc_host,
        1,
        DialArgs {
            checked: &checked,
            route_k: &route.k,
            expected_peer_key: &host_public,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: None,
        },
    )
    .await;
    match &dial_result {
        Ok(_) => println!("fingerprint tamper (lying JS host): rust dial outcome = connected"),
        Err(e) => println!(
            "fingerprint tamper (lying JS host): rust dial outcome = {} ({})",
            e.code, e.message
        ),
    }

    let mismatch = host.wait_event(Duration::from_secs(20), |v| {
        v["event"] == "debug" && v["name"] == "host:fingerprint-mismatch"
    });
    println!("JS host detected the mismatch: {mismatch:?}");

    host.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// The `S6` conformance negative (i), JS-dialer direction: a JS dialer
/// whose own fingerprint check is fed a corrupted `remoteFingerprint`
/// (`lieAboutFingerprint`) refuses to surface a connection to a *real* Rust
/// host, `E_AUTH`. The Rust host's own outcome is not asserted, for the
/// same reason as the other direction above.
async fn fingerprint_tamper_js_lying_dialer_rust_hosts(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut viewer = JsPeer::spawn(&home);
    let started =
        viewer.call(json!({"cmd": "start", "nodeUrl": node.url, "lieAboutFingerprint": true}));
    assert_eq!(started["ok"], true);

    let (my_secret, my_public) = keys_from_seed(0xD4);
    let my_hex = hex::encode(my_public.to_bytes());
    let route = route::mint_v1("k6-fp-b", &my_hex, rc);
    let params = route::params_bytes(&route.params);
    let wasm = rc.known.get(&route.code).expect("current signalling wasm");
    let addr = node::contract_key(wasm, &params);
    let payload_key = signal::payload_key(&route.k);

    // One connection throughout (see the same note in `js_dials_rust_host`).
    let mut host_client = Client::connect(&node.url).await.expect("host client");
    host_client
        .put(wasm, &params, b"{\"e\":[]}".to_vec())
        .await
        .expect("put the signalling instance");
    host_client
        .subscribe(addr.key.id())
        .await
        .expect("subscribe");

    let rtc_host = RtcHost::new(vec![]);

    let dial_started = viewer.call(json!({
        "cmd": "dial", "route": route_to_json(&route), "expectedPeerKeyHex": my_hex
    }));
    assert_eq!(dial_started["ok"], true);

    let accept_result = dial::accept_one(
        &mut host_client,
        &rtc_host,
        1,
        AcceptArgs {
            link_params: &params,
            contract_key: &addr.key,
            payload_key: &payload_key,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: None,
        },
    )
    .await;
    match &accept_result {
        Ok(_) => println!("fingerprint tamper (lying JS dialer): rust accept outcome = connected"),
        Err(e) => println!(
            "fingerprint tamper (lying JS dialer): rust accept outcome = {} ({})",
            e.code, e.message
        ),
    }

    let err = viewer.wait_event(Duration::from_secs(20), |v| v["event"] == "dialError");
    assert_eq!(
        err["code"].as_str(),
        Some("E_AUTH"),
        "js dialer refuses with E_AUTH: {err:?}"
    );
    println!("JS dialer detected the mismatch: {err:?}");

    viewer.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// `'sha-256 AB:CD:…'` -> the first hex digit after the space, changed
/// (`rtc_peer.js::flipHexDigit`'s twin, over `dial.rs::DialArgs`/
/// `AcceptArgs`'s `lie_about_fingerprint` test seam instead of a JS relay).
fn flip_hex_digit(fingerprint: String) -> String {
    let Some(space) = fingerprint.find(' ') else {
        return fingerprint;
    };
    let (head, rest) = fingerprint.split_at(space + 1);
    let mut chars: Vec<char> = rest.chars().collect();
    for c in chars.iter_mut() {
        if c.is_ascii_hexdigit() {
            *c = if c.eq_ignore_ascii_case(&'A') {
                'B'
            } else {
                'A'
            };
            break;
        }
    }
    format!("{head}{}", chars.into_iter().collect::<String>())
}

/// The `S6` conformance negative (i), live on the Rust side: Rust `dial`s a
/// *real, honest* JS host, but `DialArgs::lie_about_fingerprint` rewrites
/// what `dial()` itself treats as the presented fingerprint before its own
/// `check_fingerprint` call sees it — the same seam `rtc_peer.js`'s
/// `lieAboutFingerprint` relay is for the JS side, proving *this* side's
/// own check refuses a certificate its signed SDP does not name, without a
/// real DTLS mismatch (which would fail at the transport layer with
/// `E_HOST_UNREACHABLE` instead, before this check ever runs).
async fn fingerprint_tamper_rust_dialer_lies_to_itself(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut host = JsPeer::spawn(&home);
    let started = host.call(json!({"cmd": "start", "nodeUrl": node.url}));
    assert_eq!(started["ok"], true);
    let host_pub_hex = started["publicKeyHex"].as_str().unwrap().to_string();
    let announced = host.call(json!({"cmd": "announce", "linkId": "k6-fp-c"}));
    let route = route_from_json(&announced["route"]);

    let (my_secret, _my_public) = keys_from_seed(0xE5);
    let host_public = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(hex::decode(&host_pub_hex).expect("hex")).expect("32 bytes"),
    )
    .expect("host public key");
    let checked = route::verify_v1(&route, &host_pub_hex, rc).expect("route verifies");

    let rtc_host = RtcHost::new(vec![]);
    let mut client = Client::connect(&node.url)
        .await
        .expect("connect node client");

    let dial_result = dial::dial(
        &mut client,
        &rtc_host,
        1,
        DialArgs {
            checked: &checked,
            route_k: &route.k,
            expected_peer_key: &host_public,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: Some(flip_hex_digit),
        },
    )
    .await;
    let err = match dial_result {
        Ok(_) => panic!("rust dial must refuse its own (test-seam) mismatch, not connect"),
        Err(e) => e,
    };
    assert_eq!(err.code, Code::EAuth, "rust dialer refuses with E_AUTH");
    println!(
        "fingerprint tamper (rust dialer lies to itself): rust dial outcome = {} ({})",
        err.code, err.message
    );

    // Refused, not left dangling: the connection this side just refused
    // must actually close at the RTC layer too.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(rtc::RtcEvent::Close { .. }) = rtc_host.recv_event().await {
                return;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the connection must close, not be surfaced, after the refusal"
    );

    host.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// The `S6` conformance negative (i), live on the Rust side, host role: a
/// *real, honest* JS viewer dials Rust's `accept_one`, but
/// `AcceptArgs::lie_about_fingerprint` rewrites what `accept_one` itself
/// treats as the presented fingerprint — see
/// `fingerprint_tamper_rust_dialer_lies_to_itself`'s doc comment for why
/// this is the seam that proves it, not a real DTLS mismatch.
async fn fingerprint_tamper_rust_host_lies_to_itself(node: &LocalNode, rc: &RouteContracts) {
    let home = ScratchHome::new().expect("scratch home");
    let mut viewer = JsPeer::spawn(&home);
    let started = viewer.call(json!({"cmd": "start", "nodeUrl": node.url}));
    assert_eq!(started["ok"], true);

    let (my_secret, my_public) = keys_from_seed(0xF6);
    let my_hex = hex::encode(my_public.to_bytes());
    let route = route::mint_v1("k6-fp-d", &my_hex, rc);
    let params = route::params_bytes(&route.params);
    let wasm = rc.known.get(&route.code).expect("current signalling wasm");
    let addr = node::contract_key(wasm, &params);
    let payload_key = signal::payload_key(&route.k);

    // One connection throughout (see the same note in `js_dials_rust_host`).
    let mut host_client = Client::connect(&node.url).await.expect("host client");
    host_client
        .put(wasm, &params, b"{\"e\":[]}".to_vec())
        .await
        .expect("put the signalling instance");
    host_client
        .subscribe(addr.key.id())
        .await
        .expect("subscribe");

    let rtc_host = RtcHost::new(vec![]);

    let dial_started = viewer.call(json!({
        "cmd": "dial", "route": route_to_json(&route), "expectedPeerKeyHex": my_hex
    }));
    assert_eq!(dial_started["ok"], true);

    let accept_result = dial::accept_one(
        &mut host_client,
        &rtc_host,
        1,
        AcceptArgs {
            link_params: &params,
            contract_key: &addr.key,
            payload_key: &payload_key,
            my_secret: &my_secret,
            ice_servers: vec![],
            timeout: Duration::from_secs(20),
            lie_about_fingerprint: Some(flip_hex_digit),
        },
    )
    .await;
    let err = match accept_result {
        Ok(_) => panic!("rust host must refuse its own (test-seam) mismatch, not connect"),
        Err(e) => e,
    };
    assert_eq!(err.code, Code::EAuth, "rust host refuses with E_AUTH");
    println!(
        "fingerprint tamper (rust host lies to itself): rust accept outcome = {} ({})",
        err.code, err.message
    );

    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(rtc::RtcEvent::Close { .. }) = rtc_host.recv_event().await {
                return;
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the connection must close, not be surfaced, after the refusal"
    );

    viewer.call(json!({"cmd": "stop"}));
    rtc_host.close_all("test done");
}

/// Offer→connected p50/p95 (n = 20, no ICE servers, loopback) and 16 MiB
/// transferred in 65 536-byte messages, Rust `RtcHost` to Rust `RtcHost` —
/// this is a WebRTC-library measurement (str0m's own driving loop), not an
/// interop one, so it stays JS-independent (comparing against
/// `node-datachannel`'s own measured number, not re-measuring it).
///
/// > 2026-09-29, K10: `RtcHost::new` now also binds the primary interface
/// > and offers a second host candidate; this measurement relays exactly
/// > one candidate per side, so it builds its hosts with
/// > `RtcHost::loopback_only` (K6's binding, unchanged numbers' basis).
fn measure_offer_to_connected_and_throughput() {
    block_on(async {
        let mut samples_ms = Vec::with_capacity(20);
        for i in 0..20u64 {
            let dialer = RtcHost::loopback_only(vec![]);
            let host = RtcHost::loopback_only(vec![]);
            let conn_id = 1000 + i;
            dialer.open(conn_id, Some(vec![]));
            host.open(conn_id, Some(vec![]));
            let started = Instant::now();

            let d_cand = next_signal(&dialer, conn_id).await;
            let h_cand = next_signal(&host, conn_id).await;
            dialer.open_channel(conn_id, 0, wire::BOOTSTRAP_LABEL);
            let offer = next_signal(&dialer, conn_id).await;
            let rtc::SignalMsg::Offer { sdp } = offer else {
                panic!("expected offer")
            };
            host.signal(conn_id, rtc::SignalMsg::Offer { sdp });
            let answer = next_signal(&host, conn_id).await;
            let rtc::SignalMsg::Answer { sdp } = answer else {
                panic!("expected answer")
            };
            dialer.signal(conn_id, rtc::SignalMsg::Answer { sdp });
            host.signal(conn_id, d_cand);
            dialer.signal(conn_id, h_cand);

            wait_connected(&dialer, conn_id).await;
            wait_connected(&host, conn_id).await;
            samples_ms.push(started.elapsed().as_secs_f64() * 1000.0);

            dialer.close_all("measured");
            host.close_all("measured");
        }
        samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = samples_ms[samples_ms.len() / 2];
        let p95 = samples_ms[(samples_ms.len() as f64 * 0.95) as usize];
        println!(
            "offer->connected p50/p95 (n={}): {:.2}/{:.2} ms",
            samples_ms.len(),
            p50,
            p95
        );

        // 16 MiB in 65_536-byte messages, one direction, over one channel.
        let dialer = RtcHost::loopback_only(vec![]);
        let host = RtcHost::loopback_only(vec![]);
        dialer.open(1, Some(vec![]));
        host.open(1, Some(vec![]));
        let d_cand = next_signal(&dialer, 1).await;
        let h_cand = next_signal(&host, 1).await;
        dialer.open_channel(1, 0, "zxterm/throughput");
        let offer = next_signal(&dialer, 1).await;
        let rtc::SignalMsg::Offer { sdp } = offer else {
            panic!("expected offer")
        };
        host.signal(1, rtc::SignalMsg::Offer { sdp });
        let answer = next_signal(&host, 1).await;
        let rtc::SignalMsg::Answer { sdp } = answer else {
            panic!("expected answer")
        };
        dialer.signal(1, rtc::SignalMsg::Answer { sdp });
        host.signal(1, d_cand);
        dialer.signal(1, h_cand);
        wait_connected(&dialer, 1).await;
        wait_connected(&host, 1).await;
        let chan_id = wait_channel_opened(&host, 1).await;
        wait_channel_opened(&dialer, 1).await;

        const TOTAL: usize = 16 * 1024 * 1024;
        const MSG: usize = 65536;
        let mut remaining_to_send = TOTAL / MSG;
        let payload = vec![0x42u8; MSG];
        let started = Instant::now();
        let mut received: usize = 0;
        let mut paused = false;
        // Paced by the dialer's own `Flow` events: `rtc.rs::send` queues
        // (and `str0m`'s SCTP send buffer bounds) rather than drops, but
        // firing all the writes in one burst with nothing ever polling
        // `dialer.recv_event()` in between starves the very `Flow` events
        // that would otherwise pace it, since nothing here yields to the
        // task processing them until this loop's own `.await` point.
        while received < TOTAL {
            if !paused && remaining_to_send > 0 {
                dialer.send(1, 0, payload.clone());
                remaining_to_send -= 1;
            }
            tokio::select! {
                ev = dialer.recv_event() => {
                    if let Some(rtc::RtcEvent::Flow { paused: p, .. }) = ev {
                        paused = p;
                    }
                }
                ev = host.recv_event() => {
                    if let Some(rtc::RtcEvent::Data { data, .. }) = ev {
                        received += data.len();
                    }
                }
            }
        }
        let elapsed = started.elapsed();
        let mib_s = (received as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        println!(
            "16 MiB / {MSG}-byte messages: {:.3} s, {:.2} MiB/s (node-datachannel P-6: 12.87 MiB/s, reported not gated); chan_id={chan_id}",
            elapsed.as_secs_f64(),
            mib_s
        );
        dialer.close_all("measured");
        host.close_all("measured");
    });
}

async fn next_signal(rtc: &RtcHost, conn_id: u64) -> rtc::SignalMsg {
    loop {
        match rtc.recv_event().await.expect("event stream ended") {
            rtc::RtcEvent::Signal { conn_id: c, msg } if c == conn_id => return msg,
            _ => {}
        }
    }
}

async fn wait_connected(rtc: &RtcHost, conn_id: u64) {
    loop {
        match rtc.recv_event().await.expect("event stream ended") {
            rtc::RtcEvent::State {
                conn_id: c,
                state: rtc::IceState::Connected,
                ..
            } if c == conn_id => return,
            _ => {}
        }
    }
}

async fn wait_channel_opened(rtc: &RtcHost, conn_id: u64) -> u32 {
    loop {
        match rtc.recv_event().await.expect("event stream ended") {
            rtc::RtcEvent::Channel {
                conn_id: c,
                chan_id,
                op: rtc::ChannelOp::Opened,
                ..
            } if c == conn_id => {
                return chan_id;
            }
            _ => {}
        }
    }
}

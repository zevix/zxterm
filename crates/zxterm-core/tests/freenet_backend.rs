//! K10 core-to-core: two `zxterm_core::freenet::backend::Backend`s on one
//! throwaway `LocalNode` (never the owner's node): every `BACKEND_MEMBERS`
//! method, the connection on both sides, JSON and raw channels (framing,
//! back-pressure and drain, close), withdraw, stop twice, and the three
//! admission refusals of design §7 layer 4 (`half-open`,
//! `half-open-viewer`, `rate`) plus a policy refusal (`admission`), each
//! triggered on its own and asserted.
//!
//! Needs `freenet` on `PATH`; skips with a printed reason otherwise.
//! No ICE servers: host candidates on loopback only.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use zxterm_core::Code;
use zxterm_core::freenet::backend::{
    self, Admission, Backend, BackendEvent, BackendOptions, ConnHandle, Refusal,
};
use zxterm_core::freenet::channel::QUEUE_HIGH_WATER;
use zxterm_core::freenet::rtc::{RtcEvent, RtcHost, SignalMsg};
use zxterm_core::freenet::{node, route, signal};
use zxterm_testkit::local_node::{LocalNode, freenet_available};

const T: Duration = Duration::from_secs(30);

fn key(label: &str) -> SigningKey {
    let seed = blake3::hash(
        format!(
            "{label}/{}/{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        )
        .as_bytes(),
    );
    SigningKey::from_bytes(seed.as_bytes())
}

fn opts(url: &str, clock: Option<backend::Clock>) -> BackendOptions {
    BackendOptions {
        node_url: url.to_string(),
        ice_servers: Some(vec![]),
        clock,
        loopback_only: true,
        legacy_v1_routes: false,
    }
}

struct Peer {
    backend: Backend,
    events: UnboundedReceiver<BackendEvent>,
    seen: Vec<BackendEvent>,
    key: SigningKey,
}

impl Peer {
    async fn start(url: &str, label: &str, clock: Option<backend::Clock>) -> Peer {
        let backend = Backend::new(opts(url, clock));
        let events = backend.subscribe();
        let key = key(label);
        start_with_retry(&backend, &key).await;
        Peer {
            backend,
            events,
            seen: Vec::new(),
            key,
        }
    }

    fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Waits for (and removes) the first event `pred` accepts.
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
                .expect("event stream");
            if pred(&ev) {
                return ev;
            }
            self.seen.push(ev);
        }
    }

    async fn debug(&mut self, name: &str) -> Value {
        match self
            .wait(
                name,
                |e| matches!(e, BackendEvent::Debug { event, .. } if event == name),
            )
            .await
        {
            BackendEvent::Debug { details, .. } => details,
            _ => unreachable!(),
        }
    }

    /// Everything that arrives within `ms`, kept for later `wait`s.
    async fn settle(&mut self, ms: u64) {
        let until = Instant::now() + Duration::from_millis(ms);
        while let Ok(Some(ev)) = tokio::time::timeout(
            until.saturating_duration_since(Instant::now()),
            self.events.recv(),
        )
        .await
        {
            self.seen.push(ev);
        }
    }
}

/// `Backend::start`, three tries: a node still starting under a loaded
/// test run may not open its WebSocket within `node::OPEN_TIMEOUT_MS`.
async fn start_with_retry(backend: &Backend, key: &SigningKey) {
    let mut tries = 0;
    while let Err(e) = backend.start(key.clone()).await {
        tries += 1;
        assert!(tries < 3, "start: {e:?}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn start_node(test: &str) -> Option<LocalNode> {
    if !freenet_available() {
        println!("SKIP {test}: freenet binary not on PATH");
        return None;
    }
    Some(LocalNode::start().expect("start a LocalNode"))
}

/// Connects `viewer` to `host`'s announced route; returns (viewer conn,
/// host conn).
async fn connect(
    host: &mut Peer,
    viewer: &mut Peer,
    r: &route::Route,
    link: &str,
) -> (ConnHandle, ConnHandle) {
    let handle = viewer
        .backend
        .dial(r.clone(), host.public(), Some(json!({"t": "dial"})));
    let dial_id = handle.id;
    let vconn = tokio::time::timeout(T, handle.connected)
        .await
        .expect("dial within 30 s")
        .expect("dial channel")
        .expect("dial connected");
    match viewer
        .wait(
            "viewer connection",
            |e| matches!(e, BackendEvent::Connection { conn, .. } if *conn == vconn),
        )
        .await
    {
        BackendEvent::Connection {
            remote_peer_key,
            initiator,
            link_id,
            ..
        } => {
            assert_eq!(
                remote_peer_key,
                host.public(),
                "the dial reached the expected key"
            );
            assert!(initiator);
            assert_eq!(link_id, None);
        }
        _ => unreachable!(),
    }
    viewer
        .wait("dialConnected", |e| matches!(e, BackendEvent::DialConnected { dial, conn } if *dial == dial_id && *conn == vconn))
        .await;
    let link = link.to_string();
    let viewer_key = viewer.public();
    let hconn = match host
        .wait("host connection", |e| matches!(e, BackendEvent::Connection { link_id: Some(l), remote_peer_key, .. } if *l == link && *remote_peer_key == viewer_key))
        .await
    {
        BackendEvent::Connection { conn, initiator, .. } => {
            assert!(!initiator);
            conn
        }
        _ => unreachable!(),
    };
    (vconn, hconn)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_backend_member_core_to_core() {
    let Some(node) = start_node("every_backend_member_core_to_core") else {
        return;
    };

    // describe, health and localPeerKey before start.
    let cold = Backend::new(opts(&node.url, None));
    let d = cold.describe();
    assert_eq!(d["id"], "freenet");
    assert_eq!(d["label"], "Freenet (experimental)");
    assert_eq!(d["interfaceVersion"], 1);
    assert_eq!(d["capabilities"], backend::CAPABILITIES);
    assert_eq!(
        cold.health(),
        json!({"started": false, "listening": false, "detail": null})
    );
    assert_eq!(cold.local_peer_key(), None);
    assert_eq!(cold.diagnostics()["announced"], 0);
    let err = cold.announce("x", None, None).await.unwrap_err();
    assert_eq!(err.code, Code::EBackendUnavailable, "announce before start");

    let mut host = Peer::start(&node.url, "host", None).await;
    let mut viewer = Peer::start(&node.url, "viewer", None).await;
    assert_eq!(host.backend.local_peer_key(), Some(host.public()));
    assert_eq!(
        host.backend.health(),
        json!({"started": true, "listening": false, "detail": null})
    );
    host.backend
        .start(host.key.clone())
        .await
        .expect("a second start is a no-op");

    // routeFor: minted offline, with the pointer; a stored route comes back.
    let minted = host.backend.route_for("link-a", None).expect("mint");
    assert_eq!(minted.params.host, hex::encode(host.public()));
    assert!(minted.ptr.is_some());
    assert_eq!(
        host.backend
            .route_for("link-a", Some(minted.clone()))
            .unwrap(),
        minted
    );
    assert_eq!(host.backend.history_route_for(), None);

    // announce: listening, counted, idempotent per link.
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-a", Some(minted.clone()), Some(json!({"t": "a"})))
        .await
        .expect("announce");
    assert_eq!(ann.route, minted);
    assert_eq!(ann.link_id, "link-a");
    host.debug("host:announce").await;
    assert_eq!(host.backend.health()["listening"], true);
    assert_eq!(host.backend.diagnostics()["announced"], 1);
    let again = host
        .backend
        .announce("link-a", None, None)
        .await
        .expect("announce again");
    assert_eq!(again.route, minted, "a known link keeps its route");
    assert_eq!(host.backend.diagnostics()["announced"], 1);

    // The pointer record names the link's own instance (design §5.2).
    let bundled = zxterm_core::freenet::contracts::bundled().unwrap();
    let ptr_params = route::pointer_params_bytes(&minted.params.host, &minted.params.n);
    let ptr_addr = node::contract_key(bundled.pointer_wasm, &ptr_params);
    assert_eq!(Some(&ptr_addr.id), minted.ptr.as_ref());
    let mut probe = node::Client::connect(&node.url).await.expect("client");
    let record: Value = serde_json::from_slice(
        &probe
            .get(ptr_addr.key.id(), 5000)
            .await
            .expect("the pointer record"),
    )
    .unwrap();
    assert_eq!(record["ver"], 1);
    assert_eq!(record["sig"], minted.sig);

    // dial: a connection on both sides.
    let (vconn, hconn) = connect(&mut host, &mut viewer, &minted, "link-a").await;
    assert!(
        !host.seen.iter().any(
            |e| matches!(e, BackendEvent::Debug { event, .. } if event == "host:pointer:error")
        ),
        "the pointer record was put: {:?}",
        host.seen
    );
    let hd = host.backend.diagnostics();
    assert_eq!(hd["conns"].as_array().unwrap().len(), 1);
    assert_eq!(hd["conns"][0]["peer"], hex::encode(viewer.public()));
    assert_eq!(hd["links"][0]["halfOpen"], 0);
    assert_eq!(hd["links"][0]["answeredLastMinute"], 1);
    assert_eq!(hd["ice"]["hostCandidatesOnly"], true);
    assert!(
        !hd.to_string().contains(&minted.k),
        "diagnostics never carry k"
    );

    // A JSON channel, both directions, a message larger than one part.
    let vctl = viewer
        .backend
        .open_channel(vconn, "zbterm/ctl", &[1])
        .expect("open ctl");
    let (proto, id) = match host
        .wait("incoming ctl", |e| matches!(e, BackendEvent::IncomingChannel { conn, protocol, .. } if *conn == hconn && protocol == "zbterm/ctl"))
        .await
    {
        BackendEvent::IncomingChannel { protocol, id, .. } => (protocol, id),
        _ => unreachable!(),
    };
    assert_eq!(id, vec![1]);
    let hctl = host
        .backend
        .open_channel(hconn, &proto, &id)
        .expect("take ctl");
    let big = json!({"type": "hello", "body": "x".repeat(150_000)});
    assert!(viewer.backend.send(vctl, &big));
    match host
        .wait(
            "ctl message",
            |e| matches!(e, BackendEvent::Message { chan, .. } if *chan == hctl),
        )
        .await
    {
        BackendEvent::Message { value, .. } => assert_eq!(value, big),
        _ => unreachable!(),
    }
    assert!(host.backend.send(hctl, &json!({"type": "welcome"})));
    match viewer
        .wait(
            "ctl reply",
            |e| matches!(e, BackendEvent::Message { chan, .. } if *chan == vctl),
        )
        .await
    {
        BackendEvent::Message { value, .. } => assert_eq!(value, json!({"type": "welcome"})),
        _ => unreachable!(),
    }

    // serveHistory / attachHistory: the raw history channel, idempotent.
    let hh = host.backend.serve_history(hconn).expect("serveHistory");
    assert_eq!(
        host.backend.serve_history(hconn).unwrap(),
        hh,
        "idempotent per connection"
    );
    // Before the viewer takes it, the opener cannot send: its queue grows
    // past the mark and reports back-pressure.
    let early = vec![7u8; QUEUE_HIGH_WATER + 1000];
    assert!(
        !host.backend.send_bytes(hh, &early),
        "back-pressure before READY"
    );
    match viewer
        .wait("incoming history", |e| matches!(e, BackendEvent::IncomingChannel { conn, protocol, .. } if *conn == vconn && protocol == "zbterm/history"))
        .await
    {
        BackendEvent::IncomingChannel { id, .. } => assert_eq!(id, backend::HISTORY_ID.to_vec()),
        _ => unreachable!(),
    }
    let vh = viewer.backend.attach_history(vconn).expect("attachHistory");
    host.wait(
        "drain",
        |e| matches!(e, BackendEvent::Drain { chan } if *chan == hh),
    )
    .await;
    let mut got = Vec::new();
    let mut sizes = Vec::new();
    while got.len() < early.len() {
        match viewer
            .wait(
                "history bytes",
                |e| matches!(e, BackendEvent::Bytes { chan, .. } if *chan == vh),
            )
            .await
        {
            BackendEvent::Bytes { bytes, .. } => {
                sizes.push(bytes.len());
                got.extend(bytes);
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(got, early, "the bytes arrive unchanged and in order");
    assert!(
        sizes.iter().all(|s| *s <= 65_536),
        "no data-channel message above 65 536 bytes"
    );
    // Raw bytes the other way, message boundaries kept for sends <= 64 KiB.
    for i in 0..5u8 {
        assert!(viewer.backend.send_bytes(vh, &vec![i; 1000 + i as usize]));
    }
    for i in 0..5u8 {
        match host
            .wait(
                "viewer bytes",
                |e| matches!(e, BackendEvent::Bytes { chan, .. } if *chan == hh),
            )
            .await
        {
            BackendEvent::Bytes { bytes, .. } => assert_eq!(bytes, vec![i; 1000 + i as usize]),
            _ => unreachable!(),
        }
    }

    // withdraw: the count falls, the connection survives, idempotent.
    host.backend.withdraw("link-a").await;
    host.debug("host:withdraw").await;
    assert_eq!(host.backend.diagnostics()["announced"], 0);
    assert_eq!(host.backend.health()["listening"], false);
    host.backend.withdraw("link-a").await;
    assert!(viewer.backend.send(vctl, &json!({"after": "withdraw"})));
    host.wait("message after withdraw", |e| matches!(e, BackendEvent::Message { chan, value } if *chan == hctl && value["after"] == "withdraw")).await;

    // Closing a channel closes it on the other side too.
    viewer.backend.close_channel(vctl);
    viewer
        .wait(
            "own close",
            |e| matches!(e, BackendEvent::ChannelClosed { chan } if *chan == vctl),
        )
        .await;
    host.wait(
        "remote close",
        |e| matches!(e, BackendEvent::ChannelClosed { chan } if *chan == hctl),
    )
    .await;

    // Cancelling a connected dial never closes the connection.
    let before = viewer.backend.diagnostics()["conns"]
        .as_array()
        .unwrap()
        .len();
    for id in 1..4 {
        viewer.backend.cancel_dial(id);
    }
    assert_eq!(
        viewer.backend.diagnostics()["conns"]
            .as_array()
            .unwrap()
            .len(),
        before
    );

    // Closing the connection ends it on both sides.
    viewer.backend.close_connection(vconn, "done");
    viewer
        .wait(
            "viewer conn closed",
            |e| matches!(e, BackendEvent::ConnectionClosed { conn, .. } if *conn == vconn),
        )
        .await;
    host.wait(
        "host conn closed",
        |e| matches!(e, BackendEvent::ConnectionClosed { conn, .. } if *conn == hconn),
    )
    .await;
    host.wait(
        "history closed with it",
        |e| matches!(e, BackendEvent::ChannelClosed { chan } if *chan == hh),
    )
    .await;

    // stop, twice.
    viewer.backend.stop().await;
    viewer.backend.stop().await;
    host.backend.stop().await;
    host.backend.stop().await;
    assert_eq!(host.backend.health()["started"], false);
    assert_eq!(host.backend.diagnostics()["announced"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_to_the_wrong_key_never_connects_and_start_without_a_node_fails() {
    let Some(node) =
        start_node("a_dial_to_the_wrong_key_never_connects_and_start_without_a_node_fails")
    else {
        return;
    };
    let host = Peer::start(&node.url, "host2", None).await;
    let viewer = Peer::start(&node.url, "viewer2", None).await;
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-b", None, None)
        .await
        .expect("announce");
    let wrong = key("wrong").verifying_key().to_bytes();
    let mut handle = viewer.backend.dial(ann.route.clone(), wrong, None);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(handle.connected.try_recv().is_err(), "still pending");
    viewer.backend.cancel_dial(handle.id);
    let res = tokio::time::timeout(T, handle.connected)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(res.unwrap_err().message, "Dial was cancelled");
    assert!(
        host.backend.diagnostics()["conns"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // No node: E_BACKEND_UNAVAILABLE and the D-12 health detail.
    let port = zxterm_testkit::local_node::free_port().unwrap();
    let url = format!("ws://127.0.0.1:{port}/v1/contract/command");
    let lonely = Backend::new(opts(&url, None));
    let err = lonely.start(key("lonely")).await.unwrap_err();
    assert_eq!(err.code, Code::EBackendUnavailable);
    let detail = format!("no Freenet node at ws://127.0.0.1:{port}");
    assert_eq!(err.details.as_deref(), Some(detail.as_str()));
    assert_eq!(
        lonely.health(),
        json!({"started": false, "listening": false, "detail": detail})
    );
    let probe = Backend::probe(&url, 500).await;
    assert_eq!(probe, json!({"state": "broken", "detail": detail}));
    let ok = Backend::probe(&node.url, 2000).await;
    assert_eq!(ok, json!({"state": "available", "detail": null}));
    host.backend.stop().await;
    viewer.backend.stop().await;
}

/// A real SDP offer (str0m's), taken from a throwaway peer connection that
/// is closed at once, so a host that answers it never completes ICE: the
/// session stays half-open.
async fn throwaway_offer() -> String {
    let rtc = RtcHost::loopback_only(vec![]);
    rtc.open(1, Some(vec![]));
    rtc.open_channel(1, 0, zxterm_core::wire::BOOTSTRAP_LABEL);
    let sdp = tokio::time::timeout(T, async {
        loop {
            if let Some(RtcEvent::Signal {
                msg: SignalMsg::Offer { sdp },
                ..
            }) = rtc.recv_event().await
            {
                return sdp;
            }
        }
    })
    .await
    .expect("an offer");
    rtc.close_all("taken");
    sdp
}

/// A viewer that writes signed, sealed offers straight to the link's
/// signalling contract and never completes the handshake.
struct FakeViewers {
    client: node::Client,
    route: route::Route,
    params: Vec<u8>,
    key: freenet_stdlib::prelude::ContractKey,
    sdp: String,
}

impl FakeViewers {
    async fn offer(&mut self, viewer: &SigningKey) {
        let cid =
            hex::encode(&blake3::hash(format!("{:?}", Instant::now()).as_bytes()).as_bytes()[..16]);
        let payload = json!({"cid": cid, "m": [{"type": "offer", "sdp": self.sdp}]});
        let p = signal::seal(&signal::payload_key(&self.route.k), &payload);
        let r = format!("v:{}", hex::encode(viewer.verifying_key().to_bytes()));
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let e = signal::sign_entry(
            viewer,
            &self.params,
            &signal::EntryFields {
                l: &cid,
                r: &r,
                s: 0,
                t,
                d: false,
                p: &p,
            },
        );
        let delta =
            json!({"e": [{"l": e.l, "r": e.r, "s": e.s, "t": e.t, "d": e.d, "p": e.p, "g": e.g}]});
        self.client
            .update(
                &self.key,
                serde_json::to_vec(&delta).unwrap(),
                node::REQUEST_TIMEOUT_MS,
            )
            .await
            .expect("write an offer");
    }
}

/// Offers from `viewer` and returns the host's verdict: `None` answered,
/// `Some(reason)` refused.
async fn verdict(host: &mut Peer, fake: &mut FakeViewers, viewer: &SigningKey) -> Option<String> {
    fake.offer(viewer).await;
    let peer = hex::encode(viewer.verifying_key().to_bytes());
    let ev = host
        .wait("an offer verdict", |e| {
            matches!(e, BackendEvent::Debug { event, details }
                if (event == "host:offer" || event == "host:offer-refused") && details["peer"] == peer)
        })
        .await;
    match ev {
        BackendEvent::Debug { event, details } if event == "host:offer-refused" => {
            let reason = details["reason"].as_str().unwrap().to_string();
            let refusal = Refusal::parse(&reason).expect("a known reason");
            assert_eq!(details["code"], refusal.to_error().code.as_str());
            Some(reason)
        }
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_refusals_half_open_viewer_half_open_and_rate() {
    let Some(node) = start_node("admission_refusals_half_open_viewer_half_open_and_rate") else {
        return;
    };
    let now = Arc::new(AtomicU64::new(1_000_000_000));
    let clock_now = now.clone();
    let clock: backend::Clock = Arc::new(move || clock_now.load(Ordering::SeqCst));
    let mut host = Peer::start(&node.url, "limits-host", Some(clock)).await;
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-limits", None, None)
        .await
        .expect("announce");
    let bundled = zxterm_core::freenet::contracts::bundled().unwrap();
    let params = route::params_bytes(&ann.route.params);
    let addr = node::contract_key(&bundled.route.known[&ann.route.code], &params);
    let mut fake = FakeViewers {
        client: node::Client::connect(&node.url).await.expect("client"),
        route: ann.route.clone(),
        params,
        key: addr.key,
        sdp: throwaway_offer().await,
    };
    let viewers: Vec<SigningKey> = (0..20).map(|i| key(&format!("v{i}"))).collect();

    // half-open-viewer: one key holds at most MAX_HALF_OPEN_PER_VIEWER.
    assert_eq!(verdict(&mut host, &mut fake, &viewers[0]).await, None);
    assert_eq!(verdict(&mut host, &mut fake, &viewers[0]).await, None);
    assert_eq!(
        verdict(&mut host, &mut fake, &viewers[0]).await.as_deref(),
        Some("half-open-viewer")
    );

    // half-open: the link holds at most MAX_HALF_OPEN.
    for v in &viewers[1..4] {
        assert_eq!(verdict(&mut host, &mut fake, v).await, None);
        assert_eq!(verdict(&mut host, &mut fake, v).await, None);
    }
    assert_eq!(
        host.backend.diagnostics()["links"][0]["halfOpen"],
        backend::MAX_HALF_OPEN
    );
    assert_eq!(
        verdict(&mut host, &mut fake, &viewers[4]).await.as_deref(),
        Some("half-open")
    );

    // rate: past the half-open deadline the slots free (S-22), but at most
    // MAX_ANSWERS_PER_MINUTE offers are answered per window.
    let mut answered = 8;
    let mut next = 5;
    while answered < backend::MAX_ANSWERS_PER_MINUTE {
        now.fetch_add(backend::HALF_OPEN_TIMEOUT_MS + 1000, Ordering::SeqCst);
        for _ in 0..8 {
            if answered == backend::MAX_ANSWERS_PER_MINUTE {
                break;
            }
            let v = viewers[next / 2].clone();
            next += 1;
            assert_eq!(
                verdict(&mut host, &mut fake, &v).await,
                None,
                "answer {answered}"
            );
            answered += 1;
        }
    }
    host.settle(200).await;
    let expired = host
        .seen
        .iter()
        .filter(
            |e| matches!(e, BackendEvent::Debug { event, .. } if event == "host:half-open-expired"),
        )
        .count();
    assert!(
        expired >= 16,
        "stale half-open sessions expired ({expired})"
    );
    assert_eq!(
        host.backend.diagnostics()["links"][0]["answeredLastMinute"],
        30
    );
    let fresh_viewer = key("rate-viewer");
    assert_eq!(
        verdict(&mut host, &mut fake, &fresh_viewer)
            .await
            .as_deref(),
        Some("rate")
    );
    // Past the window, offers are answered again.
    now.fetch_add(backend::ANSWER_WINDOW_MS, Ordering::SeqCst);
    let later = key("later-viewer");
    assert_eq!(verdict(&mut host, &mut fake, &later).await, None);
    host.backend.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admission_policy_refuses_and_a_pinned_key_is_admitted() {
    let Some(node) = start_node("the_admission_policy_refuses_and_a_pinned_key_is_admitted") else {
        return;
    };
    let mut host = Peer::start(&node.url, "policy-host", None).await;
    let mut viewer = Peer::start(&node.url, "policy-viewer", None).await;
    // The default policy admits nobody.
    let ann = host
        .backend
        .announce("link-p", None, None)
        .await
        .expect("announce");
    let bundled = zxterm_core::freenet::contracts::bundled().unwrap();
    let params = route::params_bytes(&ann.route.params);
    let addr = node::contract_key(&bundled.route.known[&ann.route.code], &params);
    let mut fake = FakeViewers {
        client: node::Client::connect(&node.url).await.expect("client"),
        route: ann.route.clone(),
        params,
        key: addr.key,
        sdp: throwaway_offer().await,
    };
    let stranger = key("stranger");
    assert_eq!(
        verdict(&mut host, &mut fake, &stranger).await.as_deref(),
        Some("admission")
    );
    // A key set admits exactly its keys: the real viewer connects.
    let mut keys = std::collections::HashSet::new();
    keys.insert(viewer.public());
    host.backend.set_admission(Admission::Keys(keys));
    let (vconn, _hconn) = connect(&mut host, &mut viewer, &ann.route, "link-p").await;
    assert!(viewer.backend.connection_info(vconn).is_some());
    assert_eq!(host.backend.diagnostics()["links"][0]["refused"], 1);
    host.backend.stop().await;
    viewer.backend.stop().await;
}

/// Design §5.2: a route whose contract code this build does not ship is
/// followed through its pointer record, which names the link's instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_with_an_unknown_code_follows_the_pointer_record() {
    let Some(node) = start_node("a_dial_with_an_unknown_code_follows_the_pointer_record") else {
        return;
    };
    let mut host = Peer::start(&node.url, "ptr-host", None).await;
    let mut viewer = Peer::start(&node.url, "ptr-viewer", None).await;
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-ptr", None, None)
        .await
        .expect("announce");
    let mut moved = ann.route.clone();
    moved.code = hex::encode([0x5a; 32]);
    moved.sig = route::instance_id_b58(&moved.code, &route::params_bytes(&moved.params));
    let (vconn, _) = connect(&mut host, &mut viewer, &moved, "link-ptr").await;
    viewer
        .wait(
            "viewer:pointer",
            |e| matches!(e, BackendEvent::Debug { event, .. } if event == "viewer:pointer"),
        )
        .await;
    assert!(viewer.backend.connection_info(vconn).is_some());
    host.backend.stop().await;
    viewer.backend.stop().await;
}

/// Reported, not gated (`X-10`'s throughput question): 16 MiB over a raw
/// channel between two Rust backends, in 64 KiB sends that wait for a
/// drain under back-pressure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_channel_throughput_reported_not_gated() {
    let Some(node) = start_node("raw_channel_throughput_reported_not_gated") else {
        return;
    };
    let mut host = Peer::start(&node.url, "tp-host", None).await;
    let mut viewer = Peer::start(&node.url, "tp-viewer", None).await;
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-tp", None, None)
        .await
        .expect("announce");
    let (vconn, hconn) = connect(&mut host, &mut viewer, &ann.route, "link-tp").await;
    let vch = viewer
        .backend
        .open_raw(vconn, "zxterm/bulk", &[9])
        .expect("open");
    host.wait("incoming bulk", |e| matches!(e, BackendEvent::IncomingChannel { protocol, .. } if protocol == "zxterm/bulk")).await;
    let hch = host
        .backend
        .open_raw(hconn, "zxterm/bulk", &[9])
        .expect("take");
    const TOTAL: usize = 16 * 1024 * 1024;
    let chunk = vec![0xabu8; 64 * 1024];
    let started = Instant::now();
    let sender = viewer.backend.clone();
    let mut viewer_events = viewer.events;
    let send = tokio::spawn(async move {
        let mut sent = 0;
        while sent < TOTAL {
            let more = sender.send_bytes(vch, &chunk);
            sent += chunk.len();
            if !more {
                loop {
                    match viewer_events.recv().await {
                        Some(BackendEvent::Drain { chan }) if chan == vch => break,
                        Some(_) => {}
                        None => return,
                    }
                }
            }
        }
    });
    let mut got = 0usize;
    while got < TOTAL {
        match host
            .wait(
                "bulk bytes",
                |e| matches!(e, BackendEvent::Bytes { chan, .. } if *chan == hch),
            )
            .await
        {
            BackendEvent::Bytes { bytes, .. } => got += bytes.len(),
            _ => unreachable!(),
        }
    }
    let secs = started.elapsed().as_secs_f64();
    send.await.unwrap();
    println!(
        "raw channel throughput (reported, not gated): 16 MiB in {secs:.2} s = {:.2} MiB/s",
        16.0 / secs
    );
    assert_eq!(got, TOTAL);
    host.backend.stop().await;
    viewer.backend.stop().await;
}

/// K11 (`R-11`, `R-12`): a raw channel flooded faster than the connection
/// carries it says so. `send_bytes` returns `false` once the channel's
/// backlog passes the marks (before K11 `str0m` refused writes long before
/// its own buffer reached `rtc::HIGH_WATER_MARK`, the refused parts waited
/// without bound, and a sender never heard of it), each episode is one
/// `Backpressure` event and ends with one `Drain`, in that order on the
/// event stream, and nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flooded_raw_channel_reports_backpressure_then_drains_in_order() {
    let Some(node) = start_node("a_flooded_raw_channel_reports_backpressure_then_drains_in_order")
    else {
        return;
    };
    let mut host = Peer::start(&node.url, "bp-host", None).await;
    let mut viewer = Peer::start(&node.url, "bp-viewer", None).await;
    host.backend.set_admission(Admission::All(true));
    let ann = host
        .backend
        .announce("link-bp", None, None)
        .await
        .expect("announce");
    let (vconn, hconn) = connect(&mut host, &mut viewer, &ann.route, "link-bp").await;
    let vch = viewer
        .backend
        .open_raw(vconn, "zxterm/flood", &[7])
        .expect("open");
    host.wait("incoming flood", |e| matches!(e, BackendEvent::IncomingChannel { protocol, .. } if protocol == "zxterm/flood")).await;
    let hch = host
        .backend
        .open_raw(hconn, "zxterm/flood", &[7])
        .expect("take");
    const TOTAL: usize = 8 * 1024 * 1024;
    let chunk = vec![0x5au8; 64 * 1024];
    // The whole flood at once, ignoring every refusal (advisory
    // back-pressure: nothing is dropped).
    let mut refused = 0;
    for _ in 0..TOTAL / chunk.len() {
        if !viewer.backend.send_bytes(vch, &chunk) {
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "send_bytes reported back-pressure during the flood"
    );
    let mut got = 0usize;
    while got < TOTAL {
        match host
            .wait(
                "flood bytes",
                |e| matches!(e, BackendEvent::Bytes { chan, .. } if *chan == hch),
            )
            .await
        {
            BackendEvent::Bytes { bytes, .. } => got += bytes.len(),
            _ => unreachable!(),
        }
    }
    assert_eq!(got, TOTAL, "every byte arrived");
    // The viewer's events: Backpressure and Drain alternate, starting with
    // Backpressure and ending with Drain.
    viewer.settle(500).await;
    let flow: Vec<&'static str> = viewer
        .seen
        .iter()
        .filter_map(|e| match e {
            BackendEvent::Backpressure { chan } if *chan == vch => Some("backpressure"),
            BackendEvent::Drain { chan } if *chan == vch => Some("drain"),
            _ => None,
        })
        .collect();
    assert!(!flow.is_empty(), "the refusals were reported");
    for (i, kind) in flow.iter().enumerate() {
        let want = if i % 2 == 0 { "backpressure" } else { "drain" };
        assert_eq!(*kind, want, "event {i} of {flow:?}");
    }
    assert_eq!(flow.last(), Some(&"drain"), "the last episode drained");
    println!(
        "flooded raw channel: {refused} refused sends, {} back-pressure episodes",
        flow.len() / 2
    );
    host.backend.stop().await;
    viewer.backend.stop().await;
}

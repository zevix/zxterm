//! K13 core-to-core conformance of the session protocol v2
//! (`docs/projects/260928_zxterm-core/protocol.md`): two or more
//! `zxterm_core::session::SessionService`s, each on its own
//! `zxterm_core::freenet::backend::Backend`, over one throwaway `LocalNode`
//! (`zxterm_testkit::local_node`, never the owner's node, loopback only, no
//! ICE servers). Every case of the plan's step 10 is its own test, each
//! independently asserted:
//!
//! - join with approval, and with denial;
//! - `VIEW_LIVE` live frames, decrypted in order;
//! - `SEND_INPUT`-gated input (a viewer without it is refused), and input
//!   dropped while the input mode is `'host'`;
//! - rotation on every join (three joins, three rotations, the `except`
//!   rule counted), **no** rotation on a viewer disconnect (owner `Q-15`,
//!   `protocol.md` §4 and §15: the plan's "rotation on leave" is dropped);
//! - rotation on member revocation and on link revocation, a revoked
//!   member's stale envelope failing to decrypt the post-rotation live
//!   frames, and a late join on a revoked link refused in-band;
//! - ZBTerm `S-42` (approving a join after `revokeLink` is refused, the
//!   pending approval is cancelled) and `S-43` (a restarted viewer's input
//!   is accepted after it rejoins);
//! - lag resync under a synthetic flood, with `_resyncPeer`'s doubling
//!   backoff checked event by event;
//! - identity verified, unknown (no claim presented) and failed (a claim
//!   with a bad signature);
//! - a `pv`-less route refused by the v2 verifier with the named-upgrade
//!   message, and a `pv: 2` route verified normally;
//! - the `history` channel's range request answered, an unknown link
//!   answered `ENDED`, a single-use link consumed.
//!
//! Needs `freenet` on `PATH`; every test skips with a printed reason
//! otherwise.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crypto_box::aead::OsRng;
use crypto_box::aead::rand_core::RngCore;
use ed25519_dalek::SigningKey;
use ed25519_dalek::ed25519::signature::Signer;
use tokio::sync::mpsc::UnboundedReceiver;

use zxterm_core::Code;
use zxterm_core::freenet::backend::{Admission, Backend, BackendEvent, BackendOptions};
use zxterm_core::freenet::route::{self, Route};
use zxterm_core::identity::claim::{self, Claim};
use zxterm_core::identity::github::PublishedKey;
use zxterm_core::identity::resolver::{FetchAnswer, IdentityResolver, ResolverOptions};
use zxterm_core::idkey::IdentityKey;
use zxterm_core::session::caps::{FULL_CAPS, READ_HISTORY, SEND_INPUT, VIEW_LIVE};
use zxterm_core::session::envelope;
use zxterm_core::session::host::{LinkKind, LinkSpec, MemberStatus};
use zxterm_core::session::messages::{InputMode, JoinReason, LiveMsg, SessionInfo};
use zxterm_core::session::packet;
use zxterm_core::session::service::{
    HostOpen, JoinSpec, JoinStatus, LiveKind, RotationReason, ServiceOptions, SessionEvent,
    SessionService,
};
use zxterm_core::session::{LAG_RESYNC_MAX_MS, LAG_RESYNC_MS, LocalIdentity};
use zxterm_core::ssh::sshsig;
use zxterm_core::wire;
use zxterm_testkit::local_node::{LocalNode, freenet_available};

const T: Duration = Duration::from_secs(30);

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

fn start_node(test: &str) -> Option<LocalNode> {
    if !freenet_available() {
        println!("SKIP {test}: freenet binary not on PATH");
        return None;
    }
    Some(LocalNode::start().expect("start a LocalNode"))
}

/// The published SSH keys the test resolver answers with (no network).
type Registry = Arc<Mutex<Vec<PublishedKey>>>;

fn resolver(registry: &Registry) -> Arc<IdentityResolver> {
    let registry = registry.clone();
    Arc::new(IdentityResolver::new(ResolverOptions {
        fetch: Some(Box::new(move |_provider, _subject| {
            Ok(FetchAnswer {
                status: "ok".into(),
                keys: registry.lock().unwrap().clone(),
            })
        })),
        ..Default::default()
    }))
}

/// A device identity: a fresh X25519 device key, an identity key and its
/// proof over the device key; with `claim`, a GitHub claim signed by a fresh
/// SSH key published in `registry`, and the auth key that answers
/// challenges (`tamper`: the claim's SSHSIG is corrupted).
fn identity(name: &str, claim: Option<(&Registry, bool)>) -> LocalIdentity {
    let (device_pk, device_sk) = envelope::generate_device_key();
    let id = IdentityKey::from_seed(random::<64>().to_vec());
    let mut local = LocalIdentity {
        device_secret_key: device_sk,
        identity_key: id.identity_public_key(),
        identity_proof: id.bootstrap(device_pk, now_ms()),
        device_name: name.to_string(),
        claim: None,
        auth_secret_key: None,
    };
    if let Some((registry, tamper)) = claim {
        let auth = SigningKey::from_bytes(&random::<32>());
        let mut auth_secret = [0u8; 64];
        auth_secret[..32].copy_from_slice(&auth.to_bytes());
        auth_secret[32..].copy_from_slice(&auth.verifying_key().to_bytes());
        let ssh = SigningKey::from_bytes(&random::<32>());
        let blob = claim::encode_ed25519_public_key(&ssh.verifying_key().to_bytes()).unwrap();
        let fingerprint = zxterm_core::ssh::key::fingerprint(&blob);
        let blob_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&blob)
        };
        let mut c = Claim {
            provider: Some("github".into()),
            subject: Some(format!("{name}-user")),
            identity_key: Some(hex::encode(local.identity_key)),
            auth_key: Some(hex::encode(auth.verifying_key().to_bytes())),
            ssh_fingerprint: Some(fingerprint.clone()),
            issued_at: Some(now_ms() as i64),
            nonce: Some(hex::encode(random::<16>())),
            signature: None,
            ssh_public_key: Some(blob_b64.clone()),
        };
        let signed =
            sshsig::signed_data_blob(wire::NAMESPACE, wire::HASH_ALG, &claim::claim_bytes(&c));
        let mut raw = ssh.sign(&signed).to_bytes();
        if tamper {
            raw[10] ^= 0x55;
        }
        c.signature = Some(
            sshsig::build_armored_signature(&blob, &raw, wire::NAMESPACE, wire::HASH_ALG).unwrap(),
        );
        registry.lock().unwrap().push(PublishedKey {
            key_type: "ssh-ed25519".into(),
            blob_base64: blob_b64,
            fingerprint,
        });
        local.claim = Some(c);
        local.auth_secret_key = Some(auth_secret);
    }
    local
}

/// One service on its own backend, with every event it reported.
struct Side {
    svc: SessionService,
    rx: UnboundedReceiver<SessionEvent>,
    /// Events not yet taken by a `wait`.
    seen: Vec<SessionEvent>,
    /// Every event, in order.
    all: Vec<SessionEvent>,
    /// Answer `BootstrapNeeded` at once (the host's caller building its
    /// screen).
    auto_bootstrap: bool,
    boots: u64,
    key: SigningKey,
}

impl Side {
    async fn start(url: &str, opts: ServiceOptions) -> Side {
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
        Side {
            svc,
            rx,
            seen: Vec::new(),
            all: Vec::new(),
            auto_bootstrap: true,
            boots: 0,
            key,
        }
    }

    fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn take(&mut self, ev: SessionEvent) {
        if let SessionEvent::BootstrapNeeded {
            session_id,
            request_id,
            scrollback,
            ..
        } = &ev
            && self.auto_bootstrap
        {
            self.boots += 1;
            let doc = serde_json::json!({"boot": self.boots, "resync": scrollback.is_some()});
            self.svc
                .provide_bootstrap(session_id, *request_id, doc.to_string().as_bytes())
                .expect("provide bootstrap");
        }
        self.all.push(ev.clone());
        self.seen.push(ev);
    }

    /// Waits for (and removes from `seen`) the first event `pred` accepts.
    async fn wait(
        &mut self,
        what: &str,
        mut pred: impl FnMut(&SessionEvent) -> bool,
    ) -> SessionEvent {
        if let Some(pos) = self.seen.iter().position(&mut pred) {
            return self.seen.remove(pos);
        }
        let deadline = Instant::now() + T;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let ev = tokio::time::timeout(left, self.rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}; seen {:#?}", self.seen))
                .expect("event stream");
            self.take(ev);
            if let Some(pos) = self.seen.iter().position(&mut pred) {
                return self.seen.remove(pos);
            }
        }
    }

    /// Everything that arrives within `ms`.
    async fn settle(&mut self, ms: u64) {
        let until = Instant::now() + Duration::from_millis(ms);
        while let Ok(Some(ev)) = tokio::time::timeout(
            until.saturating_duration_since(Instant::now()),
            self.rx.recv(),
        )
        .await
        {
            self.take(ev);
        }
    }

    fn count(&self, pred: impl Fn(&SessionEvent) -> bool) -> usize {
        self.all.iter().filter(|e| pred(e)).count()
    }

    async fn join_status(&mut self, join_id: &str, status: JoinStatus) -> SessionEvent {
        let j = join_id.to_string();
        self.wait(status.as_str(), move |e| {
            matches!(e, SessionEvent::JoinChanged { join_id, status: s, .. } if *join_id == j && *s == status)
        })
        .await
    }

    /// The join's end: failed or left, with its code/reason/message.
    async fn join_failed(
        &mut self,
        join_id: &str,
    ) -> (Option<Code>, Option<JoinReason>, Option<String>) {
        let j = join_id.to_string();
        match self
            .wait("the join to fail", move |e| {
                matches!(e, SessionEvent::JoinChanged { join_id, status: JoinStatus::Failed, .. } if *join_id == j)
            })
            .await
        {
            SessionEvent::JoinChanged {
                code,
                reason,
                message,
                ..
            } => (code, reason, message),
            _ => unreachable!(),
        }
    }
}

struct Hosted {
    sid: String,
    route: Route,
}

fn link(kind: LinkKind, auto_join: bool, caps: Option<u8>) -> LinkSpec {
    LinkSpec {
        link_id: random::<16>(),
        kind,
        max_viewers: 99,
        auto_join,
        caps,
    }
}

/// Opens a hosted session (input mode `input`) and announces `link`.
async fn host_session(
    h: &mut Side,
    local: LocalIdentity,
    link: &LinkSpec,
    input: InputMode,
) -> Hosted {
    let sid = hex::encode(random::<32>());
    h.svc
        .host_open(HostOpen {
            session_id: sid.clone(),
            info: SessionInfo {
                name: "conformance".into(),
                created_at: now_ms(),
                sensitive: false,
                quick_catchup_kb: 0,
                cols: 80,
                rows: 24,
            },
            input_mode: input,
            log_key: random::<32>(),
            meta_key: random::<32>(),
            local,
            first_epoch: 1,
        })
        .expect("host_open");
    h.svc.backend().set_admission(Admission::All(true));
    let route = add_link(h, &sid, link).await;
    Hosted { sid, route }
}

async fn add_link(h: &mut Side, sid: &str, link: &LinkSpec) -> Route {
    let ann = h
        .svc
        .backend()
        .announce(&hex::encode(link.link_id), None, None)
        .await
        .expect("announce");
    h.svc.add_link(sid, link.clone()).expect("add_link");
    ann.route
}

fn join(v: &Side, host: &Side, hosted: &Hosted, link: &LinkSpec, local: LocalIdentity) -> String {
    v.svc
        .join(JoinSpec {
            route: hosted.route.clone(),
            expected_peer_key: host.public(),
            link_id: link.link_id,
            local,
        })
        .expect("join")
}

/// Joins through an auto-join link and waits for `joined` (or `syncing`
/// for a peer without `VIEW_LIVE`).
async fn join_ok(
    v: &mut Side,
    host: &mut Side,
    hosted: &Hosted,
    link: &LinkSpec,
    local: LocalIdentity,
) -> String {
    let j = join(v, host, hosted, link, local);
    v.join_status(&j, JoinStatus::Confirmed).await;
    if link.caps.is_none_or(|c| c & VIEW_LIVE != 0) {
        // The host's caller answers the grant's BootstrapNeeded.
        host.wait("the grant's bootstrap request", |e| {
            matches!(
                e,
                SessionEvent::BootstrapNeeded {
                    scrollback: None,
                    ..
                }
            )
        })
        .await;
        v.join_status(&j, JoinStatus::Joined).await;
    } else {
        v.join_status(&j, JoinStatus::Syncing).await;
    }
    j
}

fn epochs(h: &Side, reason: RotationReason) -> Vec<u32> {
    h.all
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Epoch {
                epoch, reason: r, ..
            } if *r == reason => Some(*epoch),
            _ => None,
        })
        .collect()
}

fn rekeys(v: &Side) -> Vec<u32> {
    v.all
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Rekey { epoch, .. } => Some(*epoch),
            _ => None,
        })
        .collect()
}

fn opts() -> ServiceOptions {
    ServiceOptions::default()
}

// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_with_approval() {
    let Some(node) = start_node("join_with_approval") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, false, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let local = identity("viewer", None);
    let identity_key = local.identity_key;
    let j = join(&v, &h, &hosted, &l, local);
    v.join_status(&j, JoinStatus::ApprovalPending).await;
    let pending = match h
        .wait("share.pending", |e| {
            matches!(e, SessionEvent::Pending { .. })
        })
        .await
    {
        SessionEvent::Pending {
            join_id,
            identity_key: k,
            link_id,
            ..
        } => {
            assert_eq!(k, identity_key);
            assert_eq!(link_id, l.link_id);
            join_id
        }
        _ => unreachable!(),
    };
    assert_eq!(
        h.svc.host_status(&hosted.sid).unwrap().epoch,
        1,
        "nothing rotates before the grant"
    );
    h.svc.approve(&hosted.sid, &pending).expect("approve");
    h.wait("the grant's bootstrap request", |e| {
        matches!(
            e,
            SessionEvent::BootstrapNeeded {
                scrollback: None,
                ..
            }
        )
    })
    .await;
    let confirmed = v.join_status(&j, JoinStatus::Confirmed).await;
    let SessionEvent::JoinChanged {
        confirm: Some(c), ..
    } = confirmed
    else {
        panic!("no confirm info")
    };
    assert_eq!(c.session_id, hosted.sid);
    assert_eq!(c.epoch, 2, "the join rotated to epoch 2");
    assert_eq!(c.caps, FULL_CAPS);
    v.join_status(&j, JoinStatus::Joined).await;
    // No claims: both sides record `unknown`.
    h.wait(
        "host peerIdentity",
        |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status == "unknown"),
    )
    .await;
    v.wait(
        "viewer peerIdentity",
        |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status == "unknown"),
    )
    .await;
    let st = h.svc.host_status(&hosted.sid).unwrap();
    assert_eq!(st.epoch, 2);
    assert_eq!(st.confirmed.len(), 1);
    assert_eq!(st.members, vec![(identity_key, MemberStatus::Active)]);
    // The `except` rule: the joiner gets its epoch in `Confirm`, no `Rekey`.
    v.settle(300).await;
    assert!(rekeys(&v).is_empty(), "no rekey for the joiner");
    println!("join with approval: ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_with_denial() {
    let Some(node) = start_node("join_with_denial") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, false, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let j = join(&v, &h, &hosted, &l, identity("viewer", None));
    let pending = match h
        .wait("share.pending", |e| {
            matches!(e, SessionEvent::Pending { .. })
        })
        .await
    {
        SessionEvent::Pending { join_id, .. } => join_id,
        _ => unreachable!(),
    };
    h.svc.deny(&hosted.sid, &pending).expect("deny");
    let (code, reason, message) = v.join_failed(&j).await;
    assert_eq!(code, Some(Code::EAuth));
    assert_eq!(reason, Some(JoinReason::Denied));
    assert_eq!(message.as_deref(), Some("Join request denied"));
    let st = h.svc.host_status(&hosted.sid).unwrap();
    assert_eq!((st.epoch, st.confirmed.len(), st.members.len()), (1, 0, 0));
    assert!(
        h.svc.approve(&hosted.sid, &pending).is_err(),
        "no longer pending"
    );
    println!("join with denial: ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn view_live_frames_arrive_decrypted_in_order() {
    let Some(node) = start_node("view_live_frames_arrive_decrypted_in_order") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, true, Some(VIEW_LIVE));
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    join_ok(&mut v, &mut h, &hosted, &l, identity("viewer", None)).await;
    let first = v
        .all
        .iter()
        .find_map(|e| match e {
            SessionEvent::Live {
                kind: LiveKind::Bootstrap,
                data,
                ..
            } => Some(String::from_utf8(data.clone()).unwrap()),
            _ => None,
        })
        .expect("the first Bootstrap");
    assert!(first.contains("\"boot\":1"), "{first}");
    for i in 0..5u8 {
        h.svc
            .push(&hosted.sid, format!("line {i}\r\n").as_bytes(), i == 4)
            .unwrap();
    }
    let mut got = Vec::new();
    while got.len() < 5 {
        match v
            .wait("output", |e| matches!(e, SessionEvent::Output { .. }))
            .await
        {
            SessionEvent::Output { data, hd, .. } => {
                got.push((String::from_utf8(data).unwrap(), hd))
            }
            _ => unreachable!(),
        }
    }
    let want: Vec<(String, bool)> = (0..5).map(|i| (format!("line {i}\r\n"), i == 4)).collect();
    assert_eq!(got, want);
    // A viewer without READ_HISTORY gets no timeline.
    h.svc
        .send_live_json(&hosted.sid, LiveKind::Timeline, b"{\"items\":[]}", None)
        .unwrap();
    h.svc.push(&hosted.sid, b"after", false).unwrap();
    v.wait(
        "output after",
        |e| matches!(e, SessionEvent::Output { data, .. } if data == b"after"),
    )
    .await;
    assert_eq!(
        v.count(|e| matches!(
            e,
            SessionEvent::Live {
                kind: LiveKind::Timeline,
                ..
            }
        )),
        0
    );
    println!("live frames: 5 in order");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_is_gated_by_send_input() {
    let Some(node) = start_node("input_is_gated_by_send_input") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut with = Side::start(&node.url, opts()).await;
    let mut without = Side::start(&node.url, opts()).await;
    let l_input = link(LinkKind::Group, true, Some(VIEW_LIVE | SEND_INPUT));
    let l_view = link(LinkKind::Group, true, Some(VIEW_LIVE));
    let hosted = host_session(&mut h, identity("host", None), &l_input, InputMode::All).await;
    let route2 = add_link(&mut h, &hosted.sid, &l_view).await;
    join_ok(
        &mut with,
        &mut h,
        &hosted,
        &l_input,
        identity("typist", None),
    )
    .await;
    let hosted2 = Hosted {
        sid: hosted.sid.clone(),
        route: route2,
    };
    join_ok(
        &mut without,
        &mut h,
        &hosted2,
        &l_view,
        identity("watcher", None),
    )
    .await;

    assert_eq!(with.svc.input(&hosted.sid, b"ls\n").unwrap(), 1);
    match h
        .wait("share.input", |e| matches!(e, SessionEvent::Input { .. }))
        .await
    {
        SessionEvent::Input { data, .. } => assert_eq!(data, b"ls\n"),
        _ => unreachable!(),
    }
    // Without SEND_INPUT: sealed and sent, refused by the host.
    without.svc.input(&hosted.sid, b"rm -rf /\n").unwrap();
    match h
        .wait("share.inputRefused", |e| {
            matches!(e, SessionEvent::InputRefused { .. })
        })
        .await
    {
        SessionEvent::InputRefused { error, .. } => {
            assert_eq!(error.code, Code::EAuth);
            assert_eq!(error.message, "Peer is not allowed to send input");
        }
        _ => unreachable!(),
    }
    // Input mode 'host': dropped unopened.
    h.svc
        .set_info(&hosted.sid, None, Some(InputMode::Host))
        .unwrap();
    with.wait("info", |e| {
        matches!(
            e,
            SessionEvent::Info {
                input_mode: Some(InputMode::Host),
                ..
            }
        )
    })
    .await;
    with.svc.input(&hosted.sid, b"x").unwrap();
    h.wait(
        "dropped",
        |e| matches!(e, SessionEvent::Debug { event, .. } if event == "host:input:dropped"),
    )
    .await;
    h.settle(300).await;
    assert_eq!(
        h.count(|e| matches!(e, SessionEvent::Input { .. })),
        1,
        "only the permitted input reached the PTY"
    );
    println!("input gate: ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_join_rotates_and_a_disconnect_does_not() {
    let Some(node) = start_node("every_join_rotates_and_a_disconnect_does_not") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut a = Side::start(&node.url, opts()).await;
    let mut b = Side::start(&node.url, opts()).await;
    let mut c = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, true, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    join_ok(&mut a, &mut h, &hosted, &l, identity("a", None)).await;
    join_ok(&mut b, &mut h, &hosted, &l, identity("b", None)).await;
    let jc = join_ok(&mut c, &mut h, &hosted, &l, identity("c", None)).await;
    // Three joins, three rotations (not only the first).
    assert_eq!(epochs(&h, RotationReason::Join), vec![2, 3, 4]);
    // `_broadcastRekey` with `except`: a gets 3 and 4, b gets 4, c none.
    a.wait("a's rekey to 4", |e| {
        matches!(e, SessionEvent::Rekey { epoch: 4, .. })
    })
    .await;
    b.wait("b's rekey to 4", |e| {
        matches!(e, SessionEvent::Rekey { epoch: 4, .. })
    })
    .await;
    c.settle(300).await;
    assert_eq!(rekeys(&a), vec![3, 4]);
    assert_eq!(rekeys(&b), vec![4]);
    assert_eq!(rekeys(&c), Vec::<u32>::new());

    // c leaves: its channels close, the host sees the peer go, nothing
    // rotates (Q-15).
    c.svc.leave(&jc);
    h.wait("peerLeft", |e| matches!(e, SessionEvent::PeerLeft { .. }))
        .await;
    h.settle(1500).await;
    let epoch_events = h.count(|e| matches!(e, SessionEvent::Epoch { .. }));
    assert_eq!(
        epoch_events, 4,
        "open + three joins, and no rotation on the disconnect"
    );
    let st = h.svc.host_status(&hosted.sid).unwrap();
    assert_eq!(st.epoch, 4);
    assert_eq!(st.confirmed.len(), 2);
    assert!(
        st.members.iter().all(|(_, s)| *s == MemberStatus::Active),
        "a disconnect revokes nothing"
    );
    // The remaining viewers still decrypt epoch-4 frames.
    h.svc.push(&hosted.sid, b"still here", false).unwrap();
    a.wait(
        "a output",
        |e| matches!(e, SessionEvent::Output { data, .. } if data == b"still here"),
    )
    .await;
    b.wait(
        "b output",
        |e| matches!(e, SessionEvent::Output { data, .. } if data == b"still here"),
    )
    .await;
    println!("rotation: joins 2,3,4; disconnect none");
}

/// The member's stale envelope (its `Confirm`'s, the last it got) opens
/// only the old epoch: a real post-rotation live frame fails its AEAD under
/// that key and opens under the remaining member's new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_revoke_rotates_and_the_stale_envelope_fails() {
    let Some(node) = start_node("member_revoke_rotates_and_the_stale_envelope_fails") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut a = Side::start(
        &node.url,
        ServiceOptions {
            tap_live: true,
            ..Default::default()
        },
    )
    .await;
    let mut b = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, true, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let a_local = identity("a", None);
    let a_sk = a_local.device_secret_key;
    join_ok(&mut a, &mut h, &hosted, &l, a_local).await;
    let b_local = identity("b", None);
    let (b_sk, b_identity) = (b_local.device_secret_key, b_local.identity_key);
    let jb = join_ok(&mut b, &mut h, &hosted, &l, b_local.clone()).await;
    let stale = b
        .all
        .iter()
        .find_map(|e| match e {
            SessionEvent::JoinChanged {
                confirm: Some(c), ..
            } => Some(c.envelope.clone()),
            _ => None,
        })
        .expect("b's confirm envelope");
    assert!(h.svc.revoke_member(&hosted.sid, &b_identity).unwrap());
    let _ = jb;
    b.wait("b offline", |e| matches!(e, SessionEvent::Offline { .. }))
        .await;
    h.wait("the member-revoke rotation", |e| {
        matches!(
            e,
            SessionEvent::Epoch {
                epoch: 4,
                reason: RotationReason::MemberRevoke,
                ..
            }
        )
    })
    .await;
    assert_eq!(epochs(&h, RotationReason::MemberRevoke), vec![4]);
    let fresh = match a
        .wait("a's rekey to 4", |e| {
            matches!(e, SessionEvent::Rekey { epoch: 4, .. })
        })
        .await
    {
        SessionEvent::Rekey { envelope, .. } => envelope,
        _ => unreachable!(),
    };
    h.svc.push(&hosted.sid, b"secret", false).unwrap();
    let frame = match a
        .wait("a tapped epoch-4 data", |e| {
            matches!(e, SessionEvent::LiveFrame { message: LiveMsg::Data { frame, .. }, .. } if frame.epoch == 4)
        })
        .await
    {
        SessionEvent::LiveFrame {
            message: LiveMsg::Data { frame, .. },
            ..
        } => frame,
        _ => unreachable!(),
    };
    a.wait(
        "a output",
        |e| matches!(e, SessionEvent::Output { data, .. } if data == b"secret"),
    )
    .await;
    let old = envelope::open(&b_sk, &stale).expect("b's own envelope opens");
    assert_eq!(old.epoch, 3);
    let old_live: [u8; 32] = old.live_key.unwrap().try_into().unwrap();
    let err = packet::decrypt(
        &old_live,
        &hosted.sid,
        frame.epoch,
        frame.seq,
        &frame.device_key,
        &frame.ciphertext,
    )
    .unwrap_err();
    assert_eq!(err.code, Code::ECorrupt);
    assert_eq!(err.message, "Encrypted data failed authentication");
    assert!(
        envelope::open(&b_sk, &fresh).is_err(),
        "the new envelope is not b's"
    );
    let new_live: [u8; 32] = envelope::open(&a_sk, &fresh)
        .unwrap()
        .live_key
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        packet::decrypt(
            &new_live,
            &hosted.sid,
            frame.epoch,
            frame.seq,
            &frame.device_key,
            &frame.ciphertext
        )
        .unwrap(),
        b"secret"
    );
    // The revoked member cannot join again.
    let again = b
        .svc
        .join(JoinSpec {
            route: hosted.route.clone(),
            expected_peer_key: h.public(),
            link_id: l.link_id,
            local: b_local,
        })
        .unwrap();
    let (code, reason, message) = b.join_failed(&again).await;
    assert_eq!(code, Some(Code::EAuth));
    assert_eq!(reason, Some(JoinReason::DeviceRevoked));
    assert_eq!(message.as_deref(), Some("This device has been revoked"));
    println!("member revoke: epoch 4, stale envelope refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_revoke_rotates_and_refuses_a_late_join() {
    let Some(node) = start_node("link_revoke_rotates_and_refuses_a_late_join") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut a = Side::start(&node.url, opts()).await;
    let mut b = Side::start(&node.url, opts()).await;
    let l1 = link(LinkKind::Group, true, None);
    let l2 = link(LinkKind::Group, true, None);
    let hosted = host_session(&mut h, identity("host", None), &l1, InputMode::Host).await;
    let route2 = add_link(&mut h, &hosted.sid, &l2).await;
    let hosted2 = Hosted {
        sid: hosted.sid.clone(),
        route: route2,
    };
    join_ok(&mut a, &mut h, &hosted, &l1, identity("a", None)).await;
    join_ok(&mut b, &mut h, &hosted2, &l2, identity("b", None)).await;
    assert!(h.svc.revoke_link(&hosted.sid, &l1.link_id).unwrap());
    a.wait("a offline", |e| matches!(e, SessionEvent::Offline { .. }))
        .await;
    h.wait("the link-revoke rotation", |e| {
        matches!(
            e,
            SessionEvent::Epoch {
                epoch: 4,
                reason: RotationReason::LinkRevoke,
                ..
            }
        )
    })
    .await;
    assert_eq!(epochs(&h, RotationReason::LinkRevoke), vec![4]);
    b.wait("b's rekey to 4", |e| {
        matches!(e, SessionEvent::Rekey { epoch: 4, .. })
    })
    .await;
    let st = h.svc.host_status(&hosted.sid).unwrap();
    assert!(
        st.links
            .iter()
            .any(|l| l.spec.link_id == l1.link_id && l.revoked)
    );
    assert_eq!(
        st.members
            .iter()
            .filter(|(_, s)| *s == MemberStatus::Revoked)
            .count(),
        1
    );
    // A late join with the revoked link's id, reaching the host through a
    // route that is still announced (the host stays reachable by peer key,
    // protocol.md §13): refused in-band, nothing confirmed. (Through the
    // withdrawn route itself it ends unreachable at the join timeout,
    // which §13 allows too.)
    let late = b
        .svc
        .join(JoinSpec {
            route: hosted2.route.clone(),
            expected_peer_key: h.public(),
            link_id: l1.link_id,
            local: identity("late", None),
        })
        .unwrap();
    let (code, reason, message) = b.join_failed(&late).await;
    assert_eq!(code, Some(Code::EAuth));
    assert_eq!(reason, Some(JoinReason::Revoked));
    assert_eq!(message.as_deref(), Some("Invite is no longer valid"));
    assert_eq!(h.svc.host_status(&hosted.sid).unwrap().confirmed.len(), 1);
    println!("link revoke: epoch 4, late join refused in-band");
}

/// ZBTerm `S-42`, fixed by v2 (`protocol.md` §8): revoking a link cancels
/// its pending approvals, and a later approve is refused; the link stays
/// revoked and nobody is confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s42_approve_after_revoke_link_is_refused() {
    let Some(node) = start_node("s42_approve_after_revoke_link_is_refused") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, false, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let j = join(&v, &h, &hosted, &l, identity("viewer", None));
    let pending = match h
        .wait("share.pending", |e| {
            matches!(e, SessionEvent::Pending { .. })
        })
        .await
    {
        SessionEvent::Pending { join_id, .. } => join_id,
        _ => unreachable!(),
    };
    assert!(h.svc.revoke_link(&hosted.sid, &l.link_id).unwrap());
    let p2 = pending.clone();
    h.wait(
        "approvalCancelled",
        move |e| matches!(e, SessionEvent::ApprovalCancelled { join_id, .. } if *join_id == p2),
    )
    .await;
    let err = h.svc.approve(&hosted.sid, &pending).unwrap_err();
    assert_eq!(err.message, "Approval request is no longer pending");
    let (_, reason, message) = v.join_failed(&j).await;
    assert_eq!(reason, Some(JoinReason::Revoked));
    assert_eq!(message.as_deref(), Some("Invite is no longer valid"));
    let st = h.svc.host_status(&hosted.sid).unwrap();
    assert!(st.links[0].revoked, "the link stays revoked");
    assert_eq!((st.confirmed.len(), st.members.len(), st.epoch), (0, 0, 1));
    assert_eq!(h.count(|e| matches!(e, SessionEvent::Granted { .. })), 0);
    println!("S-42: refused");
}

/// ZBTerm `S-43`, fixed by v2 (`protocol.md` §10): the counter is per
/// device and epoch, so a viewer that restarts (a fresh service, counter
/// from 1) and rejoins has its input accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s43_a_restarted_viewer_input_is_accepted() {
    let Some(node) = start_node("s43_a_restarted_viewer_input_is_accepted") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, true, Some(VIEW_LIVE | SEND_INPUT));
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::All).await;
    let local = identity("viewer", None);
    {
        let mut v = Side::start(&node.url, opts()).await;
        let j = join_ok(&mut v, &mut h, &hosted, &l, local.clone()).await;
        for i in 1..=5u64 {
            assert_eq!(v.svc.input(&hosted.sid, b"k").unwrap(), i);
        }
        for _ in 0..5 {
            h.wait("input", |e| matches!(e, SessionEvent::Input { .. }))
                .await;
        }
        v.svc.leave(&j);
        v.svc.backend().stop().await;
        h.wait("peerLeft", |e| matches!(e, SessionEvent::PeerLeft { .. }))
            .await;
    }
    // The "restarted" viewer: same device and identity, a new process state.
    let mut v2 = Side::start(&node.url, opts()).await;
    join_ok(&mut v2, &mut h, &hosted, &l, local).await;
    // The first viewer leaving turned input back to 'host'
    // (`_disableInputWhenEmpty`); the host allows it again.
    h.svc
        .set_info(&hosted.sid, None, Some(InputMode::All))
        .unwrap();
    assert_eq!(
        v2.svc.input(&hosted.sid, b"after restart").unwrap(),
        1,
        "the counter restarts at 1"
    );
    match h
        .wait("input after restart", |e| {
            matches!(
                e,
                SessionEvent::Input { .. } | SessionEvent::InputRefused { .. }
            )
        })
        .await
    {
        SessionEvent::Input { data, .. } => assert_eq!(data, b"after restart"),
        other => panic!("refused: {other:?}"),
    }
    println!("S-43: accepted");
}

/// A viewer whose whole runtime can be frozen: its backend, RTC tasks and
/// session service run on a current-thread runtime of their own thread,
/// which [`FrozenViewer::freeze`] blocks, so the host's data channel toward
/// it backs up deterministically (a debug build cannot outrun a loopback
/// data channel that is read).
struct FrozenViewer {
    handle: tokio::runtime::Handle,
    ctl: tokio::sync::mpsc::UnboundedSender<Option<Duration>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FrozenViewer {
    fn new() -> FrozenViewer {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("viewer runtime");
        let handle = rt.handle().clone();
        let (ctl, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<Duration>>();
        let thread = std::thread::Builder::new()
            .name("frozen-viewer".into())
            .spawn(move || {
                rt.block_on(async move {
                    while let Some(Some(d)) = rx.recv().await {
                        // Blocks the runtime's only thread: nothing of the
                        // viewer runs, its UDP socket is not read.
                        std::thread::sleep(d);
                    }
                });
            })
            .expect("viewer thread");
        FrozenViewer {
            handle,
            ctl,
            thread: Some(thread),
        }
    }

    async fn side(&self, url: &str) -> Side {
        let backend = {
            let _g = self.handle.enter();
            Backend::new(BackendOptions {
                node_url: url.to_string(),
                ice_servers: Some(vec![]),
                clock: None,
                loopback_only: true,
                legacy_v1_routes: false,
            })
        };
        let key = SigningKey::from_bytes(&random::<32>());
        let (svc, rx) = {
            let _g = self.handle.enter();
            SessionService::new(backend.clone(), opts())
        };
        let (b, k) = (backend.clone(), key.clone());
        self.handle
            .spawn(async move {
                let mut tries = 0;
                while let Err(e) = b.start(k.clone()).await {
                    tries += 1;
                    assert!(tries < 3, "start: {e:?}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            })
            .await
            .expect("viewer start");
        Side {
            svc,
            rx,
            seen: Vec::new(),
            all: Vec::new(),
            auto_bootstrap: true,
            boots: 0,
            key,
        }
    }

    fn freeze(&self, d: Duration) {
        self.ctl.send(Some(d)).expect("viewer thread");
    }

    async fn stop(mut self, v: &Side) {
        let b = v.svc.backend().clone();
        let _ = self.handle.spawn(async move { b.stop().await }).await;
        let _ = self.ctl.send(None);
        if let Some(t) = self.thread.take() {
            t.join().expect("viewer thread ends");
        }
    }
}

/// `protocol.md` §11 under a synthetic flood: the lagging peer's `Data` is
/// skipped, a resync `Bootstrap` (`RESYNC_SCROLLBACK`, `RESYNC_TAIL_BYTES`)
/// replaces it, and every lag episode's delay follows `_resyncPeer`'s rule
/// (500 ms first, doubled up to 8000 ms after a resync that met
/// back-pressure, 500 ms again after one that did not). The viewer is
/// frozen for 3 s of the flood, so its channel backs up for certain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lag_resync_under_a_flood() {
    let Some(node) = start_node("lag_resync_under_a_flood") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let fv = FrozenViewer::new();
    let mut v = fv.side(&node.url).await;
    let l = link(LinkKind::Group, true, Some(VIEW_LIVE));
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let j = {
        let _g = fv.handle.enter();
        join(&v, &h, &hosted, &l, identity("viewer", None))
    };
    v.join_status(&j, JoinStatus::Confirmed).await;
    h.wait("the grant's bootstrap request", |e| {
        matches!(
            e,
            SessionEvent::BootstrapNeeded {
                scrollback: None,
                ..
            }
        )
    })
    .await;
    v.join_status(&j, JoinStatus::Joined).await;

    let chunk = vec![b'x'; 16 * 1024];
    let started = Instant::now();
    let mut pushed = 0u64;
    fv.freeze(Duration::from_secs(3));
    while started.elapsed() < Duration::from_secs(6) {
        h.svc.push(&hosted.sid, &chunk, false).unwrap();
        pushed += chunk.len() as u64;
        // Keep the host's event queue drained (and answer resyncs).
        while let Ok(ev) = h.rx.try_recv() {
            h.take(ev);
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // Until a resync goes out without back-pressure (the link caught up).
    h.wait("a clean resync", |e| {
        matches!(e, SessionEvent::Debug { event, details } if event == "host:peer:resync" && details["backpressure"] == false)
    })
    .await;
    let resync_requests = h.count(|e| {
        matches!(
            e,
            SessionEvent::BootstrapNeeded {
                scrollback: Some(500),
                tail_bytes: Some(65536),
                ..
            }
        )
    });
    assert!(resync_requests >= 1, "a resync bootstrap was asked for");
    // The backoff, event by event.
    let mut expected_next = LAG_RESYNC_MS;
    let mut episodes = Vec::new();
    let mut backpressured = Vec::new();
    for e in &h.all {
        if let SessionEvent::Debug { event, details } = e {
            if event == "host:peer:lagging" {
                let got = details["retryMs"].as_u64().unwrap();
                assert_eq!(got, expected_next, "lag delays so far {episodes:?}");
                episodes.push(got);
            } else if event == "host:peer:resync" {
                let bp = details["backpressure"].as_bool().unwrap();
                backpressured.push(bp);
                let last = *episodes.last().expect("a resync follows a lag");
                expected_next = if bp {
                    LAG_RESYNC_MAX_MS.min(last * 2)
                } else {
                    LAG_RESYNC_MS
                };
            }
        }
    }
    assert!(!episodes.is_empty(), "the flood made the peer lag");
    assert!(
        backpressured.iter().any(|b| *b),
        "a resync met back-pressure while the viewer was frozen, so the delay doubled: {episodes:?}"
    );
    assert!(
        episodes.windows(2).any(|w| w[1] == w[0] * 2),
        "doubling seen: {episodes:?}"
    );
    // The viewer got the resync screen, after the join's.
    v.wait("the resync bootstrap", |e| {
        matches!(e, SessionEvent::Live { kind: LiveKind::Bootstrap, data, .. } if String::from_utf8_lossy(data).contains("\"resync\":true"))
    })
    .await;
    let st = h.svc.host_status(&hosted.sid).unwrap();
    let lag = st.lag[0].1.clone();
    assert!(lag.resyncs >= 1);
    println!(
        "lag resync (reported, not gated): pushed {} KiB in 6 s (viewer frozen 3 s), lag delays {episodes:?}, resyncs {} ({} met back-pressure)",
        pushed / 1024,
        lag.resyncs,
        lag.resyncs_backpressured
    );
    fv.stop(&v).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_verified_unknown_and_failed() {
    let Some(node) = start_node("identity_verified_unknown_and_failed") else {
        return;
    };
    let registry: Registry = Arc::new(Mutex::new(Vec::new()));
    let with_resolver = || ServiceOptions {
        resolver: Some(resolver(&registry)),
        ..Default::default()
    };
    let mut h = Side::start(&node.url, with_resolver()).await;
    let mut good = Side::start(&node.url, with_resolver()).await;
    let mut none = Side::start(&node.url, with_resolver()).await;
    let mut bad = Side::start(&node.url, with_resolver()).await;
    let l = link(LinkKind::Group, true, None);
    let hosted = host_session(
        &mut h,
        identity("host", Some((&registry, false))),
        &l,
        InputMode::Host,
    )
    .await;

    // Verified, both ways (the viewer also checks the host's claim).
    let g = join_ok(
        &mut good,
        &mut h,
        &hosted,
        &l,
        identity("good", Some((&registry, false))),
    )
    .await;
    let host_view = h
        .wait(
            "host: viewer verified",
            |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status != "pending"),
        )
        .await;
    let SessionEvent::PeerIdentity(p) = host_view else {
        unreachable!()
    };
    assert_eq!(
        (p.status.as_str(), p.provider.as_str()),
        ("verified", "github"),
        "{p:?}"
    );
    let viewer_view = good
        .wait(
            "viewer: host verified",
            |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status != "pending"),
        )
        .await;
    let SessionEvent::PeerIdentity(p) = viewer_view else {
        unreachable!()
    };
    assert_eq!(p.status, "verified", "{p:?}");
    let _ = g;

    // Unknown: no claim presented, no challenge, allowed.
    join_ok(&mut none, &mut h, &hosted, &l, identity("none", None)).await;
    let SessionEvent::PeerIdentity(p) = h
        .wait(
            "host: viewer unknown",
            |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status == "unknown"),
        )
        .await
    else {
        unreachable!()
    };
    assert_eq!(p.provider, "unknown");

    // Failed: a claim whose signature does not verify refuses the join.
    let jb = join(
        &bad,
        &h,
        &hosted,
        &l,
        identity("bad", Some((&registry, true))),
    );
    let SessionEvent::PeerIdentity(p) = h
        .wait(
            "host: viewer failed",
            |e| matches!(e, SessionEvent::PeerIdentity(p) if p.status == "failed"),
        )
        .await
    else {
        unreachable!()
    };
    assert!(
        p.reason.as_deref().unwrap_or("").contains("signature"),
        "{p:?}"
    );
    let (code, reason, message) = bad.join_failed(&jb).await;
    assert_eq!(code, Some(Code::EAuth));
    assert_eq!(reason, Some(JoinReason::Identity));
    assert_eq!(message.as_deref(), Some("Identity verification failed"));
    assert_eq!(h.svc.host_status(&hosted.sid).unwrap().confirmed.len(), 2);
    println!("identity: verified, unknown, failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pvless_route_is_refused_and_a_pv2_route_verifies() {
    let Some(node) = start_node("a_pvless_route_is_refused_and_a_pv2_route_verifies") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Group, true, None);
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    let bundled = zxterm_core::freenet::contracts::bundled().unwrap();
    // pv: 2, verified normally.
    assert_eq!(hosted.route.params.pv, Some(2));
    route::verify(&hosted.route, &hex::encode(h.public()), &bundled.route).expect("v2 verifies");
    // The same route without pv, re-signed so its sig verifies as v1.
    let mut v1 = hosted.route.clone();
    v1.params.pv = None;
    v1.sig = route::instance_id_b58(&v1.code, &route::params_bytes(&v1.params));
    route::verify_v1(&v1, &hex::encode(h.public()), &bundled.route).expect("a valid v1 route");
    let err = v
        .svc
        .join(JoinSpec {
            route: v1.clone(),
            expected_peer_key: h.public(),
            link_id: l.link_id,
            local: identity("viewer", None),
        })
        .unwrap_err();
    assert_eq!(err.code, Code::EBackendUnsupported);
    assert!(
        err.message.contains("protocol") && err.message.contains("upgrade"),
        "{err:?}"
    );
    assert_ne!(err.message, "The Freenet route is malformed");
    // The backend's own dial refuses it too, before any node traffic.
    let mut events = v.svc.backend().subscribe();
    let handle = v.svc.backend().dial(v1, h.public(), None);
    let dial_err = tokio::time::timeout(T, handle.connected)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(dial_err.code, Code::EBackendUnsupported);
    assert_eq!(dial_err.message, route::OLDER_PROTOCOL_MESSAGE);
    while let Ok(ev) = events.try_recv() {
        assert!(
            !matches!(ev, BackendEvent::Connection { .. }),
            "never connected"
        );
    }
    // And the v2 route joins.
    join_ok(&mut v, &mut h, &hosted, &l, identity("viewer", None)).await;
    println!("pv: v1 refused ({}), v2 joined", err.message);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_unknown_link_and_single_use() {
    let Some(node) = start_node("history_unknown_link_and_single_use") else {
        return;
    };
    let mut h = Side::start(&node.url, opts()).await;
    let mut v = Side::start(&node.url, opts()).await;
    let mut w = Side::start(&node.url, opts()).await;
    let l = link(LinkKind::Single, true, Some(VIEW_LIVE | READ_HISTORY));
    let hosted = host_session(&mut h, identity("host", None), &l, InputMode::Host).await;
    join_ok(&mut v, &mut h, &hosted, &l, identity("viewer", None)).await;
    // history: a range request is answered (nothing served in C2).
    let id = v.svc.request_history(&hosted.sid, 5, 10, 4).unwrap();
    match v
        .wait("historyDone", |e| {
            matches!(e, SessionEvent::HistoryDone { .. })
        })
        .await
    {
        SessionEvent::HistoryDone {
            request_id, next, ..
        } => assert_eq!((request_id, next), (id, 5)),
        _ => unreachable!(),
    }
    // A single-use link is consumed.
    let second = join(&w, &h, &hosted, &l, identity("second", None));
    let (_, reason, message) = w.join_failed(&second).await;
    assert_eq!(reason, Some(JoinReason::Consumed));
    assert_eq!(message.as_deref(), Some("Invite has already been used"));
    // A link the host does not know (same route, another link id): ENDED.
    let mut unknown = l.clone();
    unknown.link_id = random::<16>();
    let third = join(&w, &h, &hosted, &unknown, identity("third", None));
    let (code, reason, message) = w.join_failed(&third).await;
    assert_eq!(code, Some(Code::EAuth));
    assert_eq!(reason, Some(JoinReason::Ended));
    assert_eq!(message.as_deref(), Some("This share is no longer active"));
    println!("history done, consumed, ended");
}

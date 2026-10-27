//! End-to-end seam tests (K7): profile ownership, the `sidecar`/`ctl`
//! binary contract, and — behind `seam-test` — the concurrent-reply-id and
//! flood/back-pressure behaviour this phase's Acceptance criteria and
//! Gotchas call for.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zxterm_testkit::ScratchHome;

fn zxterm_core_bin() -> &'static str {
    env!("CARGO_BIN_EXE_zxterm-core")
}

fn wait_for<F: Fn() -> bool>(deadline: Duration, cond: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

/// A profile directory short enough that `<profile>/zxterm-core.sock` stays
/// well under the 108-byte `AF_UNIX` path limit (this phase's own Gotchas).
fn scratch_profile(home: &ScratchHome) -> std::path::PathBuf {
    let dir = home.path().join("p");
    std::fs::create_dir_all(&dir).expect("create profile dir");
    dir
}

#[test]
fn try_acquire_profile_lock_refuses_a_second_owner_in_process() {
    let home = ScratchHome::new().expect("scratch home");
    let profile = scratch_profile(&home);

    let first = zxterm_core::seam::try_acquire_profile_lock(&profile).expect("first lock attempt");
    assert!(matches!(first, zxterm_core::seam::LockOutcome::Acquired(_)));

    let second =
        zxterm_core::seam::try_acquire_profile_lock(&profile).expect("second lock attempt");
    assert!(matches!(second, zxterm_core::seam::LockOutcome::Held));

    drop(first);
    let third = zxterm_core::seam::try_acquire_profile_lock(&profile).expect("third lock attempt");
    assert!(
        matches!(third, zxterm_core::seam::LockOutcome::Acquired(_)),
        "releasing the first lock lets a later attempt acquire it"
    );
}

/// A running sidecar, spawned as a real subprocess (the same binary K9's
/// `client.js` spawns) — Process safety: this is a PID this test started
/// itself, killed by that exact `Child` handle, never by pattern.
struct RunningSidecar {
    child: std::process::Child,
    #[allow(dead_code)]
    home: ScratchHome,
    profile: std::path::PathBuf,
}

impl RunningSidecar {
    fn spawn() -> Self {
        let home = ScratchHome::new().expect("scratch home");
        let profile = scratch_profile(&home);
        let child = Command::new(zxterm_core_bin())
            .args(["sidecar", "--profile"])
            .arg(&profile)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn zxterm-core sidecar");
        let socket = zxterm_core::seam::socket_path(&profile);
        let ready = wait_for(Duration::from_secs(10), || socket.exists());
        assert!(ready, "sidecar socket never appeared at {socket:?}");
        RunningSidecar {
            child,
            home,
            profile,
        }
    }

    fn ctl(&self, method: &str, args: &str) -> std::process::Output {
        Command::new(zxterm_core_bin())
            .args(["ctl", "--profile"])
            .arg(&self.profile)
            .args([method, args])
            .output()
            .expect("spawn zxterm-core ctl")
    }
}

impl Drop for RunningSidecar {
    fn drop(&mut self) {
        // Signals only the exact PID this test spawned (Process safety).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_second_sidecar_on_the_same_profile_refuses_and_exits_non_zero() {
    let sidecar = RunningSidecar::spawn();

    let second = Command::new(zxterm_core_bin())
        .args(["sidecar", "--profile"])
        .arg(&sidecar.profile)
        .output()
        .expect("spawn a second zxterm-core sidecar");
    assert!(
        !second.status.success(),
        "a second sidecar on an owned profile must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already owned") || stderr.contains("lock held"),
        "stderr should explain the profile is already owned: {stderr}"
    );

    // The original sidecar's socket is still the one and only owner.
    assert!(zxterm_core::seam::socket_path(&sidecar.profile).exists());
}

#[test]
fn ctl_core_version_against_a_running_sidecar_prints_json_and_exits_0() {
    let sidecar = RunningSidecar::spawn();
    let output = sidecar.ctl("core.version", "{}");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("ctl core.version did not print valid JSON ({e}): {stdout}"));
    assert!(
        value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
}

#[test]
fn ctl_against_no_running_sidecar_fails_clearly_and_quickly_never_hangs() {
    let home = ScratchHome::new().expect("scratch home");
    let profile = scratch_profile(&home);
    let started = Instant::now();
    let output = Command::new(zxterm_core_bin())
        .args(["ctl", "--profile"])
        .arg(&profile)
        .args(["core.version", "{}"])
        .output()
        .expect("spawn zxterm-core ctl");
    let elapsed = started.elapsed();
    assert!(
        !output.status.success(),
        "ctl against nothing listening must fail"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "ctl must fail quickly, not hang (took {elapsed:?})"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.trim().is_empty(), "ctl must explain why it failed");
}

#[test]
fn ctl_identity_ssh_candidates_against_an_empty_home_returns_an_empty_list() {
    let sidecar = RunningSidecar::spawn();
    let home = ScratchHome::new().expect("candidate home");
    let args = serde_json::json!({ "home": home.path(), "env": {} }).to_string();
    let output = sidecar.ctl("identity.sshCandidates", &args);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).expect("valid JSON");
    assert_eq!(value["candidates"].as_array().expect("array").len(), 0);
}

fn ctl_json(sidecar: &RunningSidecar, method: &str, args: serde_json::Value) -> serde_json::Value {
    let output = sidecar.ctl(method, &args.to_string());
    assert!(
        output.status.success(),
        "{method} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).expect("valid JSON")
}

/// K10: the Freenet transport service as JSON-mirrored `ctl` calls: every
/// `BACKEND_MEMBERS` method that needs no peer, against a throwaway
/// `LocalNode` (skips without `freenet`), and the error mapping.
#[test]
fn freenet_methods_over_ctl() {
    let sidecar = RunningSidecar::spawn();
    let describe = ctl_json(&sidecar, "freenet.describe", serde_json::json!({}));
    assert_eq!(describe["id"], "freenet");
    assert_eq!(
        ctl_json(&sidecar, "freenet.health", serde_json::json!({})),
        serde_json::json!({"started": false, "listening": false, "detail": null})
    );
    let err = sidecar.ctl("freenet.announce", r#"{"linkId":"x"}"#);
    assert!(!err.status.success());
    let stderr = String::from_utf8_lossy(&err.stderr);
    assert!(stderr.contains("E_BACKEND_UNAVAILABLE"), "{stderr}");

    if !zxterm_testkit::local_node::freenet_available() {
        println!("SKIP freenet_methods_over_ctl (node part): freenet binary not on PATH");
        return;
    }
    let node = zxterm_testkit::local_node::LocalNode::start().expect("LocalNode");
    let probe = ctl_json(
        &sidecar,
        "freenet.probe",
        serde_json::json!({"nodeUrl": node.url}),
    );
    assert_eq!(probe["state"], "available");
    let seed = "11".repeat(32);
    let started = ctl_json(
        &sidecar,
        "freenet.start",
        serde_json::json!({"secretKey": seed, "nodeUrl": node.url, "iceServers": []}),
    );
    let public = started["publicKey"]
        .as_str()
        .expect("publicKey")
        .to_string();
    assert_eq!(
        ctl_json(&sidecar, "freenet.localPeerKey", serde_json::json!({})),
        serde_json::Value::String(public.clone())
    );
    assert_eq!(
        ctl_json(&sidecar, "freenet.health", serde_json::json!({}))["started"],
        true
    );
    let route = ctl_json(
        &sidecar,
        "freenet.routeFor",
        serde_json::json!({"linkId": "l1"}),
    );
    assert_eq!(route["params"]["host"], public);
    assert_eq!(
        ctl_json(
            &sidecar,
            "freenet.routeFor",
            serde_json::json!({"linkId": "l1", "stored": {"route": route}})
        ),
        route
    );
    ctl_json(
        &sidecar,
        "freenet.setAdmission",
        serde_json::json!({"policy": [public]}),
    );
    let ann = ctl_json(
        &sidecar,
        "freenet.announce",
        serde_json::json!({"linkId": "l1", "route": route}),
    );
    assert_eq!(ann["route"], route);
    assert_eq!(ann["linkId"], "l1");
    let health = ctl_json(&sidecar, "freenet.health", serde_json::json!({}));
    assert_eq!(health["listening"], true);
    assert_eq!(
        ctl_json(&sidecar, "freenet.diagnostics", serde_json::json!({}))["announced"],
        1
    );
    assert_eq!(
        ctl_json(&sidecar, "freenet.historyRouteFor", serde_json::json!({})),
        serde_json::Value::Null
    );
    ctl_json(
        &sidecar,
        "freenet.withdraw",
        serde_json::json!({"linkId": "l1"}),
    );
    assert_eq!(
        ctl_json(&sidecar, "freenet.diagnostics", serde_json::json!({}))["announced"],
        0
    );
    let bad = sidecar.ctl("freenet.serveHistory", r#"{"conn":99}"#);
    assert!(String::from_utf8_lossy(&bad.stderr).contains("E_HOST_UNREACHABLE"));
    ctl_json(&sidecar, "freenet.stop", serde_json::json!({}));
    ctl_json(&sidecar, "freenet.stop", serde_json::json!({}));
    assert_eq!(
        ctl_json(&sidecar, "freenet.health", serde_json::json!({}))["started"],
        false
    );
}

/// K9: the identity-key methods ZBTerm's `engine/crypto.js` and
/// `engine/account-store.js` call instead of the upstream package.
#[test]
fn idkey_create_verify_and_rederive_over_the_seam() {
    let sidecar = RunningSidecar::spawn();
    let device = "11".repeat(32);
    let created = ctl_json(
        &sidecar,
        "idkey.create",
        serde_json::json!({ "devicePublicKeyHex": device }),
    );
    let mnemonic = created["mnemonic"].as_str().expect("mnemonic");
    assert_eq!(mnemonic.split(' ').count(), 24, "a 24-word mnemonic");
    let identity = created["identityPublicKey"].as_str().expect("identity key");
    let valid = ctl_json(
        &sidecar,
        "idkey.verify",
        serde_json::json!({
            "proofHex": created["identityProof"],
            "identityPublicKeyHex": identity,
            "devicePublicKeyHex": device,
        }),
    );
    assert_eq!(valid["valid"], true);
    let rederived = ctl_json(
        &sidecar,
        "idkey.derive",
        serde_json::json!({ "mnemonic": mnemonic }),
    );
    assert_eq!(rederived["identityPublicKey"], identity);
}

/// K9: `identity.get` falls back to `unknown` with the identity key's own
/// display id, and the live-challenge pair round trips.
#[test]
fn identity_get_and_the_challenge_pair_over_the_seam() {
    let sidecar = RunningSidecar::spawn();
    let identity_key = "ab".repeat(32);
    let got = ctl_json(
        &sidecar,
        "identity.get",
        serde_json::json!({ "identityKeyHex": identity_key, "deviceKeyHex": "cd".repeat(32) }),
    );
    assert_eq!(got["provider"], "unknown");
    assert_eq!(got["identityKey"], identity_key.as_str());
    assert_eq!(got["deviceStatus"], "active");
    assert!(got["displayId"].as_str().is_some_and(|d| !d.is_empty()));

    use ed25519_dalek::SigningKey;
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&[5u8; 32]);
    secret[32..].copy_from_slice(signing.verifying_key().as_bytes());
    let challenge = serde_json::json!({
        "sessionId": "s", "challengeId": "c", "nonce": "n",
        "verifierDhtKey": "v", "proverDhtKey": "p", "role": "viewer",
    });
    let signed = ctl_json(
        &sidecar,
        "identity.signChallenge",
        serde_json::json!({ "authSecretKeyHex": hex::encode(secret), "challenge": challenge }),
    );
    let signature = signed["signatureHex"].as_str().expect("signature");
    let ok = ctl_json(
        &sidecar,
        "identity.verifyChallenge",
        serde_json::json!({
            "authKeyHex": hex::encode(signing.verifying_key().as_bytes()),
            "challenge": challenge,
            "signatureHex": signature,
        }),
    );
    assert_eq!(ok["valid"], true);
    let mut relayed = challenge.clone();
    relayed["proverDhtKey"] = serde_json::json!("someone-else");
    let refused = ctl_json(
        &sidecar,
        "identity.verifyChallenge",
        serde_json::json!({
            "authKeyHex": hex::encode(signing.verifying_key().as_bytes()),
            "challenge": relayed,
            "signatureHex": signature,
        }),
    );
    assert_eq!(refused["valid"], false);
}

/// K9: `--exit-on-stdin-eof` makes the sidecar exit with the process that
/// spawned it — closing its stdin pipe is what a parent's death looks like.
#[test]
fn exit_on_stdin_eof_exits_when_the_parent_side_of_stdin_closes() {
    let home = ScratchHome::new().expect("scratch home");
    let profile = scratch_profile(&home);
    let mut child = Command::new(zxterm_core_bin())
        .args(["sidecar", "--exit-on-stdin-eof", "--profile"])
        .arg(&profile)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn zxterm-core sidecar");
    let socket = zxterm_core::seam::socket_path(&profile);
    assert!(wait_for(Duration::from_secs(10), || socket.exists()));
    drop(child.stdin.take());
    let started = Instant::now();
    let mut exited = false;
    while started.elapsed() < Duration::from_secs(5) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        // Signals only the exact PID this test spawned (Process safety).
        let _ = child.kill();
    }
    let _ = child.wait();
    assert!(exited, "the sidecar must exit once its stdin closes");
}

#[cfg(feature = "seam-test")]
mod seam_test_feature {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use zxterm_core::seam::{self, Frame};

    /// The Gotcha this test pins: "A `Reply`'s `id` must round-trip exactly
    /// what the `Request` sent, including for concurrent in-flight requests
    /// on one connection... since a naive 'reply arrives in send order'
    /// implementation will pass every single-request test and still be
    /// wrong." A slow `test.flood` is sent first; a fast `test.echo` right
    /// behind it must still be answered first, and both replies must carry
    /// back their own `id`.
    #[tokio::test]
    async fn concurrent_requests_complete_out_of_order_and_each_reply_matches_its_own_id() {
        let home = ScratchHome::new().expect("scratch home");
        let profile = home.path().join("p");
        std::fs::create_dir_all(&profile).unwrap();

        let lock = match seam::try_acquire_profile_lock(&profile).unwrap() {
            seam::LockOutcome::Acquired(g) => g,
            seam::LockOutcome::Held => panic!("fresh profile should not be held"),
        };
        let listener = seam::bind_socket(&profile).expect("bind socket");
        let dispatcher = std::sync::Arc::new(seam::Dispatcher::new(profile.clone()));
        let serve_task = tokio::spawn(seam::serve(listener, dispatcher));

        let stream = tokio::net::UnixStream::connect(seam::socket_path(&profile))
            .await
            .expect("connect");
        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // A flood large enough to take noticeably longer than one
        // core-local dispatch, so "echo" genuinely has a chance to finish
        // first if (and only if) requests are handled concurrently.
        seam::write_frame(
            &mut write_half,
            &Frame::Request {
                id: "flood".into(),
                method: "test.flood".into(),
                args: serde_json::json!({"bytes": 4 * 1024 * 1024}).to_string(),
            },
        )
        .await
        .unwrap();
        seam::write_frame(
            &mut write_half,
            &Frame::Request {
                id: "echo".into(),
                method: "test.echo".into(),
                args: serde_json::json!({"payload": "hi"}).to_string(),
            },
        )
        .await
        .unwrap();

        // Drain Output/Event frames as they arrive (this connection is the
        // flood's own target) so the flood is never artificially starved by
        // this test's own reader falling behind.
        let mut first_reply_id: Option<String> = None;
        let mut second_reply_id: Option<String> = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        while (first_reply_id.is_none() || second_reply_id.is_none()) && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(5), seam::read_frame(&mut read_half))
                .await
            {
                Ok(Ok(Some(Frame::Reply { id, ok }))) => {
                    assert!(ok.is_ok(), "unexpected error reply for {id}: {ok:?}");
                    if first_reply_id.is_none() {
                        first_reply_id = Some(id);
                    } else {
                        second_reply_id = Some(id);
                    }
                }
                Ok(Ok(Some(_other))) => {} // Output/Event: drain and ignore
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("read error: {e}"),
                Err(_) => panic!("timed out waiting for replies"),
            }
        }

        assert_eq!(
            first_reply_id.as_deref(),
            Some("echo"),
            "the fast request must complete (and be matched by id) before the slow one"
        );
        assert_eq!(second_reply_id.as_deref(), Some("flood"));

        // `tokio::io::split` only closes the underlying stream once *both*
        // halves are dropped (dropping just one does not shut down or send
        // EOF on the other) — drop both here, rather than blocking on a
        // read that would never see anything once the server has nothing
        // left to say, which the first version of this test learned the
        // hard way (a real hang, not a seam bug: `read_half.read(..).await`
        // with no timeout, after the assertions above had already passed).
        drop(write_half);
        drop(read_half);
        drop(lock);
        serve_task.abort();
    }

    /// Behind the flood: a client that stops reading forces the seam's
    /// `OutputSink` to drop to a snapshot instead of growing without bound
    /// (`super::backlog`, the `S-35` rule moved here) — and once the client
    /// resumes reading, everything still completes cleanly (the flood's own
    /// `Reply` still arrives, no hang).
    #[tokio::test]
    async fn a_client_that_stops_reading_does_not_hang_the_flood() {
        let home = ScratchHome::new().expect("scratch home");
        let profile = home.path().join("p");
        std::fs::create_dir_all(&profile).unwrap();

        let lock = match seam::try_acquire_profile_lock(&profile).unwrap() {
            seam::LockOutcome::Acquired(g) => g,
            seam::LockOutcome::Held => panic!("fresh profile should not be held"),
        };
        let listener = seam::bind_socket(&profile).expect("bind socket");
        let dispatcher = std::sync::Arc::new(seam::Dispatcher::new(profile.clone()));
        let serve_task = tokio::spawn(seam::serve(listener, dispatcher));

        let stream = tokio::net::UnixStream::connect(seam::socket_path(&profile))
            .await
            .expect("connect");
        let (mut read_half, mut write_half) = tokio::io::split(stream);

        seam::write_frame(
            &mut write_half,
            &Frame::Request {
                id: "flood".into(),
                method: "test.flood".into(),
                args: serde_json::json!({"bytes": 2 * 1024 * 1024}).to_string(),
            },
        )
        .await
        .unwrap();

        // Deliberately do not read anything for a while: the flood must
        // still finish (bounded time), not hang forever waiting on a full
        // socket buffer.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut saw_flood_reply = false;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !saw_flood_reply && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(5), seam::read_frame(&mut read_half))
                .await
            {
                Ok(Ok(Some(Frame::Reply { id, ok }))) => {
                    assert_eq!(id, "flood");
                    let value: serde_json::Value =
                        serde_json::from_str(&ok.expect("flood reply ok")).unwrap();
                    assert!(value["droppedChunks"].as_u64().unwrap_or(0) > 0);
                    saw_flood_reply = true;
                }
                Ok(Ok(Some(_other))) => {}
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("read error: {e}"),
                Err(_) => panic!("timed out waiting for the flood reply"),
            }
        }
        assert!(
            saw_flood_reply,
            "the flood must complete even once this client fell behind"
        );

        write_half.shutdown().await.ok();
        drop(lock);
        serve_task.abort();
    }
}

/// K13: the session protocol's `share.*` methods over `ctl` (request and
/// reply; the two-peer protocol itself is `tests/session_conformance.rs`):
/// the service needs the Freenet backend, a v2 core mints `pv: 2` routes,
/// refuses a `pv`-less one at `share.join` and at `freenet.announce` (PV-1,
/// PV-3), and hosts a session's links.
#[test]
fn share_methods_over_ctl() {
    let sidecar = RunningSidecar::spawn();
    let err = sidecar.ctl("share.status", r#"{"sessionId":"x"}"#);
    assert!(!err.status.success());
    assert!(String::from_utf8_lossy(&err.stderr).contains("E_BACKEND_UNAVAILABLE"));
    if !zxterm_testkit::local_node::freenet_available() {
        println!("SKIP share_methods_over_ctl (node part): freenet binary not on PATH");
        return;
    }
    let node = zxterm_testkit::local_node::LocalNode::start().expect("LocalNode");
    ctl_json(
        &sidecar,
        "freenet.start",
        serde_json::json!({"secretKey": "22".repeat(32), "nodeUrl": node.url, "iceServers": []}),
    );
    let link = "ab".repeat(16);
    let route = ctl_json(
        &sidecar,
        "freenet.routeFor",
        serde_json::json!({"linkId": link}),
    );
    assert_eq!(route["params"]["pv"], 2, "{route}");
    let sid = "cd".repeat(32);
    ctl_json(
        &sidecar,
        "share.hostOpen",
        serde_json::json!({
            "sessionId": sid, "logKey": "01".repeat(32), "metaKey": "02".repeat(32),
            "inputMode": "all", "info": {"name": "s", "cols": 80, "rows": 24},
            "local": {"deviceSecretKey": "03".repeat(32), "identityKey": "04".repeat(32),
                      "identityProof": "0506", "deviceName": "host"},
        }),
    );
    ctl_json(
        &sidecar,
        "share.addLink",
        serde_json::json!({"sessionId": sid, "linkId": link, "type": "group", "autoJoin": true}),
    );
    let status = ctl_json(
        &sidecar,
        "share.status",
        serde_json::json!({"sessionId": sid}),
    );
    assert_eq!(status["epoch"], 1);
    assert_eq!(status["inputMode"], "all");
    assert_eq!(status["links"][0]["linkId"], link);
    assert_eq!(status["links"][0]["revoked"], false);

    let mut v1 = route.clone();
    v1["params"].as_object_mut().unwrap().remove("pv");
    let join = sidecar.ctl(
        "share.join",
        &serde_json::json!({
            "route": v1, "expectedPeerKey": route["params"]["host"], "linkId": link,
            "local": {"deviceSecretKey": "07".repeat(32), "identityKey": "08".repeat(32),
                      "identityProof": "09"},
        })
        .to_string(),
    );
    assert!(!join.status.success());
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(
        stderr.contains("E_BACKEND_UNSUPPORTED") && stderr.contains("upgrade"),
        "{stderr}"
    );
    let announce = sidecar.ctl(
        "freenet.announce",
        &serde_json::json!({"linkId": link, "route": v1}).to_string(),
    );
    assert!(String::from_utf8_lossy(&announce.stderr).contains("E_BACKEND_UNSUPPORTED"));

    assert_eq!(
        ctl_json(
            &sidecar,
            "share.revokeLink",
            serde_json::json!({"sessionId": sid, "linkId": link})
        )["revoked"],
        true
    );
    let status = ctl_json(
        &sidecar,
        "share.status",
        serde_json::json!({"sessionId": sid}),
    );
    assert_eq!(status["links"][0]["revoked"], true);
    assert_eq!(
        status["epoch"], 1,
        "no member joined through it: no rotation"
    );
    ctl_json(
        &sidecar,
        "share.hostClose",
        serde_json::json!({"sessionId": sid}),
    );
    ctl_json(&sidecar, "freenet.stop", serde_json::json!({}));
}

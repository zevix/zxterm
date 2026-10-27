//! K5 acceptance gate (spike S1): a live local Freenet node, Rust
//! `route::mint` + `node::Client::put`/`update` on one side and ZBTerm's own
//! JS backend `Get`ting and verifying on the other, and the reverse
//! (`Route::mint` "route.js::mint" bytes cross the process boundary as
//! plain JSON, never as a wire/derivation string minted here). Also
//! measures put -> notification latency (n = 20) against P-1's 37/44 ms,
//! and probes which of `S-05`'s four symptoms this machine's
//! `freenet`/`freenet-stdlib` actually shows.
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
//! > 2026-09-30, K13: ZBTerm's reference JS is a v1 peer (`protocol.md`
//! > §12): the two cross-language directions exchange v1 routes
//! > (`route::mint_v1`, `route::verify_v1`); the Rust-only probes mint v2
//! > ones.
use std::future::Future;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use zxterm_core::freenet::node::{self, Client};
use zxterm_core::freenet::route::{self, Contracts as RouteContracts, Route, RouteParams};
use zxterm_core::freenet::signal::{self, EntryFields};
use zxterm_testkit::local_node::{LocalNode, freenet_available};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

fn route_contracts(c: &zxterm_testkit::contracts::Contracts) -> RouteContracts {
    RouteContracts {
        known: c.known.clone(),
        current: c.current.clone(),
        pointer_code: c.pointer.code.clone(),
    }
}

fn entry_delta_json(e: &signal::Entry) -> Vec<u8> {
    serde_json::to_vec(&json!({"e": [{
        "l": e.l, "r": e.r, "s": e.s, "t": e.t, "d": e.d, "p": e.p, "g": e.g,
    }]}))
    .expect("serialize entry delta")
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = (((sorted_ms.len() - 1) as f64) * p).round() as usize;
    sorted_ms[idx.min(sorted_ms.len() - 1)]
}

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(fut)
}

#[test]
fn freenet_node_client_and_signalling_round_trip() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP freenet_node_client_and_signalling_round_trip: {reason}");
        return;
    }
    if !freenet_available() {
        println!("SKIP freenet_node_client_and_signalling_round_trip: freenet binary not on PATH");
        return;
    }

    let contracts = zxterm_testkit::contracts::load();
    let rc = route_contracts(&contracts);
    let node = LocalNode::start().expect("start a local freenet node");

    block_on(async {
        // Preflight: a trivial Put, before any of the real gates run.
        // R-01 (register.md, resolved 2026-09-29): this node's public WS
        // endpoint defaults to a flatbuffers wire encoding no published
        // `freenet-stdlib` Rust client speaks; `node::Client::connect`
        // fixes this by always appending `?encodingProtocol=native`
        // (`node::with_native_encoding`), which switches the node onto the
        // bincode `EncodingProtocol::Native` path every `freenet-stdlib`
        // Rust client actually encodes. This preflight exists so a
        // regression of that fix fails fast, with one clear message,
        // instead of every gate below failing the same way independently.
        preflight(&node.url, &rc)
            .await
            .expect("preflight Put must succeed now that connect() requests the native encoding");

        rust_mints_js_verifies(&node, &rc).await;
        put_to_notification_latency(&node, &rc).await;
        js_mints_rust_verifies(&node, &rc).await;
        s05_symptom_probe(&node, &rc).await;
    });
}

/// A trivial `Put` of a throwaway instance, to fail fast (and with a clear
/// reason) if this machine's node does not speak the wire format this
/// `freenet-stdlib` version's Rust client encodes, rather than have every
/// later `.expect()` in this file panic with the same underlying cause.
async fn preflight(url: &str, rc: &RouteContracts) -> Result<(), String> {
    let mut client = Client::connect(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let host_sk = SigningKey::from_bytes(&[1u8; 32]);
    let host_hex = hex::encode(host_sk.verifying_key().to_bytes());
    let r = route::mint("link-preflight", &host_hex, rc);
    let wasm = rc
        .known
        .get(&r.code)
        .expect("current signalling wasm")
        .clone();
    let params_bytes = route::params_bytes(&r.params);
    client
        .put(&wasm, &params_bytes, b"{\"e\":[]}".to_vec())
        .await
        .map_err(|e| format!("put: {e}"))?;
    Ok(())
}

/// Direction 1: Rust mints the route and writes the signalling instance;
/// ZBTerm's own JS `Get`s it and verifies the entry with
/// `signal.js::verifyEntry` and the route with `route.js::verify`.
async fn rust_mints_js_verifies(node: &LocalNode, rc: &RouteContracts) {
    let host_sk = SigningKey::from_bytes(&[101u8; 32]);
    let host_vk = host_sk.verifying_key();
    let host_hex = hex::encode(host_vk.to_bytes());

    let r = route::mint_v1("link-rust", &host_hex, rc);
    let wasm = rc
        .known
        .get(&r.code)
        .expect("current signalling wasm must be in `known`")
        .clone();
    let params_bytes = route::params_bytes(&r.params);

    let mut client = Client::connect(&node.url)
        .await
        .expect("connect rust client (direction 1)");
    client
        .put(&wasm, &params_bytes, b"{\"e\":[]}".to_vec())
        .await
        .expect("put empty signalling state");

    let viewer_sk = SigningKey::from_bytes(&[102u8; 32]);
    let viewer_vk = viewer_sk.verifying_key();
    let viewer_hex = hex::encode(viewer_vk.to_bytes());
    let entry = signal::sign_entry(
        &viewer_sk,
        &params_bytes,
        &EntryFields {
            l: "cid00000000000000000000000rust1",
            r: &format!("v:{viewer_hex}"),
            s: 0,
            t: now_ms(),
            d: false,
            p: "hello-from-rust",
        },
    );

    let addr = node::contract_key(&wasm, &params_bytes);
    client
        .update(
            &addr.key,
            entry_delta_json(&entry),
            node::REQUEST_TIMEOUT_MS,
        )
        .await
        .expect("update: sign+put the entry");

    let route_json = json!({
        "sig": r.sig,
        "code": r.code,
        "params": {"ttl_ms": r.params.ttl_ms, "host": r.params.host, "n": r.params.n},
        "ptr": r.ptr,
        "k": r.k,
    });
    let js_input = json!({
        "nodeUrl": node.url,
        "route": route_json,
        "viewerPublicKeyHex": viewer_hex,
        "hostPublicKeyHex": host_hex,
        "entryL": entry.l,
        "entryR": entry.r,
        "entrySeq": entry.s,
    });
    let output = zxterm_testkit::js::run_with_stdin(
        "freenet_node_get_verify.js",
        &[],
        &serde_json::to_vec(&js_input).unwrap(),
    )
    .expect("spawn freenet_node_get_verify.js");
    assert!(
        output.status.success(),
        "freenet_node_get_verify.js failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out: Value =
        serde_json::from_slice(&output.stdout).expect("parse freenet_node_get_verify.js output");
    assert_eq!(
        out["entryFound"],
        json!(true),
        "JS must find the Rust-written entry"
    );
    assert_eq!(
        out["routeChecked"],
        json!(true),
        "route.js::verify must accept the Rust-minted route"
    );
    assert_eq!(
        out["entryVerified"],
        json!(true),
        "direction rust-mint-write/js-get-verify: verified: true expected"
    );
    println!("direction rust-mint-write/js-get-verify: verified: true");
}

/// Spike S1's own measure: put -> notification latency, n = 20, compared to
/// P-1's 37/44 ms (`design.md` §2, §6 S1).
async fn put_to_notification_latency(node: &LocalNode, rc: &RouteContracts) {
    let host_sk = SigningKey::from_bytes(&[111u8; 32]);
    let host_hex = hex::encode(host_sk.verifying_key().to_bytes());
    let r = route::mint("link-latency", &host_hex, rc);
    let wasm = rc.known.get(&r.code).unwrap().clone();
    let params_bytes = route::params_bytes(&r.params);
    let addr = node::contract_key(&wasm, &params_bytes);

    let mut client = Client::connect(&node.url)
        .await
        .expect("connect rust client (latency)");
    client
        .put(&wasm, &params_bytes, b"{\"e\":[]}".to_vec())
        .await
        .expect("put empty state (latency)");
    client
        .subscribe(addr.key.id())
        .await
        .expect("subscribe (latency)");

    let viewer_sk = SigningKey::from_bytes(&[112u8; 32]);
    let viewer_hex = hex::encode(viewer_sk.verifying_key().to_bytes());

    let mut samples_ms: Vec<f64> = Vec::with_capacity(20);
    for i in 0..20u32 {
        let e = signal::sign_entry(
            &viewer_sk,
            &params_bytes,
            &EntryFields {
                l: "cid00000000000000000000latency1",
                r: &format!("v:{viewer_hex}"),
                s: i,
                t: now_ms(),
                d: false,
                p: "lat",
            },
        );
        let start = Instant::now();
        client
            .update(&addr.key, entry_delta_json(&e), node::REQUEST_TIMEOUT_MS)
            .await
            .expect("update (latency sample)");
        match client
            .recv_notification(addr.key.id(), node::REQUEST_TIMEOUT_MS)
            .await
        {
            Ok(_) => samples_ms.push(start.elapsed().as_secs_f64() * 1000.0),
            Err(e) => println!("put->notification sample {i}: no notification observed ({e})"),
        }
    }
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if samples_ms.is_empty() {
        println!(
            "put->notification p50/p95: no notifications observed in 20 attempts (see R-nn for S-05(d))"
        );
    } else {
        let p50 = percentile(&samples_ms, 0.50);
        let p95 = percentile(&samples_ms, 0.95);
        println!(
            "put->notification p50/p95 = {p50:.1}/{p95:.1} ms (n={} of 20 attempted); P-1's 37/44 ms",
            samples_ms.len()
        );
    }
}

/// Direction 2: ZBTerm's own JS mints the route and writes the signalling
/// instance; Rust `Get`s it and verifies with `signal::verify_entry` and
/// `route::verify`.
async fn js_mints_rust_verifies(node: &LocalNode, rc: &RouteContracts) {
    let host_sk = SigningKey::from_bytes(&[121u8; 32]);
    let host_hex = hex::encode(host_sk.verifying_key().to_bytes());
    let viewer_seed = [122u8; 32];

    let js_input = json!({
        "nodeUrl": node.url,
        "hostPublicKeyHex": host_hex,
        "viewerSeedHex": hex::encode(viewer_seed),
        "entryL": "cid00000000000000000000000000js",
        "entrySeq": 0,
        "entryPayload": "hello-from-js",
    });
    let output = zxterm_testkit::js::run_with_stdin(
        "freenet_node_mint_put.js",
        &[],
        &serde_json::to_vec(&js_input).unwrap(),
    )
    .expect("spawn freenet_node_mint_put.js");
    assert!(
        output.status.success(),
        "freenet_node_mint_put.js failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out: Value =
        serde_json::from_slice(&output.stdout).expect("parse freenet_node_mint_put.js output");

    let jr = &out["route"];
    let route2 = Route {
        sig: jr["sig"].as_str().unwrap().to_string(),
        code: jr["code"].as_str().unwrap().to_string(),
        params: RouteParams {
            ttl_ms: jr["params"]["ttl_ms"].as_u64().unwrap(),
            host: jr["params"]["host"].as_str().unwrap().to_string(),
            n: jr["params"]["n"].as_str().unwrap().to_string(),
            pv: None,
        },
        ptr: jr["ptr"].as_str().map(|s| s.to_string()),
        k: jr["k"].as_str().unwrap().to_string(),
    };
    let checked =
        route::verify_v1(&route2, &host_hex, rc).expect("JS-minted route must verify in Rust");

    let addr2 = node::contract_key(&checked.wasm, &checked.params);
    let mut client2 = Client::connect(&node.url)
        .await
        .expect("connect rust client (direction 2)");
    let state = client2
        .get(addr2.key.id(), node::REQUEST_TIMEOUT_MS)
        .await
        .expect("get the JS-written state");
    let state_json: Value = serde_json::from_slice(&state).expect("parse state JSON");
    let entries = state_json["e"]
        .as_array()
        .expect("state has an entries array");
    let js_entry = entries
        .iter()
        .find(|e| e["l"] == json!("cid00000000000000000000000000js") && e["s"] == json!(0))
        .expect("the JS-written entry must be present");

    let entry2 = signal::Entry {
        l: js_entry["l"].as_str().unwrap().to_string(),
        r: js_entry["r"].as_str().unwrap().to_string(),
        s: js_entry["s"].as_u64().unwrap() as u32,
        t: js_entry["t"].as_u64().unwrap(),
        d: js_entry["d"].as_bool().unwrap_or(false),
        p: js_entry["p"].as_str().unwrap().to_string(),
        g: js_entry["g"].as_str().unwrap().to_string(),
    };
    let viewer_vk_bytes: [u8; 32] = hex::decode(out["viewerPublicKeyHex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let viewer_vk2 = VerifyingKey::from_bytes(&viewer_vk_bytes).unwrap();
    assert!(
        signal::verify_entry(&viewer_vk2, &checked.params, &entry2),
        "direction js-mint-write/rust-get-verify: verified: true expected"
    );
    println!("direction js-mint-write/rust-get-verify: verified: true");
}

/// Records, by printing, which of `S-05`'s four symptoms this machine's
/// `freenet`/`freenet-stdlib` actually shows (K5 step 11; the caller turns
/// these into `R-nn` register rows at landing time — see K5's handoff
/// notes for what was observed on this run).
async fn s05_symptom_probe(node: &LocalNode, rc: &RouteContracts) {
    let host_sk = SigningKey::from_bytes(&[131u8; 32]);
    let host_hex = hex::encode(host_sk.verifying_key().to_bytes());
    let r = route::mint("link-s05", &host_hex, rc);
    let wasm = rc.known.get(&r.code).unwrap().clone();
    let params_bytes = route::params_bytes(&r.params);
    let addr = node::contract_key(&wasm, &params_bytes);

    let mut client = Client::connect(&node.url)
        .await
        .expect("connect rust client (S-05 probe)");

    // (b) A second Put of the same instance: our client refuses to call
    // put() twice by convention, but this probe deliberately issues the
    // node request twice to observe the node's actual behaviour, exactly
    // the workaround's justification. Elapsed time distinguishes a prompt
    // (even if unusual) answer from a genuine hang against this probe's
    // own timeout (REQUEST_TIMEOUT_MS).
    client
        .put(&wasm, &params_bytes, b"{\"e\":[]}".to_vec())
        .await
        .expect("first put (S-05 probe)");
    let start = Instant::now();
    let second_put = client
        .put(&wasm, &params_bytes, b"{\"e\":[]}".to_vec())
        .await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    match second_put {
        Ok(()) => println!(
            "S-05(b) probe: a second Put of the same instance was answered as Ok in {elapsed_ms:.0} ms (not hung) on this machine"
        ),
        Err(e) if elapsed_ms >= node::REQUEST_TIMEOUT_MS as f64 * 0.9 => {
            let backlog = client.backlog_kinds();
            println!(
                "S-05(b) probe: a second Put of the same instance was never answered as a PutResponse within {} ms ({elapsed_ms:.0} ms elapsed; backlog now holds {backlog:?}), matching the JS-side symptom (an UpdateResponse the caller's put() never watches for): {e:?}",
                node::REQUEST_TIMEOUT_MS
            );
        }
        Err(e) => println!(
            "S-05(b) probe: a second Put of the same instance answered promptly in {elapsed_ms:.0} ms with an error (not a hang): {e:?}"
        ),
    }

    // (a) subscribe ack path: our Client::subscribe already tolerates a
    // PutResponse standing in for the SDK's own ack; elapsed time and the
    // response kind together say whether the SDK's own SubscribeResponse
    // now arrives, or a PutResponse still stands in for it.
    let start = Instant::now();
    let subscribed = client.subscribe(addr.key.id()).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    match subscribed {
        Ok(kind) => println!(
            "S-05(a) probe: subscribe() acked in {elapsed_ms:.0} ms (of a {} ms budget) via a {kind}",
            node::REQUEST_TIMEOUT_MS
        ),
        Err(e) => println!(
            "S-05(a) probe: subscribe() did not ack within {} ms ({elapsed_ms:.0} ms elapsed): {e:?}",
            node::REQUEST_TIMEOUT_MS
        ),
    }

    // (c) Get of a genuinely missing instance: never assume the SDK's own
    // 30s timer; use a short timeout and report whether anything answers,
    // and whether an answer (if any) arrived promptly or near the timeout.
    let missing_wasm = b"not-a-real-contract-wasm-for-s05-c-probe";
    let missing_params = b"{}";
    let missing_addr = node::contract_key(missing_wasm, missing_params);
    let mut probe_client = Client::connect(&node.url)
        .await
        .expect("connect rust client (S-05 c probe)");
    let get_timeout_ms = 1_500u64;
    let start = Instant::now();
    let missing_get = probe_client
        .get(missing_addr.key.id(), get_timeout_ms)
        .await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    match missing_get {
        Ok(_) => println!(
            "S-05(c) probe: Get of a missing instance was answered with state in {elapsed_ms:.0} ms (unexpected)"
        ),
        Err(e) if elapsed_ms >= get_timeout_ms as f64 * 0.9 => println!(
            "S-05(c) probe: Get of a missing instance never answered, hit our own {get_timeout_ms} ms timeout ({elapsed_ms:.0} ms elapsed), matching the JS-side symptom: {e:?}"
        ),
        Err(e) => println!(
            "S-05(c) probe: Get of a missing instance answered promptly in {elapsed_ms:.0} ms with a clean error (not a hang), NOT matching the JS-side symptom: {e:?}"
        ),
    }

    // (d) notification shape: already exercised by `notification_parts` in
    // `put_to_notification_latency`; this reports the raw variant seen.
    let viewer_sk = SigningKey::from_bytes(&[132u8; 32]);
    let viewer_hex = hex::encode(viewer_sk.verifying_key().to_bytes());
    let e = signal::sign_entry(
        &viewer_sk,
        &params_bytes,
        &EntryFields {
            l: "cid0000000000000000000000s05dp",
            r: &format!("v:{viewer_hex}"),
            s: 0,
            t: now_ms(),
            d: false,
            p: "s05d",
        },
    );
    client
        .update(&addr.key, entry_delta_json(&e), node::REQUEST_TIMEOUT_MS)
        .await
        .expect("update (S-05 d probe)");
    match client
        .recv_notification_with_kind(addr.key.id(), node::REQUEST_TIMEOUT_MS)
        .await
    {
        Ok((parts, kind)) => println!(
            "S-05(d) probe: notification carried a {kind} ({} part(s), {} byte(s) total)",
            parts.len(),
            parts.iter().map(Vec::len).sum::<usize>()
        ),
        Err(e) => println!("S-05(d) probe: no notification observed: {e}"),
    }
}

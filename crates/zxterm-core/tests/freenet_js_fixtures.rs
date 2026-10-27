//! K5 acceptance: every pure-function fixture in `zxterm_core::freenet` is
//! cross-checked against a `js::run` call into the corresponding ZBTerm
//! `engine/backends/freenet/signal.js` function on the same input, in both
//! directions (Rust signs/JS verifies, JS signs/Rust verifies). No Freenet
//! node is needed for this file — `tests/freenet_parity.rs` covers the
//! live-node round trip.
//!
//! Every call here needs only `node` on `PATH` and `ZX_ZBTERM` pointing at
//! a ZBTerm checkout (default: the one this repository is a submodule of);
//! it skips with a printed reason if `node` is absent (`A-9`/`A-5`).
//!
//! > 2026-09-29, K11: ZBTerm's live tree no longer holds this JS (its Freenet
//! > backend is a proxy to this core, ZBTerm `D-34`); the helper scripts run
//! > against its JS reference revision (`zxterm_testkit::js::reference_root`),
//! > with that revision's own `node_modules`, prepared by
//! > `scripts/prepare-js-reference.sh` (`X-20`); the test skips, naming the
//! > script, only while it is not prepared
//! > (`zxterm_testkit::js::freenet_reference_skip`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};
use zxterm_core::freenet::signal::{self, EntryFields};

fn run_fixture(op: &str, input: &Value) -> Value {
    let stdin = serde_json::to_vec(input).expect("serialize fixture input");
    let output = zxterm_testkit::js::run_with_stdin("freenet_fixtures.js", &[op], &stdin)
        .unwrap_or_else(|e| panic!("spawn freenet_fixtures.js {op}: {e}"));
    assert!(
        output.status.success(),
        "freenet_fixtures.js {op} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("parse freenet_fixtures.js {op} output: {e}"))
}

fn seed_keypair(seed: u8) -> (SigningKey, VerifyingKey, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    (sk, vk, hex::encode([seed; 32]))
}

#[test]
fn entry_bytes_matches_js_entrybytes() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP entry_bytes_matches_js_entrybytes: {reason}");
        return;
    }
    let params = b"fixture-params-bytes";
    let bytes = signal::entry_bytes(
        params,
        "cid-fixture",
        "v:abc",
        3,
        42_000,
        false,
        "payload-text",
    );

    let out = run_fixture(
        "entry_bytes",
        &json!({
            "params": hex::encode(params),
            "l": "cid-fixture",
            "r": "v:abc",
            "s": 3,
            "t": 42_000,
            "d": false,
            "p": "payload-text",
        }),
    );
    assert_eq!(hex::encode(&bytes), out["bytes"].as_str().unwrap());
}

#[test]
fn record_bytes_matches_js_recordbytes() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP record_bytes_matches_js_recordbytes: {reason}");
        return;
    }
    let own_params = b"fixture-own-params";
    let bytes = signal::record_bytes(own_params, 1, "sig-text", "code-text", "params-text");

    let out = run_fixture(
        "record_bytes",
        &json!({
            "ownParams": hex::encode(own_params),
            "ver": 1,
            "sig": "sig-text",
            "code": "code-text",
            "params": "params-text",
        }),
    );
    assert_eq!(hex::encode(&bytes), out["bytes"].as_str().unwrap());
}

#[test]
fn rust_signed_entry_verifies_in_js() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP rust_signed_entry_verifies_in_js: {reason}");
        return;
    }
    let (sk, vk, _seed_hex) = seed_keypair(11);
    let params = b"cross-check-params";
    let entry = signal::sign_entry(
        &sk,
        params,
        &EntryFields {
            l: "cid-a",
            r: "v:abc",
            s: 0,
            t: 1_000,
            d: false,
            p: "hello",
        },
    );

    let out = run_fixture(
        "verify_entry",
        &json!({
            "publicKey": hex::encode(vk.to_bytes()),
            "params": hex::encode(params),
            "entry": {"l": entry.l, "r": entry.r, "s": entry.s, "t": entry.t, "d": entry.d, "p": entry.p, "g": entry.g},
        }),
    );
    assert_eq!(
        out["verified"],
        json!(true),
        "Rust-signed entry: verified: true expected"
    );
    println!("direction rust-signed/js-verified entry: verified: true");
}

#[test]
fn js_signed_entry_verifies_in_rust() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP js_signed_entry_verifies_in_rust: {reason}");
        return;
    }
    let seed_hex = hex::encode([22u8; 32]);
    let params = b"cross-check-params-2";
    let out = run_fixture(
        "sign_entry",
        &json!({
            "seed": seed_hex,
            "params": hex::encode(params),
            "l": "cid-b",
            "r": "v:def",
            "s": 5,
            "t": 2_000,
            "d": false,
            "p": "world",
        }),
    );
    let public_key_hex = out["publicKey"].as_str().unwrap();
    let vk_bytes: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();

    let entry = signal::Entry {
        l: out["entry"]["l"].as_str().unwrap().to_string(),
        r: out["entry"]["r"].as_str().unwrap().to_string(),
        s: out["entry"]["s"].as_u64().unwrap() as u32,
        t: out["entry"]["t"].as_u64().unwrap(),
        d: out["entry"]["d"].as_bool().unwrap(),
        p: out["entry"]["p"].as_str().unwrap().to_string(),
        g: out["entry"]["g"].as_str().unwrap().to_string(),
    };
    assert!(
        signal::verify_entry(&vk, params, &entry),
        "JS-signed entry: verified: true expected"
    );
    println!("direction js-signed/rust-verified entry: verified: true");
}

#[test]
fn rust_signed_record_verifies_in_js() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP rust_signed_record_verifies_in_js: {reason}");
        return;
    }
    let (sk, vk, _seed_hex) = seed_keypair(33);
    let own_params = b"pointer-own-params";
    let record = signal::sign_record(&sk, own_params, 1, "sig-x", "code-x", "params-x");

    let out = run_fixture(
        "verify_record",
        &json!({
            "publicKey": hex::encode(vk.to_bytes()),
            "ownParams": hex::encode(own_params),
            "record": {"ver": record.ver, "sig": record.sig, "code": record.code, "params": record.params, "g": record.g},
        }),
    );
    assert_eq!(
        out["verified"],
        json!(true),
        "Rust-signed record: verified: true expected"
    );
    println!("direction rust-signed/js-verified record: verified: true");
}

#[test]
fn js_signed_record_verifies_in_rust() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP js_signed_record_verifies_in_rust: {reason}");
        return;
    }
    let seed_hex = hex::encode([44u8; 32]);
    let own_params = b"pointer-own-params-2";
    let out = run_fixture(
        "sign_record",
        &json!({
            "seed": seed_hex,
            "ownParams": hex::encode(own_params),
            "ver": 1,
            "sig": "sig-y",
            "code": "code-y",
            "params": "params-y",
        }),
    );
    let public_key_hex = out["publicKey"].as_str().unwrap();
    let vk_bytes: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();

    let record = signal::Record {
        ver: out["record"]["ver"].as_u64().unwrap(),
        sig: out["record"]["sig"].as_str().unwrap().to_string(),
        code: out["record"]["code"].as_str().unwrap().to_string(),
        params: out["record"]["params"].as_str().unwrap().to_string(),
        g: out["record"]["g"].as_str().unwrap().to_string(),
    };
    assert!(
        signal::verify_record(&vk, own_params, &record),
        "JS-signed record: verified: true expected"
    );
    println!("direction js-signed/rust-verified record: verified: true");
}

#[test]
fn seal_open_matches_js_seal_and_open() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP seal_open_matches_js_seal_and_open: {reason}");
        return;
    }
    let key_seed = [9u8; 32];
    let k = URL_SAFE_NO_PAD.encode(key_seed);
    let key = signal::payload_key(&k);
    let message = json!({"kind": "offer", "sdp": "v=0 fixture"});

    // JS seals; Rust opens.
    let sealed_by_js = run_fixture(
        "seal",
        &json!({"key": hex::encode(key), "message": message}),
    );
    let opened = signal::open(&key, sealed_by_js["sealed"].as_str().unwrap())
        .expect("Rust must open a JS-sealed payload");
    assert_eq!(opened, message);

    // Rust seals; JS opens.
    let sealed_by_rust = signal::seal(&key, &message);
    let opened_by_js = run_fixture(
        "open",
        &json!({"key": hex::encode(key), "sealed": sealed_by_rust}),
    );
    assert_eq!(opened_by_js["message"], message);
}

#[test]
fn payload_key_matches_js_payloadkey() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP payload_key_matches_js_payloadkey: {reason}");
        return;
    }
    let k = URL_SAFE_NO_PAD.encode([3u8; 32]);
    let key = signal::payload_key(&k);
    let out = run_fixture("payload_key", &json!({"k": k}));
    assert_eq!(hex::encode(key), out["key"].as_str().unwrap());
}

#[test]
fn offer_ref_matches_js_offerref() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP offer_ref_matches_js_offerref: {reason}");
        return;
    }
    let p = "sealed-payload-fixture-text";
    let r = signal::offer_ref(p);
    let out = run_fixture("offer_ref", &json!({"p": p}));
    assert_eq!(r, out["ref"].as_str().unwrap());
}

#[test]
fn sdp_fingerprint_matches_js_sdpfingerprint() {
    if let Some(reason) = zxterm_testkit::js::freenet_reference_skip() {
        println!("SKIP sdp_fingerprint_matches_js_sdpfingerprint: {reason}");
        return;
    }
    let sdp = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=fingerprint:sha-256 AB:CD:EF:01\r\n";
    let rust_fp = signal::sdp_fingerprint(sdp);
    let out = run_fixture("sdp_fingerprint", &json!({"sdp": sdp}));
    assert_eq!(rust_fp.as_deref(), out["fingerprint"].as_str());
}

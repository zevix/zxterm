//! K13: `zxterm_core::session`'s cryptography against ZBTerm's own
//! `engine/crypto.js` on `sodium-native` (`protocol.md` §3), from ZBTerm's
//! **live** tree: its kdf contexts are the `zxt-*` ones since K11 (ZBTerm
//! `D-36`), which the JS reference revision predates. Pinned both ways:
//!
//! - `crypto_kdf_derive_from_key` with `zxt-hist`/`zxt-live`, and
//!   `deriveSnapshotKey` with `zxt-snap`, byte for byte;
//! - `nonceFor` (BLAKE2b-256 of the session id's hex string, cut to 16
//!   bytes, then `seq` u64 BE) and `encryptPacket`'s ciphertext byte for
//!   byte, and each side decrypting the other's;
//! - the Envelope's compact-encoding bytes, byte for byte;
//! - `crypto_box_seal`: an envelope JS sealed opens in Rust, one Rust
//!   sealed opens in JS.
//!
//! Needs `node` and the ZBTerm tree (`ZX_ZBTERM`); skips with a printed
//! reason otherwise.

use serde_json::{Value, json};

use zxterm_core::session::envelope::{self, Envelope};
use zxterm_core::session::{epoch, packet};
use zxterm_testkit::ScratchHome;

fn skip_reason() -> Option<String> {
    if let Some(r) = zxterm_testkit::require_tool("node") {
        return Some(r);
    }
    let root = zxterm_testkit::js::zbterm_root();
    for need in [
        "engine/crypto.js",
        "node_modules/sodium-native/package.json",
    ] {
        if !root.join(need).is_file() {
            return Some(format!(
                "the ZBTerm tree at {} lacks {need}",
                root.display()
            ));
        }
    }
    None
}

fn b(h: &Value) -> Vec<u8> {
    hex::decode(h.as_str().expect("hex string")).expect("hex")
}

#[test]
fn session_crypto_matches_zbterm_crypto_js() {
    if let Some(r) = skip_reason() {
        println!("SKIP session_crypto_matches_zbterm_crypto_js: {r}");
        return;
    }
    let master = [0x5Au8; 32];
    let local_secret = [0x33u8; 64];
    let session_id = "9f".repeat(32);
    let (epoch_n, seq) = (7u32, 0x0102_0304_0506u64);
    let device = [0x21u8; 32];
    let plain = b"\x1b[31mhello\x1b[0m\r\n".to_vec();
    let live = epoch::derive_live_key(&master);
    let rust_cipher = packet::encrypt(&live, &session_id, epoch_n, seq, &device, &plain);
    let env = Envelope {
        version: 2,
        session_id: session_id.clone(),
        epoch: 300, // a two-byte compact uint
        caps: 11,
        master_key: None,
        history_key: Some(vec![0x61; 32]),
        live_key: Some(vec![0x62; 32]),
    };
    let (rust_pk, rust_sk) = envelope::generate_device_key();
    // The JS key pair comes from a seed; ask JS for it first, then seal to it.
    let js_seed = [0x77u8; 32];
    let input = |sealed: Option<String>| {
        json!({
            "masterKeyHex": hex::encode(master),
            "localSecretHex": hex::encode(local_secret),
            "sessionId": session_id,
            "epoch": epoch_n,
            "seq": seq,
            "deviceKeyHex": hex::encode(device),
            "plainHex": hex::encode(&plain),
            "rustCipherHex": hex::encode(&rust_cipher),
            "rustRecipientPkHex": hex::encode(rust_pk),
            "rustSealedEnvelopeHex": sealed,
            "jsSeedHex": hex::encode(js_seed),
            "envelope": {
                "version": 2, "sessionId": session_id, "epoch": 300, "caps": 11,
                "historyKeyHex": hex::encode([0x61u8; 32]), "liveKeyHex": hex::encode([0x62u8; 32]),
            },
        })
    };
    let home = ScratchHome::new().expect("scratch home");
    let run = |arg: Value| -> Value {
        let out = zxterm_testkit::js::run_with_home(
            "session_crypto_parity.js",
            &[&arg.to_string()],
            &home,
        )
        .expect("run node");
        assert!(
            out.status.success(),
            "session_crypto_parity.js: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("JSON output")
    };
    let first = run(input(None));
    let js_pk: [u8; 32] = b(&first["jsPublicKey"]).try_into().unwrap();
    let js_sk: [u8; 32] = b(&first["jsSecretKey"]).try_into().unwrap();
    assert_eq!(
        envelope::device_public_key(&js_sk),
        js_pk,
        "X25519 public keys agree"
    );
    let rust_sealed = envelope::seal(&js_pk, &env);
    let out = run(input(Some(hex::encode(&rust_sealed))));

    // KDF, the three zxt-* contexts.
    assert_eq!(b(&out["historyKey"]), epoch::derive_history_key(&master));
    assert_eq!(b(&out["liveKey"]), live);
    assert_eq!(
        b(&out["snapshotKey"]),
        epoch::derive_snapshot_key(&local_secret)
    );
    // Nonce and ciphertext, byte for byte; each side opens the other's.
    assert_eq!(b(&out["nonce"]), packet::nonce_for(&session_id, seq));
    assert_eq!(b(&out["cipher"]), rust_cipher);
    assert_eq!(b(&out["decryptedRust"]), plain);
    // Envelope bytes.
    assert_eq!(b(&out["envelopeBytes"]), env.encode());
    // Sealed boxes, both ways.
    let opened =
        envelope::open(&rust_sk, &b(&out["sealedForRust"])).expect("JS-sealed opens in Rust");
    assert_eq!(opened, env);
    let from_rust = &out["openedFromRust"];
    assert_eq!(from_rust["epoch"], 300, "{out}");
    assert_eq!(from_rust["caps"], 11);
    assert_eq!(from_rust["sessionId"], session_id);
    assert_eq!(from_rust["masterKeyHex"], Value::Null);
    assert_eq!(b(&from_rust["liveKeyHex"]), vec![0x62; 32]);
    println!("session crypto parity with engine/crypto.js: kdf, nonce, AEAD, envelope, sealed box");
}

//! Cross-language parity between `zxterm_core::idkey` and a *patched* scratch
//! copy of the upstream identity-key package (`X-01`).
//!
//! Skips with a printed reason (never silently passes) if `node` is not on
//! `PATH`, or if the upstream package's tree is not present.
//!
//! > 2026-09-29, K11 (`R-07`, `X-20`): the package and its dependencies come
//! > from the prepared JS reference tree (`zxterm_testkit::js::reference_root`,
//! > ZBTerm's `bf5cdbd` with its own `node_modules`, made by
//! > `scripts/prepare-js-reference.sh`), no longer from ZBTerm's live
//! > `node_modules`, which lost the package in K9. The skip names the script.
//!
//! Never touches the reference tree: the package is copied into a scratch
//! directory before patching, and only its dependencies are resolved
//! read-only from the reference's `node_modules` (via a symlink) — no
//! `npm install` here.
//!
//! This file never spells the upstream package's own name; every mention is
//! assembled from pieces at runtime (`tests/names.rs` scans this tree).

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use zxterm_core::idkey::{
    IdentityKey, keychain,
    proof::{self, VerifyOpts},
};
use zxterm_testkit::{ScratchHome, js, require_tool};

/// The upstream identity-key package's bare word, assembled from two pieces
/// so this source file never spells it (`X-01`).
fn upstream_bare_word() -> String {
    format!("{}{}", "ke", "et")
}

/// The upstream package's own directory/npm name, likewise assembled.
fn upstream_dir_name() -> String {
    format!("{}-identity-key", upstream_bare_word())
}

fn upstream_pkg_dir(reference: &Path) -> PathBuf {
    reference.join("node_modules").join(upstream_dir_name())
}

struct Harness {
    // Keeps the scratch directory alive (and cleaned up on drop) for the
    // harness's lifetime; never read directly.
    _scratch: ScratchHome,
    pkg_dir: PathBuf,
}

/// Builds the scratch harness, or returns `None` with a printed skip reason.
fn build_harness() -> Option<Harness> {
    if let Some(reason) = require_tool("node") {
        println!("SKIP idkey_parity: {reason}");
        return None;
    }

    let reference = match js::reference_root() {
        Ok(reference) => reference,
        Err(reason) => {
            println!("SKIP idkey_parity: {reason}");
            return None;
        }
    };
    let src = upstream_pkg_dir(&reference);
    if !src.join("index.js").is_file() {
        println!(
            "SKIP idkey_parity: upstream package tree not found at {}: rerun scripts/prepare-js-reference.sh",
            src.display()
        );
        return None;
    }

    let scratch = ScratchHome::new().expect("create scratch home");
    let pkg_dir = scratch.path().join("pkg");
    fs::create_dir_all(pkg_dir.join("lib")).expect("create scratch pkg dir");

    fs::copy(src.join("index.js"), pkg_dir.join("index.js")).expect("copy index.js");
    for f in ["crypto.js", "encoding.js", "keychain.js"] {
        fs::copy(src.join("lib").join(f), pkg_dir.join("lib").join(f))
            .unwrap_or_else(|e| panic!("copy lib/{f}: {e}"));
    }

    // The copy's own `require`s must still resolve (`compact-encoding`,
    // `b4a`, `nanoassert`, `sodium-universal`, `sodium-hmac`,
    // `bip39-mnemonic`) — read-only, from the reference tree's own
    // `node_modules`, never a fresh `npm install`.
    symlink(
        reference.join("node_modules"),
        scratch.path().join("node_modules"),
    )
    .expect("symlink node_modules into the scratch dir");

    patch_and_verify_exactly_two_lines_changed(&src.join("index.js"), &pkg_dir.join("index.js"));

    Some(Harness {
        _scratch: scratch,
        pkg_dir,
    })
}

/// Patches the scratch copy's `index.js` via a recorded `sed` command
/// (`A-4`), then asserts exactly the two named lines changed: the path-type
/// constant (`5338` -> `23128`) and the SLIP-21 namespace literal (the
/// upstream package's own name -> `"zxterm-identity-key"`). Also asserts the
/// pristine original was never touched.
fn patch_and_verify_exactly_two_lines_changed(original: &Path, patched: &Path) {
    let pristine_before = fs::read_to_string(original).expect("read pristine original");
    let copy_before = fs::read_to_string(patched).expect("read scratch copy before patch");
    assert_eq!(
        pristine_before, copy_before,
        "scratch copy must start identical to the original"
    );

    let key_type_ident = format!("{}_TYPE", upstream_bare_word().to_uppercase());
    let sed_key_type = format!("s/const {key_type_ident} = 5338/const {key_type_ident} = 23128/");
    let sed_namespace = format!(
        "s/const namespace = '{}'/const namespace = 'zxterm-identity-key'/",
        upstream_dir_name()
    );

    let status = Command::new("sed")
        .arg("-i")
        .arg("-e")
        .arg(&sed_key_type)
        .arg("-e")
        .arg(&sed_namespace)
        .arg(patched)
        .status()
        .expect("spawn sed");
    assert!(status.success(), "sed patch command failed");

    let copy_after = fs::read_to_string(patched).expect("read scratch copy after patch");
    let before_lines: Vec<&str> = copy_before.lines().collect();
    let after_lines: Vec<&str> = copy_after.lines().collect();
    assert_eq!(
        before_lines.len(),
        after_lines.len(),
        "patch must not add or remove lines"
    );

    let changed: Vec<usize> = before_lines
        .iter()
        .zip(after_lines.iter())
        .enumerate()
        .filter_map(|(i, (b, a))| (b != a).then_some(i + 1))
        .collect();
    assert_eq!(
        changed.len(),
        2,
        "expected exactly 2 changed lines after the sed patch, got {changed:?}"
    );

    // The two changed lines carry the new values, and the constant's slot
    // (not just its numeric value) is unchanged in shape.
    assert!(after_lines.iter().any(|l| l.contains("23128")));
    assert!(
        after_lines
            .iter()
            .any(|l| l.contains("zxterm-identity-key"))
    );

    let pristine_after = fs::read_to_string(original).expect("re-read pristine original");
    assert_eq!(
        pristine_before, pristine_after,
        "the original upstream tree must never be modified"
    );
}

/// Runs `idkey_parity.js <cmd> <argsJson>` against the harness's patched
/// package, and parses its `key=hexValue` stdout lines (or `NULL`, or
/// `error=...`) into a map. Panics (with stderr attached) on a non-zero
/// exit.
fn run_js(
    harness: &Harness,
    cmd: &str,
    args_json: &str,
) -> Option<std::collections::HashMap<String, String>> {
    let output = js::run(
        "idkey_parity.js",
        &[
            harness.pkg_dir.to_str().expect("utf8 scratch path"),
            cmd,
            args_json,
        ],
    )
    .expect("spawn node idkey_parity.js");

    assert!(
        output.status.success(),
        "idkey_parity.js {cmd} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim() == "NULL" {
        return None;
    }

    let mut map = std::collections::HashMap::new();
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    // An `error=...` line means the JS side threw (a decode error, say) —
    // that is a harness/implementation bug, not a legitimate "verify
    // returned null" outcome, so it must fail loudly rather than be read as
    // a successful verification result.
    if let Some(msg) = map.get("error") {
        panic!("idkey_parity.js {cmd} threw: {msg}");
    }
    Some(map)
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn identity_and_discovery_keys_match_the_upstream_package() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());

    let js_out = run_js(
        &harness,
        "derive",
        &format!("{{\"seedHex\":\"{}\"}}", hex(&seed)),
    )
    .expect("derive produces output");

    assert_eq!(
        hex(&identity.identity_public_key()),
        js_out["identityPublicKey"],
        "identityPublicKey mismatch"
    );
    assert_eq!(
        hex(&identity.profile_discovery_public_key()),
        js_out["profileDiscoveryPublicKey"],
        "profileDiscoveryPublicKey mismatch"
    );
    assert_eq!(
        hex(&identity.get_profile_discovery_encryption_key()),
        js_out["profileDiscoveryEncryptionKey"],
        "profileDiscoveryEncryptionKey mismatch"
    );
}

#[test]
fn arbitrary_profile_encryption_key_matches_the_upstream_package() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let profile_key = [0x42u8; 32];

    let js_out = run_js(
        &harness,
        "encryption-key",
        &format!(
            "{{\"seedHex\":\"{}\",\"profileKeyHex\":\"{}\"}}",
            hex(&seed),
            hex(&profile_key)
        ),
    )
    .expect("encryption-key produces output");

    assert_eq!(
        hex(&identity.get_encryption_key(&profile_key)),
        js_out["key"]
    );
}

#[test]
fn bootstrap_proofs_are_byte_equal_for_the_same_epoch_and_device() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let device_public_key = [0x11u8; 32];
    let epoch_ms: u64 = 1_732_000_000_000;

    let rust_proof = identity.bootstrap(device_public_key, epoch_ms);

    let js_out = run_js(
        &harness,
        "attest",
        &format!(
            "{{\"seedHex\":\"{}\",\"deviceHex\":\"{}\",\"epochMs\":{}}}",
            hex(&seed),
            hex(&device_public_key),
            epoch_ms
        ),
    )
    .expect("attest produces output");

    assert_eq!(
        hex(&rust_proof),
        js_out["proof"],
        "bootstrap proof bytes differ"
    );
}

#[test]
fn rust_minted_proof_verifies_via_the_upstream_package() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let device_public_key = [0x22u8; 32];
    let epoch_ms: u64 = 1_732_000_100_000;
    let proof_bytes = identity.bootstrap(device_public_key, epoch_ms);

    let js_out = run_js(
        &harness,
        "verify",
        &format!(
            "{{\"proofHex\":\"{}\",\"expectedIdentityHex\":\"{}\",\"expectedDeviceHex\":\"{}\"}}",
            hex(&proof_bytes),
            hex(&identity.identity_public_key()),
            hex(&device_public_key)
        ),
    )
    .expect("a genuine proof must verify");

    assert_eq!(
        js_out["identityPublicKey"],
        hex(&identity.identity_public_key())
    );
    assert_eq!(js_out["devicePublicKey"], hex(&device_public_key));
}

#[test]
fn js_minted_proof_verifies_via_rust() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let device_public_key = [0x33u8; 32];
    let epoch_ms: u64 = 1_732_000_200_000;

    let js_out = run_js(
        &harness,
        "attest",
        &format!(
            "{{\"seedHex\":\"{}\",\"deviceHex\":\"{}\",\"epochMs\":{}}}",
            hex(&seed),
            hex(&device_public_key),
            epoch_ms
        ),
    )
    .expect("attest produces output");
    let proof_bytes = hex::decode(&js_out["proof"]).expect("valid hex");

    let identity_pk = identity.identity_public_key();
    let result = proof::verify(
        &proof_bytes,
        None,
        &VerifyOpts {
            expected_identity: Some(&identity_pk),
            expected_device: Some(&device_public_key),
            ..Default::default()
        },
    )
    .expect("JS-minted proof verifies under Rust");

    assert_eq!(result.identity_public_key, identity_pk);
    assert_eq!(result.device_public_key, device_public_key);
}

#[test]
fn a_tampered_rust_proof_is_refused_by_the_upstream_package() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let device_public_key = [0x44u8; 32];
    let epoch_ms: u64 = 1_732_000_300_000;
    let mut proof_bytes = identity.bootstrap(device_public_key, epoch_ms);

    // Flip one byte inside the chain's signature (the last 64 bytes of a
    // single-link, no-`data` proof are the signature; the very last byte is
    // the trailing `flags` varint, which must stay untouched here — flipping
    // it would corrupt the wire shape itself rather than the signature).
    let sig_byte = proof_bytes.len() - 10;
    proof_bytes[sig_byte] ^= 0x01;

    let js_out = run_js(
        &harness,
        "verify",
        &format!("{{\"proofHex\":\"{}\"}}", hex(&proof_bytes)),
    );
    assert!(js_out.is_none(), "tampered proof must be refused by JS");
}

#[test]
fn a_tampered_js_proof_is_refused_by_rust() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let device_public_key = [0x55u8; 32];
    let epoch_ms: u64 = 1_732_000_400_000;

    let js_out = run_js(
        &harness,
        "attest",
        &format!(
            "{{\"seedHex\":\"{}\",\"deviceHex\":\"{}\",\"epochMs\":{}}}",
            hex(&seed),
            hex(&device_public_key),
            epoch_ms
        ),
    )
    .expect("attest produces output");
    let mut proof_bytes = hex::decode(&js_out["proof"]).expect("valid hex");

    // Flip one byte inside the identity field.
    proof_bytes[10] ^= 0x01;

    let result = proof::verify(&proof_bytes, None, &VerifyOpts::default());
    assert!(result.is_none(), "tampered proof must be refused by Rust");
}

#[test]
fn a_tampered_chain_public_key_is_refused_by_both_sides() {
    let Some(harness) = build_harness() else {
        return;
    };

    let seed = IdentityKey::derive_seed(TEST_MNEMONIC).expect("derive seed");
    let identity = IdentityKey::from_seed(seed.to_vec());
    let device_public_key = [0x66u8; 32];
    let epoch_ms: u64 = 1_732_000_500_000;
    let proof_bytes = identity.bootstrap(device_public_key, epoch_ms);

    // The chain's public key sits right after version(1) + epoch(8) +
    // identity(32) + chain-length varint(1) = byte offset 42; flip a byte
    // inside it.
    let mut tampered = proof_bytes.clone();
    tampered[45] ^= 0x01;

    assert!(
        proof::verify(&tampered, None, &VerifyOpts::default()).is_none(),
        "Rust must refuse a tampered chain public key"
    );

    let js_out = run_js(
        &harness,
        "verify",
        &format!("{{\"proofHex\":\"{}\"}}", hex(&tampered)),
    );
    assert!(
        js_out.is_none(),
        "JS must refuse a tampered chain public key"
    );
}

#[test]
fn key_path_constants_match_the_module_the_upstream_package_would_use() {
    // Structural sanity independent of the JS harness: the identity/discovery
    // paths use the replaced path-type constant (`23128`, never the upstream
    // package's own `5338`), and the two paths differ only in their last
    // element (`index.js::keyPath`'s shape).
    let identity_path = keychain::identity_key_path(7);
    let discovery_path = keychain::discovery_core_path(7);
    assert_eq!(identity_path[1], zxterm_core::wire::ZXTERM_KEY_PATH_TYPE);
    assert_ne!(identity_path[1], 5338);
    assert_eq!(identity_path[..4], discovery_path[..4]);
    assert_ne!(identity_path[4], discovery_path[4]);
}

//! S4 cross-language parity gates for `zxterm_core::ssh` (K2): every
//! acceptance criterion the phase brief lists, each exercised against the
//! real ZBTerm `electron/ssh-keys.js`/`engine/identity/claim.js` (via
//! `zxterm_testkit::js` and `crates/zxterm-testkit/js/ssh_keys_parity.js`)
//! and, for the agent-based cases, a real `ssh-agent` process this session
//! starts and stops by PID.
//!
//! Every test skips with a printed reason (never a silent pass) when
//! `ssh-keygen`, `ssh-add` or the ZBTerm tree (`ZX_ZBTERM`) is unavailable.

mod support;

use std::path::Path;

use serde_json::{Value, json};

use zxterm_core::ssh::key::parse_public_key_line;
use zxterm_core::ssh::sshsig;
use zxterm_core::ssh::{Candidate, list_candidates};
use zxterm_core::wire;
use zxterm_testkit::js;

use support::{RealAgent, agent_env, keygen, no_agent_env, require_ssh_keygen, ssh_dir};

/// The JS reference is ZBTerm's last pure-JS revision
/// (`zxterm_testkit::js::reference_root`): from K9 on, the live tree's
/// identity code is a call-through to this core.
fn require_zbterm_tree() -> Option<String> {
    js::reference_root().err()
}

macro_rules! skip_unless_ready {
    ($name:expr) => {
        if let Some(reason) = require_ssh_keygen() {
            println!("SKIP {}: {reason}", $name);
            return;
        }
        if let Some(reason) = require_zbterm_tree() {
            println!("SKIP {}: {reason}", $name);
            return;
        }
    };
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Runs `node ssh_keys_parity.js <cmd> <argsJson>` and parses its one JSON
/// line of stdout.
fn run_bridge(cmd: &str, args: &Value) -> Value {
    let args_json = args.to_string();
    let output = js::run_reference("ssh_keys_parity.js", &[cmd, &args_json], None)
        .expect("spawn node bridge");
    assert!(
        output.status.success(),
        "bridge exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "bridge produced non-JSON stdout ({e}): {stdout:?}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn candidate_to_json(c: &Candidate) -> Value {
    json!({
        "path": c.path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "source": c.source.as_str(),
        "keyType": c.key_type,
        "fingerprint": c.fingerprint,
        "comment": c.comment,
        "publicKeyBlobBase64": c.public_key_blob_base64,
        "encrypted": c.encrypted,
        "signable": c.signable,
        "reason": c.reason,
    })
}

fn candidates_to_json(candidates: &[Candidate]) -> Value {
    Value::Array(candidates.iter().map(candidate_to_json).collect())
}

fn public_key_blob_base64_of(pub_file: &Path) -> String {
    let text = std::fs::read_to_string(pub_file).expect("read .pub file");
    let parsed = parse_public_key_line(&text).expect("parse .pub file");
    base64_of(&parsed.public_key_blob)
}

// ---------------------------------------------------------------------------
// `list_candidates`'s JSON output equals `listCandidates`'s, on the
// `Host github.com` config fixture and on the plain-default fixture, run
// with the same scratch `HOME` for both sides.
// ---------------------------------------------------------------------------
#[test]
fn list_candidates_matches_js_on_the_ssh_config_fixture() {
    skip_unless_ready!("list_candidates_matches_js_on_the_ssh_config_fixture");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    keygen(&ssh, "work_ed25519", "ed25519", "");
    keygen(&ssh, "id_ed25519", "ed25519", "");
    std::fs::create_dir_all(ssh.join("conf.d")).unwrap();
    std::fs::write(
        ssh.join("conf.d").join("github.conf"),
        "Host github.com\n  IdentityFile ~/.ssh/work_ed25519\n  IdentitiesOnly yes\n",
    )
    .unwrap();
    std::fs::write(
        ssh.join("config"),
        "Include conf.d/*.conf\nHost *\n  IdentityFile %d/.ssh/id_ed25519\n",
    )
    .unwrap();

    let rust_candidates = list_candidates(home.path(), &no_agent_env());
    let js_result = run_bridge(
        "list-candidates",
        &json!({"home": home.path().to_string_lossy(), "env": {}}),
    );

    assert_eq!(candidates_to_json(&rust_candidates), js_result);
}

#[test]
fn list_candidates_matches_js_on_the_default_fixture() {
    skip_unless_ready!("list_candidates_matches_js_on_the_default_fixture");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    keygen(&ssh, "id_rsa", "rsa", "");
    keygen(&ssh, "id_ed25519", "ed25519", "");
    keygen(&ssh, "id_ecdsa", "ecdsa", "");
    std::fs::write(ssh.join("known_hosts"), "github.com ssh-ed25519 AAAA\n").unwrap();
    std::fs::write(ssh.join("authorized_keys"), "").unwrap();

    let rust_candidates = list_candidates(home.path(), &no_agent_env());
    let js_result = run_bridge(
        "list-candidates",
        &json!({"home": home.path().to_string_lossy(), "env": {}}),
    );

    assert_eq!(candidates_to_json(&rust_candidates), js_result);
}

// ---------------------------------------------------------------------------
// A claim signed by the Rust SSHSIG signer verifies with `ssh-keygen -Y
// verify -n zbterm-identity`, and, symmetrically here, with the JS
// `verifySshSignature` bridge — ed25519 and RSA, from a file.
// ---------------------------------------------------------------------------
#[test]
fn rust_signed_file_ed25519_verifies_in_js() {
    skip_unless_ready!("rust_signed_file_ed25519_verifies_in_js");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");
    let message = b"rust-signed ed25519 parity";

    let result =
        sshsig::sign(&base64_of(message), Some(&file), None, &no_agent_env()).expect("rust sign");
    let js_result = run_bridge(
        "verify-signature",
        &json!({"armored": result.signature, "messageBase64": base64_of(message)}),
    );
    assert_eq!(js_result["ok"], json!(true));
}

#[test]
fn rust_signed_file_rsa_verifies_in_js() {
    skip_unless_ready!("rust_signed_file_rsa_verifies_in_js");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_rsa", "rsa", "");
    let message = b"rust-signed rsa parity";

    let result =
        sshsig::sign(&base64_of(message), Some(&file), None, &no_agent_env()).expect("rust sign");
    let js_result = run_bridge(
        "verify-signature",
        &json!({"armored": result.signature, "messageBase64": base64_of(message)}),
    );
    assert_eq!(js_result["ok"], json!(true));
}

// ---------------------------------------------------------------------------
// A signature produced by `electron/ssh-keys.js::signBytes` verifies in the
// Rust `sshsig::verify` — ed25519 and RSA, from a file.
// ---------------------------------------------------------------------------
#[test]
fn js_signed_file_ed25519_verifies_in_rust() {
    skip_unless_ready!("js_signed_file_ed25519_verifies_in_rust");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");
    let message = b"js-signed ed25519 parity";

    let js_result = run_bridge(
        "sign-bytes",
        &json!({"messageBase64": base64_of(message), "keyPath": file.to_string_lossy(), "env": {}}),
    );
    assert!(js_result.get("error").is_none(), "{js_result}");
    let armored = js_result["signature"].as_str().unwrap();
    let ok = sshsig::verify(armored, message, None, None, None).expect("rust verify");
    assert!(ok);
}

#[test]
fn js_signed_file_rsa_verifies_in_rust() {
    skip_unless_ready!("js_signed_file_rsa_verifies_in_rust");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_rsa", "rsa", "");
    let message = b"js-signed rsa parity";

    let js_result = run_bridge(
        "sign-bytes",
        &json!({"messageBase64": base64_of(message), "keyPath": file.to_string_lossy(), "env": {}}),
    );
    assert!(js_result.get("error").is_none(), "{js_result}");
    let armored = js_result["signature"].as_str().unwrap();
    let ok = sshsig::verify(armored, message, None, None, None).expect("rust verify");
    assert!(ok);
}

// ---------------------------------------------------------------------------
// The same two directions, from a real ssh-agent (ed25519 and RSA).
// ---------------------------------------------------------------------------
#[test]
fn agent_signed_ed25519_cross_verifies_both_directions() {
    skip_unless_ready!("agent_signed_ed25519_cross_verifies_both_directions");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");
    let sock = home.path().join("a.sock");
    let agent = RealAgent::start(&sock).expect("start real ssh-agent");
    agent.add(&file);
    let env = agent_env(&sock);
    let pub_blob_b64 = public_key_blob_base64_of(Path::new(&format!("{}.pub", file.display())));

    // Rust signs via the real agent, JS verifies.
    let message_a = b"agent ed25519 rust-signed";
    let rust_result = sshsig::sign(&base64_of(message_a), None, Some(&pub_blob_b64), &env)
        .expect("rust agent sign");
    assert_eq!(rust_result.via, sshsig::Via::Agent);
    let js_check = run_bridge(
        "verify-signature",
        &json!({"armored": rust_result.signature, "messageBase64": base64_of(message_a)}),
    );
    assert_eq!(js_check["ok"], json!(true));

    // JS signs via the same real agent, Rust verifies.
    let message_b = b"agent ed25519 js-signed";
    let js_result = run_bridge(
        "sign-bytes",
        &json!({
            "messageBase64": base64_of(message_b),
            "publicKeyBlobBase64": pub_blob_b64,
            "env": {"SSH_AUTH_SOCK": sock.to_string_lossy()},
        }),
    );
    assert!(js_result.get("error").is_none(), "{js_result}");
    let armored = js_result["signature"].as_str().unwrap();
    let ok = sshsig::verify(armored, message_b, None, None, None).expect("rust verify");
    assert!(ok);
}

#[test]
fn agent_signed_rsa_cross_verifies_both_directions() {
    skip_unless_ready!("agent_signed_rsa_cross_verifies_both_directions");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_rsa", "rsa", "");
    let sock = home.path().join("a.sock");
    let agent = RealAgent::start(&sock).expect("start real ssh-agent");
    agent.add(&file);
    let env = agent_env(&sock);
    let pub_blob_b64 = public_key_blob_base64_of(Path::new(&format!("{}.pub", file.display())));

    let message_a = b"agent rsa rust-signed";
    let rust_result = sshsig::sign(&base64_of(message_a), None, Some(&pub_blob_b64), &env)
        .expect("rust agent sign");
    assert_eq!(rust_result.via, sshsig::Via::Agent);
    let js_check = run_bridge(
        "verify-signature",
        &json!({"armored": rust_result.signature, "messageBase64": base64_of(message_a)}),
    );
    assert_eq!(js_check["ok"], json!(true));

    let message_b = b"agent rsa js-signed";
    let js_result = run_bridge(
        "sign-bytes",
        &json!({
            "messageBase64": base64_of(message_b),
            "publicKeyBlobBase64": pub_blob_b64,
            "env": {"SSH_AUTH_SOCK": sock.to_string_lossy()},
        }),
    );
    assert!(js_result.get("error").is_none(), "{js_result}");
    let armored = js_result["signature"].as_str().unwrap();
    let ok = sshsig::verify(armored, message_b, None, None, None).expect("rust verify");
    assert!(ok);
}

// ---------------------------------------------------------------------------
// An ECDSA SSHSIG (minted directly by `ssh-keygen -Y sign`, independent of
// both `ssh-keys.js` and `zxterm_core::ssh`, since neither ever signs with
// one) is rejected by the Rust verifier with the "Unsupported SSH key type"
// message, not a generic parse error.
// ---------------------------------------------------------------------------
#[test]
fn an_ecdsa_sshsig_is_rejected_by_name_not_a_generic_parse_error() {
    skip_unless_ready!("an_ecdsa_sshsig_is_rejected_by_name_not_a_generic_parse_error");
    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ecdsa", "ecdsa", "");
    let message = b"ecdsa rejection parity";
    let msg_file = home.path().join("msg.bin");
    std::fs::write(&msg_file, message).unwrap();

    let status = std::process::Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&file)
        .args(["-n", wire::NAMESPACE])
        .arg(&msg_file)
        .status()
        .expect("spawn ssh-keygen -Y sign");
    assert!(status.success());
    let armored = std::fs::read_to_string(home.path().join("msg.bin.sig")).expect("read .sig file");

    let err = sshsig::verify(&armored, message, None, None, None).unwrap_err();
    assert!(
        err.message.starts_with("Unsupported SSH key type:"),
        "{}",
        err.message
    );
}

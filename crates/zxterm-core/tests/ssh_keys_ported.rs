//! Rust port of every case in ZBTerm `test/ssh-keys.test.js` (16 top-level
//! `test(` cases as of 2026-09-28, recounted at execution time below),
//! exercising `zxterm_core::ssh` for the same behaviour ZBTerm's JS asserts,
//! including exact reason/error text where the JS test itself asserts on
//! text.
//!
//! Every test gets its own scratch `HOME`/`.ssh` (`zxterm_testkit::
//! ScratchHome`) — the real `$HOME`/`~/.ssh` is never touched, mirroring the
//! JS file's own `makeHome`.

mod support;

use std::io::{Read, Write};
use std::path::Path;

use zxterm_core::ssh::sshsig::{self, Via};
use zxterm_core::ssh::{Source, inspect_key, list_candidates};
use zxterm_core::wire;
use zxterm_testkit::{FakeAgent, ScratchHome};

use support::{agent_env, keygen, no_agent_env, require_ssh_keygen, ssh_dir};

macro_rules! skip_without_ssh_keygen {
    ($name:expr) => {
        if let Some(reason) = require_ssh_keygen() {
            println!("SKIP {}: {reason}", $name);
            return;
        }
    };
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// "ssh-config Host github.com IdentityFile wins and sorts first"
// ---------------------------------------------------------------------------
#[test]
fn ssh_config_host_github_com_identity_file_wins_and_sorts_first() {
    skip_without_ssh_keygen!("ssh_config_host_github_com_identity_file_wins_and_sorts_first");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    keygen(&ssh, "work_ed25519", "ed25519", "");
    let default_ed25519 = keygen(&ssh, "id_ed25519", "ed25519", "");

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

    let candidates = list_candidates(home.path(), &no_agent_env());
    assert_eq!(
        candidates[0].path.as_deref(),
        Some(ssh.join("work_ed25519").as_path())
    );
    assert_eq!(candidates[0].source, Source::SshConfig);
    assert_eq!(candidates[0].key_type.as_deref(), Some(wire::KEY_TYPE));
    assert!(candidates[0].signable);
    assert_eq!(candidates[0].reason, None);
    assert!(!candidates[0].encrypted);
    assert!(
        candidates[0]
            .fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:")
    );
    // The `Host *` block only applies when github.com did not match first.
    assert!(
        !candidates
            .iter()
            .any(|c| c.path.as_deref() == Some(default_ed25519.as_path())),
        "config match must suppress the default glob"
    );
}

// ---------------------------------------------------------------------------
// "the config fingerprint and comment match ssh-keygen"
// ---------------------------------------------------------------------------
#[test]
fn the_config_fingerprint_and_comment_match_ssh_keygen() {
    skip_without_ssh_keygen!("the_config_fingerprint_and_comment_match_ssh_keygen");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");

    let candidates = list_candidates(home.path(), &no_agent_env());
    let candidate = &candidates[0];

    let out = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(format!("{}.pub", file.display()))
        .output()
        .expect("ssh-keygen -lf");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let fingerprint = candidate.fingerprint.clone().unwrap();
    assert!(
        stdout.contains(&fingerprint),
        "{} contains {fingerprint}",
        stdout.trim()
    );
    assert_eq!(candidate.comment, "id_ed25519@test");
}

// ---------------------------------------------------------------------------
// "without a config, id_ed25519 precedes id_rsa and both are signable"
// ---------------------------------------------------------------------------
#[test]
fn without_a_config_id_ed25519_precedes_id_rsa_and_both_are_signable() {
    skip_without_ssh_keygen!("without_a_config_id_ed25519_precedes_id_rsa_and_both_are_signable");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    keygen(&ssh, "id_rsa", "rsa", "");
    keygen(&ssh, "id_ed25519", "ed25519", "");
    keygen(&ssh, "id_ecdsa", "ecdsa", "");
    std::fs::write(ssh.join("known_hosts"), "github.com ssh-ed25519 AAAA\n").unwrap();
    std::fs::write(ssh.join("authorized_keys"), "").unwrap();

    let candidates = list_candidates(home.path(), &no_agent_env());
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates[0].path.as_ref().unwrap().file_name().unwrap(),
        "id_ed25519"
    );
    assert_eq!(candidates[0].source, Source::Default);
    assert!(candidates[0].signable);

    let rsa = candidates
        .iter()
        .find(|c| c.path.as_ref().unwrap().file_name().unwrap() == "id_rsa")
        .unwrap();
    assert_eq!(rsa.key_type.as_deref(), Some(wire::RSA_KEY_TYPE));
    assert!(rsa.signable, "Phase 8: RSA keys are signable");
    assert_eq!(rsa.reason, None);

    let ecdsa = candidates
        .iter()
        .find(|c| c.path.as_ref().unwrap().file_name().unwrap() == "id_ecdsa")
        .unwrap();
    assert!(!ecdsa.signable);
    assert_eq!(
        ecdsa.reason.as_deref(),
        Some(
            format!(
                "ZBTerm can only sign with ssh-ed25519 or ssh-rsa keys (this key is {})",
                ecdsa.key_type.as_deref().unwrap()
            )
            .as_str()
        )
    );
}

// ---------------------------------------------------------------------------
// "a passphrase-protected key is listed, encrypted and unsignable without an agent"
// ---------------------------------------------------------------------------
#[test]
fn a_passphrase_protected_key_is_listed_encrypted_and_unsignable_without_an_agent() {
    skip_without_ssh_keygen!(
        "a_passphrase_protected_key_is_listed_encrypted_and_unsignable_without_an_agent"
    );
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "hunter2hunter2");

    let candidates = list_candidates(home.path(), &no_agent_env());
    let candidate = &candidates[0];
    assert!(candidate.encrypted);
    assert!(!candidate.signable);
    assert!(candidate.reason.as_deref().unwrap().contains("ssh-agent"));
    assert_eq!(candidate.key_type.as_deref(), Some(wire::KEY_TYPE));

    let out = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(format!("{}.pub", file.display()))
        .output()
        .expect("ssh-keygen -lf");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(candidate.fingerprint.as_deref().unwrap()));
    assert_eq!(candidate.comment, "id_ed25519@test");
}

// ---------------------------------------------------------------------------
// "a truncated key file yields an unsignable candidate rather than throwing"
// ---------------------------------------------------------------------------
#[test]
fn a_truncated_key_file_yields_an_unsignable_candidate_rather_than_throwing() {
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    std::fs::write(
        ssh.join("id_ed25519"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZX\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(ssh.join("id_garbage"), "not a key at all\n").unwrap();

    let candidates = list_candidates(home.path(), &no_agent_env());
    assert_eq!(candidates.len(), 2);
    for candidate in &candidates {
        assert!(!candidate.signable);
        assert!(candidate.reason.is_some(), "{:?}", candidate.path);
        assert_eq!(candidate.public_key_blob_base64, None);
    }
}

// ---------------------------------------------------------------------------
// "a .pub without its private key is agent-signable only"
// ---------------------------------------------------------------------------
#[test]
fn a_pub_without_its_private_key_is_agent_signable_only() {
    skip_without_ssh_keygen!("a_pub_without_its_private_key_is_agent_signable_only");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");
    std::fs::remove_file(&file).unwrap();

    let candidates = list_candidates(home.path(), &no_agent_env());
    let candidate = &candidates[0];
    assert_eq!(candidate.path.as_deref(), Some(file.as_path()));
    assert_eq!(candidate.key_type.as_deref(), Some(wire::KEY_TYPE));
    assert!(!candidate.signable);
    assert!(candidate.reason.as_deref().unwrap().contains("ssh-agent"));
    assert!(candidate.public_key_blob_base64.is_some());
}

// ---------------------------------------------------------------------------
// "signBytes produces an SSHSIG that ssh-keygen -Y verify accepts"
// ---------------------------------------------------------------------------
#[test]
fn sign_bytes_produces_an_sshsig_that_ssh_keygen_verify_accepts() {
    skip_without_ssh_keygen!("sign_bytes_produces_an_sshsig_that_ssh_keygen_verify_accepts");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "");
    let message = b"zbterm-identity-claim/v1\nprovider=github\n";

    let result =
        sshsig::sign(&base64_of(message), Some(&file), None, &no_agent_env()).expect("sign");
    assert_eq!(result.via, Via::File);
    assert!(result.signature.starts_with(wire::ARMOR_BEGIN));
    assert!(
        sshsig::verify(&result.signature, message, None, None, None).expect("verify"),
        "verifies in-process"
    );

    let sig_file = home.path().join("claim.sig");
    let msg_file = home.path().join("claim.bin");
    let allowed = home.path().join("allowed_signers");
    std::fs::write(&sig_file, &result.signature).unwrap();
    std::fs::write(&msg_file, message).unwrap();
    let pub_text = std::fs::read_to_string(format!("{}.pub", file.display())).unwrap();
    let pub_parts: Vec<&str> = pub_text.split_whitespace().collect();
    std::fs::write(
        &allowed,
        format!("tester {} {}\n", pub_parts[0], pub_parts[1]),
    )
    .unwrap();

    let mut child = std::process::Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "tester", "-n", wire::NAMESPACE, "-s"])
        .arg(&sig_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen -Y verify");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(&msg_file).unwrap())
        .unwrap();
    let output = child.wait_with_output().expect("wait ssh-keygen -Y verify");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let fp_out = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(format!("{}.pub", file.display()))
        .output()
        .unwrap();
    let fp_stdout = String::from_utf8_lossy(&fp_out.stdout);
    let expected_fp = fp_stdout.split_whitespace().nth(1).unwrap();
    assert_eq!(result.fingerprint, expected_fp);
}

// ---------------------------------------------------------------------------
// "signBytes signs with an RSA key file and ssh-keygen -Y verify accepts it"
// ---------------------------------------------------------------------------
#[test]
fn sign_bytes_signs_with_an_rsa_key_file_and_ssh_keygen_verify_accepts_it() {
    skip_without_ssh_keygen!(
        "sign_bytes_signs_with_an_rsa_key_file_and_ssh_keygen_verify_accepts_it"
    );
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_rsa", "rsa", "");
    let message = b"zbterm-identity-claim/v1\nprovider=github\n";

    let result =
        sshsig::sign(&base64_of(message), Some(&file), None, &no_agent_env()).expect("sign");
    assert_eq!(result.via, Via::File);
    assert!(
        sshsig::verify(&result.signature, message, None, None, None).expect("verify"),
        "verifies in-process"
    );

    let sig_file = home.path().join("claim.sig");
    let allowed = home.path().join("allowed_signers");
    std::fs::write(&sig_file, &result.signature).unwrap();
    let pub_text = std::fs::read_to_string(format!("{}.pub", file.display())).unwrap();
    let pub_parts: Vec<&str> = pub_text.split_whitespace().collect();
    assert_eq!(pub_parts[0], "ssh-rsa");
    std::fs::write(
        &allowed,
        format!("tester {} {}\n", pub_parts[0], pub_parts[1]),
    )
    .unwrap();

    let mut child = std::process::Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "tester", "-n", wire::NAMESPACE, "-s"])
        .arg(&sig_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen -Y verify");
    child.stdin.take().unwrap().write_all(message).unwrap();
    let output = child.wait_with_output().expect("wait ssh-keygen -Y verify");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let fp_out = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(format!("{}.pub", file.display()))
        .output()
        .unwrap();
    let fp_stdout = String::from_utf8_lossy(&fp_out.stdout);
    let expected_fp = fp_stdout.split_whitespace().nth(1).unwrap();
    assert_eq!(result.fingerprint, expected_fp);
}

// ---------------------------------------------------------------------------
// "signBytes refuses key types that are still out of scope"
// ---------------------------------------------------------------------------
#[test]
fn sign_bytes_refuses_key_types_that_are_still_out_of_scope() {
    skip_without_ssh_keygen!("sign_bytes_refuses_key_types_that_are_still_out_of_scope");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ecdsa", "ecdsa", "");

    let err = sshsig::sign(&base64_of(b"x"), Some(&file), None, &no_agent_env()).unwrap_err();
    assert!(
        err.message.contains("ssh-ed25519 or ssh-rsa"),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// "signBytes without an agent socket reports no agent"
// ---------------------------------------------------------------------------
#[test]
fn sign_bytes_without_an_agent_socket_reports_no_agent() {
    skip_without_ssh_keygen!("sign_bytes_without_an_agent_socket_reports_no_agent");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "hunter2hunter2");

    let err = sshsig::sign(&base64_of(b"x"), Some(&file), None, &no_agent_env()).unwrap_err();
    assert!(err.message.contains("SSH_AUTH_SOCK"), "{}", err.message);
}

// ---------------------------------------------------------------------------
// "a dead SSH_AUTH_SOCK degrades to no agent instead of failing discovery"
// ---------------------------------------------------------------------------
#[test]
fn a_dead_ssh_auth_sock_degrades_to_no_agent_instead_of_failing_discovery() {
    skip_without_ssh_keygen!(
        "a_dead_ssh_auth_sock_degrades_to_no_agent_instead_of_failing_discovery"
    );
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    keygen(&ssh, "id_ed25519", "ed25519", "");

    let env = agent_env(&home.path().join("no-such-agent.sock"));
    let candidates = list_candidates(home.path(), &env);
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].signable);
}

// ---------------------------------------------------------------------------
// Minimal in-process ssh-agent wire framing, mirroring the JS test file's own
// `fakeAgent()` helper (which also hand-rolls the protocol rather than
// reusing production code).
// ---------------------------------------------------------------------------

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn read_str(buf: &[u8], offset: usize) -> (Vec<u8>, usize) {
    let len = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    (buf[start..start + len].to_vec(), start + len)
}

fn write_str(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn read_one_frame(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("read frame header");
    let len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).expect("read frame payload");
    payload
}

// ---------------------------------------------------------------------------
// "an agent-held encrypted key becomes signable and signs via the agent"
// ---------------------------------------------------------------------------
#[test]
fn an_agent_held_encrypted_key_becomes_signable_and_signs_via_the_agent() {
    skip_without_ssh_keygen!(
        "an_agent_held_encrypted_key_becomes_signable_and_signs_via_the_agent"
    );
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let locked = keygen(&ssh, "id_ed25519", "ed25519", "");
    let material = zxterm_core::ssh::key::parse_openssh_private_key(
        &std::fs::read_to_string(&locked).unwrap(),
    )
    .expect("parse freshly generated key");
    // Same key, now passphrase-protected on disk but still held "by the
    // agent" (the fake agent below signs with the pre-encryption secret).
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-p", "-f"])
        .arg(&locked)
        .args(["-P", "", "-N", "hunter2hunter2"])
        .status()
        .expect("spawn ssh-keygen -p");
    assert!(status.success());

    let secret_key = material.secret_key.expect("unencrypted secret key");
    let public_key_blob = material.public_key_blob.clone();
    let sock = home.path().join("a.sock");
    let _agent = FakeAgent::start(&sock, move |mut stream| {
        let payload = read_one_frame(&mut stream);
        let reply = if payload.first() == Some(&11) {
            let mut count = Vec::new();
            count.extend_from_slice(&1u32.to_be_bytes());
            let mut body = vec![12u8];
            body.extend_from_slice(&count);
            body.extend_from_slice(&write_str(&public_key_blob));
            body.extend_from_slice(&write_str(b"agent-key"));
            body
        } else if payload.first() == Some(&13) {
            let (blob, at) = read_str(&payload, 1);
            let (data, _at2) = read_str(&payload, at);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&secret_key[..32]);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let signature: ed25519_dalek::Signature =
                ed25519_dalek::ed25519::signature::Signer::sign(&signing_key, &data);
            let _ = blob;
            let sig_blob = {
                let mut v = write_str(b"ssh-ed25519");
                v.extend_from_slice(&write_str(&signature.to_bytes()));
                v
            };
            let mut body = vec![14u8];
            body.extend_from_slice(&write_str(&sig_blob));
            body
        } else {
            vec![5u8]
        };
        let _ = stream.write_all(&frame(&reply));
    })
    .expect("start fake agent");

    let env = agent_env(&sock);
    let candidates = list_candidates(home.path(), &env);
    let held = candidates
        .iter()
        .find(|c| c.encrypted)
        .expect("encrypted candidate");
    assert!(
        held.signable,
        "the agent covers the passphrase-protected file"
    );
    assert_eq!(held.reason, None);

    let message = b"agent-signed claim";
    let result =
        sshsig::sign(&base64_of(message), Some(&locked), None, &env).expect("sign via agent");
    assert_eq!(result.via, Via::Agent);
    assert!(sshsig::verify(&result.signature, message, None, None, None).expect("verify"));
}

// ---------------------------------------------------------------------------
// "parseOpenSshPrivateKey reports encryption without decrypting"
// ---------------------------------------------------------------------------
#[test]
fn parse_openssh_private_key_reports_encryption_without_decrypting() {
    skip_without_ssh_keygen!("parse_openssh_private_key_reports_encryption_without_decrypting");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "id_ed25519", "ed25519", "hunter2hunter2");

    let parsed =
        zxterm_core::ssh::key::parse_openssh_private_key(&std::fs::read_to_string(&file).unwrap())
            .expect("parse encrypted key container");
    assert!(parsed.encrypted);
    assert_eq!(parsed.secret_key, None);
    assert_eq!(parsed.key_type, wire::KEY_TYPE);
}

/// Generates a fresh 2048-bit RSA key with `ssh-keygen` into a location
/// *outside* any scanned `.ssh` directory, purely for its key material (an
/// "agent-only" key in the tests below never has a private file `zxterm_
/// core::ssh` could discover on disk).
fn rsa_agent_key(dir: &Path) -> (zxterm_core::ssh::key::RsaFields, Vec<u8>) {
    let file = keygen(dir, "rsa_agent_only", "rsa", "");
    let parsed =
        zxterm_core::ssh::key::parse_openssh_private_key(&std::fs::read_to_string(&file).unwrap())
            .expect("parse freshly generated RSA key");
    (parsed.rsa.expect("rsa fields"), parsed.public_key_blob)
}

fn rsa_sign_pkcs1_sha512(rsa: &zxterm_core::ssh::key::RsaFields, message: &[u8]) -> Vec<u8> {
    use rsa::BigUint;
    use sha2::{Digest, Sha512};

    fn strip_mpint(v: &[u8]) -> &[u8] {
        if v.is_empty() {
            return v;
        }
        let mut at = 0;
        while at < v.len() - 1 && v[at] == 0 {
            at += 1;
        }
        &v[at..]
    }

    let n_bytes = strip_mpint(&rsa.n);
    let k = n_bytes.len();
    let n = BigUint::from_bytes_be(n_bytes);
    let d = BigUint::from_bytes_be(strip_mpint(&rsa.d));
    let digest = Sha512::digest(message);
    let prefix = hex::decode(wire::PKCS1_SHA512_PREFIX_HEX).unwrap();
    let mut suffix = prefix;
    suffix.extend_from_slice(&digest);
    let padding_len = k - suffix.len() - 3;
    let mut em = vec![0x00u8, 0x01];
    em.extend(std::iter::repeat_n(0xffu8, padding_len));
    em.push(0x00);
    em.extend_from_slice(&suffix);
    let m = BigUint::from_bytes_be(&em);
    let s = m.modpow(&d, &n);
    let s_bytes = s.to_bytes_be();
    let mut sig = vec![0u8; k - s_bytes.len()];
    sig.extend_from_slice(&s_bytes);
    sig
}

// ---------------------------------------------------------------------------
// "an agent-held RSA key signs as rsa-sha2-512, with the SHA-2 flag set"
// ---------------------------------------------------------------------------
#[test]
fn an_agent_held_rsa_key_signs_as_rsa_sha2_512_with_the_sha2_flag_set() {
    skip_without_ssh_keygen!("an_agent_held_rsa_key_signs_as_rsa_sha2_512_with_the_sha2_flag_set");
    let home = ScratchHome::new().expect("scratch home");
    let (rsa_fields, public_key_blob) = rsa_agent_key(home.path());
    let flags_seen: std::sync::Arc<std::sync::Mutex<Vec<u32>>> = Default::default();
    let flags_seen_clone = flags_seen.clone();

    let sock = home.path().join("a.sock");
    let _agent = FakeAgent::start(&sock, move |mut stream| {
        let payload = read_one_frame(&mut stream);
        let reply = if payload.first() == Some(&11) {
            let mut body = vec![12u8];
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&write_str(&public_key_blob));
            body.extend_from_slice(&write_str(b"rsa@agent"));
            body
        } else if payload.first() == Some(&13) {
            let (_blob, at) = read_str(&payload, 1);
            let (data, at2) = read_str(&payload, at);
            let flags = u32::from_be_bytes(payload[at2..at2 + 4].try_into().unwrap());
            flags_seen_clone.lock().unwrap().push(flags);
            // A well-behaved agent honours the flag; without it the answer
            // would be a SHA-1 `ssh-rsa` signature.
            let sig_type: &[u8] = if flags == 4 {
                b"rsa-sha2-512"
            } else {
                b"ssh-rsa"
            };
            let raw_sig = rsa_sign_pkcs1_sha512(&rsa_fields, &data);
            let sig_blob = {
                let mut v = write_str(sig_type);
                v.extend_from_slice(&write_str(&raw_sig));
                v
            };
            let mut body = vec![14u8];
            body.extend_from_slice(&write_str(&sig_blob));
            body
        } else {
            vec![5u8]
        };
        let _ = stream.write_all(&frame(&reply));
    })
    .expect("start fake agent");

    let env = agent_env(&sock);
    let candidates = list_candidates(home.path(), &env);
    let candidate = &candidates[0];
    assert_eq!(candidate.source, Source::Agent);
    assert_eq!(candidate.key_type.as_deref(), Some(wire::RSA_KEY_TYPE));
    assert!(candidate.signable);
    assert_eq!(candidate.reason, None);

    let message = b"agent-signed rsa claim";
    let result = sshsig::sign(
        &base64_of(message),
        None,
        Some(candidate.public_key_blob_base64.as_deref().unwrap()),
        &env,
    )
    .expect("sign via agent");
    assert_eq!(result.via, Via::Agent);
    assert_eq!(
        &*flags_seen.lock().unwrap(),
        &[4u32],
        "SSH_AGENT_RSA_SHA2_512 is set on the sign request"
    );
    assert!(sshsig::verify(&result.signature, message, None, None, None).expect("verify"));
}

// ---------------------------------------------------------------------------
// "an agent that ignores the SHA-2 flag and answers ssh-rsa is refused"
// ---------------------------------------------------------------------------
#[test]
fn an_agent_that_ignores_the_sha2_flag_and_answers_ssh_rsa_is_refused() {
    skip_without_ssh_keygen!("an_agent_that_ignores_the_sha2_flag_and_answers_ssh_rsa_is_refused");
    let home = ScratchHome::new().expect("scratch home");
    let (rsa_fields, public_key_blob) = rsa_agent_key(home.path());
    let public_key_blob_for_bridge = public_key_blob.clone();

    let sock = home.path().join("a.sock");
    let _agent = FakeAgent::start(&sock, move |mut stream| {
        let payload = read_one_frame(&mut stream);
        let reply = if payload.first() == Some(&11) {
            let mut body = vec![12u8];
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&write_str(&public_key_blob));
            body.extend_from_slice(&write_str(b""));
            body
        } else if payload.first() == Some(&13) {
            let _ = &rsa_fields; // unused: the refusal below never inspects raw_sig bytes
            // Deliberately answers with the legacy SHA-1 `ssh-rsa` signature
            // *type name*, ignoring the SHA-2 flag. The refusal in
            // `zxterm_core::ssh::agent::agent_sign` is keyed off this type
            // string alone, before any signature bytes are ever inspected,
            // so a dummy payload here exercises the exact same path a real
            // (but legacy) SHA-1 signature would.
            let sig_blob = {
                let mut v = write_str(b"ssh-rsa");
                v.extend_from_slice(&write_str(b"dummy-legacy-signature-bytes"));
                v
            };
            let mut body = vec![14u8];
            body.extend_from_slice(&write_str(&sig_blob));
            body
        } else {
            vec![5u8]
        };
        let _ = stream.write_all(&frame(&reply));
    })
    .expect("start fake agent");

    let env = agent_env(&sock);
    let b64 = base64_of(&public_key_blob_for_bridge);
    let err = sshsig::sign(&base64_of(b"x"), None, Some(&b64), &env).unwrap_err();
    assert!(
        err.message.contains("unsupported signature type: ssh-rsa")
            && err.message.contains("expected rsa-sha2-512"),
        "{}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// "listCandidates never reads the real home when one is supplied"
// ---------------------------------------------------------------------------
#[test]
fn list_candidates_never_reads_the_real_home_when_one_is_supplied() {
    let home = ScratchHome::new().expect("scratch home");
    let candidates = list_candidates(home.path(), &no_agent_env());
    assert_eq!(candidates.len(), 0);
}

// ---------------------------------------------------------------------------
// `inspect_key` (ssh-keys.js::inspectKey) is exercised alongside the ported
// suite above, though ssh-keys.test.js does not itself call it directly.
// ---------------------------------------------------------------------------
#[test]
fn inspect_key_reports_source_manual() {
    skip_without_ssh_keygen!("inspect_key_reports_source_manual");
    let home = ScratchHome::new().expect("scratch home");
    let ssh = ssh_dir(home.path());
    let file = keygen(&ssh, "manual_key", "ed25519", "");

    let candidate =
        inspect_key(&file.to_string_lossy(), home.path(), &no_agent_env()).expect("inspect");
    assert_eq!(candidate.source, Source::Manual);
    assert!(candidate.signable);
}

/// Recount of `test/ssh-keys.test.js`'s `test(` cases at execution time,
/// so a change in the JS file does not silently drift from this file's own
/// case count (`grep -c "^test(" test/ssh-keys.test.js`, `A-5`).
#[test]
fn zbterm_test_file_still_has_16_top_level_cases() {
    let root = zxterm_testkit::js::zbterm_root();
    let path = root.join("test/ssh-keys.test.js");
    let Ok(text) = std::fs::read_to_string(&path) else {
        println!(
            "SKIP zbterm_test_file_still_has_16_top_level_cases: ZBTerm tree not found at {}",
            path.display()
        );
        return;
    };
    let count = text.lines().filter(|l| l.starts_with("test(")).count();
    assert_eq!(
        count, 16,
        "test/ssh-keys.test.js's top-level case count drifted from 16; re-port before trusting this suite"
    );
}

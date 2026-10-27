//! Ports every case of ZBTerm `test/github-keys.test.js` (10 `test(` cases,
//! recounted 2026-09-29) to `zxterm_core::identity::github`.

mod support;

use std::net::TcpStream;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use support::{RawServer, respond, respond_partial_and_stall};
use zxterm_core::identity::github::{MAX_BODY_BYTES, fetch_keys, parse_keys_body};

fn require_ssh_keygen() -> Option<String> {
    zxterm_testkit::require_tool("ssh-keygen")
}

fn keygen_fingerprint(pub_file: &std::path::Path) -> String {
    let out = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(pub_file)
        .output()
        .expect("spawn ssh-keygen -lf");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

fn first_two_fields(pub_file: &std::path::Path) -> String {
    let text = std::fs::read_to_string(pub_file).unwrap();
    text.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_200_body_parses_every_key_type_and_matches_ssh_keygen_fingerprints() {
    if let Some(reason) = require_ssh_keygen() {
        println!(
            "SKIP a_200_body_parses_every_key_type_and_matches_ssh_keygen_fingerprints: {reason}"
        );
        return;
    }

    let home = zxterm_testkit::ScratchHome::new().expect("scratch home");
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let ed = support::keygen(&ssh, "ed", "ed25519", "");
    let rsa = support::keygen(&ssh, "rsa", "rsa", "");
    let commented = support::keygen(&ssh, "commented", "ed25519", "");

    let ed_pub = ed.with_extension("pub");
    let rsa_pub = rsa.with_extension("pub");
    let commented_pub = commented.with_extension("pub");

    let ed_line = first_two_fields(&ed_pub);
    let rsa_line = first_two_fields(&rsa_pub);
    let commented_line = std::fs::read_to_string(&commented_pub)
        .unwrap()
        .trim()
        .to_string();

    let body = [ed_line, rsa_line, commented_line.clone(), String::new()].join("\n");
    let server = RawServer::start(Arc::new(move |path, stream: &mut TcpStream| {
        assert_eq!(path, "/octocat.keys");
        respond(
            stream,
            200,
            "OK",
            &[("Content-Type", "text/plain")],
            body.as_bytes(),
        );
    }))
    .expect("start raw server");

    let result = fetch_keys("octocat", Some(&server.base_url), None).expect("fetch keys");
    assert_eq!(result.status, "ok");
    assert_eq!(
        result.keys.len(),
        3,
        "all three key types are kept - the caller filters to ed25519"
    );
    assert_eq!(result.keys[0].key_type, "ssh-ed25519");
    assert_eq!(result.keys[1].key_type, "ssh-rsa");
    assert_eq!(result.keys[2].key_type, "ssh-ed25519");
    assert_eq!(result.keys[0].fingerprint, keygen_fingerprint(&ed_pub));
    assert_eq!(result.keys[1].fingerprint, keygen_fingerprint(&rsa_pub));
    assert_eq!(
        result.keys[2].fingerprint,
        keygen_fingerprint(&commented_pub)
    );
    let commented_blob = commented_line.split_whitespace().nth(1).unwrap();
    assert_eq!(
        result.keys[2].blob_base64, commented_blob,
        "blob excludes the comment"
    );
}

#[test]
fn e404_is_not_found_not_an_error() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        respond(stream, 404, "Not Found", &[], b"Not Found");
    }))
    .expect("start raw server");
    let result = fetch_keys("nobody", Some(&server.base_url), None).expect("fetch keys");
    assert_eq!(result.status, "not-found");
    assert!(result.keys.is_empty());
}

#[test]
fn a_200_with_an_empty_body_is_ok_with_no_keys() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        respond(stream, 200, "OK", &[("Content-Type", "text/plain")], b"");
    }))
    .expect("start raw server");
    let result = fetch_keys("keyless", Some(&server.base_url), None).expect("fetch keys");
    assert_eq!(result.status, "ok");
    assert!(
        result.keys.is_empty(),
        "a user with no published keys is ok, not not-found"
    );
}

#[test]
fn a_non_2xx_other_than_404_rejects() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        respond(stream, 503, "Service Unavailable", &[], b"nope");
    }))
    .expect("start raw server");
    let err = fetch_keys("octocat", Some(&server.base_url), None).unwrap_err();
    assert!(err.message.contains("HTTP 503"), "{}", err.message);
}

#[test]
fn follows_a_redirect_for_a_renamed_account() {
    let server = RawServer::start(Arc::new(|path, stream: &mut TcpStream| {
        if path == "/OldName.keys" {
            respond(
                stream,
                301,
                "Moved Permanently",
                &[("Location", "/newname.keys")],
                b"",
            );
            return;
        }
        let body = format!("ssh-ed25519 {}\n", "A".repeat(68));
        respond(
            stream,
            200,
            "OK",
            &[("Content-Type", "text/plain")],
            body.as_bytes(),
        );
    }))
    .expect("start raw server");
    let result = fetch_keys("OldName", Some(&server.base_url), None).expect("fetch keys");
    assert_eq!(result.status, "ok");
    assert_eq!(result.keys.len(), 1);
}

#[test]
fn rejects_a_redirect_that_leaves_the_keys_path() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        respond(stream, 302, "Found", &[("Location", "/login")], b"");
    }))
    .expect("start raw server");
    let err = fetch_keys("octocat", Some(&server.base_url), None).unwrap_err();
    assert!(
        err.message.contains("left the .keys path"),
        "{}",
        err.message
    );
}

#[test]
fn rejects_more_than_two_redirects() {
    let hops = Arc::new(AtomicUsize::new(0));
    let hops_clone = hops.clone();
    let server = RawServer::start(Arc::new(move |_path, stream: &mut TcpStream| {
        let n = hops_clone.fetch_add(1, Ordering::SeqCst) + 1;
        respond(
            stream,
            302,
            "Found",
            &[("Location", &format!("/hop{n}.keys"))],
            b"",
        );
    }))
    .expect("start raw server");
    let err = fetch_keys("octocat", Some(&server.base_url), None).unwrap_err();
    assert!(err.message.contains("redirects"), "{}", err.message);
    assert_eq!(
        hops.load(Ordering::SeqCst),
        3,
        "the original request plus exactly two follows"
    );
}

#[test]
fn aborts_a_body_over_the_64_kib_cap() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        let body = format!("ssh-ed25519 {}\n", "A".repeat(MAX_BODY_BYTES + 1024));
        respond(
            stream,
            200,
            "OK",
            &[("Content-Type", "text/plain")],
            body.as_bytes(),
        );
    }))
    .expect("start raw server");
    let err = fetch_keys("octocat", Some(&server.base_url), None).unwrap_err();
    assert!(
        err.message.contains("exceeded 65536 bytes"),
        "{}",
        err.message
    );
}

#[test]
fn times_out_on_a_stalled_response() {
    let server = RawServer::start(Arc::new(|_path, stream: &mut TcpStream| {
        respond_partial_and_stall(stream, b"ssh-ed25519 ");
    }))
    .expect("start raw server");
    let err = fetch_keys("octocat", Some(&server.base_url), Some(150)).unwrap_err();
    assert!(
        err.message.contains("timed out after 150ms"),
        "{}",
        err.message
    );
}

#[test]
fn ignores_lines_that_are_not_recognisable_key_lines() {
    let keys = parse_keys_body(
        &[
            "# a comment",
            "",
            "sk-ssh-ed25519@openssh.com AAAA",
            "not-a-key",
            "ssh-dss AAAAB3NzaC1kc3MAAA",
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
            "",
        ]
        .join("\n"),
    );
    assert_eq!(keys.len(), 1, "only the ecdsa line survives");
    assert_eq!(keys[0].key_type, "ecdsa-sha2-nistp256");
    assert!(keys[0].fingerprint.starts_with("SHA256:"));
}

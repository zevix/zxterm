//! Verifies every `zxterm_core::wire` constant against ZBTerm's current JS
//! source (design §4.9, `A-5`). Reads the ZBTerm tree named by `ZX_ZBTERM`
//! (default: the ZBTerm checkout this repository is a submodule of) and
//! asserts each constant's literal value appears in the cited source file. If the tree is absent, the whole
//! test is skipped with a printed reason — it never silently passes.
//!
//! > 2026-09-29, K9: "current JS source" is now ZBTerm's last pure-JS
//! > revision (`zxterm_testkit::js::ZBTERM_JS_REFERENCE_REV`), extracted
//! > read-only; K9 moved those constants' uses into this core.
//!
//! > 2026-09-30, K13: two more tables. `LIVE_ENTRIES` are checked against
//! > ZBTerm's **live** tree (`zxterm_testkit::js::zbterm_root`): the kdf
//! > contexts `zxt-hist`/`zxt-live`/`zxt-snap` date from K11 (ZBTerm
//! > `D-36`), after the reference revision. `PROTOCOL_ENTRIES` are the new
//! > zxterm session channel labels, which exist in no ZBTerm tree yet (K14
//! > adopts them): they are checked against `protocol.md`, their spec.

use std::fs;
use std::path::PathBuf;

struct Entry {
    /// Name of the `zxterm_core::wire` constant, for failure messages.
    name: &'static str,
    /// The constant's value, as re-exported from `zxterm_core::wire`.
    value: &'static str,
    /// Path of the ZBTerm source file that defines this string, relative to
    /// the ZBTerm tree root.
    file: &'static str,
}

const ENTRIES: &[Entry] = &[
    Entry {
        name: "NAMESPACE",
        value: zxterm_core::wire::NAMESPACE,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "SSHSIG_MAGIC",
        value: zxterm_core::wire::SSHSIG_MAGIC,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "KEY_TYPE",
        value: zxterm_core::wire::KEY_TYPE,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "RSA_KEY_TYPE",
        value: zxterm_core::wire::RSA_KEY_TYPE,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "RSA_SIG_ALG",
        value: zxterm_core::wire::RSA_SIG_ALG,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "HASH_ALG",
        value: zxterm_core::wire::HASH_ALG,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "ARMOR_BEGIN",
        value: zxterm_core::wire::ARMOR_BEGIN,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "ARMOR_END",
        value: zxterm_core::wire::ARMOR_END,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "PKCS1_SHA512_PREFIX_HEX",
        value: zxterm_core::wire::PKCS1_SHA512_PREFIX_HEX,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "CLAIM_MAGIC",
        value: zxterm_core::wire::CLAIM_MAGIC,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "CHALLENGE_MAGIC",
        value: zxterm_core::wire::CHALLENGE_MAGIC,
        file: "engine/identity/claim.js",
    },
    Entry {
        name: "SIGNAL_DOMAIN",
        value: zxterm_core::wire::SIGNAL_DOMAIN,
        file: "engine/backends/freenet/signal.js",
    },
    Entry {
        name: "POINTER_DOMAIN",
        value: zxterm_core::wire::POINTER_DOMAIN,
        file: "engine/backends/freenet/signal.js",
    },
    Entry {
        name: "PAYLOAD_CONTEXT",
        value: zxterm_core::wire::PAYLOAD_CONTEXT,
        file: "engine/backends/freenet/signal.js",
    },
    Entry {
        name: "BOOTSTRAP_LABEL",
        value: zxterm_core::wire::BOOTSTRAP_LABEL,
        file: "engine/backends/freenet/connection.js",
    },
    Entry {
        name: "BOOTSTRAP_LABEL (index.js)",
        value: zxterm_core::wire::BOOTSTRAP_LABEL,
        file: "engine/backends/freenet/index.js",
    },
    Entry {
        name: "HISTORY_PROTOCOL",
        value: zxterm_core::wire::HISTORY_PROTOCOL,
        file: "engine/backends/freenet/history.js",
    },
    Entry {
        name: "CTL_PROTOCOL",
        value: zxterm_core::wire::CTL_PROTOCOL,
        file: "engine/share-manager.js",
    },
    Entry {
        name: "LINK_PREFIX",
        value: zxterm_core::wire::LINK_PREFIX,
        file: "engine/invite.js",
    },
];

/// Constants read from ZBTerm's live tree (K13).
const LIVE_ENTRIES: &[Entry] = &[
    Entry {
        name: "HIST_CONTEXT",
        value: zxterm_core::wire::HIST_CONTEXT,
        file: "engine/crypto.js",
    },
    Entry {
        name: "LIVE_CONTEXT",
        value: zxterm_core::wire::LIVE_CONTEXT,
        file: "engine/crypto.js",
    },
    Entry {
        name: "SNAP_CONTEXT",
        value: zxterm_core::wire::SNAP_CONTEXT,
        file: "engine/crypto.js",
    },
];

/// The v2 session labels, from their spec (K13), relative to this
/// repository's root.
const PROTOCOL_ENTRIES: &[Entry] = &[
    Entry {
        name: "SESSION_CTL_PROTOCOL",
        value: zxterm_core::wire::SESSION_CTL_PROTOCOL,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
    Entry {
        name: "SESSION_LIVE_PROTOCOL",
        value: zxterm_core::wire::SESSION_LIVE_PROTOCOL,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
    Entry {
        name: "SESSION_HISTORY_PROTOCOL",
        value: zxterm_core::wire::SESSION_HISTORY_PROTOCOL,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
    Entry {
        name: "HIST_CONTEXT (protocol.md)",
        value: zxterm_core::wire::HIST_CONTEXT,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
    Entry {
        name: "LIVE_CONTEXT (protocol.md)",
        value: zxterm_core::wire::LIVE_CONTEXT,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
    Entry {
        name: "SNAP_CONTEXT (protocol.md)",
        value: zxterm_core::wire::SNAP_CONTEXT,
        file: "docs/projects/260928_zxterm-core/protocol.md",
    },
];

fn check(root: &std::path::Path, entries: &[Entry]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries {
        let path = root.join(entry.file);
        match fs::read_to_string(&path) {
            Ok(contents) if contents.contains(entry.value) => {}
            Ok(_) => failures.push(format!(
                "{}: {:?} not found in {}",
                entry.name,
                entry.value,
                path.display()
            )),
            Err(e) => failures.push(format!(
                "{}: could not read {}: {}",
                entry.name,
                path.display(),
                e
            )),
        }
    }
    failures
}

#[test]
fn wire_parity_live_tree() {
    let root = zxterm_testkit::js::zbterm_root();
    if !root.join("engine/crypto.js").is_file() {
        println!(
            "SKIP wire_parity_live_tree: no ZBTerm tree at {} (ZX_ZBTERM)",
            root.display()
        );
        return;
    }
    let failures = check(&root, LIVE_ENTRIES);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn wire_parity_protocol_spec() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // The spec lives in the maintainers' project notes, which a public
    // checkout does not carry.
    let spec = root.join(PROTOCOL_ENTRIES[0].file);
    if !spec.is_file() {
        println!(
            "SKIP wire_parity_protocol_spec: no protocol spec at {}",
            spec.display()
        );
        return;
    }
    let failures = check(&root, PROTOCOL_ENTRIES);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// ZBTerm's last pure-JS revision (`zxterm_testkit::js::reference_root`):
/// from K9 on, several of these constants live only in this core.
fn zbterm_root() -> Result<PathBuf, String> {
    zxterm_testkit::js::reference_root()
}

#[test]
fn wire_parity() {
    let root = match zbterm_root() {
        Ok(root) => root,
        Err(reason) => {
            println!("SKIP wire_parity: {reason}");
            return;
        }
    };

    let mut failures = Vec::new();
    for entry in ENTRIES {
        let path = root.join(entry.file);
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!(
                    "{}: could not read {}: {}",
                    entry.name,
                    path.display(),
                    e
                ));
                continue;
            }
        };
        if !contents.contains(entry.value) {
            failures.push(format!(
                "{}: {:?} not found in {}",
                entry.name,
                entry.value,
                path.display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "wire parity mismatches against {}:\n{}",
        root.display(),
        failures.join("\n")
    );
}

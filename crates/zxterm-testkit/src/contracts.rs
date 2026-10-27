//! Test-time loader for ZBTerm's Freenet contracts (K5), the Rust mirror of
//! `engine/backends/freenet/contracts.js`: reads
//! `$ZX_ZBTERM/engine/backends/freenet/contracts/hashes.json` and the two
//! `.wasm` files it names, and verifies each file's BLAKE3 digest and byte
//! length against that manifest before handing back its bytes.
//!
//! `hashes.json` is the live ZBTerm tree's own ledger, not a fact this crate
//! is allowed to freeze: a mismatch panics with the observed and the
//! manifest's numbers rather than silently trusting either one. This is
//! test/dev-only code (no `include_bytes!` — that lands in K10's `A-6`), so
//! it lives in this crate rather than in `zxterm-core` itself.
//!
//! > 2026-09-29, K10: the embedding landed as
//! > `zxterm_core::freenet::contracts` (this repository's `contracts/`,
//! > `X-16`); this loader still reads ZBTerm's live tree, for the parity
//! > tests that compare against it.
//!
//! > 2026-09-29, K11: ZBTerm's copy is gone (its Freenet backend is a proxy
//! > to this core, ZBTerm `D-35`); this loader reads this repository's
//! > `contracts/`, whose pins equal the ones ZBTerm shipped until then.

use std::collections::HashMap;
use std::path::Path;

/// The signalling version `route::mint` mints new links with
/// (`contracts.js::CURRENT`).
const CURRENT: &str = "signalling-v1";
/// `contracts.js::POINTER`.
const POINTER: &str = "pointer-v1";

/// The pointer contract this build ships: its hex BLAKE3 code and raw wasm
/// (`contracts.js`'s `pointer`).
#[derive(Debug, Clone)]
pub struct PointerContract {
    /// Hex BLAKE3 of `wasm`.
    pub code: String,
    pub wasm: Vec<u8>,
}

/// The Rust mirror of `contracts.js`'s exported shape: `{ known, current,
/// pointer }`. `manifest` is kept too, so a caller can report exactly what
/// the live tree's ledger said without re-reading the file.
#[derive(Debug, Clone)]
pub struct Contracts {
    /// hex BLAKE3 -> raw wasm, signalling versions only
    /// (`route.js::verify`'s `contracts.known`).
    pub known: HashMap<String, Vec<u8>>,
    /// hex BLAKE3 of the `signalling-v1` wasm (`contracts.js::current`).
    pub current: String,
    pub pointer: PointerContract,
    /// The raw `hashes.json` text, for a caller that wants to report it.
    pub manifest_text: String,
}

/// Loads and verifies the contracts from this repository's own `contracts/`
/// (`X-16`). Until K11 it read ZBTerm's `engine/backends/freenet/contracts/`,
/// which K11 removed; the two directories held the same pinned bytes
/// (`tests/contract_pins.rs::the_pins_are_zbterms_pins`).
///
/// # Panics
///
/// Panics (loudly, naming the file and the numbers that disagreed) if
/// `hashes.json` is missing or malformed, if it has no `signalling-v1` or
/// `pointer-v1` entry, or if a `.wasm` file's actual BLAKE3 or byte length
/// does not match its manifest entry. This is deliberate: the manifest is
/// the live tree's own ledger, never a fact this crate hard-codes, so a
/// disagreement is a bug worth stopping the test suite for, not something to
/// paper over.
pub fn load() -> Contracts {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let manifest_path = dir.join("hashes.json");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text)
        .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
    let obj = manifest
        .as_object()
        .unwrap_or_else(|| panic!("{}: not a JSON object", manifest_path.display()));

    let mut known = HashMap::new();
    let mut current: Option<String> = None;
    let mut pointer: Option<PointerContract> = None;

    for (name, entry) in obj {
        let blake3_hex = entry
            .get("blake3")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                panic!(
                    "{}: {name}.blake3 missing or not a string",
                    manifest_path.display()
                )
            })
            .to_string();
        let bytes_len = entry
            .get("bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                panic!(
                    "{}: {name}.bytes missing or not a number",
                    manifest_path.display()
                )
            });

        let wasm = load_and_verify(&dir, name, &blake3_hex, bytes_len);

        if name == CURRENT {
            current = Some(blake3_hex.clone());
        }
        if name.starts_with("signalling-v") {
            known.insert(blake3_hex.clone(), wasm.clone());
        }
        if name == POINTER {
            pointer = Some(PointerContract {
                code: blake3_hex.clone(),
                wasm,
            });
        }
    }

    let current =
        current.unwrap_or_else(|| panic!("{}: has no {CURRENT} entry", manifest_path.display()));
    if !known.contains_key(&current) {
        panic!(
            "{}: {CURRENT}'s own entry did not load into `known` (bug in this loader)",
            manifest_path.display()
        );
    }
    let pointer =
        pointer.unwrap_or_else(|| panic!("{}: has no {POINTER} entry", manifest_path.display()));

    Contracts {
        known,
        current,
        pointer,
        manifest_text,
    }
}

fn load_and_verify(dir: &Path, name: &str, want_blake3_hex: &str, want_bytes: u64) -> Vec<u8> {
    let path = dir.join(format!("{name}.wasm"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    if bytes.len() as u64 != want_bytes {
        panic!(
            "{}: {} bytes, hashes.json says {want_bytes}",
            path.display(),
            bytes.len()
        );
    }
    let got_hex = blake3::hash(&bytes).to_hex().to_string();
    if got_hex != want_blake3_hex {
        panic!(
            "{}: blake3 {got_hex}, hashes.json says {want_blake3_hex}",
            path.display()
        );
    }
    bytes
}

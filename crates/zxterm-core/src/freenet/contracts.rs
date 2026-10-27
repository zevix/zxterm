//! The Freenet contracts this build ships (K10, `A-6`), the Rust twin of
//! ZBTerm `engine/backends/freenet/contracts.js`: the raw `.wasm` of every
//! pinned contract, embedded with `include_bytes!` from this repository's
//! `contracts/` directory, and the manifest `contracts/hashes.json` that pins
//! each one's BLAKE3 and size.
//!
//! The bytes are copied from ZBTerm's tree byte for byte and rebuilt
//! reproducibly by `scripts/build-contracts.sh`; `tests/contract_pins.rs`
//! checks every file against the manifest and that no stray `.wasm` exists.
//! [`bundled`] checks the same thing at runtime, once, before any route is
//! minted from these bytes: a build whose embedded bytes disagree with its
//! own manifest must never put a contract.
//!
//! `-v1` names the contract generation. A fix ships as `-v2` next to the
//! `-v1` bytes, which stay (a contract's key is the hash of its code).

use std::collections::HashMap;
use std::sync::OnceLock;

use super::route;

/// `contracts/signalling-v1.wasm`: the signalling mailbox contract.
pub const SIGNALLING_V1: &[u8] = include_bytes!("../../../../contracts/signalling-v1.wasm");
/// `contracts/pointer-v1.wasm`: the pointer record contract.
pub const POINTER_V1: &[u8] = include_bytes!("../../../../contracts/pointer-v1.wasm");
/// `contracts/segment-v1.wasm`: the offline-history contract (K16, `X-26`).
pub const SEGMENT_V1: &[u8] = include_bytes!("../../../../contracts/segment-v1.wasm");
/// `contracts/hashes.json`, verbatim.
pub const HASHES_JSON: &str = include_str!("../../../../contracts/hashes.json");

/// `contracts.js::CURRENT`: the signalling version new routes are minted with.
pub const CURRENT: &str = "signalling-v1";
/// `contracts.js::POINTER`.
pub const POINTER: &str = "pointer-v1";
/// The offline-history contract's manifest name (K16).
pub const SEGMENT: &str = "segment-v1";

/// The contracts this build ships (`contracts.js`'s `{ known, current,
/// pointer }`).
pub struct Bundled {
    /// What `route::mint`/`route::verify` need.
    pub route: route::Contracts,
    /// The raw pointer wasm (`contracts.js`'s `pointer.wasm`).
    pub pointer_wasm: &'static [u8],
}

/// The embedded file of a manifest name, or `None` for a name this build
/// does not embed.
pub fn embedded(name: &str) -> Option<&'static [u8]> {
    match name {
        CURRENT => Some(SIGNALLING_V1),
        POINTER => Some(POINTER_V1),
        SEGMENT => Some(SEGMENT_V1),
        _ => None,
    }
}

/// One `hashes.json` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub name: String,
    pub blake3: String,
    pub bytes: u64,
}

/// Parses `hashes.json` text: `{"<name>": {"blake3": hex, "bytes": n}}`.
pub fn parse_manifest(text: &str) -> Result<Vec<Pin>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("hashes.json: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "hashes.json: not a JSON object".to_string())?;
    let mut pins = Vec::new();
    for (name, entry) in obj {
        let blake3 = entry
            .get("blake3")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("hashes.json: {name} has no blake3"))?;
        let bytes = entry
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("hashes.json: {name} has no bytes"))?;
        pins.push(Pin {
            name: name.clone(),
            blake3: blake3.to_string(),
            bytes,
        });
    }
    Ok(pins)
}

/// Checks every embedded file against [`HASHES_JSON`]: each pinned name is
/// embedded, and its size and BLAKE3 match. `Err` names the first mismatch.
pub fn verify_embedded() -> Result<(), String> {
    let pins = parse_manifest(HASHES_JSON)?;
    for name in [CURRENT, POINTER, SEGMENT] {
        if !pins.iter().any(|p| p.name == name) {
            return Err(format!("hashes.json has no {name} entry"));
        }
    }
    for pin in &pins {
        let bytes = embedded(&pin.name).ok_or_else(|| {
            format!(
                "hashes.json names {} but this build embeds no such file",
                pin.name
            )
        })?;
        let hash = blake3::hash(bytes).to_hex().to_string();
        if bytes.len() as u64 != pin.bytes || hash != pin.blake3 {
            return Err(format!(
                "{}: embedded {} bytes, blake3 {hash}; hashes.json pins {} bytes, blake3 {}",
                pin.name,
                bytes.len(),
                pin.bytes,
                pin.blake3
            ));
        }
    }
    Ok(())
}

/// The bundled contracts, verified once against their manifest
/// ([`verify_embedded`]). `Err` carries the mismatch.
pub fn bundled() -> Result<&'static Bundled, String> {
    static BUNDLED: OnceLock<Result<Bundled, String>> = OnceLock::new();
    BUNDLED
        .get_or_init(|| {
            verify_embedded()?;
            let current = blake3::hash(SIGNALLING_V1).to_hex().to_string();
            let pointer_code = blake3::hash(POINTER_V1).to_hex().to_string();
            let mut known = HashMap::new();
            known.insert(current.clone(), SIGNALLING_V1.to_vec());
            Ok(Bundled {
                route: route::Contracts {
                    known,
                    current,
                    pointer_code,
                },
                pointer_wasm: POINTER_V1,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_contracts_match_their_manifest() {
        verify_embedded().expect("embedded bytes match hashes.json");
        let b = bundled().expect("bundled");
        assert_eq!(b.route.known.len(), 1);
        assert!(b.route.known.contains_key(&b.route.current));
    }

    #[test]
    fn parse_manifest_reports_a_missing_field() {
        let err = parse_manifest(r#"{"x":{"bytes":1}}"#).unwrap_err();
        assert!(err.contains("no blake3"), "{err}");
    }
}

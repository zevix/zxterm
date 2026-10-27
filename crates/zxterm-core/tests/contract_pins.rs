//! K10 (`A-6`): the contracts this repository ships are pinned. Mirrors
//! ZBTerm `test/backends/freenet-contracts.test.js`'s
//! `'freenet: every contract in hashes.json exists, hashes and sizes as
//! recorded (the pin)'`: every `contracts/<name>.wasm` that
//! `contracts/hashes.json` names exists, has the recorded size and BLAKE3,
//! starts with the WASM magic (raw WASM, not an `fdev` package), no other
//! `.wasm` sits in `contracts/`, and the bytes `zxterm_core` embeds with
//! `include_bytes!` are those same files.
//!
//! The manifest is this repository's copy of ZBTerm's
//! `engine/backends/freenet/contracts/hashes.json`; `scripts/build-contracts.sh`
//! rebuilds both crates and refuses to continue unless the rebuilt bytes
//! reproduce it.

use std::fs;
use std::path::PathBuf;

use zxterm_core::freenet::contracts;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

#[test]
fn every_contract_in_hashes_json_exists_hashes_and_sizes_as_recorded() {
    let dir = contracts_dir();
    let text = fs::read_to_string(dir.join("hashes.json")).expect("read contracts/hashes.json");
    let pins = contracts::parse_manifest(&text).expect("parse hashes.json");

    let mut names: Vec<&str> = pins.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![contracts::POINTER, contracts::SEGMENT, contracts::CURRENT],
        "hashes.json names the shipped contracts"
    );

    for pin in &pins {
        let file = dir.join(format!("{}.wasm", pin.name));
        let bytes = fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        assert_eq!(
            bytes.len() as u64,
            pin.bytes,
            "{}.wasm is {} bytes",
            pin.name,
            pin.bytes
        );
        assert_eq!(
            blake3::hash(&bytes).to_hex().to_string(),
            pin.blake3,
            "{}.wasm hashes to its recorded BLAKE3",
            pin.name
        );
        assert_eq!(
            hex::encode(&bytes[..4]),
            "0061736d",
            "{}.wasm is raw WASM, not an fdev package",
            pin.name
        );
        assert_eq!(
            contracts::embedded(&pin.name),
            Some(bytes.as_slice()),
            "the core embeds {}.wasm byte for byte",
            pin.name
        );
    }

    let mut wasm_files: Vec<String> = fs::read_dir(&dir)
        .expect("list contracts/")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|f| f.ends_with(".wasm"))
        .collect();
    wasm_files.sort();
    let mut pinned: Vec<String> = pins.iter().map(|p| format!("{}.wasm", p.name)).collect();
    pinned.sort();
    assert_eq!(
        wasm_files, pinned,
        "no .wasm in contracts/ that hashes.json does not pin"
    );

    // The embedded manifest is the file on disk, and the runtime check
    // agrees.
    assert_eq!(contracts::HASHES_JSON, text);
    let bundled = contracts::bundled().expect("the embedded contracts verify");
    let current = pins.iter().find(|p| p.name == contracts::CURRENT).unwrap();
    let pointer = pins.iter().find(|p| p.name == contracts::POINTER).unwrap();
    assert_eq!(
        bundled.route.current, current.blake3,
        "new links use signalling-v1"
    );
    assert_eq!(
        bundled.route.pointer_code, pointer.blake3,
        "the pointer record is pointer-v1"
    );
    assert!(bundled.route.known.contains_key(&bundled.route.current));
    assert!(
        !bundled
            .route
            .known
            .contains_key(&bundled.route.pointer_code),
        "the pointer code is not a signalling code"
    );
}

/// The pins are ZBTerm's, and this repository adds one: every entry of
/// the `hashes.json` ZBTerm shipped until K11 removed its copy (read from
/// its JS reference revision, `zxterm_testkit::js::reference_root`) is
/// byte-identical in this repository's, and `segment-v1` (K16, `X-26`,
/// zxterm's own contract) is the only entry ZBTerm never had. Skips with a
/// printed reason when that tree is absent.
#[test]
fn the_pins_are_zbterms_pins() {
    let root = match zxterm_testkit::js::reference_root() {
        Ok(root) => root,
        Err(e) => {
            println!("SKIP the_pins_are_zbterms_pins: {e}");
            return;
        }
    };
    let zbterm = root.join("engine/backends/freenet/contracts/hashes.json");
    let Ok(theirs) = fs::read_to_string(&zbterm) else {
        println!(
            "SKIP the_pins_are_zbterms_pins: {} not found",
            zbterm.display()
        );
        return;
    };
    let theirs = contracts::parse_manifest(&theirs).expect("parse ZBTerm's hashes.json");
    let ours = contracts::parse_manifest(contracts::HASHES_JSON).expect("parse hashes.json");
    assert_eq!(
        theirs.len(),
        2,
        "ZBTerm pinned signalling-v1 and pointer-v1"
    );
    for pin in &theirs {
        assert!(ours.contains(pin), "{} is ZBTerm's pin", pin.name);
    }
    let added: Vec<&str> = ours
        .iter()
        .filter(|p| !theirs.iter().any(|t| t.name == p.name))
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(added, vec![contracts::SEGMENT], "only segment-v1 is new");
}

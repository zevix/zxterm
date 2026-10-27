//! The invite `route` of a Freenet link (design §4.3, §5; K5), one to one
//! with ZBTerm `engine/backends/freenet/route.js`.
//!
//! ```text
//! route = { sig, code, params: { ttl_ms, host, n }, ptr, k }
//! ```
//!
//! > 2026-09-30, K13 (`protocol.md` §12): a v2 route carries the route
//! > protocol version as a key of `params`, `params.pv = 2`
//! > ([`PROTOCOL_VERSION`]), and [`params_bytes`] serialises it last when
//! > present, so a v1 verifier's check 3 refuses a v2 route and a v2
//! > verifier ([`verify`]) refuses a `pv`-less one first (rule PV-1,
//! > [`check_pv`]), before any other check, with `E_BACKEND_UNSUPPORTED`
//! > naming the upgrade. [`mint`] mints v2 routes. [`mint_v1`]/[`verify_v1`]
//! > are today's v1 rules, kept only for the interop tests against the
//! > frozen v1 JS reference (`X-19`); no product path calls them unless a
//! > [`super::backend::BackendOptions::legacy_v1_routes`] backend does.
//!
//! `sig` is the signalling instance id, base58(blake3(code ‖
//! paramsBytes(params))); `code` the hex BLAKE3 of the raw signalling wasm;
//! `ptr` the pointer record's instance id for `{host, n}`; `k` the payload
//! key seed, which never reaches the node.
//!
//! `route.js::instanceId` (base58 of blake3(codeHash ‖ params)) is a
//! *different* function from `node-client.js::instanceId` (the raw digest,
//! see `super::node::instance_id`) even though both files export a function
//! of that name — this module keeps the base58 form as `instance_id_b58`
//! so the two are never conflated.

use std::collections::HashMap;

use crypto_secretbox::aead::rand_core::RngCore;

use crate::error::{Code, Error};

/// `route.js::ROUTE_TTL_MS`.
pub const ROUTE_TTL_MS: u64 = 120_000;

/// The route protocol version a v2 build mints and accepts
/// (`protocol.md` §12, `params.pv`).
pub const PROTOCOL_VERSION: u64 = 2;

/// PV-1's message for a route older than [`PROTOCOL_VERSION`] (or with no
/// `pv` at all).
pub const OLDER_PROTOCOL_MESSAGE: &str = "The invite uses an older Freenet session protocol; the host must upgrade and share a new invite";
/// PV-1's detail for an older route.
pub const OLDER_PROTOCOL_DETAIL: &str = "route protocol version is older than 2";
/// PV-1's detail for a newer route.
pub const NEWER_PROTOCOL_DETAIL: &str = "route protocol version is newer than 2";

/// The largest integer JS's `Number.isSafeInteger` accepts.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random32_base64url() -> String {
    let mut buf = [0u8; 32];
    crypto_secretbox::aead::OsRng.fill_bytes(&mut buf);
    base64url(&buf)
}

/// The contracts a build ships, the Rust mirror of `contracts.js`'s shape
/// (`zxterm_testkit::contracts::Contracts` builds this at test time from
/// the live ZBTerm tree; K10's `A-6` embeds it for real).
pub struct Contracts {
    /// hex BLAKE3 -> raw signalling wasm.
    pub known: HashMap<String, Vec<u8>>,
    /// hex BLAKE3 of the signalling wasm `mint` mints new links with.
    pub current: String,
    pub pointer_code: String,
}

/// The signalling contract's parameters, key order fixed (`ttl_ms, host,
/// n`, then `pv` when present): it is part of the signed/hashed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParams {
    pub ttl_ms: u64,
    /// hex ed25519 public key of the minting host.
    pub host: String,
    /// base64url(32 random bytes).
    pub n: String,
    /// The route protocol version (`protocol.md` §12): `Some(2)` on every
    /// route a v2 build mints, `None` on a v1 route.
    pub pv: Option<u64>,
}

/// `route.js::paramsBytes`: `JSON.stringify({ttl_ms, host, n})` UTF-8, in
/// that key order, and from v2 `,"pv":<pv>` last when `pv` is present
/// (`protocol.md` §12.2; the `pv`-less bytes are unchanged). Built by
/// hand-concatenation, never through `serde_json` serialization of a
/// struct: a struct's field order is not guaranteed to match the wire's,
/// and this exact byte sequence is signed and hashed over.
pub fn params_bytes(params: &RouteParams) -> Vec<u8> {
    let pv = params
        .pv
        .map(|pv| format!(",\"pv\":{pv}"))
        .unwrap_or_default();
    format!(
        "{{\"ttl_ms\":{},\"host\":\"{}\",\"n\":\"{}\"{pv}}}",
        params.ttl_ms, params.host, params.n
    )
    .into_bytes()
}

/// Rule PV-1 on a route built in Rust: `pv` must be exactly
/// [`PROTOCOL_VERSION`]. `E_BACKEND_UNSUPPORTED` naming the upgrade
/// otherwise, never a corruption error.
pub fn check_pv(pv: Option<u64>) -> Result<(), Error> {
    match pv {
        Some(PROTOCOL_VERSION) => Ok(()),
        Some(v) if v > PROTOCOL_VERSION => Err(Error::with_details(
            Code::EBackendUnsupported,
            format!(
                "The invite uses a newer Freenet session protocol (version {v}); upgrade to join it"
            ),
            NEWER_PROTOCOL_DETAIL,
        )),
        _ => Err(Error::with_details(
            Code::EBackendUnsupported,
            OLDER_PROTOCOL_MESSAGE,
            OLDER_PROTOCOL_DETAIL,
        )),
    }
}

/// Rule PV-1 on a route as JSON, before a single other field is read:
/// `route.params.pv` absent (including a route or `params` that is not an
/// object), not an integer, or an integer below 2 is the older refusal;
/// an integer above 2 the newer one.
pub fn check_pv_json(route: &serde_json::Value) -> Result<(), Error> {
    let pv = route.get("params").and_then(|p| p.get("pv"));
    match pv {
        Some(v) if v.is_u64() => check_pv(v.as_u64()),
        _ => check_pv(None),
    }
}

/// `route.js::pointerParamsBytes(hostHex, n)`, the `{host, n}` form only
/// (K5's routes always mint `n`; the pre-F6 `{host}`-alone shape is out of
/// scope here).
pub fn pointer_params_bytes(host_hex: &str, n: &str) -> Vec<u8> {
    format!("{{\"host\":\"{host_hex}\",\"n\":\"{n}\"}}").into_bytes()
}

/// `route.js::instanceId`: base58(blake3(code ‖ params)) — a *route's*
/// `sig`/`ptr`, distinct from `super::node::instance_id` (the raw digest).
pub fn instance_id_b58(code_hex: &str, params: &[u8]) -> String {
    let code = hex::decode(code_hex).expect("instance_id_b58: code_hex is not valid hex");
    let mut both = Vec::with_capacity(code.len() + params.len());
    both.extend_from_slice(&code);
    both.extend_from_slice(params);
    let digest = blake3::hash(&both);
    bs58::encode(digest.as_bytes()).into_string()
}

/// A minted route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub sig: String,
    pub code: String,
    pub params: RouteParams,
    pub ptr: Option<String>,
    /// The payload key seed. Never sent to the node.
    pub k: String,
}

/// `route.js::mint`, v2 (rule PV-3: every route a v2 build mints has
/// `pv: 2`): `link_id` is not part of the route (the 32-byte nonce `n`
/// alone makes the instance unique and unguessable), kept only for
/// signature parity with `route.js::mint(linkId, hostKey, contracts)`.
pub fn mint(link_id: &str, host_pubkey_hex: &str, contracts: &Contracts) -> Route {
    mint_with(link_id, host_pubkey_hex, contracts, Some(PROTOCOL_VERSION))
}

/// `route.js::mint` exactly as v1 minted it (no `pv`): only for the interop
/// tests against the frozen v1 JS reference (`X-19`).
pub fn mint_v1(link_id: &str, host_pubkey_hex: &str, contracts: &Contracts) -> Route {
    mint_with(link_id, host_pubkey_hex, contracts, None)
}

fn mint_with(
    _link_id: &str,
    host_pubkey_hex: &str,
    contracts: &Contracts,
    pv: Option<u64>,
) -> Route {
    let params = RouteParams {
        ttl_ms: ROUTE_TTL_MS,
        host: host_pubkey_hex.to_lowercase(),
        n: random32_base64url(),
        pv,
    };
    let sig = instance_id_b58(&contracts.current, &params_bytes(&params));
    let ptr = instance_id_b58(
        &contracts.pointer_code,
        &pointer_params_bytes(&params.host, &params.n),
    );
    Route {
        sig,
        code: contracts.current.clone(),
        params,
        ptr: Some(ptr),
        k: random32_base64url(),
    }
}

fn refuse(code: Code, message: &str, detail: &str) -> Error {
    Error::with_details(code, message, detail)
}

/// What a dial needs from a verified route: the contract's code hash, its
/// wasm, and the params bytes (`route.js::verify`'s success shape,
/// `{code, wasm, params}` with `params` as bytes, not the object).
#[derive(Debug)]
pub struct Checked {
    pub code: String,
    pub wasm: Vec<u8>,
    pub params: Vec<u8>,
}

/// `route.js::verify`'s five checks, in order:
/// 1. well-formedness (`E_CORRUPT`),
/// 2. `params.host` names the expected peer (`E_AUTH`),
/// 3. `sig` is the instance of `code` and `params` (`E_CORRUPT`),
/// 4. if `ptr` is set, it is the pointer instance of `host`/`n`
///    (`E_CORRUPT`),
/// 5. `code` is a signalling contract this build ships
///    (`E_BACKEND_UNSUPPORTED`).
///
/// Most of JS's well-formedness sub-checks (`typeof x === 'string'`) are
/// guaranteed by this module's own types (`RouteParams.n: String`,
/// `Route.ptr: Option<String>`, …) rather than re-checked at runtime; the
/// checks below are exactly the ones a well-typed `Route` can still fail:
/// `code`/`host`'s hex-64 format and `ttl_ms`'s safe-integer bound.
///
/// > 2026-09-30, K13: this is the v2 verifier. Rule PV-1 ([`check_pv`])
/// > runs first, before check 1 and before `sig` is recomputed, so a
/// > `pv`-less route is refused as an older protocol even when its `sig`
/// > would verify; check 3 then recomputes `sig` over the v2 bytes.
pub fn verify(
    route: &Route,
    expected_peer_key_hex: &str,
    contracts: &Contracts,
) -> Result<Checked, Error> {
    check_pv(route.params.pv)?;
    verify_v1(route, expected_peer_key_hex, contracts)
}

/// `route.js::verify`'s five checks without rule PV-1: today's v1
/// verifier, kept only for the interop tests against the frozen v1 JS
/// reference (`X-19`) and for [`verify`] after PV-1 has passed.
pub fn verify_v1(
    route: &Route,
    expected_peer_key_hex: &str,
    contracts: &Contracts,
) -> Result<Checked, Error> {
    if !is_hex64(&route.code)
        || route.params.ttl_ms > MAX_SAFE_INTEGER
        || !is_hex64(&route.params.host)
    {
        return Err(refuse(
            Code::ECorrupt,
            "The Freenet route is malformed",
            "malformed route",
        ));
    }

    if route.params.host != expected_peer_key_hex.to_lowercase() {
        return Err(refuse(
            Code::EAuth,
            "The Freenet route names a different host than the invite",
            "route host is not the expected peer",
        ));
    }

    let bytes = params_bytes(&route.params);
    if route.sig != instance_id_b58(&route.code, &bytes) {
        return Err(refuse(
            Code::ECorrupt,
            "The Freenet route does not match its contract code and parameters",
            "sig is not the instance of code and params",
        ));
    }

    if let Some(ptr) = &route.ptr {
        let expected_ptr = instance_id_b58(
            &contracts.pointer_code,
            &pointer_params_bytes(&route.params.host, &route.params.n),
        );
        if *ptr != expected_ptr {
            return Err(refuse(
                Code::ECorrupt,
                "The Freenet route's pointer record is not the link's",
                "ptr is not the pointer instance of the host and nonce",
            ));
        }
    }

    let wasm = contracts.known.get(&route.code).cloned().ok_or_else(|| {
        refuse(
            Code::EBackendUnsupported,
            "The Freenet route uses a signalling contract this build does not ship",
            "unknown contract code",
        )
    })?;

    Ok(Checked {
        code: route.code.clone(),
        wasm,
        params: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn fixture_contracts() -> Contracts {
        let mut known = HashMap::new();
        let code = hex64(0xAA);
        known.insert(code.clone(), vec![1, 2, 3]);
        Contracts {
            known,
            current: code,
            pointer_code: hex64(0xBB),
        }
    }

    fn fixture_route(contracts: &Contracts, host_hex: &str) -> Route {
        mint("link-id-unused", host_hex, contracts)
    }

    #[test]
    fn params_bytes_key_order_and_shape() {
        let params = RouteParams {
            ttl_ms: 120_000,
            host: "aa".repeat(32),
            n: "nonce-text".to_string(),
            pv: None,
        };
        let text = String::from_utf8(params_bytes(&params)).unwrap();
        assert_eq!(
            text,
            format!(
                "{{\"ttl_ms\":120000,\"host\":\"{}\",\"n\":\"nonce-text\"}}",
                "aa".repeat(32)
            )
        );
    }

    #[test]
    fn v2_params_bytes_end_with_pv() {
        let params = RouteParams {
            ttl_ms: 120_000,
            host: "aa".repeat(32),
            n: "nonce-text".to_string(),
            pv: Some(2),
        };
        let text = String::from_utf8(params_bytes(&params)).unwrap();
        assert_eq!(
            text,
            format!(
                "{{\"ttl_ms\":120000,\"host\":\"{}\",\"n\":\"nonce-text\",\"pv\":2}}",
                "aa".repeat(32)
            )
        );
    }

    #[test]
    fn mint_sets_pv_2_and_mint_v1_none() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        assert_eq!(mint("l", &host_hex, &contracts).params.pv, Some(2));
        assert_eq!(mint_v1("l", &host_hex, &contracts).params.pv, None);
    }

    /// The acceptance criterion: PV-1 runs before `sig` is computed. The
    /// route below is a v1 route whose `sig` verifies (the v1 verifier
    /// accepts it), and the v2 verifier refuses it as an older protocol,
    /// not as corruption.
    #[test]
    fn pv1_refuses_a_pvless_route_whose_sig_would_verify() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let v1 = mint_v1("l", &host_hex, &contracts);
        assert!(
            verify_v1(&v1, &host_hex, &contracts).is_ok(),
            "sig verifies"
        );
        let err = verify(&v1, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::EBackendUnsupported);
        assert_eq!(err.message, OLDER_PROTOCOL_MESSAGE);
        assert!(err.message.contains("protocol") && err.message.contains("upgrade"));
        assert_eq!(err.details.as_deref(), Some(OLDER_PROTOCOL_DETAIL));
        // Even a malformed pv-less route is refused by PV-1, not check 1.
        let mut broken = v1.clone();
        broken.code = "not-hex".into();
        assert_eq!(
            verify(&broken, &host_hex, &contracts)
                .unwrap_err()
                .details
                .as_deref(),
            Some(OLDER_PROTOCOL_DETAIL)
        );
    }

    #[test]
    fn pv1_older_and_newer_versions() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        for (pv, detail) in [
            (Some(0), OLDER_PROTOCOL_DETAIL),
            (Some(1), OLDER_PROTOCOL_DETAIL),
            (Some(3), NEWER_PROTOCOL_DETAIL),
        ] {
            let mut r = mint("l", &host_hex, &contracts);
            r.params.pv = pv;
            r.sig = instance_id_b58(&contracts.current, &params_bytes(&r.params));
            let err = verify(&r, &host_hex, &contracts).unwrap_err();
            assert_eq!(err.code, Code::EBackendUnsupported);
            assert_eq!(err.details.as_deref(), Some(detail));
        }
        let mut r = mint("l", &host_hex, &contracts);
        r.params.pv = Some(3);
        assert_eq!(
            verify(&r, &host_hex, &contracts).unwrap_err().message,
            "The invite uses a newer Freenet session protocol (version 3); upgrade to join it"
        );
    }

    #[test]
    fn pv1_on_json_runs_before_field_extraction() {
        use serde_json::json;
        for v in [
            json!(null),
            json!("route"),
            json!({"params": 5}),
            json!({"params": {}}),
            json!({"params": {"pv": "2"}}),
            json!({"params": {"pv": 2.5}}),
            json!({"params": {"pv": -1}}),
            json!({"params": {"pv": 1}}),
        ] {
            let err = check_pv_json(&v).unwrap_err();
            assert_eq!(err.details.as_deref(), Some(OLDER_PROTOCOL_DETAIL), "{v}");
        }
        assert_eq!(
            check_pv_json(&json!({"params": {"pv": 7}}))
                .unwrap_err()
                .details
                .as_deref(),
            Some(NEWER_PROTOCOL_DETAIL)
        );
        assert!(check_pv_json(&json!({"params": {"pv": 2}})).is_ok());
    }

    /// `protocol.md` §12.4: a v1 verifier refuses a v2 route at check 3.
    #[test]
    fn a_v1_verifier_refuses_a_v2_route_at_check_3() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let v2 = mint("l", &host_hex, &contracts);
        let mut seen_by_v1 = v2.clone();
        seen_by_v1.params.pv = None; // a v1 paramsBytes never serialises pv
        let err = verify_v1(&seen_by_v1, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(
            err.details.as_deref(),
            Some("sig is not the instance of code and params")
        );
    }

    #[test]
    fn mint_produces_a_route_that_verifies() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let route = fixture_route(&contracts, &host_hex);
        let checked = verify(&route, &host_hex, &contracts).expect("mint()'d route must verify");
        assert_eq!(checked.code, contracts.current);
        assert_eq!(checked.wasm, contracts.known[&contracts.current]);
    }

    #[test]
    fn check1_malformed_code_is_ecorrupt() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        route.code = "not-hex".to_string();
        let err = verify(&route, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(err.details.as_deref(), Some("malformed route"));
    }

    #[test]
    fn check1_ttl_ms_beyond_safe_integer_is_ecorrupt() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        route.params.ttl_ms = MAX_SAFE_INTEGER + 1;
        let err = verify(&route, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(err.details.as_deref(), Some("malformed route"));
    }

    #[test]
    fn check2_wrong_host_is_eauth() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let route = fixture_route(&contracts, &host_hex);
        let other_host = hex64(0xDD);
        let err = verify(&route, &other_host, &contracts).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(
            err.details.as_deref(),
            Some("route host is not the expected peer")
        );
    }

    #[test]
    fn check3_tampered_sig_is_ecorrupt() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        route.sig = instance_id_b58(&contracts.current, b"different-params");
        let err = verify(&route, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(
            err.details.as_deref(),
            Some("sig is not the instance of code and params")
        );
    }

    #[test]
    fn check4_tampered_ptr_is_ecorrupt() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        route.ptr = Some(instance_id_b58(
            &contracts.pointer_code,
            b"wrong-pointer-params",
        ));
        let err = verify(&route, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(
            err.details.as_deref(),
            Some("ptr is not the pointer instance of the host and nonce")
        );
    }

    #[test]
    fn check4_absent_ptr_skips_the_check() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        route.ptr = None;
        assert!(verify(&route, &host_hex, &contracts).is_ok());
    }

    #[test]
    fn check5_unknown_code_is_ebackendunsupported() {
        let contracts = fixture_contracts();
        let host_hex = hex64(0xCC);
        let mut route = fixture_route(&contracts, &host_hex);
        let unknown_code = hex64(0xEE);
        // Re-sign sig/ptr against the unknown code so checks 1-4 pass and
        // only check 5 (unknown contract) fails.
        route.code = unknown_code.clone();
        route.sig = instance_id_b58(&unknown_code, &params_bytes(&route.params));
        let err = verify(&route, &host_hex, &contracts).unwrap_err();
        assert_eq!(err.code, Code::EBackendUnsupported);
        assert_eq!(err.details.as_deref(), Some("unknown contract code"));
    }
}

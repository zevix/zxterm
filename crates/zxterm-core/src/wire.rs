//! Every current ZBTerm wire, signature and derivation string, as `pub
//! const`s (design §4.9). This module is the *only* place such a string
//! lives in this crate. Each constant is the exact, current, post-rename
//! `zbterm/…` (or `zbterm-…`) byte value ZBTerm ships today — this project
//! does not rename them again (`A-2`). New strings this project mints are
//! `zxterm/…` and land in later phases, never retrofitted here.
//!
//! Verified against ZBTerm `main` at `664cb4a` (2026-09-28) by
//! `tests/wire_parity.rs`, which re-reads the cited ZBTerm source file for
//! every constant below.
//!
//! > 2026-09-30, K13: the session protocol v2 adds the kdf contexts ZBTerm
//! > has shipped since K11 (`HIST_CONTEXT`, `LIVE_CONTEXT`, `SNAP_CONTEXT`,
//! > ZBTerm `D-36`, checked against ZBTerm's live tree) and the first
//! > zxterm-minted wire strings, the session channel protocols
//! > `SESSION_CTL_PROTOCOL`/`SESSION_LIVE_PROTOCOL`/`SESSION_HISTORY_PROTOCOL`
//! > (`zxterm/…`, checked against `protocol.md`).

/// SSHSIG namespace for identity claims.
///
/// ZBTerm source: `engine/identity/claim.js::NAMESPACE`.
pub const NAMESPACE: &str = "zbterm-identity";

/// SSHSIG container magic (`draft-miller-ssh-sigformat`).
///
/// ZBTerm source: `engine/identity/claim.js::SSHSIG_MAGIC`.
pub const SSHSIG_MAGIC: &str = "SSHSIG";

/// ed25519 SSH key-type/signature-algorithm name.
///
/// ZBTerm source: `engine/identity/claim.js::KEY_TYPE`.
pub const KEY_TYPE: &str = "ssh-ed25519";

/// RSA SSH key-type name.
///
/// ZBTerm source: `engine/identity/claim.js::RSA_KEY_TYPE`.
pub const RSA_KEY_TYPE: &str = "ssh-rsa";

/// RSA SSHSIG signature-algorithm name (SHA-2/512 variant; a bare `ssh-rsa`
/// (SHA-1) signature is refused, never accepted).
///
/// ZBTerm source: `engine/identity/claim.js::RSA_SIG_ALG`.
pub const RSA_SIG_ALG: &str = "rsa-sha2-512";

/// SSHSIG signed-data hash algorithm name.
///
/// ZBTerm source: `engine/identity/claim.js::HASH_ALG`.
pub const HASH_ALG: &str = "sha512";

/// SSHSIG PEM armor markers.
///
/// ZBTerm source: `engine/identity/claim.js::ARMOR_BEGIN`/`ARMOR_END`.
pub const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
pub const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

/// PKCS#1 v1.5 DigestInfo prefix for SHA-512 (RFC 8017 A.2.4), hex-encoded.
///
/// ZBTerm source: `engine/identity/claim.js::PKCS1_SHA512_PREFIX`.
pub const PKCS1_SHA512_PREFIX_HEX: &str = "3051300d060960864801650304020305000440";

/// Identity claim magic.
///
/// ZBTerm source: `engine/identity/claim.js::CLAIM_MAGIC`.
pub const CLAIM_MAGIC: &str = "zbterm-identity-claim/v1";

/// Identity handshake challenge magic.
///
/// ZBTerm source: `engine/identity/claim.js::CHALLENGE_MAGIC`.
pub const CHALLENGE_MAGIC: &str = "zbterm-identity-challenge/v1";

/// Freenet WebRTC signalling domain separator.
///
/// ZBTerm source: `engine/backends/freenet/signal.js::SIGNAL_DOMAIN`.
pub const SIGNAL_DOMAIN: &str = "zbterm/fnet-signal/1";

/// Freenet pointer-contract domain separator.
///
/// ZBTerm source: `engine/backends/freenet/signal.js::POINTER_DOMAIN`.
pub const POINTER_DOMAIN: &str = "zbterm/fnet-pointer/1";

/// Freenet route payload-key derivation context.
///
/// ZBTerm source: `engine/backends/freenet/signal.js::PAYLOAD_CONTEXT`.
pub const PAYLOAD_CONTEXT: &str = "zbterm/fnet-payload/1";

/// Bootstrap data-channel label opened over a Freenet WebRTC connection.
///
/// ZBTerm source: `engine/backends/freenet/connection.js::BOOTSTRAP_LABEL`
/// (also `engine/backends/freenet/index.js::BOOTSTRAP_LABEL`).
pub const BOOTSTRAP_LABEL: &str = "zbterm/fnet-bootstrap";

/// History-replication data-channel protocol label.
///
/// ZBTerm source: `engine/backends/freenet/history.js::HISTORY_PROTOCOL`.
pub const HISTORY_PROTOCOL: &str = "zbterm/history";

/// `ctl` control-channel protocol label.
///
/// ZBTerm source: `engine/share-manager.js::PROTOCOL`.
pub const CTL_PROTOCOL: &str = "zbterm/ctl";

/// Invite link scheme/prefix.
///
/// ZBTerm source: `engine/invite.js::LINK_PREFIX`.
pub const LINK_PREFIX: &str = "zbterm://join/";

/// SLIP-48 path-type slot (`index.js::keyPath`'s second element) for the
/// identity-key derivation path (`idkey::keychain::identity_key_path`/
/// `discovery_core_path`). Replaces the upstream identity-key package's own
/// value `5338` in exactly this slot (`X-01`/`A-4`); a new, zxterm-minted
/// constant, not a ZBTerm wire byte.
pub const ZXTERM_KEY_PATH_TYPE: u32 = 23128;

/// SLIP-21 symmetric-derivation namespace (`index.js::symmetricPath`'s
/// `namespace` local). Replaces the upstream identity-key package's own name,
/// used as a namespace string in exactly this slot (`X-01`/`A-4`); a new,
/// zxterm-minted constant, not a ZBTerm wire byte.
pub const ZXTERM_SYMMETRIC_NAMESPACE: &str = "zxterm-identity-key";

/// The history-key kdf context (`crypto_kdf`, exactly 8 bytes), ZBTerm's
/// since K11 (ZBTerm `D-36`, owner `Q-14`); `protocol.md` §1.
///
/// ZBTerm source: `engine/crypto.js::HIST_CONTEXT` (live tree).
pub const HIST_CONTEXT: &str = "zxt-hist";

/// The live-key kdf context, 8 bytes (ZBTerm `D-36`).
///
/// ZBTerm source: `engine/crypto.js::LIVE_CONTEXT` (live tree).
pub const LIVE_CONTEXT: &str = "zxt-live";

/// The local snapshot-key kdf context, 8 bytes (ZBTerm `D-36`); never on
/// the wire.
///
/// ZBTerm source: `engine/crypto.js::SNAP_CONTEXT` (live tree).
pub const SNAP_CONTEXT: &str = "zxt-snap";

/// The v2 session control channel's protocol (`protocol.md` §1, §5): the
/// label is `"zxterm/ctl <linkIdHex>"`. A new zxterm string (design §4.9).
pub const SESSION_CTL_PROTOCOL: &str = "zxterm/ctl";

/// The v2 session live channel's protocol (`protocol.md` §1, §5).
pub const SESSION_LIVE_PROTOCOL: &str = "zxterm/live";

/// The v2 session history message channel's protocol (`protocol.md` §1,
/// §5). Hypercore replication keeps [`HISTORY_PROTOCOL`] in C2.
pub const SESSION_HISTORY_PROTOCOL: &str = "zxterm/history";

/// Domain prefix of the message a C3 signed head signs
/// (`crate::history::head::SignedHead`, K15): this string, the session id's
/// 64 hex bytes, the head's `length` u64 LE, the 32-byte chain root.
pub const HISTORY_HEAD_CONTEXT: &str = "zxterm/history-head-v1";

/// Domain prefix of the message a C3 metadata record signs
/// (`crate::history::metadata`, K15): this string, then the record's
/// `postcard` body bytes.
pub const HISTORY_META_CONTEXT: &str = "zxterm/history-meta-v1";

/// Domain prefix of both records the offline-history contract checks
/// (`contracts/src/segment`'s `DOMAIN`, `crate::history::contract`, K16):
/// a segment record signs this string, `u8(1)`, `lp(params)`, `u32le(index)`,
/// the 32-byte chain root before it and `lp(record)`; a head signs this
/// string, `u8(2)`, `lp(params)`, `u64le(length)` and the chain root.
pub const SEGMENT_CONTRACT_DOMAIN: &str = "zxterm/segment/1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_nonempty_and_distinct() {
        let all = [
            NAMESPACE,
            SSHSIG_MAGIC,
            KEY_TYPE,
            RSA_KEY_TYPE,
            RSA_SIG_ALG,
            HASH_ALG,
            ARMOR_BEGIN,
            ARMOR_END,
            PKCS1_SHA512_PREFIX_HEX,
            CLAIM_MAGIC,
            CHALLENGE_MAGIC,
            SIGNAL_DOMAIN,
            POINTER_DOMAIN,
            PAYLOAD_CONTEXT,
            BOOTSTRAP_LABEL,
            HISTORY_PROTOCOL,
            CTL_PROTOCOL,
            LINK_PREFIX,
            ZXTERM_SYMMETRIC_NAMESPACE,
            HIST_CONTEXT,
            LIVE_CONTEXT,
            SNAP_CONTEXT,
            SESSION_CTL_PROTOCOL,
            SESSION_LIVE_PROTOCOL,
            SESSION_HISTORY_PROTOCOL,
            HISTORY_HEAD_CONTEXT,
            HISTORY_META_CONTEXT,
            SEGMENT_CONTRACT_DOMAIN,
        ];
        for value in all {
            assert!(!value.is_empty());
        }
        let mut sorted = all;
        sorted.sort_unstable();
        for i in 1..sorted.len() {
            assert_ne!(sorted[i - 1], sorted[i], "duplicate wire constant value");
        }
    }

    #[test]
    fn kdf_contexts_are_eight_bytes() {
        for c in [HIST_CONTEXT, LIVE_CONTEXT, SNAP_CONTEXT] {
            assert_eq!(c.len(), 8, "{c}");
        }
    }

    #[test]
    fn key_path_type_replaces_the_upstream_value() {
        // The upstream identity-key package's own value is `5338`; this
        // must not be it (`X-01`/`A-4`).
        assert_ne!(ZXTERM_KEY_PATH_TYPE, 5338);
        assert_eq!(ZXTERM_KEY_PATH_TYPE, 23128);
    }
}

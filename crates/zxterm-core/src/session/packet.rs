//! Packet AEAD (`protocol.md` §3.3), ZBTerm `engine/crypto.js::
//! encryptPacket`/`decryptPacket` byte for byte: XChaCha20-Poly1305-IETF,
//! nonce = BLAKE2b-256(`sessionId`'s UTF-8 bytes)[..16] ‖ `seq` u64 BE,
//! associated data = `sessionId` bytes ‖ `epoch` u32 BE ‖ `seq` u64 BE ‖
//! `deviceKey`.
//!
//! > 2026-09-30, K13: the plan's step 3 wrote the nonce as
//! > `blake2b(sessionId)[..16]`; it is BLAKE2b with a **32-byte** output
//! > over the hex string's bytes, then truncated (`protocol.md` §3.3,
//! > §15). `tests/session_crypto_parity.rs` pins it against `sodium-native`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Code, Error};

/// `crypto_aead_xchacha20poly1305_ietf_ABYTES`.
pub const TAG_BYTES: usize = 16;

/// `crypto.js::nonceFor(sessionId, seq)`.
pub fn nonce_for(session_id: &str, seq: u64) -> [u8; 24] {
    let prefix = crate::idkey::proof::blake2b_256(session_id.as_bytes());
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(&prefix[..16]);
    nonce[16..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// `crypto.js::associatedData(sessionId, epoch, seq, deviceKey)`.
pub fn associated_data(session_id: &str, epoch: u32, seq: u64, device_key: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(session_id.len() + 12 + device_key.len());
    ad.extend_from_slice(session_id.as_bytes());
    ad.extend_from_slice(&epoch.to_be_bytes());
    ad.extend_from_slice(&seq.to_be_bytes());
    ad.extend_from_slice(device_key);
    ad
}

/// `crypto.js::encryptPacket`.
pub fn encrypt(
    key: &[u8; 32],
    session_id: &str,
    epoch: u32,
    seq: u64,
    device_key: &[u8],
    plain: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce_for(session_id, seq);
    let ad = associated_data(session_id, epoch, seq, device_key);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &ad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption does not fail")
}

/// `crypto.js::decryptPacket`: `E_CORRUPT 'Encrypted data failed
/// authentication'` (details `{epoch, seq}`) on any failure.
pub fn decrypt(
    key: &[u8; 32],
    session_id: &str,
    epoch: u32,
    seq: u64,
    device_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = nonce_for(session_id, seq);
    let ad = associated_data(session_id, epoch, seq, device_key);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| {
            Error::with_details(
                Code::ECorrupt,
                "Encrypted data failed authentication",
                format!("{{\"epoch\":{epoch},\"seq\":{seq}}}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_every_bound_field_matters() {
        let sid = "ef".repeat(32);
        let key = [5u8; 32];
        let dev = [6u8; 32];
        let ct = encrypt(&key, &sid, 3, 7, &dev, b"hello");
        assert_eq!(ct.len(), 5 + TAG_BYTES);
        assert_eq!(decrypt(&key, &sid, 3, 7, &dev, &ct).unwrap(), b"hello");
        for bad in [
            decrypt(&[4u8; 32], &sid, 3, 7, &dev, &ct),
            decrypt(&key, &"ee".repeat(32), 3, 7, &dev, &ct),
            decrypt(&key, &sid, 4, 7, &dev, &ct),
            decrypt(&key, &sid, 3, 8, &dev, &ct),
            decrypt(&key, &sid, 3, 7, &[7u8; 32], &ct),
        ] {
            let e = bad.unwrap_err();
            assert_eq!(e.code, Code::ECorrupt);
            assert_eq!(e.message, "Encrypted data failed authentication");
        }
    }

    #[test]
    fn nonce_is_blake2b_256_truncated_then_seq_be() {
        let sid = "00".repeat(32);
        let n = nonce_for(&sid, 0x0102);
        let h = crate::idkey::proof::blake2b_256(sid.as_bytes());
        assert_eq!(&n[..16], &h[..16]);
        assert_eq!(&n[16..], &[0, 0, 0, 0, 0, 0, 1, 2]);
    }
}

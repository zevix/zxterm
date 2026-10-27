//! The key envelope (`protocol.md` §3.2): ZBTerm `engine/crypto.js::
//! Envelope`'s compact-encoding bytes, hand-encoded (v2 keeps them, so the
//! envelopes ZBTerm persists in the session's meta Hyperbee have one
//! reader), and the anonymous-sender sealed box (`crypto_box_seal`) that
//! carries them and the sealed input (`sealEnvelope`/`sealBytes`,
//! `openEnvelope`/`openSealedBytes`).
//!
//! > 2026-09-30, K13: K13's plan step 1 asked for a postcard-derived
//! > struct; `protocol.md` §3.2 (K12, `X-21`) supersedes it, and this
//! > module follows `protocol.md`.

use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};

use crate::error::{Code, Error};

/// `schema.js::VERSION`, the only envelope version that decodes.
pub const ENVELOPE_VERSION: u64 = 2;
/// `crypto_box_SEALBYTES`: a sealed box's overhead.
pub const SEAL_BYTES: usize = 48;

/// `crypto.js::Envelope`'s fields, in encoding order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u64,
    pub session_id: String,
    pub epoch: u64,
    pub caps: u64,
    pub master_key: Option<Vec<u8>>,
    pub history_key: Option<Vec<u8>>,
    pub live_key: Option<Vec<u8>>,
}

fn put_uint(out: &mut Vec<u8>, v: u64) {
    if v < 0xFD {
        out.push(v as u8);
    } else if v <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn put_buffer(out: &mut Vec<u8>, b: &[u8]) {
    put_uint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn malformed() -> Error {
    Error::with_details(
        Code::ECorrupt,
        "Envelope is malformed",
        "compact-encoding out of bounds",
    )
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or_else(malformed)?;
        let s = self.buf.get(self.at..end).ok_or_else(malformed)?;
        self.at = end;
        Ok(s)
    }

    fn uint(&mut self) -> Result<u64, Error> {
        let first = self.take(1)?[0];
        Ok(match first {
            0xFD => u16::from_le_bytes(self.take(2)?.try_into().expect("2")) as u64,
            0xFE => u32::from_le_bytes(self.take(4)?.try_into().expect("4")) as u64,
            0xFF => u64::from_le_bytes(self.take(8)?.try_into().expect("8")),
            b => b as u64,
        })
    }

    fn buffer(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.uint()?;
        let n = usize::try_from(n).map_err(|_| malformed())?;
        Ok(self.take(n)?.to_vec())
    }
}

impl Envelope {
    /// `c.encode(Envelope, env)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uint(&mut out, self.version);
        put_buffer(&mut out, self.session_id.as_bytes());
        put_uint(&mut out, self.epoch);
        put_uint(&mut out, self.caps);
        let mut flags = 0u64;
        if self.master_key.is_some() {
            flags |= 1;
        }
        if self.history_key.is_some() {
            flags |= 2;
        }
        if self.live_key.is_some() {
            flags |= 4;
        }
        put_uint(&mut out, flags);
        for key in [&self.master_key, &self.history_key, &self.live_key]
            .into_iter()
            .flatten()
        {
            put_buffer(&mut out, key);
        }
        out
    }

    /// `c.decode(Envelope, bytes)`: `E_CORRUPT 'Unknown envelope version'`
    /// for a version other than [`ENVELOPE_VERSION`].
    pub fn decode(bytes: &[u8]) -> Result<Envelope, Error> {
        let mut r = Reader { buf: bytes, at: 0 };
        let version = r.uint()?;
        if version != ENVELOPE_VERSION {
            return Err(Error::new(Code::ECorrupt, "Unknown envelope version"));
        }
        let session_id = String::from_utf8(r.buffer()?).map_err(|_| malformed())?;
        let epoch = r.uint()?;
        let caps = r.uint()?;
        let flags = r.uint()?;
        let master_key = if flags & 1 != 0 {
            Some(r.buffer()?)
        } else {
            None
        };
        let history_key = if flags & 2 != 0 {
            Some(r.buffer()?)
        } else {
            None
        };
        let live_key = if flags & 4 != 0 {
            Some(r.buffer()?)
        } else {
            None
        };
        Ok(Envelope {
            version,
            session_id,
            epoch,
            caps,
            master_key,
            history_key,
            live_key,
        })
    }
}

/// `crypto.js::sealBytes`: `crypto_box_seal(plain, public_key)`.
pub fn seal_bytes(public_key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    PublicKey::from(*public_key)
        .seal(&mut OsRng, plain)
        .expect("sealing to a 32-byte key never fails")
}

/// `crypto.js::openSealedBytes`: `E_NOKEY 'Could not open local key
/// envelope'` when the box does not open. The public key is derived from
/// `secret_key`, as `crypto_box_seal_open` takes it.
pub fn open_sealed_bytes(secret_key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    SecretKey::from(*secret_key)
        .unseal(sealed)
        .map_err(|_| Error::new(Code::ENoKey, "Could not open local key envelope"))
}

/// `crypto.js::sealEnvelope`.
pub fn seal(public_key: &[u8; 32], env: &Envelope) -> Vec<u8> {
    seal_bytes(public_key, &env.encode())
}

/// `crypto.js::openEnvelope`.
pub fn open(secret_key: &[u8; 32], sealed: &[u8]) -> Result<Envelope, Error> {
    Envelope::decode(&open_sealed_bytes(secret_key, sealed)?)
}

/// The X25519 public key of a device secret key (`crypto_box_keypair`'s
/// public half).
pub fn device_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    *SecretKey::from(*secret_key).public_key().as_bytes()
}

/// A fresh X25519 device key pair `(public, secret)`.
pub fn generate_device_key() -> ([u8; 32], [u8; 32]) {
    let sk = SecretKey::generate(&mut OsRng);
    (*sk.public_key().as_bytes(), sk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope {
            version: 2,
            session_id: "ab".repeat(32),
            epoch: 3,
            caps: 31,
            master_key: None,
            history_key: Some(vec![1; 32]),
            live_key: Some(vec![2; 32]),
        }
    }

    #[test]
    fn compact_encoding_layout() {
        let bytes = env().encode();
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], 64);
        assert_eq!(&bytes[2..66], "ab".repeat(32).as_bytes());
        assert_eq!(&bytes[66..70], &[3, 31, 6, 32]);
        assert_eq!(bytes.len(), 70 + 32 + 1 + 32);
        assert_eq!(Envelope::decode(&bytes).unwrap(), env());
    }

    #[test]
    fn uint_boundaries_round_trip() {
        for v in [
            0u64,
            0xFC,
            0xFD,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
        ] {
            let mut e = env();
            e.epoch = v;
            assert_eq!(Envelope::decode(&e.encode()).unwrap().epoch, v);
        }
    }

    #[test]
    fn wrong_version_and_truncation_are_ecorrupt() {
        let mut e = env();
        e.version = 1;
        let err = Envelope::decode(&e.encode()).unwrap_err();
        assert_eq!(
            (err.code, err.message.as_str()),
            (Code::ECorrupt, "Unknown envelope version")
        );
        let bytes = env().encode();
        assert_eq!(
            Envelope::decode(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .code,
            Code::ECorrupt
        );
    }

    #[test]
    fn seal_open_and_a_foreign_key_is_enokey() {
        let (pk, sk) = generate_device_key();
        assert_eq!(device_public_key(&sk), pk);
        let sealed = seal(&pk, &env());
        assert_eq!(sealed.len(), env().encode().len() + SEAL_BYTES);
        assert_eq!(open(&sk, &sealed).unwrap(), env());
        let (_, other) = generate_device_key();
        let err = open(&other, &sealed).unwrap_err();
        assert_eq!(
            (err.code, err.message.as_str()),
            (Code::ENoKey, "Could not open local key envelope")
        );
    }
}

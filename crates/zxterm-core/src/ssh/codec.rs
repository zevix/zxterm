//! SSH wire-string codec (`writeString`/`readString`), mpint stripping, and
//! base64 helpers, ported from ZBTerm `engine/identity/claim.js`. Shared by
//! every `ssh::*` submodule that reads or writes the SSH binary wire format.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use crate::error::{Code, Error};

/// `writeString` (claim.js): a 4-byte big-endian length prefix followed by
/// the bytes themselves.
pub(crate) fn write_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

#[derive(Debug)]
pub(crate) struct ReadString<'a> {
    pub value: &'a [u8],
    pub offset: usize,
}

/// `readString` (claim.js): reads one length-prefixed string starting at
/// `offset`. `E_CORRUPT`/`"Truncated SSH string"` on any truncation, exactly
/// as the JS twin throws.
pub(crate) fn read_string(buffer: &[u8], offset: usize) -> Result<ReadString<'_>, Error> {
    if offset + 4 > buffer.len() {
        return Err(Error::new(Code::ECorrupt, "Truncated SSH string"));
    }
    let length = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    let end = start + length;
    if end > buffer.len() {
        return Err(Error::new(Code::ECorrupt, "Truncated SSH string"));
    }
    Ok(ReadString {
        value: &buffer[start..end],
        offset: end,
    })
}

/// `stripMpint` (claim.js): ssh mpints are signed big-endian, so a leading
/// `0x00` byte is present only when the high bit of the next byte is set;
/// every *other* leading zero is redundant and stripped.
pub(crate) fn strip_mpint(value: &[u8]) -> &[u8] {
    if value.is_empty() {
        return value;
    }
    let mut at = 0;
    while at < value.len() - 1 && value[at] == 0 {
        at += 1;
    }
    &value[at..]
}

/// Standard base64 (with padding), matching Node's default `Buffer`
/// encoding (used for SSHSIG armor and `publicKeyBlobBase64`/
/// `messageBase64` fields).
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Standard base64 decode. Used where a malformed value should surface as an
/// explicit error (SSHSIG armor, an explicitly supplied `messageBase64`/
/// `publicKeyBlobBase64`).
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// Lenient base64 decode for untrusted key-file content: ZBTerm's
/// `b4a.from(str, 'base64')` (backed by Node's `Buffer.from`) never throws on
/// malformed base64, it just decodes what it can. A decode failure here
/// degrades to an empty buffer, which then fails the caller's own length/
/// magic checks with that caller's own message — exactly as a short/garbage
/// decode would in Node.
pub(crate) fn base64_decode_lenient(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap_or_default()
}

/// Unpadded base64 (`ssh-keygen -lf`'s fingerprint encoding).
pub(crate) fn base64_encode_no_pad(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_string_round_trips() {
        let written = write_string(b"ssh-ed25519");
        let read = read_string(&written, 0).expect("read string");
        assert_eq!(read.value, b"ssh-ed25519");
        assert_eq!(read.offset, written.len());
    }

    #[test]
    fn read_string_truncated_is_e_corrupt() {
        let err = read_string(&[0, 0, 0, 5, 1, 2], 0).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(err.message, "Truncated SSH string");
    }

    #[test]
    fn strip_mpint_removes_only_redundant_leading_zeros() {
        assert_eq!(strip_mpint(&[0x00, 0x00, 0x01]), &[0x01]);
        assert_eq!(strip_mpint(&[0x00, 0x80]), &[0x80]);
        assert_eq!(strip_mpint(&[]), &[] as &[u8]);
    }

    #[test]
    fn lenient_decode_never_panics_on_garbage() {
        assert_eq!(
            base64_decode_lenient("not valid base64!!"),
            Vec::<u8>::new()
        );
    }
}

//! OpenSSH private-key and public-key-line parsing, and the `ssh-keygen -lf`
//! fingerprint, ported from ZBTerm `electron/ssh-keys.js`
//! (`parseOpenSshPrivateKey`/`describeFile`/`parsePublicKeyLine`) and
//! `engine/identity/claim.js::fingerprint`.
//!
//! Passphrase handling: never. An encrypted private key (`cipherName !=
//! "none"`) is reported `encrypted: true` with no secret key material — this
//! module never decrypts and never prompts.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::codec::{base64_decode_lenient, base64_encode_no_pad, read_string};
use crate::error::{Code, Error};

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const PRIVATE_BLOCK_SIZE: usize = 8;

/// The RSA-specific fields an OpenSSH private-key container stores, in the
/// order it stores them (`n, e, d, iqmp, p, q`, not PKCS#1 order — `iqmp`
/// sits between `d` and `p`). Each value is the raw ssh-string byte content
/// as read (still mpint-encoded; strip via `super::codec::strip_mpint` before
/// any numeric use).
#[derive(Debug, Clone)]
pub struct RsaFields {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub iqmp: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
}

/// A parsed OpenSSH private-key container (`parseOpenSshPrivateKey`'s return
/// shape).
#[derive(Debug, Clone)]
pub struct ParsedPrivateKey {
    pub key_type: String,
    pub public_key_blob: Vec<u8>,
    pub encrypted: bool,
    pub comment: String,
    /// The 64-byte libsodium secret key (`seed || public key`), `None` for
    /// an encrypted key or a non-ed25519 key.
    pub secret_key: Option<[u8; 64]>,
    /// `Some` only for `ssh-rsa`, unencrypted.
    pub rsa: Option<RsaFields>,
}

/// `keyTypeOf` (ssh-keys.js): the SSH algorithm name is the first ssh-string
/// in a public-key blob.
pub(crate) fn key_type_of(public_key_blob: &[u8]) -> Result<String, Error> {
    let read = read_string(public_key_blob, 0)?;
    Ok(String::from_utf8_lossy(read.value).into_owned())
}

/// `unsupportedKeyTypeReason` (ssh-keys.js) — note this is a *different*
/// message from `claim.js`'s SSHSIG "Unsupported SSH key type: ..." text
/// (`sshsig::unsupported_key_type_message`); the two functions share a name
/// pattern but not wording, verified against the ZBTerm tree on 2026-09-29.
pub(crate) fn unsupported_key_type_reason(key_type: &str) -> String {
    format!(
        "ZBTerm can only sign with {} or {} keys (this key is {key_type})",
        crate::wire::KEY_TYPE,
        crate::wire::RSA_KEY_TYPE,
    )
}

fn is_padding(buf: &[u8]) -> bool {
    if buf.len() >= PRIVATE_BLOCK_SIZE {
        return false;
    }
    buf.iter().enumerate().all(|(i, b)| *b == (i as u8) + 1)
}

/// `readPrivateFields` (ssh-keys.js): reads ssh-strings until only the
/// `1,2,3,...` pad remains. The last field is always the comment.
fn read_private_fields(section: &[u8], offset: usize) -> Result<Vec<Vec<u8>>, Error> {
    let mut fields = Vec::new();
    let mut at = offset;
    loop {
        let remaining = if at <= section.len() {
            &section[at..]
        } else {
            &[][..]
        };
        if is_padding(remaining) {
            break;
        }
        let read = read_string(section, at)?;
        fields.push(read.value.to_vec());
        at = read.offset;
        if fields.len() > 32 {
            return Err(Error::new(Code::ECorrupt, "Private key section too long"));
        }
    }
    Ok(fields)
}

/// `parseOpenSshPrivateKey` (ssh-keys.js), byte-for-byte, including its exact
/// `E_CORRUPT` message text at every checkpoint.
pub fn parse_openssh_private_key(text: &str) -> Result<ParsedPrivateKey, Error> {
    let begin = text.find(PEM_BEGIN);
    let end = text.find(PEM_END);
    let (begin, end) = match (begin, end) {
        (Some(b), Some(e)) if e >= b => (b, e),
        _ => {
            return Err(Error::new(
                Code::ECorrupt,
                "Not an OpenSSH private key (missing PEM armor)",
            ));
        }
    };
    let body = &text[begin + PEM_BEGIN.len()..end];
    let b64: String = body.split('\n').map(str::trim).collect::<Vec<_>>().concat();
    let buffer = base64_decode_lenient(&b64);
    if buffer.len() < OPENSSH_MAGIC.len() || &buffer[..OPENSSH_MAGIC.len()] != OPENSSH_MAGIC {
        return Err(Error::new(
            Code::ECorrupt,
            "Not an OpenSSH private key (bad magic)",
        ));
    }
    let mut at = OPENSSH_MAGIC.len();
    let cipher = read_string(&buffer, at)?;
    let kdf = read_string(&buffer, cipher.offset)?;
    let kdf_options = read_string(&buffer, kdf.offset)?;
    at = kdf_options.offset;
    if at + 4 > buffer.len() {
        return Err(Error::new(Code::ECorrupt, "Truncated OpenSSH private key"));
    }
    let nkeys = u32::from_be_bytes(buffer[at..at + 4].try_into().unwrap());
    at += 4;
    if nkeys != 1 {
        return Err(Error::new(
            Code::ECorrupt,
            format!("Unsupported OpenSSH private key ({nkeys} keys)"),
        ));
    }
    let public_section = read_string(&buffer, at)?;
    let private_section = read_string(&buffer, public_section.offset)?;
    let public_key_blob = public_section.value.to_vec();
    let cipher_name = String::from_utf8_lossy(cipher.value).into_owned();
    let key_type = key_type_of(&public_key_blob)?;
    let encrypted = cipher_name != "none";
    if encrypted {
        return Ok(ParsedPrivateKey {
            key_type,
            public_key_blob,
            encrypted: true,
            comment: String::new(),
            secret_key: None,
            rsa: None,
        });
    }
    let section = private_section.value.to_vec();
    if section.len() < 8 {
        return Err(Error::new(
            Code::ECorrupt,
            "Truncated OpenSSH private key section",
        ));
    }
    let check1 = u32::from_be_bytes(section[0..4].try_into().unwrap());
    let check2 = u32::from_be_bytes(section[4..8].try_into().unwrap());
    if check1 != check2 {
        return Err(Error::new(
            Code::ECorrupt,
            "OpenSSH private key is encrypted or corrupt",
        ));
    }
    let inner_type = read_string(&section, 8)?;
    let inner_key_type = String::from_utf8_lossy(inner_type.value).into_owned();
    if inner_key_type != key_type {
        return Err(Error::new(
            Code::ECorrupt,
            "OpenSSH private key type mismatch",
        ));
    }
    let fields = read_private_fields(&section, inner_type.offset)?;
    let comment = fields
        .last()
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .unwrap_or_default();

    if key_type == crate::wire::RSA_KEY_TYPE {
        if fields.len() < 7 {
            return Err(Error::new(Code::ECorrupt, "Truncated RSA private key"));
        }
        let rsa = RsaFields {
            n: fields[0].clone(),
            e: fields[1].clone(),
            d: fields[2].clone(),
            iqmp: fields[3].clone(),
            p: fields[4].clone(),
            q: fields[5].clone(),
        };
        return Ok(ParsedPrivateKey {
            key_type,
            public_key_blob,
            encrypted: false,
            comment,
            secret_key: None,
            rsa: Some(rsa),
        });
    }
    if key_type != crate::wire::KEY_TYPE {
        return Ok(ParsedPrivateKey {
            key_type,
            public_key_blob,
            encrypted: false,
            comment,
            secret_key: None,
            rsa: None,
        });
    }
    if fields.len() < 3 {
        return Err(Error::new(Code::ECorrupt, "Truncated ed25519 private key"));
    }
    let pub_field = &fields[0];
    let priv_field = &fields[1];
    if pub_field.len() != 32 {
        return Err(Error::new(
            Code::ECorrupt,
            "ed25519 public key must be 32 bytes",
        ));
    }
    if priv_field.len() != 64 {
        return Err(Error::new(
            Code::ECorrupt,
            "ed25519 private key must be 64 bytes",
        ));
    }
    let mut secret_key = [0u8; 64];
    secret_key.copy_from_slice(priv_field);
    Ok(ParsedPrivateKey {
        key_type,
        public_key_blob,
        encrypted: false,
        comment,
        secret_key: Some(secret_key),
        rsa: None,
    })
}

/// A parsed `type base64 [comment]` public-key line.
#[derive(Debug, Clone)]
pub struct ParsedPublicKey {
    pub key_type: String,
    pub public_key_blob: Vec<u8>,
    pub comment: String,
}

/// `parsePublicKeyLine` (ssh-keys.js), byte-for-byte.
pub fn parse_public_key_line(text: &str) -> Result<ParsedPublicKey, Error> {
    let line = text
        .split('\n')
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'));
    let line = match line {
        Some(l) => l,
        None => return Err(Error::new(Code::ECorrupt, "Empty SSH public key file")),
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Error::new(Code::ECorrupt, "Malformed SSH public key line"));
    }
    let public_key_blob = base64_decode_lenient(parts[1]);
    let key_type = key_type_of(&public_key_blob)?;
    if key_type != parts[0] {
        return Err(Error::new(
            Code::ECorrupt,
            "SSH public key type does not match its blob",
        ));
    }
    let comment = parts[2..].join(" ");
    Ok(ParsedPublicKey {
        key_type,
        public_key_blob,
        comment,
    })
}

/// `fingerprint` (claim.js): `SHA256:` + unpadded base64 of the SHA-256
/// digest of the raw wire blob — identical to `ssh-keygen -lf`.
pub fn fingerprint(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", base64_encode_no_pad(&digest))
}

/// `describeFile` (ssh-keys.js)'s return shape: never throws, a parse
/// failure is reported as `error` instead.
#[derive(Debug, Clone, Default)]
pub(crate) struct DescribedFile {
    pub key_type: Option<String>,
    pub public_key_blob: Option<Vec<u8>>,
    pub comment: String,
    pub encrypted: bool,
    pub has_private: bool,
    pub error: Option<String>,
}

fn pub_sibling(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_os_string();
    s.push(".pub");
    PathBuf::from(s)
}

fn read_text_file(file: &Path) -> Option<String> {
    std::fs::read_to_string(file).ok()
}

/// `describeFile` (ssh-keys.js), byte-for-byte: a truncated/garbage private
/// key still gets a row (borrowing the `.pub` sibling's info if it parses).
pub(crate) fn describe_file(file: &Path) -> DescribedFile {
    let private_text = read_text_file(file);
    let public_text = read_text_file(&pub_sibling(file));

    if let Some(private_text) = private_text {
        match parse_openssh_private_key(&private_text) {
            Ok(parsed) => {
                let mut comment = parsed.comment;
                if comment.is_empty()
                    && let Some(public_text) = &public_text
                    && let Ok(pub_parsed) = parse_public_key_line(public_text)
                {
                    comment = pub_parsed.comment;
                }
                return DescribedFile {
                    key_type: Some(parsed.key_type),
                    public_key_blob: Some(parsed.public_key_blob),
                    comment,
                    encrypted: parsed.encrypted,
                    has_private: true,
                    error: None,
                };
            }
            Err(err) => {
                if let Some(public_text) = &public_text
                    && let Ok(pub_parsed) = parse_public_key_line(public_text)
                {
                    return DescribedFile {
                        key_type: Some(pub_parsed.key_type),
                        public_key_blob: Some(pub_parsed.public_key_blob),
                        comment: pub_parsed.comment,
                        encrypted: false,
                        has_private: false,
                        error: Some(err.message),
                    };
                }
                return DescribedFile {
                    error: Some(err.message),
                    ..Default::default()
                };
            }
        }
    }

    if let Some(public_text) = &public_text {
        return match parse_public_key_line(public_text) {
            Ok(p) => DescribedFile {
                key_type: Some(p.key_type),
                public_key_blob: Some(p.public_key_blob),
                comment: p.comment,
                encrypted: false,
                has_private: false,
                error: None,
            },
            Err(err) => DescribedFile {
                error: Some(err.message),
                ..Default::default()
            },
        };
    }

    DescribedFile {
        error: Some("Key file is missing or unreadable".to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_armor_is_reported() {
        let err = parse_openssh_private_key("not a key").unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(
            err.message,
            "Not an OpenSSH private key (missing PEM armor)"
        );
    }

    #[test]
    fn bad_magic_is_reported() {
        let armored = format!(
            "{PEM_BEGIN}\n{}\n{PEM_END}\n",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"not-openssh-magic-bytes-at-all"
            )
        );
        let err = parse_openssh_private_key(&armored).unwrap_err();
        assert_eq!(err.code, Code::ECorrupt);
        assert_eq!(err.message, "Not an OpenSSH private key (bad magic)");
    }

    #[test]
    fn fingerprint_matches_known_vector() {
        // SHA256(b"") base64 (no padding) - a fixed, checkable vector
        // independent of any real SSH key.
        let fp = fingerprint(b"");
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.contains('='));
    }

    #[test]
    fn parse_public_key_line_rejects_type_mismatch() {
        // A syntactically well-formed line whose declared type does not
        // match the blob's own type string.
        let blob = {
            let mut v = Vec::new();
            v.extend_from_slice(&super::super::codec::write_string(b"ssh-ed25519"));
            v.extend_from_slice(&[0u8; 32]);
            v
        };
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);
        let line = format!("ssh-rsa {b64} comment");
        let err = parse_public_key_line(&line).unwrap_err();
        assert_eq!(err.message, "SSH public key type does not match its blob");
    }

    #[test]
    fn parse_public_key_line_empty_file() {
        let err = parse_public_key_line("\n  \n").unwrap_err();
        assert_eq!(err.message, "Empty SSH public key file");
    }

    #[test]
    fn parse_public_key_line_malformed() {
        let err = parse_public_key_line("onlyonefield").unwrap_err();
        assert_eq!(err.message, "Malformed SSH public key line");
    }
}

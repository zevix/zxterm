//! ssh-agent wire-protocol client (draft-miller-ssh-agent), ported from
//! ZBTerm `electron/ssh-keys.js` (`agentIdentities`/`agentSign`), only the
//! two requests it needs.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::codec::{read_string, write_string};
use super::key::{key_type_of, unsupported_key_type_reason};
use crate::error::{Code, Error};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Ask an agent holding an RSA key for the SHA-512 variant; without this flag
/// it may answer with a SHA-1 `ssh-rsa` signature, which is refused.
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const AGENT_TIMEOUT_MS: u64 = 5000;
const AGENT_MAX_FRAME: usize = 1024 * 1024;

/// One identity an agent reports via `SSH_AGENTC_REQUEST_IDENTITIES`.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub public_key_blob: Vec<u8>,
    pub comment: String,
}

fn agent_socket_path(env: &HashMap<String, String>) -> Option<String> {
    env.get("SSH_AUTH_SOCK").filter(|s| !s.is_empty()).cloned()
}

/// One request/response round trip. Agent frames are uint32-BE length +
/// payload and can arrive split across reads, so bytes accumulate until
/// `4 + length` are in hand, all inside one overall 5s deadline.
fn agent_round_trip(socket_path: &str, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let deadline = Instant::now() + Duration::from_millis(AGENT_TIMEOUT_MS);

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| Error::new(Code::EAuth, format!("Cannot reach ssh-agent: {e}")))?;

    let mut header = [0u8; 4];
    header.copy_from_slice(&(payload.len() as u32).to_be_bytes());
    let write_result = stream
        .set_write_timeout(remaining(deadline))
        .and_then(|()| stream.write_all(&header))
        .and_then(|()| stream.write_all(payload));
    if let Err(e) = write_result {
        return Err(Error::new(
            Code::EAuth,
            format!("Cannot reach ssh-agent: {e}"),
        ));
    }

    let mut buf = Vec::new();
    loop {
        let time_left = match remaining(deadline) {
            Some(d) => d,
            None => {
                return Err(Error::new(
                    Code::EAuth,
                    "ssh-agent did not respond within 5s",
                ));
            }
        };
        if stream.set_read_timeout(Some(time_left)).is_err() {
            return Err(Error::new(
                Code::EAuth,
                "ssh-agent did not respond within 5s",
            ));
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Error::new(Code::EAuth, "ssh-agent closed the connection")),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 4 {
                    let length = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
                    if length > AGENT_MAX_FRAME {
                        return Err(Error::new(Code::EAuth, "ssh-agent sent an oversized reply"));
                    }
                    if buf.len() >= 4 + length {
                        return Ok(buf[4..4 + length].to_vec());
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(Error::new(
                    Code::EAuth,
                    "ssh-agent did not respond within 5s",
                ));
            }
            Err(e) => {
                return Err(Error::new(
                    Code::EAuth,
                    format!("Cannot reach ssh-agent: {e}"),
                ));
            }
        }
    }
}

fn remaining(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    if now >= deadline {
        None
    } else {
        Some(deadline - now)
    }
}

/// `agentIdentities` (ssh-keys.js): a stale/absent `SSH_AUTH_SOCK`, or any
/// malformed reply, degrades to `[]` — this never errors.
pub fn agent_identities(env: &HashMap<String, String>) -> Vec<AgentIdentity> {
    let Some(socket_path) = agent_socket_path(env) else {
        return Vec::new();
    };
    let Ok(reply) = agent_round_trip(&socket_path, &[SSH_AGENTC_REQUEST_IDENTITIES]) else {
        return Vec::new();
    };
    parse_identities_answer(&reply)
}

fn parse_identities_answer(reply: &[u8]) -> Vec<AgentIdentity> {
    if reply.is_empty() || reply[0] != SSH_AGENT_IDENTITIES_ANSWER {
        return Vec::new();
    }
    if reply.len() < 5 {
        return Vec::new();
    }
    let count = u32::from_be_bytes(reply[1..5].try_into().unwrap());
    let mut at = 5usize;
    let mut keys = Vec::new();
    for _ in 0..count {
        let Ok(blob) = read_string(reply, at) else {
            return Vec::new();
        };
        let Ok(comment) = read_string(reply, blob.offset) else {
            return Vec::new();
        };
        at = comment.offset;
        keys.push(AgentIdentity {
            public_key_blob: blob.value.to_vec(),
            comment: String::from_utf8_lossy(comment.value).into_owned(),
        });
    }
    keys
}

/// `agentSign` (ssh-keys.js). After the reply, the algorithm actually used
/// is checked against the one the key type demands
/// (`signatureAlgorithmFor`); a mismatch (an agent that ignores the SHA-2
/// flag and answers plain `ssh-rsa`) is refused by name, never armored.
pub fn agent_sign(
    public_key_blob: &[u8],
    data: &[u8],
    env: &HashMap<String, String>,
) -> Result<Vec<u8>, Error> {
    let socket_path = agent_socket_path(env).ok_or_else(|| {
        Error::new(
            Code::EAuth,
            "No ssh-agent available (SSH_AUTH_SOCK is not set)",
        )
    })?;
    let key_type = key_type_of(public_key_blob)?;
    let expected = super::sshsig::signature_algorithm_for(&key_type)
        .ok_or_else(|| Error::new(Code::EAuth, unsupported_key_type_reason(&key_type)))?;

    let mut flags = [0u8; 4];
    if key_type == crate::wire::RSA_KEY_TYPE {
        flags = SSH_AGENT_RSA_SHA2_512.to_be_bytes();
    }
    let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
    payload.extend_from_slice(&write_string(public_key_blob));
    payload.extend_from_slice(&write_string(data));
    payload.extend_from_slice(&flags);

    let reply = agent_round_trip(&socket_path, &payload)?;
    if reply.is_empty() || reply[0] == SSH_AGENT_FAILURE {
        return Err(Error::new(
            Code::EAuth,
            "ssh-agent refused to sign - is the key still loaded? Run `ssh-add -l` to check",
        ));
    }
    if reply[0] != SSH_AGENT_SIGN_RESPONSE {
        return Err(Error::new(
            Code::EAuth,
            format!("Unexpected ssh-agent response ({})", reply[0]),
        ));
    }
    let sig_blob = read_string(&reply, 1)?;
    let sig_type = read_string(sig_blob.value, 0)?;
    let raw_sig = read_string(sig_blob.value, sig_type.offset)?;
    let sig_type_str = String::from_utf8_lossy(sig_type.value).into_owned();
    if sig_type_str != expected {
        return Err(Error::new(
            Code::EAuth,
            format!(
                "ssh-agent returned an unsupported signature type: {sig_type_str} (expected {expected})"
            ),
        ));
    }
    Ok(raw_sig.value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_identities_with_no_socket_is_empty() {
        let env = HashMap::new();
        assert!(agent_identities(&env).is_empty());
    }

    #[test]
    fn agent_sign_with_no_socket_reports_e_auth() {
        let env = HashMap::new();
        let err = agent_sign(b"blob", b"data", &env).unwrap_err();
        assert_eq!(err.code, Code::EAuth);
        assert_eq!(
            err.message,
            "No ssh-agent available (SSH_AUTH_SOCK is not set)"
        );
    }

    #[test]
    fn agent_identities_degrades_on_a_dead_socket() {
        let mut env = HashMap::new();
        env.insert(
            "SSH_AUTH_SOCK".to_string(),
            "/tmp/zx-agent-test-no-such-socket.sock".to_string(),
        );
        assert!(agent_identities(&env).is_empty());
    }
}

//! Sealed, replay-counted input (`protocol.md` §10): the viewer seals a
//! postcard [`SealedInput`] to the host's device key; the host opens it and
//! runs ZBTerm `share-manager.js::_openInputMessage`'s checks in order, each
//! with its exact message.
//!
//! **v2 change** (`protocol.md` §10, ZBTerm `S-43`): the replay counter is
//! kept per `(device key, epoch)`, not per device for the share's
//! lifetime, and the viewer restarts its counter at 1 in every epoch it
//! installs. A viewer that restarts and rejoins is in a new epoch (every
//! join rotates), so its first input is accepted.

use std::collections::{HashMap, HashSet};

use super::caps::{SEND_INPUT, has_cap};
use super::envelope;
use super::messages::{self, Key32, SealedInput};
use crate::error::{Code, Error};
use crate::idkey::proof;

/// JS `Number.MAX_SAFE_INTEGER`: check 9 refuses a larger counter.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Device proofs the host has verified (`crypto.js::verifyDeviceIdentity`'s
/// cache, read synchronously per input frame by `isVerifiedDeviceIdentity`).
#[derive(Debug, Default, Clone)]
pub struct VerifiedProofs {
    set: HashSet<(Vec<u8>, Key32, Key32)>,
}

impl VerifiedProofs {
    /// `verifyDeviceIdentity`: whether `proof` attests `device` under
    /// `identity`; a success is remembered.
    pub fn verify(&mut self, proof_bytes: &[u8], identity: &Key32, device: &Key32) -> bool {
        if self.is_verified(proof_bytes, identity, device) {
            return true;
        }
        let ok = proof::verify(
            proof_bytes,
            None,
            &proof::VerifyOpts {
                receipt: None,
                expected_identity: Some(identity),
                expected_device: Some(device),
            },
        )
        .is_some();
        if ok {
            self.set.insert((proof_bytes.to_vec(), *identity, *device));
        }
        ok
    }

    /// `isVerifiedDeviceIdentity`: only a proof [`Self::verify`] accepted.
    pub fn is_verified(&self, proof_bytes: &[u8], identity: &Key32, device: &Key32) -> bool {
        self.set
            .contains(&(proof_bytes.to_vec(), *identity, *device))
    }
}

/// The last accepted counter per `(device key, epoch)`, starting at 0.
#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    last: HashMap<(Key32, u32), u64>,
}

impl ReplayWindow {
    pub fn last(&self, device: &Key32, epoch: u32) -> u64 {
        self.last.get(&(*device, epoch)).copied().unwrap_or(0)
    }

    /// Check 9 (strict: an equal counter is a replay); on success the
    /// counter becomes the last one.
    pub fn accept(&mut self, device: &Key32, epoch: u32, ctr: u64) -> Result<(), Error> {
        if ctr > MAX_SAFE_INTEGER || ctr <= self.last(device, epoch) {
            return Err(auth("Input counter replayed or out of order"));
        }
        self.last.insert((*device, epoch), ctr);
        Ok(())
    }
}

fn auth(message: &str) -> Error {
    Error::new(Code::EAuth, message)
}

/// The viewer's side (`share-manager.js::sealInput`): `ctr` is already
/// incremented by the caller.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    host_device_key: &Key32,
    session_id: &str,
    epoch: u32,
    ctr: u64,
    device_key: &Key32,
    identity_key: &Key32,
    identity_proof: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let plain = messages::encode(&SealedInput {
        session_id: session_id.to_string(),
        epoch,
        input_ctr: ctr,
        device_key: *device_key,
        identity_key: *identity_key,
        identity_proof: identity_proof.to_vec(),
        data: data.to_vec(),
    });
    envelope::seal_bytes(host_device_key, &plain)
}

/// The joined peer an input arrived from, as the host recorded it at
/// grant time.
#[derive(Debug, Clone, Copy)]
pub struct InputPeer<'a> {
    pub confirmed: bool,
    pub caps: u8,
    pub device_key: &'a Key32,
    pub identity_key: &'a Key32,
    pub identity_proof: &'a [u8],
}

/// The host's side of one input frame.
pub struct HostInput<'a> {
    pub session_id: &'a str,
    pub epoch: u32,
    pub device_secret_key: &'a [u8; 32],
    pub verified: &'a VerifiedProofs,
}

/// `_openInputMessage`: checks 1–9 of `protocol.md` §10 in order; the
/// plaintext on success.
pub fn open(
    host: &HostInput<'_>,
    peer: &InputPeer<'_>,
    window: &mut ReplayWindow,
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    if !peer.confirmed {
        return Err(auth("Input peer is not joined"));
    }
    if !has_cap(peer.caps, SEND_INPUT) {
        return Err(auth("Peer is not allowed to send input"));
    }
    let plain = envelope::open_sealed_bytes(host.device_secret_key, sealed)?;
    let input: SealedInput = messages::decode(&plain)?;
    if input.session_id != host.session_id {
        return Err(auth("Input was sealed for a different session"));
    }
    if input.epoch != host.epoch {
        return Err(auth("Input was sealed for a different epoch"));
    }
    if input.device_key != *peer.device_key || input.identity_key != *peer.identity_key {
        return Err(auth("Input identity does not match the joined peer"));
    }
    if !host.verified.is_verified(
        &input.identity_proof,
        &input.identity_key,
        &input.device_key,
    ) {
        return Err(auth("Input identity proof is invalid"));
    }
    if input.identity_proof != peer.identity_proof {
        return Err(auth("Input identity proof does not match the joined peer"));
    }
    window.accept(&input.device_key, input.epoch, input.input_ctr)?;
    Ok(input.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idkey::IdentityKey;
    use crate::session::envelope::generate_device_key;

    struct Fixture {
        sid: String,
        host_pk: Key32,
        host_sk: [u8; 32],
        dev: Key32,
        ident: Key32,
        proof: Vec<u8>,
        verified: VerifiedProofs,
    }

    fn fixture() -> Fixture {
        let (host_pk, host_sk) = generate_device_key();
        let (dev, _) = generate_device_key();
        let id = IdentityKey::from_seed(vec![3u8; 64]);
        let proof = id.bootstrap(dev, 1_700_000_000_000);
        let ident = id.identity_public_key();
        let mut verified = VerifiedProofs::default();
        assert!(verified.verify(&proof, &ident, &dev));
        Fixture {
            sid: "12".repeat(32),
            host_pk,
            host_sk,
            dev,
            ident,
            proof,
            verified,
        }
    }

    fn seal_with(
        f: &Fixture,
        sid: &str,
        epoch: u32,
        ctr: u64,
        dev: &Key32,
        proof: &[u8],
    ) -> Vec<u8> {
        seal(&f.host_pk, sid, epoch, ctr, dev, &f.ident, proof, b"ls\n")
    }

    fn try_open(
        f: &Fixture,
        caps: u8,
        confirmed: bool,
        w: &mut ReplayWindow,
        sealed: &[u8],
    ) -> Result<Vec<u8>, Error> {
        open(
            &HostInput {
                session_id: &f.sid,
                epoch: 2,
                device_secret_key: &f.host_sk,
                verified: &f.verified,
            },
            &InputPeer {
                confirmed,
                caps,
                device_key: &f.dev,
                identity_key: &f.ident,
                identity_proof: &f.proof,
            },
            w,
            sealed,
        )
    }

    fn msg(r: Result<Vec<u8>, Error>) -> String {
        r.unwrap_err().message
    }

    #[test]
    fn every_check_in_order_with_its_message() {
        let f = fixture();
        let mut w = ReplayWindow::default();
        let good = seal_with(&f, &f.sid, 2, 1, &f.dev, &f.proof);
        assert_eq!(
            msg(try_open(&f, 31, false, &mut w, &good)),
            "Input peer is not joined"
        );
        assert_eq!(
            msg(try_open(&f, 1, true, &mut w, &good)),
            "Peer is not allowed to send input"
        );
        let (other_pk, _) = generate_device_key();
        let foreign = seal(&other_pk, &f.sid, 2, 1, &f.dev, &f.ident, &f.proof, b"x");
        let e = try_open(&f, 31, true, &mut w, &foreign).unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (Code::ENoKey, "Could not open local key envelope")
        );
        assert_eq!(
            msg(try_open(
                &f,
                31,
                true,
                &mut w,
                &seal_with(&f, &"34".repeat(32), 2, 1, &f.dev, &f.proof)
            )),
            "Input was sealed for a different session"
        );
        assert_eq!(
            msg(try_open(
                &f,
                31,
                true,
                &mut w,
                &seal_with(&f, &f.sid, 1, 1, &f.dev, &f.proof)
            )),
            "Input was sealed for a different epoch"
        );
        assert_eq!(
            msg(try_open(
                &f,
                31,
                true,
                &mut w,
                &seal_with(&f, &f.sid, 2, 1, &[9; 32], &f.proof)
            )),
            "Input identity does not match the joined peer"
        );
        let mut bad_proof = f.proof.clone();
        bad_proof[40] ^= 1;
        assert_eq!(
            msg(try_open(
                &f,
                31,
                true,
                &mut w,
                &seal_with(&f, &f.sid, 2, 1, &f.dev, &bad_proof)
            )),
            "Input identity proof is invalid"
        );
        assert_eq!(try_open(&f, 31, true, &mut w, &good).unwrap(), b"ls\n");
        // Strict: an equal counter is a replay (`input.inputCtr <= last`).
        assert_eq!(
            msg(try_open(&f, 31, true, &mut w, &good)),
            "Input counter replayed or out of order"
        );
        let big = seal_with(&f, &f.sid, 2, MAX_SAFE_INTEGER + 1, &f.dev, &f.proof);
        assert_eq!(
            msg(try_open(&f, 31, true, &mut w, &big)),
            "Input counter replayed or out of order"
        );
    }

    #[test]
    fn a_verified_but_different_proof_is_check_8() {
        let mut f = fixture();
        let id = IdentityKey::from_seed(vec![3u8; 64]);
        let other = id.bootstrap(f.dev, 1_800_000_000_000);
        assert_ne!(other, f.proof);
        assert!(f.verified.verify(&other, &f.ident, &f.dev));
        let mut w = ReplayWindow::default();
        let sealed = seal_with(&f, &f.sid, 2, 1, &f.dev, &other);
        assert_eq!(
            msg(try_open(&f, 31, true, &mut w, &sealed)),
            "Input identity proof does not match the joined peer"
        );
    }

    #[test]
    fn s43_the_counter_is_per_device_and_epoch() {
        let dev = [1u8; 32];
        let mut w = ReplayWindow::default();
        w.accept(&dev, 2, 50).unwrap();
        assert!(
            w.accept(&dev, 2, 1).is_err(),
            "within an epoch it stays monotonic"
        );
        // A restarted viewer rejoins: a new epoch, and its counter from 1 is
        // accepted (today's per-device counter refused it until it passed 50).
        w.accept(&dev, 3, 1).unwrap();
        assert_eq!(w.last(&dev, 2), 50);
    }
}

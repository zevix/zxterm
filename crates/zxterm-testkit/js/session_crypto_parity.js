// K13: ZBTerm's own engine/crypto.js (the live tree: its kdf contexts are
// the zxt-* ones since K11, ZBTerm D-36) on sodium-native, as the reference
// for zxterm_core::session's key derivation, packet AEAD, key envelope and
// sealed box (protocol.md §3).
//
//   node session_crypto_parity.js '<json input>'
//
// Input: { masterKeyHex, localSecretHex, sessionId, epoch, seq, deviceKeyHex,
//          plainHex, rustCipherHex, rustRecipientPkHex, rustSealedEnvelopeHex?,
//          jsSeedHex, envelope: {version, sessionId, epoch, caps, masterKeyHex?,
//                     historyKeyHex?, liveKeyHex?} }
// Output (stdout, JSON): the JS side's derived keys, nonce, ciphertext and
// envelope bytes; what it made of the Rust ciphertext and the Rust-sealed
// envelope; an envelope it sealed to the Rust recipient key; and a fresh
// crypto_box key pair's box sealed to itself, for the Rust side to open.
'use strict'
const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')
const c = require(root + '/node_modules/compact-encoding')
const sodium = require(root + '/node_modules/sodium-native')
const crypto = require(root + '/engine/crypto')

const input = JSON.parse(process.argv[2])
const hex = (b) => Buffer.from(b).toString('hex')
const buf = (h) => Buffer.from(h, 'hex')
const env = input.envelope
const jsEnvelope = {
  version: env.version,
  sessionId: env.sessionId,
  epoch: env.epoch,
  caps: env.caps,
  masterKey: env.masterKeyHex ? buf(env.masterKeyHex) : null,
  historyKey: env.historyKeyHex ? buf(env.historyKeyHex) : null,
  liveKey: env.liveKeyHex ? buf(env.liveKeyHex) : null
}
const master = buf(input.masterKeyHex)
const liveKey = crypto.deriveLiveKey(master)
const out = {
  historyKey: hex(crypto.deriveHistoryKey(master)),
  liveKey: hex(liveKey),
  snapshotKey: hex(crypto.deriveSnapshotKey(buf(input.localSecretHex))),
  nonce: hex(crypto.nonceFor(input.sessionId, input.seq)),
  cipher: hex(
    crypto.encryptPacket(liveKey, input.sessionId, input.epoch, input.seq, buf(input.deviceKeyHex), buf(input.plainHex))
  ),
  envelopeBytes: hex(c.encode(crypto.Envelope, jsEnvelope))
}
try {
  out.decryptedRust = hex(
    crypto.decryptPacket(liveKey, input.sessionId, input.epoch, input.seq, buf(input.deviceKeyHex), buf(input.rustCipherHex))
  )
} catch (err) {
  out.decryptedRust = null
  out.decryptError = err.message
}
// An envelope sealed to the Rust side's key, for Rust to open.
out.sealedForRust = hex(crypto.sealEnvelope(buf(input.rustRecipientPkHex), jsEnvelope))
// A JS key pair from a fixed seed: the first call reports it, and the
// second opens the envelope Rust sealed to it (rustSealedEnvelopeHex).
const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES)
const sk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES)
sodium.crypto_box_seed_keypair(pk, sk, buf(input.jsSeedHex))
out.jsPublicKey = hex(pk)
out.jsSecretKey = hex(sk)
if (input.rustSealedEnvelopeHex) {
  try {
    const opened = crypto.openEnvelope(pk, sk, buf(input.rustSealedEnvelopeHex))
    out.openedFromRust = {
      version: opened.version,
      sessionId: opened.sessionId,
      epoch: opened.epoch,
      caps: opened.caps,
      masterKeyHex: opened.masterKey ? hex(opened.masterKey) : null,
      historyKeyHex: opened.historyKey ? hex(opened.historyKey) : null,
      liveKeyHex: opened.liveKey ? hex(opened.liveKey) : null
    }
  } catch (err) {
    out.openedFromRust = null
    out.openError = err.message
  }
}
process.stdout.write(JSON.stringify(out))

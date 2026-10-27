// K5 parity helper: dispatches to ZBTerm's `engine/backends/freenet/{signal,
// route,contracts}.js` functions by name, so Rust test code (`js::run`) can
// cross-check byte layouts, signatures and route checks against the real
// ZBTerm source on the same input, in both directions.
//
// Usage: node freenet_fixtures.js <op> < input.json
// Reads one JSON object from stdin, writes one JSON object to stdout.
'use strict'
const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')

// Resolved inside the ZBTerm tree's own node_modules: this helper script
// lives in zxterm-testkit, which has no node_modules of its own.
const sodium = require(root + '/node_modules/sodium-native')

const signal = require(root + '/engine/backends/freenet/signal.js')
const route = require(root + '/engine/backends/freenet/route.js')

function hex(buf) {
  return Buffer.from(buf).toString('hex')
}
function fromHex(s) {
  return Buffer.from(s, 'hex')
}

function seedKeypair(seedHex) {
  const seed = fromHex(seedHex)
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return { pk, sk }
}

function readStdin() {
  const fs = require('fs')
  const text = fs.readFileSync(0, 'utf8')
  return text.trim() ? JSON.parse(text) : {}
}

function main() {
  const op = process.argv[2]
  const input = readStdin()
  let out

  switch (op) {
    case 'entry_bytes': {
      const params = fromHex(input.params)
      const e = { l: input.l, r: input.r, s: input.s, t: input.t, d: !!input.d, p: input.p }
      out = { bytes: hex(signal.entryBytes(params, e)) }
      break
    }
    case 'record_bytes': {
      const ownParams = fromHex(input.ownParams)
      const rec = { ver: input.ver, sig: input.sig, code: input.code, params: input.params }
      out = { bytes: hex(signal.recordBytes(ownParams, rec)) }
      break
    }
    case 'sign_entry': {
      const { sk, pk } = seedKeypair(input.seed)
      const params = fromHex(input.params)
      const entry = signal.signEntry(sk, params, {
        l: input.l,
        r: input.r,
        s: input.s,
        t: input.t,
        d: !!input.d,
        p: input.p
      })
      out = { publicKey: hex(pk), entry }
      break
    }
    case 'verify_entry': {
      const publicKey = fromHex(input.publicKey)
      const params = fromHex(input.params)
      out = { verified: signal.verifyEntry(publicKey, params, input.entry) }
      break
    }
    case 'sign_record': {
      const { sk, pk } = seedKeypair(input.seed)
      const ownParams = fromHex(input.ownParams)
      const record = signal.signRecord(sk, ownParams, {
        ver: input.ver,
        sig: input.sig,
        code: input.code,
        params: input.params
      })
      out = { publicKey: hex(pk), record }
      break
    }
    case 'verify_record': {
      const publicKey = fromHex(input.publicKey)
      const ownParams = fromHex(input.ownParams)
      out = { verified: signal.verifyRecord(publicKey, ownParams, input.record) }
      break
    }
    case 'seal': {
      const key = fromHex(input.key)
      out = { sealed: signal.seal(key, input.message) }
      break
    }
    case 'open': {
      const key = fromHex(input.key)
      out = { message: signal.open(key, input.sealed) }
      break
    }
    case 'payload_key': {
      out = { key: hex(signal.payloadKey(input.k)) }
      break
    }
    case 'offer_ref': {
      out = { ref: signal.offerRef(input.p) }
      break
    }
    case 'sdp_fingerprint': {
      out = { fingerprint: signal.sdpFingerprint(input.sdp) }
      break
    }
    case 'verify_route': {
      const contracts = require(root + '/engine/backends/freenet/contracts.js')
      const expectedPeerKey = fromHex(input.expectedPeerKeyHex)
      try {
        const checked = route.verify(input.route, expectedPeerKey, contracts)
        out = { ok: true, code: checked.code, params: hex(checked.params) }
      } catch (err) {
        out = {
          ok: false,
          code: err.code,
          message: err.message,
          detail: err.details && err.details.detail
        }
      }
      break
    }
    default:
      throw new Error('unknown op: ' + op)
  }

  process.stdout.write(JSON.stringify(out))
}

main()

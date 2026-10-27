'use strict'

// Cross-language parity harness for zxterm_core::idkey (K4). Talks to a
// *patched* scratch copy of the upstream identity-key package (path given as
// argv[2] — the Rust test owns copying/patching/diffing it) over stdio:
// `node idkey_parity.js <patchedPkgDir> <command> <jsonArgs>` prints
// `key=hexValue` lines (or a bare `NULL` line, or `error=<message>`) to
// stdout — no JSON output, so the Rust side needs no JSON dependency.
//
// This script itself never names the upstream package (`X-01`); it only
// requires whatever path it is given.

const path = require('path')

function hex(buf) {
  return Buffer.from(buf).toString('hex')
}

function fromHex(s) {
  return Buffer.from(s, 'hex')
}

function printLine(key, hexValue) {
  process.stdout.write(key + '=' + hexValue + '\n')
}

async function main() {
  const pkgDir = process.argv[2]
  const cmd = process.argv[3]
  const args = JSON.parse(process.argv[4] || '{}')

  const IdentityKey = require(path.join(pkgDir, 'index.js'))

  switch (cmd) {
    case 'derive': {
      const identity = await IdentityKey.from({ seed: fromHex(args.seedHex) })
      printLine('identityPublicKey', hex(identity.identityPublicKey))
      printLine('profileDiscoveryPublicKey', hex(identity.profileDiscoveryPublicKey))
      printLine('profileDiscoveryEncryptionKey', hex(identity.getProfileDiscoveryEncryptionKey()))
      return
    }

    case 'encryption-key': {
      const identity = await IdentityKey.from({ seed: fromHex(args.seedHex) })
      const key = identity.getEncryptionKey(fromHex(args.profileKeyHex))
      printLine('key', hex(key))
      return
    }

    case 'attest': {
      // Builds the proof object by hand (rather than calling the async
      // `bootstrap`, which stamps `Date.now()`) so the epoch matches
      // whatever the Rust side used, for a byte-equal comparison.
      const identity = await IdentityKey.from({ seed: fromHex(args.seedHex) })
      const device = fromHex(args.deviceHex)
      const proof = {
        version: 1,
        epoch: args.epochMs,
        identity: identity.identityKeyPair.publicKey,
        chain: []
      }
      const encoded = IdentityKey.attestDevice(device, identity.identityKeyPair, proof)
      printLine('proof', hex(encoded))
      return
    }

    case 'verify': {
      const proofBuf = fromHex(args.proofHex)
      const attestedData = args.attestedDataHex ? fromHex(args.attestedDataHex) : null
      const opts = {}
      if (args.expectedIdentityHex) opts.expectedIdentity = fromHex(args.expectedIdentityHex)
      if (args.expectedDeviceHex) opts.expectedDevice = fromHex(args.expectedDeviceHex)

      let result
      try {
        result = IdentityKey.verify(proofBuf, attestedData, opts)
      } catch (err) {
        process.stdout.write('error=' + String((err && err.message) || err) + '\n')
        return
      }

      if (!result) {
        process.stdout.write('NULL\n')
        return
      }

      printLine('receipt', hex(result.receipt))
      printLine('identityPublicKey', hex(result.identityPublicKey))
      printLine('devicePublicKey', hex(result.devicePublicKey))
      return
    }

    default:
      throw new Error('unknown command: ' + cmd)
  }
}

main().catch((err) => {
  process.stderr.write((err && err.stack) || String(err))
  process.stderr.write('\n')
  process.exit(1)
})

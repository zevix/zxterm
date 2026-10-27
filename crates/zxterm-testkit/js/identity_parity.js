'use strict'

// Cross-language parity harness for zxterm_core::identity (K3, spike S4 part
// 2). `node identity_parity.js <command> <jsonArgs>` prints exactly one JSON
// line to stdout: the command's own JSON result, or `{"error": message,
// "code": code}` on a thrown `EngineError` (or a plain `Error`, `code:
// null`). `ZX_ZBTERM` names the ZBTerm tree root (`zxterm_testkit::js`
// already sets it for every script this way).

const path = require('path')

// `b4a`/`sodium-native` are ZBTerm's own dependencies, not this testkit's —
// resolved explicitly under the ZBTerm tree's `node_modules` rather than a
// bare `require('b4a')` (which would resolve relative to *this* script's
// own directory and fail to find them). Plain `Buffer` stands in for `b4a`
// here (this script only ever runs under plain Node, never Bare).
function zbtermRoot() {
  return process.env.ZX_ZBTERM || '/zeev/github/zbterm'
}

function zbtermModule(name) {
  return require(path.join(zbtermRoot(), 'node_modules', name))
}

const sodium = zbtermModule('sodium-native')

function loadClaim() {
  return require(path.join(zbtermRoot(), 'engine', 'identity', 'claim.js'))
}

function loadVerify() {
  return require(path.join(zbtermRoot(), 'engine', 'identity', 'verify.js'))
}

function loadStore() {
  return require(path.join(zbtermRoot(), 'engine', 'identity', 'store.js'))
}

function loadGithubKeys() {
  return require(path.join(zbtermRoot(), 'electron', 'github-keys.js'))
}

function hex(buf) {
  return Buffer.from(buf).toString('hex')
}

function fromHex(s) {
  return Buffer.from(s, 'hex')
}

function base64(buf) {
  return Buffer.from(buf).toString('base64')
}

// A resolver-shaped stub whose `.resolve(provider, subject)` fetches
// `electron/github-keys.js::fetchKeys` directly against `baseUrl` — no
// cache, no seam: exactly enough for `verifyPeerIdentity`'s
// `provider.needsResolver` branch in this parity harness.
function directResolver(baseUrl) {
  const { fetchKeys } = loadGithubKeys()
  return {
    async resolve(provider, subject) {
      return fetchKeys(subject, { baseUrl })
    }
  }
}

async function main() {
  const cmd = process.argv[2]
  const args = JSON.parse(process.argv[3] || '{}')

  switch (cmd) {
    case 'claim-bytes': {
      const { claimBytes } = loadClaim()
      process.stdout.write(JSON.stringify({ bytesBase64: base64(claimBytes(args)) }) + '\n')
      return
    }

    case 'challenge-bytes': {
      const { challengeBytes } = loadClaim()
      process.stdout.write(JSON.stringify({ bytesBase64: base64(challengeBytes(args)) }) + '\n')
      return
    }

    case 'mint-claim': {
      // Generates a fresh ed25519 "SSH" keypair and a fresh ed25519 auth
      // keypair, builds and signs a claim over it exactly as
      // `test/identity-*.test.js`'s own helpers do, and hands back
      // everything the Rust side needs to either verify it directly or
      // re-derive a live-challenge signature with the same auth key.
      const { claimBytes, signedDataBlob, buildArmoredSignature, encodeEd25519PublicKey, fingerprint, NAMESPACE, HASH_ALG } =
        loadClaim()
      const sshPublic = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
      const sshSecret = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
      sodium.crypto_sign_keypair(sshPublic, sshSecret)
      const authPublic = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
      const authSecret = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
      sodium.crypto_sign_keypair(authPublic, authSecret)

      const pubkeyBlob = encodeEd25519PublicKey(sshPublic)
      const claim = {
        provider: args.provider || 'github',
        subject: args.subject || 'octocat',
        identityKey: args.identityKey || 'a'.repeat(64),
        authKey: hex(authPublic),
        sshFingerprint: fingerprint(pubkeyBlob),
        issuedAt: args.issuedAt || 1750000000000,
        nonce: args.nonce || 'c'.repeat(32)
      }
      const rawSig = Buffer.alloc(sodium.crypto_sign_BYTES)
      sodium.crypto_sign_detached(rawSig, signedDataBlob(NAMESPACE, HASH_ALG, claimBytes(claim)), sshSecret)
      claim.signature = buildArmoredSignature({ pubkeyBlob, rawSig })
      claim.sshPublicKey = base64(pubkeyBlob)

      process.stdout.write(
        JSON.stringify({
          claim,
          sshPublicKeyLine: `ssh-ed25519 ${base64(pubkeyBlob)}`,
          authPublicKeyHex: hex(authPublic),
          authSecretKeyHex: hex(authSecret)
        }) + '\n'
      )
      return
    }

    case 'verify-peer-identity': {
      const { verifyPeerIdentity } = loadVerify()
      const resolver = args.baseUrl ? directResolver(args.baseUrl) : null
      const outcome = await verifyPeerIdentity({
        claim: args.claim,
        identityKey: args.identityKey,
        authKey: args.authKey,
        challenge: args.challenge,
        signature: args.signatureHex ? fromHex(args.signatureHex) : undefined,
        resolver
      })
      process.stdout.write(JSON.stringify(outcome) + '\n')
      return
    }

    case 'write-self': {
      const { IdentityStore } = loadStore()
      const store = new IdentityStore(args.dir)
      await store.ready()
      const written = await store.setSelf(args.record)
      process.stdout.write(JSON.stringify(written) + '\n')
      return
    }

    case 'read-self': {
      const { IdentityStore } = loadStore()
      const store = new IdentityStore(args.dir)
      const record = await store.getSelf()
      process.stdout.write(JSON.stringify(record) + '\n')
      return
    }

    case 'write-peer': {
      const { IdentityStore } = loadStore()
      const store = new IdentityStore(args.dir)
      await store.ready()
      const written = await store.putPeer(args.idHex, args.patch || {})
      process.stdout.write(JSON.stringify(written) + '\n')
      return
    }

    case 'read-peer': {
      const { IdentityStore } = loadStore()
      const store = new IdentityStore(args.dir)
      const record = await store.getPeer(args.idHex)
      process.stdout.write(JSON.stringify(record) + '\n')
      return
    }

    default:
      throw new Error('unknown command: ' + cmd)
  }
}

main().catch((err) => {
  process.stdout.write(
    JSON.stringify({ error: (err && err.message) || String(err), code: (err && err.code) || null }) + '\n'
  )
  process.exit(0)
})

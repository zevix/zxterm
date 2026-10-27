'use strict'

// Cross-language parity harness for zxterm_core::ssh (K2, spike S4).
// `node ssh_keys_parity.js <command> <jsonArgs>` prints exactly one JSON
// line to stdout: the command's own JSON result, or `{"error": message,
// "code": code}` on a thrown `EngineError` (or a plain `Error`, `code:
// null`). `ZX_ZBTERM` names the ZBTerm tree root (`zxterm_testkit::js`
// already sets it for every script this way).

const path = require('path')

function zbtermRoot() {
  return process.env.ZX_ZBTERM || '/zeev/github/zbterm'
}

function loadSshKeys() {
  return require(path.join(zbtermRoot(), 'electron', 'ssh-keys.js'))
}

function loadClaim() {
  return require(path.join(zbtermRoot(), 'engine', 'identity', 'claim.js'))
}

function serializeCandidate(c) {
  return {
    path: c.path,
    source: c.source,
    keyType: c.keyType,
    fingerprint: c.fingerprint,
    comment: c.comment,
    publicKeyBlobBase64: c.publicKeyBlobBase64,
    encrypted: c.encrypted,
    signable: c.signable,
    reason: c.reason
  }
}

async function main() {
  const cmd = process.argv[2]
  const args = JSON.parse(process.argv[3] || '{}')

  switch (cmd) {
    case 'list-candidates': {
      const { listCandidates } = loadSshKeys()
      const candidates = await listCandidates({ home: args.home, env: args.env || {} })
      process.stdout.write(JSON.stringify(candidates.map(serializeCandidate)) + '\n')
      return
    }

    case 'inspect-key': {
      const { inspectKey } = loadSshKeys()
      const candidate = await inspectKey({
        keyPath: args.keyPath,
        home: args.home,
        env: args.env || {}
      })
      process.stdout.write(JSON.stringify(serializeCandidate(candidate)) + '\n')
      return
    }

    case 'sign-bytes': {
      const { signBytes } = loadSshKeys()
      const result = await signBytes({
        messageBase64: args.messageBase64,
        keyPath: args.keyPath || null,
        publicKeyBlobBase64: args.publicKeyBlobBase64 || null,
        env: args.env || {}
      })
      process.stdout.write(JSON.stringify(result) + '\n')
      return
    }

    case 'verify-signature': {
      const { verifySshSignature, NAMESPACE } = loadClaim()
      const message = Buffer.from(args.messageBase64, 'base64')
      const ok = verifySshSignature({
        armored: args.armored,
        message,
        namespace: args.namespace || NAMESPACE
      })
      process.stdout.write(JSON.stringify({ ok }) + '\n')
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

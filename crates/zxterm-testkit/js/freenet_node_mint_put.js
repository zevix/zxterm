// K5 parity: mints a route with ZBTerm's own `route.js::mint`, `Put`s the
// signalling instance's empty canonical state, signs one entry with a
// seeded viewer keypair and `Update`s it in — direction "JS minted/wrote,
// Rust reads/verifies".
//
// Input (stdin, JSON): { nodeUrl, hostPublicKeyHex, viewerSeedHex, entryL,
//   entrySeq, entryPayload }
// Output (stdout, JSON): { route, viewerPublicKeyHex, entry }
'use strict'
const fs = require('fs')

const root = process.env.ZX_ZBTERM
if (!root) throw new Error('ZX_ZBTERM not set')

const sodium = require(root + '/node_modules/sodium-native')

const nodeClient = require(root + '/engine/backends/freenet/node-client.js')
const route = require(root + '/engine/backends/freenet/route.js')
const signal = require(root + '/engine/backends/freenet/signal.js')
const contracts = require(root + '/engine/backends/freenet/contracts.js')

function fromHex(s) {
  return Buffer.from(s, 'hex')
}
function hex(buf) {
  return Buffer.from(buf).toString('hex')
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'))
  const hostKey = fromHex(input.hostPublicKeyHex)

  const r = route.mint('link-js', hostKey, contracts)
  const wasm = contracts.known.get(r.code)
  const paramsBytes = route.paramsBytes(r.params)
  const { key } = nodeClient.contractKey(wasm, paramsBytes)

  const viewerSeed = fromHex(input.viewerSeedHex)
  const viewerPk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const viewerSk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(viewerPk, viewerSk, viewerSeed)

  const entry = signal.signEntry(viewerSk, paramsBytes, {
    l: input.entryL,
    r: 'v:' + hex(viewerPk),
    s: input.entrySeq,
    t: Date.now(),
    d: false,
    p: input.entryPayload
  })

  const client = await nodeClient.connect(input.nodeUrl)
  try {
    await client.put(wasm, paramsBytes, Buffer.from('{"e":[]}', 'utf8'))
    const delta = Buffer.from(JSON.stringify({ e: [entry] }), 'utf8')
    await client.update(key, delta)
  } finally {
    await client.close()
  }

  process.stdout.write(
    JSON.stringify({ route: r, viewerPublicKeyHex: hex(viewerPk), entry })
  )
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + '\n')
  process.exit(1)
})

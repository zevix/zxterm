#!/usr/bin/env bash
# Rebuilds zxterm's copy of ZBTerm's Freenet contracts (contracts/src/<name>/, copied byte for
# byte from ZBTerm's engine/backends/freenet/contracts/ in K10, A-6) and checks them against the
# pins: the RAW .wasm each crate compiles to must hash to the BLAKE3 and size that
# contracts/hashes.json records, and is then copied to contracts/<name>-v1.wasm. `fdev build`
# also writes a package under build/freenet/ (8 version bytes + the 32-byte code hash + the
# WASM); the node hashes the raw WASM, so that is what ships.
#
# K16 (X-26) adds contracts/src/segment (segment-v1, zxterm's own offline-history contract; its
# package is zxterm-segment, so its wasm is zxterm_segment.wasm, where the two ZBTerm crates
# build zbterm_<name>.wasm). Its pin was added to hashes.json once, from two builds that agreed
# (the second under a different CARGO_HOME); this script only verifies it, like the others.
#
# Ported from ZBTerm's scripts/build-contracts.sh (X-16). Two changes only: the paths (contracts/
# here, contracts/blake3.js is ZBTerm's engine/backends/freenet/blake3.js copied unchanged), and
# the manifest is VERIFIED, never rewritten: a rebuild that does not reproduce hashes.json exits
# non-zero before any pinned .wasm is overwritten. Re-pinning needs the owner's sign-off.
#
# For each crate it then cross-checks the contract id computed here (contracts/blake3.js)
# against `fdev get-contract-id` for the crate's params.json, and runs `fdev verify-merge` over
# the crate's states/ corpus.
#
#   bash scripts/build-contracts.sh
#
# Needs cargo with the wasm32-unknown-unknown target, fdev and node on PATH ($HOME/.local/bin
# and $HOME/.cargo/bin are added). Any source change moves a contract's key: a fix ships as
# -v2 next to the -v1 bytes, which stay in the tree.
#
# Reproducibility: panic locations embed the absolute paths of dependency sources, which live
# under $CARGO_HOME (/home/<user>/.cargo/registry/src/...), so without a remap the bytes, and
# the contract key, depend on the builder's home directory and CARGO_HOME. Measured 2026-09-24
# in ZBTerm: the same rustc 1.95.0 built 216 bytes more on a host whose CARGO_HOME path is 18
# characters longer. The remap below makes the crate path, the user and CARGO_HOME irrelevant.
set -euo pipefail
export PATH=$HOME/.local/bin:$HOME/.cargo/bin:$PATH
cargo_home=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo"
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/contracts
blake3=$out/blake3.js
crates=(signalling pointer segment)
# The .wasm each crate compiles to, by crate directory name.
wasm_of() {
  case "$1" in
    segment) echo zxterm_segment ;;
    *) echo "zbterm_$1" ;;
  esac
}

echo "rustc: $(rustc --version); cargo: $(cargo --version); fdev: $(fdev --version 2>&1 | tail -1)"
echo "RUSTFLAGS: --remap-path-prefix=<CARGO_HOME>=/cargo"
for name in "${crates[@]}"; do
  crate=$out/src/$name
  (cd "$crate" && fdev build --features contract >/dev/null 2>&1) || {
    echo "fdev build failed in $crate" >&2
    exit 1
  }
done

# Verify every rebuilt .wasm against the pinned manifest before touching the pinned files.
node - "$out" "$blake3" "${crates[@]}" <<'EOF'
const fs = require('fs')
const path = require('path')
const [out, blake3Path, ...crates] = process.argv.slice(2)
const { blake3 } = require(blake3Path)
const pinned = JSON.parse(fs.readFileSync(path.join(out, 'hashes.json'), 'utf8'))
let bad = 0
for (const name of crates) {
  const file = name === 'segment' ? 'zxterm_segment' : `zbterm_${name}`
  const built = path.join(out, 'src', name, 'target/wasm32-unknown-unknown/release', `${file}.wasm`)
  const bytes = fs.readFileSync(built)
  const hex = Buffer.from(blake3(new Uint8Array(bytes))).toString('hex')
  const pin = pinned[`${name}-v1`] || {}
  const ok = hex === pin.blake3 && bytes.length === pin.bytes
  console.log(`${name}-v1: rebuilt blake3 ${hex} ${bytes.length} bytes; pinned ${pin.blake3} ${pin.bytes} bytes: ${ok ? 'MATCH' : 'MISMATCH'}`)
  if (!ok) bad++
}
if (Object.keys(pinned).sort().join() !== crates.map((n) => `${n}-v1`).sort().join()) {
  console.log(`hashes.json names ${Object.keys(pinned).join(', ')}, expected ${crates.map((n) => `${n}-v1`).join(', ')}`)
  bad++
}
process.exit(bad ? 1 : 0)
EOF

for name in "${crates[@]}"; do
  cp "$out/src/$name/target/wasm32-unknown-unknown/release/$(wasm_of "$name").wasm" "$out/$name-v1.wasm"
done

for name in "${crates[@]}"; do
  crate=$out/src/$name
  ours=$(node - "$out/$name-v1.wasm" "$crate/params.json" "$blake3" <<'EOF'
const fs = require('fs')
const [wasmPath, paramsPath, blake3Path] = process.argv.slice(2)
const { blake3 } = require(blake3Path)
const code = blake3(new Uint8Array(fs.readFileSync(wasmPath)))
const params = new Uint8Array(fs.readFileSync(paramsPath))
const both = new Uint8Array(code.length + params.length)
both.set(code, 0)
both.set(params, code.length)
// base58 (bitcoin alphabet), as bs58 and fdev print it
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const id = Buffer.from(blake3(both))
let n = BigInt('0x' + id.toString('hex'))
let text = ''
while (n > 0n) {
  text = ALPHABET[Number(n % 58n)] + text
  n /= 58n
}
for (let i = 0; i < id.length && id[i] === 0; i++) text = '1' + text
console.log(text)
EOF
)
  theirs=$(fdev get-contract-id --code "$out/$name-v1.wasm" --parameters "$crate/params.json" 2>&1 | tail -1)
  if [ "$ours" != "$theirs" ]; then
    echo "$name-v1: contract id mismatch: blake3.js $ours, fdev $theirs" >&2
    exit 1
  fi
  echo "$name-v1: $(stat -c %s "$out/$name-v1.wasm") bytes, id for params.json $ours (fdev agrees)"
  states=()
  for f in "$crate"/states/*.json; do states+=(--state "$f"); done
  echo "$name-v1 verify-merge:"
  fdev verify-merge --wasm "$out/$name-v1.wasm" --params "$crate/params.json" "${states[@]}" 2>&1 |
    grep -E '^merge check|violation|^  [a-z[]|^no enforceable|^Error' || true
done
cat "$out/hashes.json"

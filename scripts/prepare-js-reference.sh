#!/usr/bin/env bash
# Prepares ZBTerm's JS reference revision for the Rust<->JS parity and
# interop tests (A-5, X-19 as amended by X-20): a read-only copy of that
# revision's `engine/`, `electron/`, `package.json` and `package-lock.json`,
# taken with `git archive` (git is only read), with its own `node_modules`
# installed by `npm ci` from that revision's lockfile. The tests find it with
# `zxterm_testkit::js::reference_root` and skip, naming this script, while it
# is missing.
#
# Usage: scripts/prepare-js-reference.sh
#   ZX_ZBTERM         the ZBTerm tree to read (default: ../zbterm next to this repository)
#   ZX_ZBTERM_JS_REF  the revision (default: the one zxterm_testkit::js names)
#
# The copy lives in this repository's target/js-reference/<rev>/ (ignored,
# like the rest of target/). Idempotent: a finished copy (its `.complete`
# marker) is left as it is; an unfinished one is rebuilt. A setup step, not a
# test: `npm ci` may reach the npm registry (offline cache first,
# `--prefer-offline`); it installs production and optional dependencies only
# (`--omit=dev`) and runs no install scripts (`--ignore-scripts`: no Electron
# download, no native build; every native module the reference needs ships
# prebuilt, node-datachannel as its platform package).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
zbterm="${ZX_ZBTERM:-$root/../zbterm}"
default_rev="$(sed -n 's/^pub const ZBTERM_JS_REFERENCE_REV: &str = "\([0-9a-f]*\)";$/\1/p' \
  "$root/crates/zxterm-testkit/src/js.rs")"
rev="${ZX_ZBTERM_JS_REF:-$default_rev}"
test -n "$rev" || { echo "prepare-js-reference: no revision" >&2; exit 1; }
dest="$root/target/js-reference/$rev"

if [ -f "$dest/.complete" ] && [ -d "$dest/node_modules" ]; then
  echo "$dest (already prepared)"
  exit 0
fi

rm -rf "$dest"
mkdir -p "$dest"
git -C "$zbterm" archive --format=tar "$rev" engine electron package.json package-lock.json |
  tar -x -C "$dest"
(cd "$dest" && ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci --omit=dev --ignore-scripts \
  --prefer-offline --no-audit --no-fund >"$dest/.npm-ci.log" 2>&1) || {
  echo "prepare-js-reference: npm ci failed, see $dest/.npm-ci.log" >&2
  exit 1
}
echo "$rev" >"$dest/.complete"
echo "$dest"

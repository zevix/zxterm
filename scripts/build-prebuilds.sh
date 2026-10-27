#!/usr/bin/env bash
# Builds the `zxterm-core` sidecar in release mode and copies it into the
# `zxterm-core-prebuilds` npm package (X-13) at
# npm/zxterm-core-prebuilds/prebuilds/<platform>-<arch>/zxterm-core[.exe],
# the directory shape electron-forge-plugin-prune-prebuilds keeps per target.
# The `prebuilds` workflow runs this once per target and publishes the
# assembled package; locally, ZBTerm can install the folder directly.
#
# Usage: scripts/build-prebuilds.sh [<rust-target-triple>]
# With no triple it builds for the host. <platform>-<arch> follows Node's
# names (linux, darwin, win32; x64, arm64).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
triple="${1:-}"

node_dir() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo linux-x64 ;;
    aarch64-unknown-linux-gnu) echo linux-arm64 ;;
    aarch64-apple-darwin) echo darwin-arm64 ;;
    x86_64-apple-darwin) echo darwin-x64 ;;
    x86_64-pc-windows-msvc) echo win32-x64 ;;
    *) echo "unsupported target: $1" >&2; return 1 ;;
  esac
}

if [ -z "$triple" ]; then
  triple="$(rustc -vV | sed -n 's/^host: //p')"
  target_dir="$root/target/release"
  cargo build --release -p zxterm-core --manifest-path "$root/Cargo.toml"
else
  target_dir="$root/target/$triple/release"
  cargo build --release -p zxterm-core --target "$triple" --manifest-path "$root/Cargo.toml"
fi

dir="$(node_dir "$triple")"
exe=zxterm-core
case "$triple" in *windows*) exe=zxterm-core.exe ;; esac

# The licence and notices travel with the binaries (ZBTerm's
# THIRD-PARTY-NOTICES.md, section 4, points at them).
cp "$root/LICENSE" "$root/THIRD-PARTY-NOTICES.md" "$root/npm/zxterm-core-prebuilds/"

out="$root/npm/zxterm-core-prebuilds/prebuilds/$dir"
mkdir -p "$out"
# Staged next to the target and renamed over it, so a running sidecar (a
# test run, an app) never makes the copy fail with "Text file busy".
cp "$target_dir/$exe" "$out/$exe.tmp"
case "$triple" in
  *windows*) ;;
  *) strip "$out/$exe.tmp" 2>/dev/null || true; chmod 0755 "$out/$exe.tmp" ;;
esac
mv -f "$out/$exe.tmp" "$out/$exe"
echo "$out/$exe"

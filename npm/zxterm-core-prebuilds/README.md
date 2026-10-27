# zxterm-core-prebuilds

Prebuilt binaries of the `zxterm-core` sidecar used by [ZBTerm](https://github.com/zevix/zbterm),
one per target under `prebuilds/<platform>-<arch>/`: `linux-x64`, `linux-arm64`, `darwin-arm64`
and `darwin-x64`.

You normally don't install this package yourself: ZBTerm depends on it and keeps only the binary
for your platform. The source, build instructions and licences are in
[zevix/zxterm](https://github.com/zevix/zxterm). The binaries statically link third-party crates,
including the LGPL-3.0 `freenet-stdlib`; see `THIRD-PARTY-NOTICES.md` in this package.

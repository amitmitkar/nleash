# Releasing nleash

Releases are driven by pushing a tag matching `v*`. The workflow at
`.github/workflows/release.yml` builds prebuilt binaries for x86_64 and
aarch64 Linux (glibc ≥ 2.35), computes `SHA256SUMS`, and creates a
**draft** GitHub Release. The maintainer reviews and publishes it.

## Cutting a release

1. **Update `CHANGELOG.md`.** Move items from `[Unreleased]` into a new
   `[vX.Y.Z] - YYYY-MM-DD` section.

2. **Commit the changelog.**
   ```sh
   git add CHANGELOG.md
   git commit -m "Release vX.Y.Z"
   ```

3. **Tag and push.**
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main vX.Y.Z
   ```

4. **Watch the workflow.** Open the [Actions
   tab](https://github.com/amitmitkar/nleash/actions) — the `release`
   workflow should start within a few seconds of the tag push.

5. **Review the draft.** When the workflow is green, the
   [Releases page](https://github.com/amitmitkar/nleash/releases)
   has a draft with both architecture tarballs and `SHA256SUMS`
   attached, plus auto-generated release notes (commits since the
   previous tag). Edit the notes if needed, then click **Publish
   release**.

## Versioning

Pre-1.0: minor bumps may contain breaking changes to the CLI or state
schema. Once we cut v1.0, we follow strict semver.

## What lives in the release

Each `nleash-vX.Y.Z-linux-{x86_64,aarch64}.tar.gz` contains:

```
nleash-vX.Y.Z-linux-<arch>/
├── bin/
│   ├── nleash         # main binary (statically linked libbpf/libelf/zlib)
│   └── nleash-helper  # setuid helper (NOT setuid in the tarball — installer must set it)
├── man/
│   └── nleash.1
├── README.md
├── DESIGN.md
├── LICENSE
└── CHANGELOG.md
```

The BPF object is embedded in the binary via the libbpf skeleton —
nothing else needs to be shipped.

## Troubleshooting

- **Workflow can't find `bpftool`.** The Ubuntu runners ship it as
  `linux-tools-<kernel>`; the workflow symlinks the first available
  `bpftool` into `/usr/local/bin/`. If a future runner changes the
  layout, adjust the install step in `release.yml`.
- **Static link fails.** Confirm the `-dev` packages for libbpf, libelf,
  zlib, and libzstd all ship their `.a` archives on the build runner.
- **aarch64 runner unavailable.** GitHub-hosted `ubuntu-22.04-arm` is
  free-tier on public repos. If your account loses access, drop the
  matrix entry or replace it with QEMU-emulated cross-build on the
  x86_64 runner.

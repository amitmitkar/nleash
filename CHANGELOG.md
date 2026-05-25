# Changelog

All notable changes to this project are documented here. Format loosely
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/) (pre-1.0 means
the CLI may still change).

## [Unreleased]

## [v0.1.0] - 2026-05-25

### Added
- Initial public release.
- Per-process bandwidth limiting via cgroup v2 and two cgroup_skb eBPF
  programs (egress and ingress).
- CLI flags: `--rate`, `--burst`, `--ingress-rate`, `--ingress-burst`,
  `--pid`, `--clear`, `--list`, `--stats`, `--json`.
- Setuid helper (`nleash-helper`) for unprivileged-user leashes.
- `--stats` reports pass/drop byte counters per direction from the BPF
  map.

### Requirements
- Linux kernel ≥ 5.15.
- cgroup v2 mounted at `/sys/fs/cgroup`.
- bpffs mounted at `/sys/fs/bpf`.

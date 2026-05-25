# nleash Architecture & Design

`nleash` is a Linux utility for per-process outbound bandwidth limiting. It uses **cgroup v2** for process grouping and a small **eBPF program attached at the cgroup egress hook** for enforcement. No `tc`, no `HTB`, no shared per-interface qdisc.

## Why this architecture

An earlier iteration of `nleash` used a global HTB qdisc on the egress interface plus an eBPF classifier filter to map cgroup ids to HTB class ids. That design had three structural problems:

1. The qdisc is **global** to the interface — any change is system-visible.
2. The BPF → HTB classification path was fragile in practice (classid encoding via `qdisc_skb_cb->tc_classid` is u16 only; `prog->res.classid` interactions differ between direct-action and not; WiFi drivers like `iwlwifi` complicate software shaping).
3. Five integration layers (cgroup, qdisc, class hierarchy, BPF classifier, HTB filter result) all had to agree.

The current design uses a single kernel mechanism end-to-end: `BPF_PROG_TYPE_CGROUP_SKB` at `BPF_CGROUP_INET_EGRESS`, attached to the leash cgroup itself. The hook runs at L3 in the cgroup egress path, well above the driver, so it works identically on any interface (WiFi, wired, virtual).

## Core components

### 1. `LeashManager` (orchestration)
Owns the leash lifecycle: identity verification, cgroup creation, BPF attach/detach, state persistence, and command spawn. Identity is the same `(pid, uid, starttime_ticks, boot_id)` tuple as before — prevents stale `--clear` of a recycled PID or cross-reboot state.

### 2. BPF program (`src/leash.bpf.c`)
A `cgroup_skb/egress` program with a single `BPF_MAP_TYPE_HASH` (`buckets`) keyed by cgroup id. The value is a token bucket protected by `bpf_spin_lock`:

```c
struct nleash_bucket {
    u64 rate_bps;
    u64 burst;
    u64 tokens;
    u64 last_ns;
    u64 pass_bytes;   // observability
    u64 drop_bytes;   // observability
    struct bpf_spin_lock lock;
};
```

For each egress skb, the program looks up the bucket by `bpf_skb_cgroup_id(skb)`, refills tokens by `(now - last_ns) * rate / 1e9`, then either consumes `skb->len` tokens and returns `1` (pass) or returns `0` (drop). Userspace populates the entry at attach time; reads `pass_bytes` / `drop_bytes` for `--stats`.

### 3. BPF egress module (`src/bpf_egress.cpp`)
Userspace shim around libbpf. Functions:
- `bpf_egress_ensure_loaded()` — idempotent: on first call, loads the BPF object via the skeleton and pins prog + map under `/sys/fs/bpf/nleash/`. Subsequent calls reopen via `bpf_obj_get`.
- `bpf_egress_attach(cgroup_id, cgroup_path, rate_bps, burst)` — inserts the bucket entry (with `BPF_F_LOCK`), creates a `bpf_link` on the cgroup at `BPF_CGROUP_INET_EGRESS`, pins the link at `/sys/fs/bpf/nleash/links/<cgroup_id>`.
- `bpf_egress_detach(cgroup_id)` — unlinks the pinned link (kernel detaches automatically) and removes the map entry.
- `bpf_egress_get_stats(cgroup_id)` — reads `pass_bytes` / `drop_bytes` with `BPF_F_LOCK`.

### 4. Cgroup identification
Same robust detection hierarchy as before:
1. `read(cgroup.id)` if the file is binary 8 bytes (rare on modern kernels — it's now a text file, so this branch falls through).
2. `name_to_handle_at()` → 8-byte file handle = the kernel's cgroup id.
3. `stat().st_ino` fallback (matches the low bits of the cgroup id).

The same id userspace reads via these calls is what `bpf_skb_cgroup_id(skb)` returns inside the BPF program, so the map key matches.

### 5. State management
`/run/nleash/state.txt` (advisory `flock` on every read/write) plus a monotonic `nextid` allocator. New schema:

```
#nleash-v2
pid uid starttime boot_id leash_id rate_bps burst_bytes cgroup_path cgroup_id
```

Old (HTB-era) lines without the `#nleash-v2` header are skipped on load.

### 6. CLI / rate parsing
`--rate` accepts `bit/kbit/mbit/gbit` suffixes (tc-style, but the kernel takes bytes/sec internally). `--burst` accepts `b/kb/mb`; default is `max(rate * 50ms, 2 * MTU)`. `--iface` no longer exists — there's no interface to pick.

## Deployment

Zero-dependency at runtime: only `libbpf`, `libelf`, `zlib`. Build needs `clang` + `bpftool` once to produce `bin/leash.bpf.o` and the generated skeleton. The BPF object is loaded via the skeleton at runtime; no shelling out to `tc`, `ip`, `modprobe`, or `bpftool`.

## Trade-offs called out

- **Drops, not pacing**: TCP backs off correctly; UDP loses packets silently. Same caveat as the previous tc/HTB design.
- **Existing sockets in `--pid` mode**: sockets opened before the leash is applied retain their original cgroup association and bypass the BPF hook. Documented in README.
- **Kernel ≥ 5.15** is now required (for `bpf_spin_lock` in cgroup_skb contexts). The older `cls_cgroup` compatibility path was removed.

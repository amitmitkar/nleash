# nleash Architecture & Design

`nleash` is a Linux utility for per-process bandwidth limiting in either or both directions. It uses **cgroup v2** for process grouping and two small **eBPF programs at the cgroup egress and ingress hooks** for enforcement. No `tc`, no qdisc surgery, no shared per-interface state.

## Hook choice

`cgroup_skb/egress` runs for every outbound skb sourced from a socket in the cgroup. `cgroup_skb/ingress` runs for every inbound skb destined for a socket in the cgroup. Both hooks fire at L3, above the driver and any qdisc, so the same code works identically on WiFi, wired, and virtual interfaces.

The hooks are independent — a leash can shape one direction, the other, or both. A rate of 0 in a direction means "do not shape that direction" and the BPF program returns 1 immediately after the lookup.

## Core components

### 1. `LeashManager` (orchestration)
Lifecycle: identity verification, cgroup creation, BPF attach/detach, state persistence, command spawn. Identity is the `(pid, uid, starttime_ticks, boot_id)` tuple — prevents stale `--clear` on a recycled PID or cross-reboot state.

### 2. BPF programs (`src/leash.bpf.c`)
Two SEC programs (`cgroup_skb/egress`, `cgroup_skb/ingress`) sharing a single `BPF_MAP_TYPE_HASH` (`buckets`) keyed by cgroup id. The value carries independent token-bucket state for each direction plus one shared `bpf_spin_lock` (the kernel permits exactly one lock per map value):

```c
struct nleash_bucket {
    struct bpf_spin_lock lock;
    u32 _pad;
    u64 egress_rate_bps;  u64 egress_burst;
    u64 egress_tokens;    u64 egress_last_ns;
    u64 egress_pass_bytes; u64 egress_drop_bytes;
    u64 ingress_rate_bps; u64 ingress_burst;
    u64 ingress_tokens;   u64 ingress_last_ns;
    u64 ingress_pass_bytes; u64 ingress_drop_bytes;
};
```

Each program reads `now` and `skb->len` outside the lock (the verifier forbids helper calls while a `bpf_spin_lock` is held), then runs the shared `shape()` helper on its direction's fields. The userspace mirror struct is verified by `static_assert` to match the BPF layout byte-for-byte.

### 3. Attach mechanism (`src/bpf_filter.cpp`)
The programs and map are loaded once via the libbpf-generated skeleton and pinned at `/sys/fs/bpf/nleash/{prog_egress, prog_ingress, buckets}`. Subsequent CLI invocations reopen them via `bpf_obj_get`.

Per-leash attach uses `bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_{EGRESS,INGRESS}, BPF_F_ALLOW_MULTI)`. We do **not** use `bpf_link_create` + `bpf_obj_pin` here: `bpf_obj_pin` on a cgroup `bpf_link` returns `EPERM` on kernel 6.17 (didn't dig further). `bpf_prog_attach` attachments persist on the cgroup without any pin file — they're undone with `bpf_prog_detach2` (or implicitly when the cgroup is destroyed), which fits the leash lifecycle cleanly.

### 4. Cgroup identification
Detection hierarchy in `read_cgroup_id`:
1. `read(cgroup.id)` if the file is binary 8 bytes.
2. `name_to_handle_at()` → 8-byte file handle = the kernel's cgroup id.
3. `stat().st_ino` fallback.

The same id userspace reads via these calls is what `bpf_skb_cgroup_id(skb)` returns inside the BPF programs, so the map key matches.

### 5. State management
`/run/nleash/state.txt` with advisory `flock` on every read/write, plus a monotonic `nextid` allocator. Schema:

```
#nleash-v3
pid uid starttime boot_id leash_id egress_rate_bps egress_burst_bytes ingress_rate_bps ingress_burst_bytes cgroup_path cgroup_id
```

Lines without the current header marker are skipped on load.

### 6. CLI / rate parsing
`--rate` (egress) and `--ingress-rate` (ingress) accept `bit/kbit/mbit/gbit` suffixes (tc-style, internally bytes/sec). Matching `--burst` / `--ingress-burst` accept `b/kb/mb`; default per direction is `max(rate * 50ms, 2 * MTU)`. At least one of `--rate` / `--ingress-rate` is required for `--pid` / `-- cmd` modes.

## Lifecycle

Each leash:
1. Resolve rates and bursts (empty rate string ⇒ 0 ⇒ that direction unshaped).
2. Create cgroup `…/nleash-<id>` under the target's existing cgroup.
3. Move target PID(s) in (or, for `-- cmd`, fork-then-move).
4. Insert bucket entry into the BPF map (with `BPF_F_LOCK`).
5. `bpf_prog_attach` both programs to the cgroup.
6. Record state.

Cleanup (in order — you can't open a removed cgroup to detach from it):
1. `bpf_prog_detach2` both programs from the cgroup.
2. Delete the bucket entry.
3. `rmdir` the cgroup.
4. Remove the state line.

## Deployment

Zero-dependency at runtime: `libbpf`, `libelf`, `zlib`. Build needs `clang` + `bpftool` once to produce `bin/leash.bpf.o` and the generated skeleton. The BPF object is loaded via the embedded skeleton at runtime; no shell-outs to `tc`, `ip`, `modprobe`, or `bpftool`.

## Trade-offs called out

- **Drops, not pacing**: TCP backs off correctly via congestion control; UDP loses packets silently.
- **Effective TCP throughput is below the cap** (30–80% typical) because drop-based shaping plus TCP loss recovery isn't a precise rate matcher. It's a ceiling, not a pacer.
- **Sub-millisecond-RTT loopback can stall TCP entirely at low rates** — TCP retransmits faster than the bucket refills and the connection collapses. The BPF drop counters confirm enforcement is happening; the connection just doesn't recover.
- **Existing sockets in `--pid` mode**: a socket's cgroup is set at `socket()` time and isn't updated when its owning process is migrated. `--pid` shapes only sockets opened after the leash takes effect.
- **Ingress shaping doesn't reduce upstream load** — bytes are dropped *after* the NIC. It controls what the receiver's TCP/UDP application sees, not what the wire carries.
- **Kernel ≥ 5.15** required (`bpf_spin_lock` in cgroup_skb programs).

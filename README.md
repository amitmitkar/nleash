# nleash

A Linux CLI that limits **network bandwidth** for a single process — either an existing PID or a command you launch under it. Egress, ingress, or both, with independent per-direction caps.

```sh
nleash --rate 1mbit -- curl -X POST --data-binary @bigfile https://upload.example.com/
nleash --ingress-rate 500kbit -- bash -c 'ncat -l 9999 > received'
nleash --rate 1mbit --ingress-rate 5mbit -- ssh user@host 'tar c /data'
nleash --pid 12345 --rate 500kbit
nleash --pid 12345 --clear
nleash --list
nleash --stats --pid 12345
```

## What it does

- Throttles bytes per process (or per command tree) — in either or both directions, independently.
- Rates are **ceilings** — TCP backs off via congestion control; offered throughput converges below the cap.
- Works on any interface (WiFi, wired, virtual) — enforcement happens at the cgroup BPF hooks, before any driver/qdisc.
- Per-leash isolation: each leash has its own token buckets; leashes do not interfere with each other or with the rest of the system's traffic.

## What it doesn't

- No daemon or background service.
- No persistence across reboot.
- For `--pid`: only sockets opened *after* the leash is applied are throttled (kernel limitation, see below).

## How it works

```
process(es)
    │
    ▼
cgroup v2: /sys/fs/cgroup/<parent>/nleash-N
    │
    ├── BPF_CGROUP_INET_EGRESS  ──▶ leash_egress  ─┐
    └── BPF_CGROUP_INET_INGRESS ──▶ leash_ingress ─┤
                                                   │
                              ┌────────────────────┘
                              ▼
                  buckets map [cgroup_id → bucket]
                  • egress  bucket: rate, burst, tokens, pass, drop
                  • ingress bucket: rate, burst, tokens, pass, drop
                  • shared spin_lock
                              │
                              └── tokens >= skb->len → return 1 (pass)
                                  tokens <  skb->len → return 0 (drop)
```

For each leash:

1. `nleash` creates a child cgroup `…/nleash-<id>` under the target's existing cgroup.
2. The target process (or the spawned child) is moved into the new cgroup. Subprocesses inherit it.
3. Two small eBPF programs (`leash.bpf.o`) are loaded once and pinned under `/sys/fs/bpf/nleash/`. Their shared `buckets` map carries per-cgroup, per-direction token bucket state.
4. Both programs are attached to the leash cgroup at `BPF_CGROUP_INET_EGRESS` and `BPF_CGROUP_INET_INGRESS` via `bpf_prog_attach`.
5. For every egress packet from (or ingress packet to) a socket in the cgroup, the corresponding program looks up the bucket, refills it from `(now - last_refill) * rate`, and either consumes `skb->len` tokens (pass) or drops the packet. A rate of 0 in either direction means "do not shape that direction" — the program returns 1 immediately. Pass/drop byte counters are tracked per direction for `--stats`.

Cleanup detaches both programs (`bpf_prog_detach2`), removes the bucket entry, and `rmdir`s the cgroup. The shared programs and map stay pinned (they're on tmpfs and disappear at reboot).

## Egress, ingress, and what they actually do

`--rate` shapes **outbound** packets from sockets in the cgroup. `--ingress-rate` shapes **inbound** packets to those sockets.

- **Egress is symmetric to what you'd expect**: bytes that exceed the rate get dropped before leaving the host. Useful for forcing an upload to behave (bulk `curl POST`, `rsync`, `iperf3 -c`).
- **Ingress drops happen *after* the bytes have arrived at the receiver's NIC.** The wire upstream of you was used regardless. What ingress shaping *does* affect is the receiver's TCP, which sees losses and signals the sender to back off. This effectively throttles the receiver-observed download rate, but doesn't reduce upstream network load.
- **Testing methodology matters.** A `curl download` only generates tiny TCP ACKs outbound — `--rate` won't visibly slow it. To see `--rate` work, push real bytes outbound. To see `--ingress-rate` work, run a workload where the leashed process is *receiving*. Self-contained examples:

```sh
# Egress: upload over loopback
ncat -l 127.0.0.1 9999 > /dev/null &
nleash --rate 1mbit -- bash -c 'dd if=/dev/zero bs=1M count=5 | ncat --send-only 127.0.0.1 9999'

# Ingress: download over loopback
nleash --ingress-rate 100mbit -- bash -c 'ncat -l 127.0.0.1 9999 > /dev/null' &
sleep 1
dd if=/dev/zero bs=1M count=5 | ncat --send-only 127.0.0.1 9999
```

## TCP vs UDP

- **TCP:** drops trigger congestion-control backoff. Effective throughput stays below the cap but typically lands at 30–80% of the configured rate, depending on RTT and how aggressive the sender is. `nleash` is a **ceiling**, not a precise pacer.
- **UDP:** packets above the rate are dropped silently. UDP applications don't get backpressure unless they implement it themselves.
- **Very low rates on loopback can stall TCP entirely.** With sub-millisecond RTT, TCP fires retransmits faster than a tiny token bucket can refill. The connection collapses. The `--stats` drop counters will still tick up (confirming the BPF is working); the connection just doesn't recover. This is TCP-on-loopback behavior, not a leash bug — pick a rate that lets TCP make forward progress, or test against a remote endpoint.

## `--pid` and existing sockets

When a process is migrated into a cgroup, **its already-open sockets retain their original cgroup association** — the kernel does not re-tag them. `nleash --pid` shapes only sockets the target opens *after* the leash is applied. For long-lived programs whose connections are already established (`ssh`, persistent HTTP/2), `--pid` will mostly be a no-op. Workaround: leash at launch with `nleash ... -- cmd`, or restart the target.

## Requirements

- Linux kernel **≥ 5.15** (`bpf_spin_lock` in `cgroup_skb` programs).
- cgroup v2 mounted at `/sys/fs/cgroup`.
- bpffs mounted at `/sys/fs/bpf` (systemd default).
- Root, or the setuid helper installed (see below).

Build dependencies: `clang`, `bpftool`, `libbpf-devel`, `libelf-devel`.

## Build and install

```sh
make
sudo ./bin/nleash --list
```

### Unprivileged usage (setuid helper)

```sh
sudo chown root:root bin/nleash-helper
sudo chmod u+s bin/nleash-helper
```

Non-root callers can then leash processes they own. The helper enforces ownership and drops privileges back to the calling user before executing the spawned command.

## Usage

```
nleash [--rate RATE] [--burst SIZE]
       [--ingress-rate RATE] [--ingress-burst SIZE]
       (--pid PID | -- cmd [args...])
nleash --pid PID --clear
nleash --list [--json]
nleash --stats [--pid PID] [--json]
```

| Option | Meaning |
|--------|---------|
| `--rate RATE` | Egress (outbound) rate cap. |
| `--ingress-rate RATE` | Ingress (inbound) rate cap. |
| `--burst SIZE` | Egress token bucket capacity. Default: `rate × 50ms`, min 3 KB. |
| `--ingress-burst SIZE` | Ingress token bucket capacity. Default: `rate × 50ms`, min 3 KB. |
| `--pid PID` | Apply to an existing process. |
| `-- cmd ...` | Spawn `cmd` and apply the leash to it (and its descendants). |
| `--clear` | Remove the leash for `PID`. Validates `(pid, starttime, boot_id)` first. |
| `--list` | Show active leashes. |
| `--stats` | Per-leash byte counters (passed, dropped) for each direction. |
| `--json` | Machine-readable output for `--list` / `--stats`. |

At least one of `--rate` / `--ingress-rate` must be given. `RATE` suffixes: `bit`, `kbit`, `mbit`, `gbit`. `SIZE` suffixes: `b`, `kb`, `mb`.

## Safety

Each leash records the target's `(pid, uid, starttime_ticks, boot_id)`. If the tuple no longer matches at `--clear` time (PID reuse, reboot), `nleash` removes only its own BPF/cgroup/state and does not touch any live process.

## State files

- `/run/nleash/state.txt` — one leash per line, preceded by a `#nleash-v3` marker.
- `/run/nleash/nextid` — monotonic leash id allocator.
- `/sys/fs/bpf/nleash/{prog_egress, prog_ingress, buckets}` — pinned BPF objects.

Both directories live on tmpfs and are cleared at reboot.

State line schema:
```
pid uid starttime boot_id leash_id egress_rate_bps egress_burst_bytes ingress_rate_bps ingress_burst_bytes cgroup_path cgroup_id
```

## License

LGPL-3.0-or-later

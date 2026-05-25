# nleash

A Linux CLI that limits **egress (outbound) network bandwidth** for a single process — either an existing PID or a command you launch under it.

```sh
nleash --rate 1mbit -- curl -X POST --data-binary @bigfile https://upload.example.com/
nleash --pid 12345 --rate 500kbit
nleash --pid 12345 --clear
nleash --list
nleash --stats --pid 12345
```

## What it does

- Throttles outbound bytes per process (or per command tree).
- Rate is the **ceiling** — TCP backs off via congestion control; offered throughput converges below the cap.
- Works on any interface (WiFi, wired, virtual) — enforcement happens at the cgroup egress hook, before the driver.
- Per-leash isolation: each leash has its own token bucket; leashes do not interfere with each other or with the rest of the system's traffic.

## What it doesn't

- No ingress (download) shaping. See **Egress, not ingress** below.
- No daemon or background service.
- No persistence across reboot.
- For `--pid`: only sockets opened *after* the leash is applied are throttled (kernel limitation, see below).

## How it works

```
process(es)
    │
    ▼
cgroup v2: /sys/fs/cgroup/<parent>/nleash-N
    │  (BPF link attached at BPF_CGROUP_INET_EGRESS)
    ▼
leash.bpf.o  ── per-skb ──▶  buckets map [cgroup_id → token bucket]
    │
    ├── tokens >= skb->len  →  return 1  (pass)
    └── tokens <  skb->len  →  return 0  (drop)
```

For each leash:

1. `nleash` creates a child cgroup `…/nleash-<id>` under the target process's existing cgroup.
2. The target process (or the spawned child) is moved into the new cgroup. Subprocesses inherit it.
3. A small eBPF program (`leash.bpf.o`) is loaded once and pinned at `/sys/fs/bpf/nleash/prog`; its `buckets` map is pinned at `/sys/fs/bpf/nleash/buckets`.
4. A `bpf_link` is created at `BPF_CGROUP_INET_EGRESS` on the leash cgroup and pinned at `/sys/fs/bpf/nleash/links/<cgroup_id>`. This survives the CLI exiting.
5. For every egress packet from a process in the cgroup, the BPF program looks up that cgroup's token bucket, refills it from `(now - last_refill) * rate`, and either consumes `skb->len` tokens (pass) or drops the packet. Pass/drop byte counters are kept in the bucket for `--stats`.

Cleanup unlinks the pinned link (the kernel detaches the program from the cgroup), removes the bucket entry, and `rmdir`s the cgroup. The shared `prog` + `buckets` pins stay around (they're on tmpfs and disappear at reboot).

## Egress, not ingress

`nleash` shapes packets going **out** of the host. A download (`curl -O ...`) is mostly inbound bytes; the only outbound traffic from the receiver is TCP ACKs, which are ~2% of total bandwidth. Throttling those to 1 mbit will *not* visibly slow a 50 mbit download.

To exercise the leash you need a workload that actually sends bytes:

```sh
# Upload to a server
nleash --rate 1mbit -- curl -X POST --data-binary @bigfile https://...

# iperf3 client mode (uploads by default)
nleash --rate 1mbit -- iperf3 -c remote.host

# Self-contained loopback test
ncat -l 127.0.0.1 9999 > /dev/null &
nleash --rate 1mbit -- bash -c 'dd if=/dev/zero bs=1M count=5 | ncat --send-only 127.0.0.1 9999'
```

## TCP vs UDP

- **TCP:** drops trigger congestion-control backoff. Effective throughput stays below the cap but typically lands at 30–80% of the configured rate, depending on RTT and how aggressive the sender is. `nleash` is a rate **ceiling**, not a precise pacer.
- **UDP:** packets above the rate are dropped silently. UDP applications don't get backpressure unless they implement it themselves.

## `--pid` and existing sockets

When a process is migrated into a cgroup, **its already-open sockets retain their original cgroup association** — the kernel does not re-tag them. `nleash --pid` throttles only the sockets the target opens *after* the leash is applied. For long-lived programs whose connections are already established (`ssh`, persistent HTTP/2), `--pid` will mostly be a no-op. Workaround: leash the process at launch with `nleash --rate ... -- cmd`, or restart the target.

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
nleash --rate RATE [--burst SIZE] -- cmd [args...]
nleash --pid PID --rate RATE [--burst SIZE]
nleash --pid PID --clear
nleash --list [--json]
nleash --stats [--pid PID] [--json]
```

| Option | Meaning |
|--------|---------|
| `--rate RATE` | Egress rate. Suffixes: `bit`, `kbit`, `mbit`, `gbit` (e.g. `500kbit`, `10mbit`). |
| `--burst SIZE` | Token bucket capacity. Suffixes: `b`, `kb`, `mb`. Default: `rate × 50ms`, minimum 3 KB. |
| `--pid PID` | Apply to an existing process. |
| `-- cmd ...` | Spawn `cmd` and apply the leash to it (and its descendants). |
| `--clear` | Remove the leash for `PID`. Validates `(pid, starttime, boot_id)` before touching the process. |
| `--list` | Show active leashes. |
| `--stats` | Show per-leash byte counters (passed, dropped) from the BPF map. |
| `--json` | Machine-readable output for `--list` / `--stats`. |

## Safety

Each leash records the target's `(pid, uid, starttime_ticks, boot_id)`. If the tuple no longer matches at `--clear` time (PID reuse, reboot), `nleash` removes only its own BPF/cgroup/state and does not touch any live process.

## State files

- `/run/nleash/state.txt` — one leash per line, preceded by a `#nleash-v2` marker.
- `/run/nleash/nextid` — monotonic leash id allocator.
- `/sys/fs/bpf/nleash/{prog,buckets,links/<cgroup_id>}` — pinned BPF objects.

Both directories live on tmpfs and are cleared at reboot.

State line schema:
```
pid uid starttime boot_id leash_id rate_bps burst_bytes cgroup_path cgroup_id
```

## License

LGPL-3.0-or-later

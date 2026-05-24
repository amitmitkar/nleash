# nleash

`nleash` is a conservative, Linux-only CLI tool that limits **egress (outbound) network bandwidth** for a specific process or for a command you launch under control. It uses **cgroup v2** for grouping and **tc (HTB + cls_cgroup)** for enforcement.

## What it does
- Apply an egress bandwidth limit to an existing PID.
- Run a command under an egress limit.
- List or clear active leashes.

## What it doesn't
- No ingress throttling.
- No daemon or background service.
- No Kubernetes abstractions.
- No eBPF programs.
- No persistence across reboot.
- No process-tree manipulation beyond cgroup inheritance.

## Why no ingress
Ingress shaping is not reliably enforceable per-process with tc + cgroup on the receiving host. It requires IFB, ingress redirection, or external network control, and behavior is especially complex for UDP. This tool intentionally restricts scope to safe, deterministic egress control.

## How it works
- Determines the target process’s **current cgroup v2 path** and creates a **child cgroup** under it.
- Moves the target process into the child cgroup (threads move together).
- Reads `cgroup.id` and installs a `tc` filter that maps that cgroup ID to a rate-limited class.
This preserves all existing CPU/memory/IO limits and container/systemd placement.

### Cgroup inheritance behavior
- Writing a PID to `cgroup.procs` moves the **entire process** (all threads).
- Child processes automatically inherit the leash when they fork/exec.

## Safety: PID reuse and reboots
Each leash is tied to a strict identity tuple:

`(pid, starttime_ticks, boot_id)`

`nleash` refuses to manipulate a live process if the identity does not match, preventing PID reuse bugs and cross-reboot corruption. Cleanup still removes stale tc and cgroup state.

## TCP vs UDP semantics
- TCP: outbound shaping behaves predictably (backpressure, reduced send rate).
- UDP: packets are dropped/queued by the shaping class, but the application may not observe backpressure, so behavior depends on the sender.

`nleash` does **not** attempt to “fix” UDP ingress semantics.

## Requirements

### Common Requirements (All Kernels)
- Linux with **cgroup v2** mounted at `/sys/fs/cgroup`
- Kernel support for `cgroup.id`
- Root or equivalent privileges (`CAP_NET_ADMIN` + cgroup write access). For non-root users, install the setuid helper.
- Userspace tools: `tc`, `ip`, `modprobe`

### Kernel-Specific Requirements

**For kernels < 6.0 (RHEL 7/8/9, older Ubuntu):**
- Kernel support for `cls_cgroup` (`CONFIG_NET_CLS_CGROUP=y`)

**For kernels ≥ 6.0 (RHEL 10, Fedora 40+, Ubuntu 24.04+):**
- `clang` (version 10+) for eBPF compilation
- `bpftool` for eBPF map management
- Kernel with eBPF cgroup helpers (kernel ≥ 4.18)

> **Note**: `nleash` automatically detects which method to use. See [KERNEL_6_MIGRATION.md](KERNEL_6_MIGRATION.md) for details.

If any requirement is missing, `nleash` exits with a clear error.

## Installation
```sh
make
sudo ./bin/nleash --list
```

## Unprivileged usage (with helper)
To allow any user to leash their **own** processes, install the helper as setuid root:
```sh
sudo chown root:root bin/nleash-helper
sudo chmod u+s bin/nleash-helper
```

This grants `nleash-helper` root privileges; audit and deploy carefully.

`nleash` will exec `nleash-helper` automatically when run without privileges (from the same
directory or from `PATH`). The helper enforces ownership: non-root callers can only act on
processes they own, and commands are executed as the calling user (not root).

## Usage
```sh
nleash --pid <PID> --rate <RATE> [--iface <IFACE>]
nleash --rate <RATE> [--iface <IFACE>] -- <cmd> [args...]
nleash --pid <PID> --clear
nleash --list [--json]
```

If the helper is not installed as setuid root, run the same commands with `sudo`.

`RATE` is a `tc` rate string such as `500kbit`, `10mbit`, `1gbit`.

If `--iface` is omitted, the default route interface is detected via `ip route show default`.

## Comparison to trickle
- `trickle` uses `LD_PRELOAD` and affects only dynamically linked applications that call sockets through libc.
- `nleash` is **kernel-native**, enforcing limits at the cgroup + qdisc level and covering all traffic from the cgroup.

## State files
`nleash` stores state in `/run/nleash/`:
- `state.txt` (one leash per line)
- `nextid` (monotonic leash id allocator)

These are **not** persistent across reboots.

State format (per line):
```
pid uid starttime boot_id leash_id iface rate cgroup_path classid
```

## License
LGPL-3.0-or-later

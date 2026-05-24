# DESIGN

## Objectives
- Safe, explicit, and conservative bandwidth limiting for outbound traffic.
- Strict process identity to prevent PID reuse issues and cross-reboot corruption.
- No disruption of existing cgroup hierarchies.

## Core design choices

### Cgroup placement
- `nleash` reads `/proc/<pid>/cgroup` and creates a **child cgroup** under the existing cgroup path.
- The target process is moved into the child via `cgroup.procs`.
- This preserves parent limits (CPU/memory/IO) and container/systemd placement.

### Process identity
Each leash is keyed by:
- `pid`
- `uid`
- `starttime_ticks` (field 22 of `/proc/<pid>/stat`)
- `boot_id` (`/proc/sys/kernel/random/boot_id`)

Cleanup only touches a live process if this tuple matches.

### Traffic shaping (egress only)
- Root qdisc: `htb` with handle `1:`.
- Parent class: `1:1` at `1000mbit` (a stable ceiling).
- Per-leash class: `1:<leash_id>` at user rate.
- Cgroup-to-class mapping via one of:
  - **cls_cgroup filter** (kernels < 6.0): Traditional cgroup-based classifier
  - **eBPF classifier** (kernels ≥ 6.0): BPF program that maps `cgroup.id` to classid

The tool automatically detects and uses the appropriate method at runtime.

Ingress shaping is intentionally out of scope for v1.

### State management
- `/run/nleash/state.txt` stores one leash per line.
- `/run/nleash/nextid` stores the next monotonic leash ID.
- State is not preserved across reboot by design.
 - Each state entry includes the caller UID to enforce per-user access via the helper.

### Unprivileged usage
`nleash` can be used by non-root users via a small setuid-root helper (`nleash-helper`). The helper:
- performs tc and cgroup operations
- enforces that non-root callers only act on their own PIDs
- drops privileges before executing `-- command`

### Safety and cleanup
- On `--clear`, the identity tuple is verified.
- If mismatch (PID reuse or reboot), tc and cgroup state are removed without touching any live process.
- For `-- command` mode, cleanup is performed after the child exits or on signal.

## Failure handling
- If any requirement is missing (cgroup v2, traffic control filters, tools), the tool exits with a clear error.
- If `tc` root/class setup fails, the tool refuses to continue to avoid disrupting existing setups.

## Kernel compatibility (hybrid approach)
Starting with kernel 6.0, `CONFIG_NET_CLS_CGROUP` was removed. To maintain backwards compatibility:

1. **Detection phase**: On startup, check for `cls_cgroup` availability
2. **Fallback to eBPF**: If `cls_cgroup` is unavailable, use eBPF-based classification
3. **Automatic compilation**: eBPF program is compiled on-demand if not already built
4. **Transparent operation**: Users see no difference in CLI or behavior

This hybrid approach ensures `nleash` works on:
- Legacy kernels (RHEL 7/8/9) using `cls_cgroup`
- Modern kernels (RHEL 10, Fedora 40+) using eBPF
- Transition period kernels with either method available

See [KERNEL_6_MIGRATION.md](KERNEL_6_MIGRATION.md) for technical details.

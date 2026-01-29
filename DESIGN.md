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
- `cls_cgroup` filter maps `cgroup.id` to the per-leash class.

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
- If any requirement is missing (cgroup v2, cls_cgroup, tools), the tool exits with a clear error.
- If `tc` root/class setup fails, the tool refuses to continue to avoid disrupting existing setups.

#pragma once

#include <cstdint>
#include <string>

// Lifecycle for the cgroup_skb egress + ingress BPF programs. Both programs
// share a single `buckets` map (per-cgroup token bucket state for each
// direction, protected by a single spin_lock). The program object and the
// map are loaded once (lazily, on the first attach) and pinned under
// /sys/fs/bpf/nleash/ so subsequent CLI invocations re-open them. Each
// leash gets its own per-direction bpf_link pinned at
// /sys/fs/bpf/nleash/links/<cgroup_id>.{egress,ingress}.

bool bpf_filter_ensure_loaded(std::string &err);

// Attach both directions to the given cgroup. A rate of 0 for either
// direction means "do not shape that direction" — the corresponding link
// is still created (so stats are observable), but the BPF program returns
// immediately when it sees rate == 0.
bool bpf_filter_attach(uint64_t cgroup_id,
                       const std::string &cgroup_path,
                       uint64_t egress_rate_bps,
                       uint64_t egress_burst_bytes,
                       uint64_t ingress_rate_bps,
                       uint64_t ingress_burst_bytes,
                       std::string &err);

// Map-side detach (removes the bucket entry). Does NOT detach the BPF
// programs from the cgroup — that needs the cgroup fd, see
// bpf_filter_detach_cgroup().
bool bpf_filter_detach(uint64_t cgroup_id, std::string &err);

// Cgroup-side detach: opens cgroup_path and detaches both programs.
// Tolerates the cgroup already being gone.
bool bpf_filter_detach_cgroup(const std::string &cgroup_path, std::string &err);

struct nleash_stats {
    uint64_t egress_pass_bytes  = 0;
    uint64_t egress_drop_bytes  = 0;
    uint64_t ingress_pass_bytes = 0;
    uint64_t ingress_drop_bytes = 0;
};

bool bpf_filter_get_stats(uint64_t cgroup_id, nleash_stats &out, std::string &err);

#pragma once

#include <cstdint>
#include <string>

// Lifecycle for the cgroup_skb/egress BPF program. The program object and the
// shared `buckets` map are loaded once (lazily, on the first attach) and
// pinned under /sys/fs/bpf/nleash/ so subsequent CLI invocations re-open them.
// Each leash gets its own bpf_link pinned at /sys/fs/bpf/nleash/links/<cookie>;
// the cookie is also the key into the buckets map.

bool bpf_egress_ensure_loaded(std::string &err);

bool bpf_egress_attach(uint64_t cookie,
                       const std::string &cgroup_path,
                       uint64_t rate_bps,
                       uint64_t burst_bytes,
                       std::string &err);

bool bpf_egress_detach(uint64_t cookie, std::string &err);

bool bpf_egress_get_stats(uint64_t cookie,
                          uint64_t &pass_bytes,
                          uint64_t &drop_bytes,
                          std::string &err);

// nleash egress rate limiter.
//
// Attached at BPF_CGROUP_INET_EGRESS to a leash cgroup. One BPF link per
// leash; each link carries an attach cookie that keys a per-leash token
// bucket in the shared `buckets` map. Returning 0 drops the skb; TCP backs
// off via its normal congestion control. UDP loses the packet (documented
// trade-off).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct nleash_bucket {
    __u64 rate_bps;     // refill rate, bytes/sec
    __u64 burst;        // bucket capacity, bytes
    __u64 tokens;       // current tokens, bytes
    __u64 last_ns;      // last refill timestamp (bpf_ktime_get_ns)
    __u64 pass_bytes;   // observability
    __u64 drop_bytes;   // observability
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct nleash_bucket);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} buckets SEC(".maps");

SEC("cgroup_skb/egress")
int leash_egress(struct __sk_buff *skb)
{
    // The skb's socket cgroup is set at socket() time and walked up to find
    // attached cgroup_skb programs — so for a packet that triggered THIS
    // program, the socket's cgroup is either our leash cgroup or one of its
    // descendants. The map is keyed by the leash cgroup id; userspace
    // populates it with the same id read from cgroup.id / name_to_handle_at.
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        return 1;

    struct nleash_bucket *b = bpf_map_lookup_elem(&buckets, &cgid);
    if (!b)
        return 1;

    // Read everything we need from outside the critical section: the
    // verifier forbids helper calls (including bpf_ktime_get_ns) while a
    // bpf_spin_lock is held, and we want to keep the lock window tiny.
    __u64 now = bpf_ktime_get_ns();
    __u64 len = skb->len;

    int allow;
    bpf_spin_lock(&b->lock);

    if (b->last_ns == 0) {
        // First packet on this leash: prime the clock so the first refill
        // doesn't grant a bogus jumbo amount from `now - 0`.
        b->last_ns = now;
    }
    __u64 elapsed_ns = now - b->last_ns;
    // Split the (elapsed * rate) / 1e9 calc so the intermediate stays well
    // below u64 max for any plausible (elapsed_ns, rate_bps). µs resolution
    // is plenty for shaping work.
    __u64 refill = (elapsed_ns / 1000ULL) * b->rate_bps / 1000000ULL;
    __u64 tokens = b->tokens + refill;
    if (tokens > b->burst)
        tokens = b->burst;
    b->last_ns = now;

    if (tokens >= len) {
        b->tokens = tokens - len;
        b->pass_bytes += len;
        allow = 1;
    } else {
        b->tokens = tokens;
        b->drop_bytes += len;
        allow = 0;
    }

    bpf_spin_unlock(&b->lock);
    return allow;
}

char _license[] SEC("license") = "GPL";

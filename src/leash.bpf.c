// nleash egress + ingress rate limiter.
//
// Two cgroup_skb programs (one per direction) share a single hash map keyed
// by cgroup id. Each bucket carries independent token-bucket state for
// egress and ingress, protected by one spin_lock (the kernel only permits
// one bpf_spin_lock per map value). A rate of 0 in either direction means
// "don't shape that direction" — the program returns 1 immediately.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct nleash_bucket {
    struct bpf_spin_lock lock;
    __u32 _pad;

    __u64 egress_rate_bps;
    __u64 egress_burst;
    __u64 egress_tokens;
    __u64 egress_last_ns;
    __u64 egress_pass_bytes;
    __u64 egress_drop_bytes;

    __u64 ingress_rate_bps;
    __u64 ingress_burst;
    __u64 ingress_tokens;
    __u64 ingress_last_ns;
    __u64 ingress_pass_bytes;
    __u64 ingress_drop_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct nleash_bucket);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} buckets SEC(".maps");

// Token-bucket logic shared between egress and ingress. We read `now` and
// `len` outside the spin_lock (the verifier forbids helper calls while a
// bpf_spin_lock is held). The caller passes pointers into whichever
// direction's fields to update.
static __always_inline int
shape(struct nleash_bucket *b, __u64 len,
      __u64 *rate_bps_p, __u64 *burst_p, __u64 *tokens_p, __u64 *last_ns_p,
      __u64 *pass_bytes_p, __u64 *drop_bytes_p)
{
    __u64 now = bpf_ktime_get_ns();
    int allow;

    bpf_spin_lock(&b->lock);

    __u64 rate_bps = *rate_bps_p;
    if (rate_bps == 0) {
        bpf_spin_unlock(&b->lock);
        return 1;
    }
    __u64 burst = *burst_p;

    if (*last_ns_p == 0)
        *last_ns_p = now;
    __u64 elapsed_ns = now - *last_ns_p;
    __u64 refill = (elapsed_ns / 1000ULL) * rate_bps / 1000000ULL;
    __u64 tokens = *tokens_p + refill;
    if (tokens > burst)
        tokens = burst;
    *last_ns_p = now;

    if (tokens >= len) {
        *tokens_p = tokens - len;
        *pass_bytes_p += len;
        allow = 1;
    } else {
        *tokens_p = tokens;
        *drop_bytes_p += len;
        allow = 0;
    }

    bpf_spin_unlock(&b->lock);
    return allow;
}

SEC("cgroup_skb/egress")
int leash_egress(struct __sk_buff *skb)
{
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        return 1;

    struct nleash_bucket *b = bpf_map_lookup_elem(&buckets, &cgid);
    if (!b)
        return 1;

    __u64 len = skb->len;
    return shape(b, len,
                 &b->egress_rate_bps, &b->egress_burst,
                 &b->egress_tokens, &b->egress_last_ns,
                 &b->egress_pass_bytes, &b->egress_drop_bytes);
}

SEC("cgroup_skb/ingress")
int leash_ingress(struct __sk_buff *skb)
{
    __u64 cgid = bpf_skb_cgroup_id(skb);
    if (cgid == 0)
        return 1;

    struct nleash_bucket *b = bpf_map_lookup_elem(&buckets, &cgid);
    if (!b)
        return 1;

    __u64 len = skb->len;
    return shape(b, len,
                 &b->ingress_rate_bps, &b->ingress_burst,
                 &b->ingress_tokens, &b->ingress_last_ns,
                 &b->ingress_pass_bytes, &b->ingress_drop_bytes);
}

char _license[] SEC("license") = "GPL";

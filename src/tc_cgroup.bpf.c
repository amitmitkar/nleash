/*
 * eBPF classifier for cgroup-based traffic control
 * This replaces cls_cgroup for kernels >= 6.0 where CONFIG_NET_CLS_CGROUP was removed.
 *
 * The program classifies packets based on their originating cgroup and maps them
 * to the appropriate HTB class ID for rate limiting.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

/* BPF helper function declarations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static __u64 (*bpf_skb_cgroup_id)(void *skb) = (void *) 79;

/* Map type and attribute macros */
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Map: cgroup_id -> classid
 * Key: cgroup ID (u64)
 * Value: HTB class ID (u32)
 * Will be automatically pinned by tc when loaded
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} cgroup_classid_map SEC(".maps");

SEC("classifier")
int tc_cgroup_classifier(struct __sk_buff *skb)
{
    __u64 cgroup_id;
    __u32 *classid;

    /* Get the cgroup ID of the packet's originating socket */
    cgroup_id = bpf_skb_cgroup_id(skb);
    if (cgroup_id == 0) {
        /* No cgroup info available, allow default handling */
        return TC_ACT_OK;
    }

    /* Lookup the classid for this cgroup */
    classid = bpf_map_lookup_elem(&cgroup_classid_map, &cgroup_id);
    if (!classid) {
        /* No mapping found, allow default handling */
        return TC_ACT_OK;
    }

    /* Set the classid for HTB qdisc to use */
    skb->priority = *classid;

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

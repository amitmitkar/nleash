/*
 * eBPF classifier for cgroup-based traffic control using skb->mark.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_classid_map SEC(".maps");

SEC("classifier")
int tc_cgroup_classifier(struct __sk_buff *skb)
{
    __u64 cgroup_id_64;
    __u32 cgroup_id_32;
    __u32 *classid;

    /* Get current process cgroup ID */
    cgroup_id_64 = bpf_get_current_cgroup_id();
    if (cgroup_id_64 == 0) {
        cgroup_id_64 = bpf_skb_cgroup_id(skb);
    }

    if (cgroup_id_64 != 0) {
        cgroup_id_32 = (__u32)(cgroup_id_64 & 0xFFFFFFFF);
        classid = bpf_map_lookup_elem(&cgroup_classid_map, &cgroup_id_32);
        if (classid) {
            /* Set both mark and priority for maximum compatibility */
            skb->mark = *classid;
            skb->priority = *classid;
            return -1;
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

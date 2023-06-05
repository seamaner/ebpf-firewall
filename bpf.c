#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define __section(NAME)                  \
	__attribute__((section(NAME), used))

/* Struct that describes a packet: srcip, dstip and flags (direction and whether it was blocked) */
typedef struct {
    __u32 flags;
    __u32 dstip;
    __u32 srcip;
} conn;

/* Map for sending flow information (srcip, dstip, direction) to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4*1024);
    __type(value, conn);
} flows_map SEC(".maps");

/* Map for blocking IP addresses from userspace */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
} blocked_map SEC(".maps");

/* Handle a packet: send its information to userspace and return whether it should be allowed */
inline bool handle_pkt(struct __sk_buff *skb, bool egress) {
    struct iphdr iph;
    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
    bpf_printk("hello world by seamaner");
    /* Check if IPs are in "blocked" map */
    bool blocked = bpf_map_lookup_elem(&blocked_map, &iph.saddr) || bpf_map_lookup_elem(&blocked_map, &iph.daddr);
    if (iph.version == 4) {
        conn c = {
            .flags = egress | (blocked << 1),
            .srcip = iph.saddr,
            .dstip = iph.daddr,
        };

        /* Send packet info to user program to display */
        bpf_map_push_elem(&flows_map, &c, 0);
    }
    /* Return whether it should be allowed or dropped */
    return !blocked;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, false);
}

/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
    return (int)handle_pkt(skb, true);
}

char __license[] __section("license") = "GPL";

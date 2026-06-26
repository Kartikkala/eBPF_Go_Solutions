//go:build ignore
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf_cgroup.c -- -I../headers -I/usr/include

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

static __always_inline int check_port(struct __sk_buff *skb, bool is_egress) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 1;

    if (iph->version == 4) {
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) > data_end)
                return 1;

            __u16 target_port = is_egress ? bpf_ntohs(tcph->dest)
                                          : bpf_ntohs(tcph->source);

            __u32 key = 0;
            __u16 *allowed_port = bpf_map_lookup_elem(&port_map, &key);
            if (allowed_port && target_port != *allowed_port)
                return 0;
        }
    } else if (iph->version == 6) {
        struct ipv6hdr *ip6h = data;
        if ((void *)(ip6h + 1) > data_end)
            return 1;

        if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
            struct tcphdr *tcph = (void *)(ip6h + 1);
            if ((void *)(tcph + 1) > data_end)
                return 1;

            __u16 target_port = is_egress ? bpf_ntohs(tcph->dest)
                                          : bpf_ntohs(tcph->source);

            __u32 key = 0;
            __u16 *allowed_port = bpf_map_lookup_elem(&port_map, &key);
            if (allowed_port && target_port != *allowed_port)
                return 0;
        }
    }

    return 1;
}

SEC("cgroup_skb/egress")
int egress_drop(struct __sk_buff *skb) {
    return check_port(skb, true);
}

SEC("cgroup_skb/ingress")
int ingress_drop(struct __sk_buff *skb) {
    return check_port(skb, false);
}

char LICENSE[] SEC("license") = "GPL";
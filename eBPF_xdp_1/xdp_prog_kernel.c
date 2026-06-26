//go:build ignore
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_prog_kernel.c -- -I../headers -I/usr/include

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

struct hdr_cursor {
    void *pos;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);

} config_map SEC(".maps");

static __always_inline int parse_ethhdr(struct hdr_cursor *hc, 
                                        void *data_end,
                                        struct ethhdr **ethheader)
{
    struct ethhdr *eth = hc->pos;

    if(hc->pos + sizeof(struct ethhdr) > data_end) {
        return -1;
    }

    hc->pos += sizeof(struct ethhdr);
    *ethheader = eth;

    return eth->h_proto;                  
}

static __always_inline int parse_iphdr(struct hdr_cursor *hc,
    void *data_end,
    struct iphdr **ipheader
)
{
    struct iphdr *ip = hc->pos;
    if(hc->pos + sizeof(struct iphdr) > data_end) 
        return -1;
    
    int hdrsize = ip->ihl * 4;
    if(hc->pos + hdrsize > data_end) {
        return -1;
    }
    hc->pos += hdrsize;

    *ipheader = ip;
    return ip->protocol;
}

static __always_inline int parse_tcp_hdr_get_dest_port(struct hdr_cursor *hc,
                                        void *data_end,
                                        struct tcphdr **tcpheader
) {
    struct tcphdr *tcp = (struct tcphdr*)hc->pos;
    if(hc->pos + sizeof(struct tcphdr) > data_end) {
        return -1;
    }

    int hdrsize = tcp->doff * 4;
    if(hc->pos + hdrsize > data_end) {
        return -1;
    }

    hc->pos += hdrsize;
    return bpf_ntohs(tcp->dest);
}

SEC("xdp")
int xdp_parser_function(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 action = XDP_PASS;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct hdr_cursor hc;
    hc.pos = data;

    int next_header_type = parse_ethhdr(&hc, data_end, &eth);
    bpf_printk("Packet captured! Packet type is: 0x%x\n", bpf_ntohs(next_header_type));
    if(next_header_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *ipheader;
        int ip_protocol = parse_iphdr(&hc, data_end, &ipheader);
        if(ip_protocol == IPPROTO_TCP) {
            struct tcphdr *tcpheader;
            int dest_port = parse_tcp_hdr_get_dest_port(&hc, data_end, &tcpheader);
            __u32 key = 0;
            __u32 *port_to_block = bpf_map_lookup_elem(&config_map, &key);
            
            bpf_printk("captured a TCP packet, applying port filter for %d\n", *port_to_block);
            if(port_to_block == NULL) {
                goto out;
            }
            if(dest_port == *port_to_block){
                action = XDP_DROP;
                bpf_printk("dropping %d traffic...", *port_to_block);
            }
        }
    }

    out:
    return action; 
}

char _license[] SEC("license") = "GPL";

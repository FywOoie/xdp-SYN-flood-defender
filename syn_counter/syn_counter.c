//go:build ignore

#include "../headers/common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define MAX_MAP_ENTRIES 2048

char __license[] SEC("license") = "Dual MIT/GPL";

// debug function. use cat /sys/kernel/debug/tracing/trace_pipe to look at the output
#define bpf_debug(fmt, ...)             \
    ({                                  \
        char ____fmt[] = fmt;           \
        bpf_trace_printk(____fmt,       \
                         sizeof(____fmt), \
                         ##__VA_ARGS__); \
    })

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

    // Check if the packet is a TCP packet
    if (ip->protocol != IPPROTO_TCP) {
        return 0;
    }

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

// SEC macro is used to specify the section name of the eBPF program.
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		goto done;
	}

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    // Parse the IP header
    struct ethhdr *eth_hdr = data;
    struct iphdr *ip_hdr = (void *)(eth_hdr + 1);

    // Parse the TCP header
    struct tcphdr *tcp_hdr = (void *)(ip_hdr + 1);
    if ((void *)(tcp_hdr + 1) > data_end) {
        bpf_debug("tcp_hdr + 1 > data_end\n");
        return 0;
    }
    
    // check if the packet is a SYN packet
    bpf_debug("tcp_hdr->syn: %d", tcp_hdr->syn);
    if (tcp_hdr->syn && !tcp_hdr->ack) {
        bpf_debug("SYN packet\n");
        __u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
        if (!pkt_count) {
            // No entry in the map for this IP address yet, so set the initial value to 1.
            __u32 init_pkt_count = 1;
            bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
        } else {
            // Entry already exists for this IP address,
            // so increment it atomically using an LLVM built-in.
            __sync_fetch_and_add(pkt_count, 1);
        }
    }

done:
	return XDP_PASS;
}
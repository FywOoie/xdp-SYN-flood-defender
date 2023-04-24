//go:build ignore

#include "../headers/common.h"
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define MAX_MAP_ENTRIES 2048
#define TIME_WINDOW_NS (5LL * 1000000000LL)
#define PACKET_RATE_LIMIT 2 // packets per second
#define MAX_KEY_LEN 100
#define MAX_VALUE_LEN 10

char __license[] SEC("license") = "Dual MIT/GPL";

// debug function. Use cat /sys/kernel/debug/tracing/trace_pipe to
#define bpf_debug(fmt, ...)             \
    ({                                  \
        char ____fmt[] = fmt;           \
        bpf_trace_printk(____fmt,       \
                         sizeof(____fmt), \
                         ##__VA_ARGS__); \
    })

/* Define struct of information of the current IP address*/
struct ip_stats
{
    __u64 first_packet_ts; // timestamp of the first packet
    __u32 packet_count; // packet count within the time window
};

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); // map的类型
	__uint(max_entries, MAX_MAP_ENTRIES); // map的最大容量
	__type(key, __u32);   // source IPv4 address
	__type(value, struct ip_stats); // information of current ip
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); // map的类型
    __uint(max_entries, MAX_MAP_ENTRIES); // map的最大容量
    __type(key, __u32);   // source IPv4 address
    __type(value, __u64);  // ban timestamp
} xdp_banned_ips_map SEC(".maps");

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

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
        bpf_debug("parse_ip_src_addr failed\n");
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
        return 0;
    }
    
    // check if the packet is a SYN packet
    if (tcp_hdr->syn && !tcp_hdr->ack) {
        // syn packet   
        struct ip_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &ip);
        __u64 curr_ts = bpf_ktime_get_ns();
        if (!stats) {
            // No entry in the map for this IP address yet, so create an new entry.
            struct ip_stats init_pkt_stats = {
                .first_packet_ts = curr_ts,
                .packet_count = 1,
            };
            bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_stats, BPF_ANY);
        } else {
            // Entry already exists for this IP address,
            // so increment it atomically using an LLVM built-in.
            __u64 elapsed_ns = curr_ts - stats->first_packet_ts;

            if (elapsed_ns < TIME_WINDOW_NS)
            {
                stats->packet_count++;
                __u64 packet_rate = stats->packet_count * 1000000000 / elapsed_ns;

                bpf_debug("packet_rate: %d", packet_rate);
                if (packet_rate > PACKET_RATE_LIMIT)
                {
                    bpf_map_update_elem(&xdp_banned_ips_map, &ip, &curr_ts, BPF_ANY);
                    return XDP_DROP;
                }
            } else {
                // The time window has expired, so reset the packet count.
                stats->first_packet_ts = curr_ts;
                stats->packet_count = 1;
            }
            
        }
    }

done:
	return XDP_PASS;
}
/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

#include "../common/parsing_helpers.h"

#define IPPROTO_UDP 17

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

SEC("xdp_sock_prog")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	int nh_type;
	void *data_end = (void *)(long)ctx->data_end;

	nh.pos = (void *)(long)ctx->data;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != ETH_P_IP)
		return XDP_PASS;

	if (parse_iphdr(&nh, data_end, &iph) != IPPROTO_UDP)
		return XDP_PASS;

	if (parse_udphdr(&nh, data_end, &udph) < 0 || !udph)
		return XDP_PASS;

	// Match UDP dst port 4242
	if (udph->dest == bpf_htons(4242)) {
		if (bpf_map_lookup_elem(&xsks_map, &index))
			return bpf_redirect_map(&xsks_map, index, 0);
	}

	// Optionally update stats
	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (pkt_count) {
		(*pkt_count)++;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

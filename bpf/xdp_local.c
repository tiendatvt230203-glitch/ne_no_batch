#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} loc_if_xsk SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *iph;
	__u32 ifidx;
	__u32 *xsk_key;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	if (eth->h_proto == bpf_htons(ETH_P_ARP))
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = data + sizeof(*eth);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->protocol == IPPROTO_ICMP)
		return XDP_PASS;

	ifidx = ctx->ingress_ifindex;
	xsk_key = bpf_map_lookup_elem(&loc_if_xsk, &ifidx);
	if (!xsk_key)
		return XDP_PASS;

	return bpf_redirect_map(&xsks_map, *xsk_key, 0);
}

char _license[] SEC("license") = "GPL";

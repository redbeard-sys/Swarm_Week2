// SPDX-License-Identifier: GPL-2.0
/* shim_router.bpf.c -- XDP router for the week 2 pheromone shim.
 *
 * Attached to every interface of r1. For each frame:
 *   1. Parse Ethernet and, if EtherType is 0x88B5, the 8-byte shim.
 *   2. Anything that isn't IPv4 (ARP, ...), or that the kernel must handle
 *      (local address, TTL 1, no neighbour entry yet): strip the shim and XDP_PASS.
 *   3. Route with bpf_fib_lookup, then decide by the egress port's role:
 *        shim present, egress FABRIC  -> update in place (path_score += hop_incr)
 *        shim present, egress HOST    -> strip   (bpf_xdp_adjust_head +8)
 *        no shim,      egress FABRIC  -> insert  (bpf_xdp_adjust_head -8)
 *        no shim,      egress HOST    -> nothing
 *      A shim that arrives on a HOST port is a forgery: counted, and its values
 *      replaced by fresh placeholders.
 *   4. Rewrite MACs, decrement TTL, bpf_redirect to the egress interface.
 *
 * Layout trick: the shim's last field (next EtherType) sits exactly where the
 * Ethernet EtherType sits once the shim is gone, and vice versa. So inserting or
 * stripping only has to move the 12 MAC bytes.
 *
 *   with shim:    dst(6) src(6) 88B5 | ver score bitmap key next_type | IP...
 *   without:              dst(6) src(6)                       type    | IP...
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "shim.h"

#ifndef AF_INET
#define AF_INET 2
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);              /* ifindex */
	__type(value, struct port_cfg);
} port_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} shim_stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&shim_stats, &idx);
	if (v)
		(*v)++;
}

static __always_inline void get_cfg(__u32 ifindex, struct port_cfg *out)
{
	struct port_cfg *c = bpf_map_lookup_elem(&port_cfg, &ifindex);
	if (c) {
		*out = *c;
		return;
	}
	out->role        = ROLE_FABRIC;
	out->init_score  = DEF_INIT_SCORE;
	out->hop_incr    = DEF_HOP_INCR;
	out->init_bitmap = DEF_INIT_BITMAP;
	out->key_hint    = DEF_KEY_HINT;
}

/* Remove the shim: move the MACs forward 8 bytes, then drop 8 bytes of head. */
static __always_inline int shim_strip(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 macs[12];

	if (data + ETH_HLEN + SHIM_LEN > data_end)
		return -1;
	__builtin_memcpy(macs, data, 12);
	if (bpf_xdp_adjust_head(ctx, SHIM_LEN))
		return -1;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + ETH_HLEN > data_end)
		return -1;
	__builtin_memcpy(data, macs, 12);
	/* bytes 12-13 are the old next_type: the original EtherType is back */
	count(ST_STRIPPED);
	return 0;
}

/* Add a shim: grow the head by 8 bytes, move the MACs back to the front. */
static __always_inline int shim_insert(struct xdp_md *ctx, const struct shim_hdr *v)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 macs[12];

	if (data + ETH_HLEN > data_end)
		return -1;
	__builtin_memcpy(macs, data, 12);
	if (bpf_xdp_adjust_head(ctx, -SHIM_LEN))
		return -1;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + ETH_HLEN + SHIM_LEN > data_end)
		return -1;

	struct ethhdr *eth = data;
	struct shim_hdr *sh = (void *)(eth + 1);
	__builtin_memcpy(data, macs, 12);
	eth->h_proto   = bpf_htons(ETH_P_SHIM);
	sh->ver_flags  = v->ver_flags;
	sh->path_score = v->path_score;
	sh->bitmap     = v->bitmap;
	sh->key_hint   = v->key_hint;
	/* sh->next_type already holds the original EtherType (old bytes 12-13) */
	count(ST_INSERTED);
	return 0;
}

static __always_inline void fib_fill(struct bpf_fib_lookup *f, struct iphdr *ip,
				     __u32 ifindex, __u16 tot_len)
{
	__builtin_memset(f, 0, sizeof(*f));
	f->family      = AF_INET;
	f->tos         = ip->tos;
	f->l4_protocol = ip->protocol;
	f->tot_len     = tot_len;
	f->ipv4_src    = ip->saddr;
	f->ipv4_dst    = ip->daddr;
	f->ifindex     = ifindex;
}

SEC("xdp")
int xdp_shim_router(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 in_if = ctx->ingress_ifindex;
	struct port_cfg in_cfg, out_cfg;
	struct shim_hdr cur = {}, nv = {};
	int has_shim = 0, trusted = 0, rc, mtu_short = 0;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	get_cfg(in_if, &in_cfg);
	__be16 l3proto = eth->h_proto;
	void *l3 = eth + 1;

	if (eth->h_proto == bpf_htons(ETH_P_SHIM)) {
		struct shim_hdr *sh = (void *)(eth + 1);
		if ((void *)(sh + 1) > data_end)
			return XDP_PASS;
		cur = *sh;
		has_shim = 1;
		l3proto = sh->next_type;
		l3 = sh + 1;
		count(ST_RX_SHIM);
		if (in_cfg.role == ROLE_HOST)
			count(ST_FORGED);      /* hosts never write the shim */
		else
			trusted = 1;
	}

	if (l3proto != bpf_htons(ETH_P_IP))
		goto to_stack;

	struct iphdr *ip = l3;
	if ((void *)(ip + 1) > data_end)
		goto to_stack;
	if (ip->ttl <= 1)
		goto to_stack;               /* let the kernel send time-exceeded */

	/* Route. Ask for MTU room for the shim first; if that fails, look again
	 * without it, and refuse later only if the egress keeps the shim. */
	struct bpf_fib_lookup fib;
	__u16 ip_len = bpf_ntohs(ip->tot_len);
	fib_fill(&fib, ip, in_if, ip_len + SHIM_LEN);
	rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
	if (rc == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
		mtu_short = 1;
		fib_fill(&fib, ip, in_if, ip_len);
		rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		goto to_stack;               /* local, no neighbour yet, unreachable... */

	get_cfg(fib.ifindex, &out_cfg);
	int want_shim = out_cfg.role != ROLE_HOST;

	if (want_shim && mtu_short) {
		count(ST_MTU_DROP);
		return XDP_DROP;
	}

	/* New shim values. */
	if (trusted) {
		nv = cur;
		__u16 s = (__u16)cur.path_score + in_cfg.hop_incr;
		nv.path_score = s > 255 ? 255 : s;
		count(ST_UPDATED);
	} else {
		nv.ver_flags  = SHIM_VERSION << 4;
		nv.path_score = in_cfg.init_score;
		nv.bitmap     = bpf_htons(in_cfg.init_bitmap);
		nv.key_hint   = bpf_htons(in_cfg.key_hint);
		nv.next_type  = l3proto;
	}

	/* Decrement TTL (incremental checksum update, RFC 1624). */
	__u32 csum = ip->check;
	csum += bpf_htons(0x0100);
	ip->check = (__u16)(csum + (csum >= 0xFFFF));
	ip->ttl--;

	if (has_shim && want_shim) {
		struct shim_hdr *sh = (void *)(eth + 1);
		if ((void *)(sh + 1) > data_end)
			return XDP_ABORTED;
		*sh = nv;                    /* update in place, no size change */
	} else if (has_shim) {
		if (shim_strip(ctx))
			return XDP_ABORTED;
	} else if (want_shim) {
		if (shim_insert(ctx, &nv))
			return XDP_ABORTED;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	count(ST_REDIRECTED);
	return bpf_redirect(fib.ifindex, 0);

to_stack:
	/* The kernel doesn't know EtherType 0x88B5: give it the original frame. */
	if (has_shim && shim_strip(ctx))
		return XDP_ABORTED;
	count(ST_TO_STACK);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

/* shim.h -- shared between shim_router.bpf.c and shimctl.c */
#ifndef SHIM_H
#define SHIM_H

#include <linux/types.h>

#define ETH_P_SHIM    0x88B5   /* IEEE 802 local experimental EtherType */
#define SHIM_LEN      8
#define SHIM_VERSION  1
#define SHIM_F_M      0x08     /* low nibble of byte 0: M T R R */
#define SHIM_F_T      0x04

/* Wire format, 8 bytes, network byte order for the 16-bit fields. */
struct shim_hdr {
	__u8   ver_flags;    /* version << 4 | M T R R */
	__u8   path_score;
	__be16 bitmap;
	__be16 key_hint;
	__be16 next_type;    /* original EtherType */
} __attribute__((packed));

/* Port roles, the same meaning as in shim.p4.
 * FABRIC: carried shim is updated, shim kept on egress.
 * HOST:   untrusted. A shim arriving here is a forgery. Shim stripped on egress. */
enum { ROLE_FABRIC = 0, ROLE_HOST = 1 };

/* port_cfg map value, keyed by ifindex. Host byte order. */
struct port_cfg {
	__u8  role;
	__u8  init_score;    /* placeholder values used when r1 inserts a shim */
	__u8  hop_incr;      /* added to path_score for shims arriving here */
	__u8  pad;
	__u16 init_bitmap;
	__u16 key_hint;
};

#define DEF_INIT_SCORE  8
#define DEF_INIT_BITMAP 0x0100
#define DEF_KEY_HINT    0x7a3f
#define DEF_HOP_INCR    1

enum {
	ST_RX_SHIM = 0,   /* frames that arrived with a shim */
	ST_UPDATED,       /* carried shim updated in place */
	ST_INSERTED,      /* shim inserted (bpf_xdp_adjust_head -8) */
	ST_STRIPPED,      /* shim removed  (bpf_xdp_adjust_head +8) */
	ST_FORGED,        /* shim arrived on a HOST port */
	ST_REDIRECTED,    /* forwarded inside XDP */
	ST_TO_STACK,      /* handed to the kernel (ARP, local, no neighbour yet) */
	ST_MTU_DROP,      /* would not fit the egress MTU with the shim */
	ST_MAX
};

#endif

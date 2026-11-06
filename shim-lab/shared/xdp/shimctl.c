// SPDX-License-Identifier: GPL-2.0
/* shimctl -- load, configure and inspect the XDP shim router on r1.
 *
 *   shimctl attach [skb|native] IF...   load (once), pin, attach to each IF
 *   shimctl detach [IF...]              detach (default eth0 eth1) and unpin
 *   shimctl role IF host|fabric [score N] [bitmap N] [key N] [hop N]
 *   shimctl roles                       show port roles
 *   shimctl stats                       counters
 *   shimctl reset                       zero counters
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "shim.h"

#define PIN_DIR   "/sys/fs/bpf/shim"
#define PIN_PROG  PIN_DIR "/prog"
#define PIN_CFG   PIN_DIR "/port_cfg"
#define PIN_STATS PIN_DIR "/shim_stats"
#define OBJ_PATH  "/tmp/shim-xdp/shim_router.bpf.o"

static const char *stat_names[ST_MAX] = {
	[ST_RX_SHIM]    = "rx with shim",
	[ST_UPDATED]    = "updated in place",
	[ST_INSERTED]   = "inserted (adjust_head -8)",
	[ST_STRIPPED]   = "stripped (adjust_head +8)",
	[ST_FORGED]     = "forged (shim on host port)",
	[ST_REDIRECTED] = "forwarded in XDP",
	[ST_TO_STACK]   = "passed to kernel",
	[ST_MTU_DROP]   = "dropped: MTU too small",
};

static int die(const char *what)
{
	fprintf(stderr, "shimctl: %s: %s\n", what, strerror(errno));
	return 1;
}

static int ifidx(const char *name)
{
	int i = if_nametoindex(name);
	if (!i)
		fprintf(stderr, "shimctl: no interface %s\n", name);
	return i;
}

static int load_or_get_prog(void)
{
	int fd = bpf_obj_get(PIN_PROG);
	if (fd >= 0)
		return fd;

	struct bpf_object *obj = bpf_object__open_file(OBJ_PATH, NULL);
	if (!obj || libbpf_get_error(obj)) {
		fprintf(stderr, "shimctl: cannot open %s (run make first)\n", OBJ_PATH);
		return -1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "shimctl: load failed, see the verifier log above\n");
		return -1;
	}
	mkdir(PIN_DIR, 0700);
	if (bpf_object__pin_maps(obj, PIN_DIR))
		return die("pin maps"), -1;
	struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_shim_router");
	if (!p || bpf_program__pin(p, PIN_PROG))
		return die("pin prog"), -1;
	return bpf_program__fd(p);
}

static int cmd_attach(int argc, char **argv)
{
	__u32 flags = XDP_FLAGS_SKB_MODE;
	int i = 0;
	if (argc > 0 && !strcmp(argv[0], "native")) { flags = XDP_FLAGS_DRV_MODE; i++; }
	else if (argc > 0 && !strcmp(argv[0], "skb")) i++;
	if (i >= argc) { fprintf(stderr, "usage: shimctl attach [skb|native] IF...\n"); return 1; }

	int fd = load_or_get_prog();
	if (fd < 0)
		return 1;
	for (; i < argc; i++) {
		int ix = ifidx(argv[i]);
		if (!ix)
			return 1;
		int err = bpf_xdp_attach(ix, fd, flags, NULL);
		if (err) {
			fprintf(stderr, "shimctl: attach %s: %s\n", argv[i], strerror(-err));
			return 1;
		}
		printf("attached xdp_shim_router to %s (%s)\n", argv[i],
		       flags == XDP_FLAGS_SKB_MODE ? "skb" : "native");
	}
	return 0;
}

static int cmd_detach(int argc, char **argv)
{
	char *def[] = { "eth0", "eth1" };
	if (argc == 0) { argc = 2; argv = def; }
	for (int i = 0; i < argc; i++) {
		int ix = if_nametoindex(argv[i]);
		if (!ix)
			continue;
		bpf_xdp_detach(ix, XDP_FLAGS_SKB_MODE, NULL);
		bpf_xdp_detach(ix, XDP_FLAGS_DRV_MODE, NULL);
		printf("detached %s\n", argv[i]);
	}
	unlink(PIN_PROG);
	unlink(PIN_CFG);
	unlink(PIN_STATS);
	rmdir(PIN_DIR);
	return 0;
}

static long num(const char *s) { return strtol(s, NULL, 0); }

static int cmd_role(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: shimctl role IF host|fabric [score N] [bitmap N] [key N] [hop N]\n");
		return 1;
	}
	__u32 ix = ifidx(argv[0]);
	if (!ix)
		return 1;
	int fd = bpf_obj_get(PIN_CFG);
	if (fd < 0)
		return die("open " PIN_CFG " (attach first)");

	struct port_cfg c;
	if (bpf_map_lookup_elem(fd, &ix, &c)) {
		memset(&c, 0, sizeof(c));
		c.init_score  = DEF_INIT_SCORE;
		c.init_bitmap = DEF_INIT_BITMAP;
		c.key_hint    = DEF_KEY_HINT;
		c.hop_incr    = DEF_HOP_INCR;
	}
	if (!strcmp(argv[1], "host"))        c.role = ROLE_HOST;
	else if (!strcmp(argv[1], "fabric")) c.role = ROLE_FABRIC;
	else { fprintf(stderr, "shimctl: role must be host or fabric\n"); return 1; }

	for (int i = 2; i + 1 < argc; i += 2) {
		long v = num(argv[i + 1]);
		if (!strcmp(argv[i], "score"))       c.init_score = v;
		else if (!strcmp(argv[i], "bitmap")) c.init_bitmap = v;
		else if (!strcmp(argv[i], "key"))    c.key_hint = v;
		else if (!strcmp(argv[i], "hop"))    c.hop_incr = v;
		else { fprintf(stderr, "shimctl: unknown option %s\n", argv[i]); return 1; }
	}
	if (bpf_map_update_elem(fd, &ix, &c, BPF_ANY))
		return die("update port_cfg");
	printf("%s: %s\n", argv[0], argv[1]);
	return 0;
}

static int cmd_roles(void)
{
	int fd = bpf_obj_get(PIN_CFG);
	if (fd < 0)
		return die("open " PIN_CFG " (attach first)");
	__u32 key, *prev = NULL;
	struct port_cfg c;
	char name[IF_NAMESIZE];
	printf("%-6s %-7s %6s %8s %8s %4s\n", "if", "role", "score", "bitmap", "key", "hop");
	while (bpf_map_get_next_key(fd, prev, &key) == 0) {
		if (bpf_map_lookup_elem(fd, &key, &c) == 0)
			printf("%-6s %-7s %6u   0x%04x   0x%04x %4u\n",
			       if_indextoname(key, name) ? name : "?",
			       c.role == ROLE_HOST ? "host" : "fabric",
			       c.init_score, c.init_bitmap, c.key_hint, c.hop_incr);
		prev = &key;
	}
	printf("(interfaces not listed are fabric with defaults: score %d bitmap 0x%04x key 0x%04x hop %d)\n",
	       DEF_INIT_SCORE, DEF_INIT_BITMAP, DEF_KEY_HINT, DEF_HOP_INCR);
	return 0;
}

static int cmd_stats(int reset)
{
	int fd = bpf_obj_get(PIN_STATS);
	if (fd < 0)
		return die("open " PIN_STATS " (attach first)");
	int ncpu = libbpf_num_possible_cpus();
	__u64 *v = calloc(ncpu, sizeof(__u64));
	for (__u32 k = 0; k < ST_MAX; k++) {
		if (reset) {
			memset(v, 0, ncpu * sizeof(__u64));
			bpf_map_update_elem(fd, &k, v, BPF_ANY);
			continue;
		}
		__u64 sum = 0;
		if (bpf_map_lookup_elem(fd, &k, v) == 0)
			for (int c = 0; c < ncpu; c++)
				sum += v[c];
		printf("  %-28s %10llu\n", stat_names[k], (unsigned long long)sum);
	}
	if (reset)
		printf("counters zeroed\n");
	free(v);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"usage: shimctl attach [skb|native] IF... | detach [IF...] |\n"
			"               role IF host|fabric [score N] [bitmap N] [key N] [hop N] |\n"
			"               roles | stats | reset\n");
		return 1;
	}
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	const char *c = argv[1];
	if (!strcmp(c, "attach")) return cmd_attach(argc - 2, argv + 2);
	if (!strcmp(c, "detach")) return cmd_detach(argc - 2, argv + 2);
	if (!strcmp(c, "role"))   return cmd_role(argc - 2, argv + 2);
	if (!strcmp(c, "roles"))  return cmd_roles();
	if (!strcmp(c, "stats"))  return cmd_stats(0);
	if (!strcmp(c, "reset"))  return cmd_stats(1);
	fprintf(stderr, "shimctl: unknown command %s\n", c);
	return 1;
}

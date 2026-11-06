# Kathará lab: the pheromone shim (week 2)

This lab implements the week 2 checklist from *Stigmergy in the Programmable Data
Plane*. Three BMv2 switches and one XDP router insert, carry, update and strip the
8-byte shim (EtherType 0x88B5) with fixed placeholder values. The end hosts run nothing.

```
 h1 ──A── s1 ──B── s2 ──C── r1 ──D── s3 ──E── h2
10.0.1.1  P4       P4      XDP       P4    10.0.2.1
                         .1.254 / .2.254
          └─────── fabric: shim on, MTU 1508 ───────┘
 host links A and E: never a shim, MTU 1500
```

A ping from h1 to h2, as `test.sh` sees it on each link:

| Link | Echo request | Echo reply |
|---|---|---|
| A  h1–s1 | no shim | no shim (s1 stripped it) |
| B  s1–s2 | **score 4** (s1 inserted) | score 6 |
| C  s2–r1 | score 5 (s2 +1) | score 5 (r1 +1) |
| D  r1–s3 | score 6 (r1 +1, in XDP) | **score 4** (s3 inserted) |
| E  s3–h2 | no shim (s3 stripped it) | no shim |

Each score is different, so a capture shows which node touched the frame. This is the
week 2 exit criterion: a ping crosses switch, router and switch with the shim on
every fabric link and on neither host link.

## Run it

```bash
docker pull kathara/p4                     # BMv2 + p4c, has an arm64 build
docker build -t kathara-shim image/        # hosts and r1: clang, libbpf, bpftool, Scapy
kathara lstart --privileged
./test.sh                                  # from your Mac, in this folder
```

`--privileged` is required. r1 attaches XDP and mounts bpffs, and the switches set
MTUs. Startup takes a while, because each switch compiles `shim.p4` when it boots.
Logs: `/var/log/p4switch.log` on the switches and `/var/log/shim-xdp.log` on r1.

`test.sh` goes through the checklist and prints PASS or FAIL per check. Its captures
stay in `shared/captures/`. To decode one:

```bash
kathara exec r1 "python3 /shared/scapy/shim.py decode /shared/captures/B.pcap"
```
```
== /shared/captures/B.pcap
  SHIM v1 -- score=4   bitmap=0x0001 (1 bit) key=0x7a3f next=0x0800 | 10.0.1.1 > 10.0.2.1 echo-request len=106
  SHIM v1 -- score=6   bitmap=0x0002 (1 bit) key=0x7a3f next=0x0800 | 10.0.2.1 > 10.0.1.1 echo-reply len=106
```

## The checklist, item by item

| Week 2 item | Where | What test.sh checks |
|---|---|---|
| Scapy layer | `shared/scapy/shim.py` | All captures are decoded with it |
| P4, insert and strip | s1, s3 | Shim on B and D, none on A and E |
| P4, update per hop | s2 | Score is 4 on B and 5 on C |
| XDP, insert and strip | r1, scenario 3 | s1 becomes a plain switch and r1's eth0 host-facing: r1 inserts on the way in (`adjust_head -8`) and strips on the way back (`+8`) |
| Interoperation | s1 → r1 → s3 | Score 5 into r1, 6 out of it, then stripped by s3 |
| Forgery | s1 (scenario 2) and r1 (3b) | h1 sends frames that already carry a shim with score 255. The edge strips the shim, counts it, and inserts its own |
| MTU | scenario 4 | A 1500-byte DF ping crosses as a 1522-byte frame on D. With r1's eth1 at 1500, the same ping fails and r1 counts MTU drops |

## Port roles

Every node gives each port a role. The P4 program and the XDP program use the same rules.

| Role | On ingress | On egress |
|---|---|---|
| `host` | A shim already present is a forgery: strip it and count it. Then insert a fresh shim with the port's placeholder values | Strip the shim |
| `fabric` | A carried shim gets `path_score += hop_incr` (saturating at 255) | Keep the shim |
| `plain` (P4 only) | Do nothing, like a non-programmable switch | Do nothing |

Placeholders: s1 and s3 insert score 4, with bitmap 0x0001 (h1) or 0x0002 (h2) and key
0x7a3f. r1 inserts score 8 and bitmap 0x0100. Every hop adds 1.

## Controls

On a switch (`kathara exec s1 "bash /shared/p4/p4ctl.sh stats"`):

| `p4ctl.sh` | Does |
|---|---|
| `stats` | Inserted, updated, stripped and forged counts, plus forged counts per port (registers) |
| `reset` | Zero the registers |
| `plain` | Clear the role tables. The switch only forwards |
| `restore s1` | Put the role entries from `s1.txt` back |
| `cli` | `simple_switch_CLI`, for example `table_dump ShimIngress.ingress_role` |

On r1:

| `shimctl` | Does |
|---|---|
| `stats` | Counters: rx with shim, updated, inserted, stripped, forged, forwarded in XDP, passed to kernel, MTU drops |
| `roles` | Port roles and placeholder values |
| `role eth0 host [score N] [bitmap N] [key N] [hop N]` | Change a port's role |
| `reset` | Zero the counters |
| `attach [skb\|native] eth0 eth1`, `detach` | Attach or detach. `bash /shared/xdp/load.sh` rebuilds and re-attaches |

Maps are pinned under `/sys/fs/bpf/shim/`, so `bpftool map dump pinned /sys/fs/bpf/shim/port_cfg` works too.

On a host, a forged frame:

```bash
kathara exec h1 "python3 /shared/scapy/shim.py forge --dst-ip 10.0.2.1 --gw 10.0.1.254 --score 255"
```

## How r1 handles the shim

r1 is a real IPv4 router, but frames with a shim never reach its kernel. The XDP
program on both interfaces:

1. Parses Ethernet and the shim, then the IPv4 header behind it.
2. Routes with `bpf_fib_lookup`, the kernel's own FIB and neighbour table.
3. Updates the shim in place, strips it, or inserts one, depending on the ingress and
   egress roles. It then rewrites the MACs, decrements the TTL and returns `bpf_redirect`.
4. For frames the kernel has to handle (ARP, packets to r1 itself, TTL 1, no neighbour
   entry yet), it strips the shim and returns `XDP_PASS`.

Inserting and stripping are cheap because of the field order. The shim's last field,
the next EtherType, sits exactly where the Ethernet EtherType sits once the shim is
gone. Either way, the program only moves the 12 MAC bytes:

```
with shim:     dst  src  88B5 | ver score bitmap key next=0800 | IPv4 ...
without:                 dst  src                     type=0800 | IPv4 ...
```

## Files

```
lab.conf                  topology
h1/h2.startup             addresses, default route via r1
s1/s2/s3.startup          -> shared/p4/switch.sh NAME "FABRIC_IFACES"
r1.startup                addresses, MTU 1508, offloads off, load XDP
image/Dockerfile          kathara-shim (Debian bookworm)
shared/p4/shim.p4         v1model program: parse, insert, update, strip, forgery
shared/p4/s1.txt ...      table entries per switch; plain.txt clears the roles
shared/p4/switch.sh       compile, start simple_switch, load tables
shared/p4/p4ctl.sh        stats / reset / plain / restore / cli
shared/xdp/shim.h         shim struct, roles, counters (shared with shimctl)
shared/xdp/shim_router.bpf.c   XDP router
shared/xdp/shimctl.c      libbpf loader + CLI
shared/xdp/load.sh        build into /tmp/shim-xdp and attach
shared/scapy/shim.py      Scapy layer + decode / check / forge
test.sh                   end-to-end checklist
```

## Caveats and choices

- **Placeholder values only.** No decay, no deposits, no thresholds: that's week 3.
  The M and T flags are always 0.
- **Frames from r1's own kernel carry no shim.** That covers ARP, and the first packet
  of a flow while r1 still resolves the next hop. XDP only sees ingress. The paper
  gives egress work to tc, which week 2 doesn't need. `test.sh` warms up the ARP
  caches first.
- **Every frame from a host port gets a shim**, ARP included, as the paper says. r1
  strips it before handing ARP to its kernel.
- **Captures on r1's receive path show frames after XDP.** Generic XDP runs before
  tcpdump, so link C is captured on s2's side.
- **MTU.** The fabric interfaces are set to 1508 in the startup files. That's enough
  with Kathará's default network plugin (`katharanp_vde`), whose links don't check
  MTU. With the legacy bridge plugin, the host-side bridge ports would need 1508 too.
- **No VLAN tags.** The paper places the shim after any VLAN tag. The lab has none,
  so the parsers don't look for them.
- **Spec gaps resolved here.** The version is 1. The 16-bit fields are big-endian.
  The key hint is carried, never recomputed.
- **BMv2 on arm64.** `kathara/p4` publishes an arm64 build. If the pull gives you
  amd64 instead, Kathará refuses to run it on Apple Silicon.

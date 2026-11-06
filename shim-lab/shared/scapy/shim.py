#!/usr/bin/env python3
"""Scapy layer for the 8-byte pheromone shim (EtherType 0x88B5).

    from shim import Shim          # importing binds it to Ether type 0x88B5
    Ether()/Shim(path_score=4, bitmap=0x0001)/IP(dst="10.0.2.1")/ICMP()

Command line:
    shim.py decode PCAP...                 one line per frame
    shim.py check PCAP --icmp request|reply --shim yes|no [--score N]
                                           exit 0 and print PASS if every matching
                                           ICMP echo frame meets the expectation
    shim.py forge --iface eth0 --dst-ip 10.0.2.1 --gw 10.0.1.254 [--score 255] [--count 3]
                                           send echo requests that already carry a
                                           (forged) shim, as a malicious host would
"""
import argparse
import sys

from scapy.all import (ARP, ICMP, IP, IPv6, Ether, Packet, BitField, ByteField,
                       XShortField, XShortEnumField, bind_layers, getmacbyip,
                       get_if_hwaddr, rdpcap, sendp)
from scapy.data import ETHER_TYPES

ETH_P_SHIM = 0x88B5


class Shim(Packet):
    name = "PheromoneShim"
    fields_desc = [
        BitField("version", 1, 4),
        BitField("m", 0, 1),        # already mirrored
        BitField("t", 0, 1),        # tagged
        BitField("rsvd", 0, 2),
        ByteField("path_score", 0),
        XShortField("bitmap", 0),   # contributor bitmap
        XShortField("key_hint", 0),
        XShortEnumField("next_type", 0x0800, ETHER_TYPES),
    ]

    def mysummary(self):
        return self.sprintf(
            "Shim v%version% score=%path_score% bitmap=%bitmap% key=%key_hint%")


bind_layers(Ether, Shim, type=ETH_P_SHIM)
bind_layers(Shim, IP, next_type=0x0800)
bind_layers(Shim, ARP, next_type=0x0806)
bind_layers(Shim, IPv6, next_type=0x86DD)


def wirelen(pkt):
    """Length on the wire (captures are taken with a short snaplen)."""
    return getattr(pkt, "wirelen", None) or len(pkt)


def describe(pkt):
    """One-line description of a frame, shim first."""
    if Shim in pkt:
        s = pkt[Shim]
        flags = ("M" if s.m else "-") + ("T" if s.t else "-")
        bits = bin(s.bitmap).count("1")
        head = (f"SHIM v{s.version} {flags} score={s.path_score:<3} "
                f"bitmap=0x{s.bitmap:04x} ({bits} bit{'s' if bits != 1 else ''}) "
                f"key=0x{s.key_hint:04x} next=0x{s.next_type:04x}")
    else:
        head = f"no shim{'':59}" if Ether in pkt else "not ethernet"
    if ICMP in pkt and IP in pkt:
        kind = {8: "echo-request", 0: "echo-reply"}.get(pkt[ICMP].type, f"icmp {pkt[ICMP].type}")
        body = f"{pkt[IP].src} > {pkt[IP].dst} {kind} len={wirelen(pkt)}"
    elif ARP in pkt:
        body = f"ARP {'who-has' if pkt[ARP].op == 1 else 'is-at'} {pkt[ARP].pdst}"
    else:
        body = pkt.lastlayer().name
    return f"{head} | {body}"


def cmd_decode(args):
    for path in args.pcap:
        print(f"== {path}")
        for p in rdpcap(path):
            print("  " + describe(p))


def cmd_check(args):
    want_type = {"request": 8, "reply": 0}[args.icmp]
    frames = [p for p in rdpcap(args.pcap)
              if ICMP in p and p[ICMP].type == want_type
              and (args.size is None or wirelen(p) >= args.size)]
    ok = bool(frames)
    for p in frames:
        good = (Shim in p) == (args.shim == "yes")
        if good and args.shim == "yes" and args.score is not None:
            good = p[Shim].path_score == args.score
        ok &= good
        print(f"  {'ok ' if good else 'BAD'} {describe(p)}")
    if not frames:
        print(f"  no ICMP echo-{args.icmp} frames in {args.pcap}")
    expect = f"shim={args.shim}" + (f" score={args.score}" if args.score is not None else "")
    print(f"{'PASS' if ok else 'FAIL'}: {args.label or args.pcap}: echo-{args.icmp} {expect}")
    return 0 if ok else 1


def cmd_forge(args):
    src = get_if_hwaddr(args.iface)
    gw_mac = getmacbyip(args.gw)
    if not gw_mac:
        sys.exit(f"cannot resolve {args.gw}")
    pkt = (Ether(src=src, dst=gw_mac)
           / Shim(path_score=args.score, bitmap=args.bitmap, key_hint=args.key)
           / IP(dst=args.dst_ip) / ICMP(id=0xf00d) / b"forged-shim")
    print("sending: " + describe(pkt))
    sendp(pkt, iface=args.iface, count=args.count, inter=0.2, verbose=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode")
    d.add_argument("pcap", nargs="+")

    c = sub.add_parser("check")
    c.add_argument("pcap")
    c.add_argument("--icmp", choices=["request", "reply"], required=True)
    c.add_argument("--shim", choices=["yes", "no"], required=True)
    c.add_argument("--score", type=int)
    c.add_argument("--size", type=int, help="only frames at least this long")
    c.add_argument("--label")

    f = sub.add_parser("forge")
    f.add_argument("--iface", default="eth0")
    f.add_argument("--dst-ip", required=True)
    f.add_argument("--gw", required=True)
    f.add_argument("--score", type=int, default=255)
    f.add_argument("--bitmap", type=lambda x: int(x, 0), default=0xffff)
    f.add_argument("--key", type=lambda x: int(x, 0), default=0xbeef)
    f.add_argument("--count", type=int, default=3)

    args = ap.parse_args()
    return {"decode": cmd_decode, "check": cmd_check, "forge": cmd_forge}[args.cmd](args) or 0


if __name__ == "__main__":
    sys.exit(main())

#!/bin/bash
# End-to-end check of the week 2 checklist. Run from your Mac, in this folder,
# after `kathara lstart --privileged`.
#
#   1  P4 insert/strip, per-hop update, XDP interop  (the week 2 exit criterion)
#   2  Forgery at a P4 edge switch
#   3  XDP insert and strip (s1 turned into a plain switch), and forgery at r1
#   4  MTU: a full-size DF packet crosses; shrink r1's fabric MTU and it can't
#
# Captures land in shared/captures/ and are decoded on r1 with shared/scapy/shim.py.
#
#   h1 --A-- s1 --B-- s2 --C-- r1 --D-- s3 --E-- h2
#   capture: A=h1:eth0  B=s2:eth0  C=s2:eth1  D=s3:eth0  E=h2:eth0
# (C is captured on s2, not r1: XDP runs before tcpdump on r1's receive path.)

cd "$(dirname "$0")"
mkdir -p shared/captures
CAPTIME=${CAPTIME:-7}
PASS=0; FAIL=0

# Run one command string in a device. Kathará splits it like a shell would
# (shlex) but doesn't run a shell, so pipes and && need an explicit bash -c.
kx() { ${KX:-kathara exec} "$1" "$2"; }

result() {   # result "check output": print it, keep score
    echo "$1"
    PASS=$((PASS + $(grep -c '^PASS' <<< "$1")))
    FAIL=$((FAIL + $(grep -c '^FAIL' <<< "$1")))
}

expect() {   # expect "label" condition-command-output grep-pattern
    if grep -qE -- "$3" <<< "$2"; then result "PASS: $1"
    else result "FAIL: $1"; sed 's/^/    /' <<< "$2"; fi
}

capture() {  # capture DEV IFACE NAME  (background, CAPTIME seconds)
    rm -f "shared/captures/$3.pcap"
    kx "$1" "timeout $CAPTIME tcpdump -i $2 -U -s 200 -w /shared/captures/$3.pcap ether proto 0x88b5 or icmp" >/dev/null 2>&1 &
}

check() {    # check NAME request|reply yes|no [score] [label] [size]
    local score=${4:+--score $4} size=${6:+--size $6}
    result "$(kx r1 "python3 /shared/scapy/shim.py check /shared/captures/$1.pcap --icmp $2 --shim $3 $score $size --label '$5'")"
}

capture_all() { capture h1 eth0 A; capture s2 eth0 B; capture s2 eth1 C; capture s3 eth0 D; capture h2 eth0 E; sleep 2; }

reset_counters() {
    for s in s1 s2 s3; do kx $s "bash /shared/p4/p4ctl.sh reset" >/dev/null; done
    kx r1 "shimctl reset" >/dev/null
}

echo "== warm-up (ARP, neighbour entries)"
kx h1 "ping -c 2 -W 1 10.0.2.1" | tail -2
reset_counters

# ---------------------------------------------------------------------------
echo; echo "== 1. ping h1 -> h2 across s1, s2, r1 (XDP), s3"
capture_all
kx h1 "ping -c 3 -i 0.3 10.0.2.1" | tail -2
wait
check A request no  "" "A h1-s1: no shim at the host"
check B request yes 4  "B s1-s2: s1 inserted, score 4"
check C request yes 5  "C s2-r1: s2 updated, score 5"
check D request yes 6  "D r1-s3: r1 (XDP) updated, score 6"
check E request no  "" "E s3-h2: s3 stripped"
check E reply   no  "" "E s3-h2: no shim at the host"
check D reply   yes 4  "D: s3 inserted the reply, score 4"
check C reply   yes 5  "C: r1 updated, score 5"
check B reply   yes 6  "B: s2 updated, score 6"
check A reply   no  "" "A: s1 stripped before h1"

# ---------------------------------------------------------------------------
echo; echo "== 2. forgery: h1 sends frames that already carry a shim (score 255)"
kx s1 "bash /shared/p4/p4ctl.sh reset" >/dev/null
capture s2 eth0 B2; sleep 2
kx h1 "python3 /shared/scapy/shim.py forge --dst-ip 10.0.2.1 --gw 10.0.1.254 --score 255 --count 3"
wait
check B2 request yes 4 "B: s1 stripped the forged shim and inserted its own (score 4, not 255)"
out=$(kx s1 "bash /shared/p4/p4ctl.sh stats")
expect "s1 counted 3 forged frames on port 0" "$out" 'forged on port 0 \(eth0\) +3$'

# ---------------------------------------------------------------------------
echo; echo "== 3. XDP insert and strip: s1 becomes a plain switch, r1's eth0 becomes host-facing"
kx s1 "bash /shared/p4/p4ctl.sh plain"
kx r1 "shimctl role eth0 host score 8 bitmap 0x0100"
kx r1 "shimctl reset" >/dev/null
capture s2 eth1 C3; capture s3 eth0 D3; sleep 2
kx h1 "ping -c 3 -i 0.3 10.0.2.1" | tail -2
wait
check C3 request no  "" "C: request arrives at r1 without a shim"
check D3 request yes 8  "D: r1 inserted it (adjust_head -8), score 8"
check D3 reply   yes 4  "D: reply carries the shim s3 inserted, score 4"
check C3 reply   no  "" "C: r1 stripped it toward the host-facing side (adjust_head +8)"
out=$(kx r1 "shimctl stats")
expect "r1 inserted >= 3" "$out" 'inserted \(adjust_head -8\) +([3-9]|[1-9][0-9]+)$'
expect "r1 stripped >= 3" "$out" 'stripped \(adjust_head \+8\) +([3-9]|[1-9][0-9]+)$'

echo; echo "== 3b. forgery at r1: a shim arriving on r1's host-facing port"
capture s3 eth0 D3b; sleep 2
kx h1 "python3 /shared/scapy/shim.py forge --dst-ip 10.0.2.1 --gw 10.0.1.254 --score 255 --count 3"
wait
check D3b request yes 8 "D: r1 replaced the forged shim (score 8, not 255)"
out=$(kx r1 "shimctl stats")
expect "r1 counted 3 forged frames" "$out" 'forged \(shim on host port\) +3$'

kx s1 "bash /shared/p4/p4ctl.sh restore s1"
kx r1 "shimctl role eth0 fabric"

# ---------------------------------------------------------------------------
echo; echo "== 4. MTU: 1500-byte IP packet, DF set (fabric MTU 1508)"
capture s3 eth0 D4; sleep 2
out=$(kx h1 "ping -M do -s 1472 -c 2 -W 2 10.0.2.1")
wait
expect "full-size DF ping crosses the lab" "$out" " 0% packet loss"
check D4 request yes 6 "D: 1522-byte frame on the wire with the shim" 1522

echo; echo "== 4b. r1 eth1 back to MTU 1500: the shimmed frame no longer fits"
kx r1 "ip link set eth1 mtu 1500"
kx r1 "shimctl reset" >/dev/null
out=$(kx h1 "ping -M do -s 1472 -c 2 -W 2 10.0.2.1")
expect "full-size DF ping fails" "$out" "100% packet loss"
out=$(kx r1 "shimctl stats")
expect "r1 counted MTU drops" "$out" 'dropped: MTU too small +[1-9]'
out=$(kx h1 "ping -c 1 -W 2 10.0.2.1")
expect "small pings still work" "$out" " 0% packet loss"
kx r1 "ip link set eth1 mtu 1508"

# ---------------------------------------------------------------------------
echo
echo "== $PASS passed, $FAIL failed"
echo "   decode any capture:  kathara exec r1 \"python3 /shared/scapy/shim.py decode /shared/captures/B.pcap\""
[ "$FAIL" -eq 0 ]

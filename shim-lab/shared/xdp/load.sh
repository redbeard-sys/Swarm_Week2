#!/bin/bash
# Build and (re)attach the shim router on r1.
#   bash /shared/xdp/load.sh        build, attach to eth0 + eth1, both fabric
#   bash /shared/xdp/load.sh off    detach and unpin
set -e
cd /shared/xdp
if [ "${1:-}" = off ]; then
    /tmp/shim-xdp/shimctl detach eth0 eth1
    exit 0
fi
make -s
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
/tmp/shim-xdp/shimctl detach eth0 eth1 >/dev/null 2>&1 || true   # fresh maps
/tmp/shim-xdp/shimctl attach ${XDP_MODE:-skb} eth0 eth1
/tmp/shim-xdp/shimctl role eth0 fabric
/tmp/shim-xdp/shimctl role eth1 fabric
ln -sf /tmp/shim-xdp/shimctl /usr/local/bin/shimctl

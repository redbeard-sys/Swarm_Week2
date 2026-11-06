#!/bin/bash
# Start one BMv2 switch.  usage: switch.sh NAME "FABRIC_IFACES"
# Compiles /shared/p4/shim.p4, runs simple_switch on eth0 (port 0) and eth1
# (port 1), then loads /shared/p4/NAME.txt. Log: /var/log/p4switch.log
NAME=$1
FABRIC=$2
exec >> /var/log/p4switch.log 2>&1
echo "== $(date) starting $NAME"

sysctl -qw net.ipv6.conf.all.disable_ipv6=1
for i in eth0 eth1; do
    ip link set $i up
    ethtool -K $i tx off rx off gro off >/dev/null 2>&1
done
for i in $FABRIC; do
    ip link set $i mtu 1508            # room for the 8-byte shim
done

mkdir -p /tmp/p4
if ! p4c-bm2-ss --std p4-16 -o /tmp/p4/$NAME.json /shared/p4/shim.p4; then
    echo "p4c failed"; exit 1
fi

[ -f /tmp/p4/$NAME.pid ] && kill "$(cat /tmp/p4/$NAME.pid)" 2>/dev/null && sleep 0.5
simple_switch -i 0@eth0 -i 1@eth1 --thrift-port 9090 /tmp/p4/$NAME.json \
    > /var/log/simple_switch-$NAME.log 2>&1 &
echo $! > /tmp/p4/$NAME.pid

for _ in $(seq 1 40); do
    echo | simple_switch_CLI --thrift-port 9090 2>/dev/null | grep -q RuntimeCmd && break
    sleep 0.5
done
grep -v '^#' /shared/p4/$NAME.txt | simple_switch_CLI --thrift-port 9090
echo "== $NAME ready"

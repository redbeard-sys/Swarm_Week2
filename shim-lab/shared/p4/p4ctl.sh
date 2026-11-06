#!/bin/bash
# Run on a switch:  bash /shared/p4/p4ctl.sh stats | reset | plain | restore NAME | cli
cli() { simple_switch_CLI --thrift-port 9090 2>/dev/null; }
case "${1:-stats}" in
  stats)
    s=$(echo "register_read ShimIngress.shim_stats" | cli | grep -o '= .*' | tr -d '= ')
    f=$(echo "register_read ShimIngress.forged_by_port" | cli | grep -o '= .*' | tr -d '= ')
    IFS=, read -r ins upd str forg <<< "$s"
    printf '  %-26s %8s\n' inserted "$ins" "updated (+hop)" "$upd" stripped "$str" forged "$forg"
    IFS=, read -r p0 p1 _ <<< "$f"
    printf '  %-26s %8s\n' "forged on port 0 (eth0)" "$p0" "forged on port 1 (eth1)" "$p1"
    ;;
  reset)
    printf 'register_reset ShimIngress.shim_stats\nregister_reset ShimIngress.forged_by_port\n' | cli >/dev/null
    echo "counters zeroed" ;;
  plain)   # act like a non-programmable switch: forward only
    grep -v '^#' /shared/p4/plain.txt | cli >/dev/null; echo "plain mode" ;;
  restore) # put the role entries from NAME.txt back
    grep '_role' /shared/p4/$2.txt | cli >/dev/null; echo "roles restored from $2.txt" ;;
  cli) simple_switch_CLI --thrift-port 9090 ;;
  *) echo "usage: p4ctl.sh stats|reset|plain|restore NAME|cli"; exit 1 ;;
esac

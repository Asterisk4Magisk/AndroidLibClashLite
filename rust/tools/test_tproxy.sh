#!/system/bin/sh
# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

set -eu
# Invoke ONLY through `unshare -n`: all routes/rules die with this namespace.
ip link set lo up
ip addr add 10.77.0.2/32 dev lo
ip -6 addr add 2001:db8:1::2/128 dev lo nodad
ip route add 198.18.0.0/24 dev lo src 10.77.0.2
ip -6 route add 2001:db8:2::/64 dev lo src 2001:db8:1::2
ip rule add pref 100 fwmark 1 lookup 100
ip route add local default dev lo table 100
ip -6 rule add pref 100 fwmark 1 lookup 100
ip -6 route add local default dev lo table 100
for tool in iptables ip6tables; do
    for proto in tcp udp; do
        "$tool" -t mangle -A OUTPUT -p "$proto" --dport 18080 -j MARK --set-mark 1
        "$tool" -t mangle -A PREROUTING -p "$proto" --dport 18080 -j TPROXY --on-port 18081 --tproxy-mark 1/1
    done
done
"$1" --ignored --exact network_tests::android_tproxy_dual_stack_roundtrip_and_restart --test-threads=1 --nocapture

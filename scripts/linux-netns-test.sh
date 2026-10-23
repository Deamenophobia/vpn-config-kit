#!/usr/bin/env bash
# Run only on a disposable Linux test machine. No routes are changed in the caller's namespace.
set -euo pipefail
if [[ ${1:-} != --inside ]]; then
  [[ $EUID == 0 ]] || { echo 'Run as root on a disposable Linux VM.' >&2; exit 1; }
  : "${VPN_CONFIG_KIT_BIN:?Set VPN_CONFIG_KIT_BIN to the absolute built Linux binary path}"
  export VPN_CONFIG_KIT_ORIGINAL_NETNS=$(readlink /proc/self/ns/net)
  export VPN_CONFIG_KIT_ORIGINAL_MOUNTNS=$(readlink /proc/self/ns/mnt)
  exec unshare --mount --net --pid --fork --mount-proc --propagation private bash "$0" --inside
fi
[[ -n ${VPN_CONFIG_KIT_ORIGINAL_NETNS:-} && $(readlink /proc/self/ns/net) != "$VPN_CONFIG_KIT_ORIGINAL_NETNS" ]] || { echo 'Missing network isolation' >&2; exit 1; }
[[ -n ${VPN_CONFIG_KIT_ORIGINAL_MOUNTNS:-} && $(readlink /proc/self/ns/mnt) != "$VPN_CONFIG_KIT_ORIGINAL_MOUNTNS" ]] || { echo 'Missing mount isolation' >&2; exit 1; }
for tool in ip wg wg-quick nft sysctl ping jq mount timeout; do
  command -v "$tool" >/dev/null || { echo "Missing test prerequisite: $tool" >&2; exit 1; }
done
[[ -x "$VPN_CONFIG_KIT_BIN" ]] || exit 1
umask 077
work=$(mktemp -d)
cleanup() {
  for ns in client gateway exit; do ip netns delete "$ns" 2>/dev/null || true; done
  # mktemp owns this exact directory; never evaluate an arbitrary input path here.
  [[ -n "$work" && -d "$work" ]] && rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
for ns in client gateway exit; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add c0 type veth peer name g0
ip link set c0 netns client
ip link set g0 netns gateway
ip -n client link set c0 name eth0
ip -n gateway link set g0 name edge0
ip link add g1 type veth peer name e0
ip link set g1 netns gateway
ip link set e0 netns exit
ip -n gateway link set g1 name egress0
ip -n exit link set e0 name eth0
ip -n client addr add 192.0.2.2/24 dev eth0
ip -n gateway addr add 192.0.2.1/24 dev edge0
ip -n gateway addr add 198.51.100.1/24 dev egress0
ip -n exit addr add 198.51.100.2/24 dev eth0
ip -n client link set eth0 up
ip -n gateway link set edge0 up
ip -n gateway link set egress0 up
ip -n exit link set eth0 up
ip -n client route add default via 192.0.2.1
ip netns exec gateway sysctl -qw net.ipv4.ip_forward=1
ip netns exec client sysctl -qw net.ipv6.conf.all.disable_ipv6=1
cat >"$work/gateway.toml" <<EOF
version=1
interface="wggw"
endpoint="192.0.2.1:51820"
egress_interface="egress0"
state_dir="$work/state"
dns_policy="preserve"
dns=[]
EOF
gw() { ip netns exec gateway "$VPN_CONFIG_KIT_BIN" --config "$work/gateway.toml" "$@"; }
gw init >"$work/init.json"
"$VPN_CONFIG_KIT_BIN" keygen --out "$work/client.key" >"$work/key.json"
public=$(jq -r .public_key "$work/key.json")
gw peer add --name test --public-key "$public" --defer >/dev/null
gw firewall-plan --out "$work/firewall.sh" >/dev/null
ip netns exec gateway nft add table inet unrelated_test
ip netns exec gateway sh "$work/firewall.sh" apply
ip netns exec gateway sh "$work/firewall.sh" apply
gw up >/dev/null
gw peer export test --private-key-file "$work/client.key" --out "$work/wgclient.conf" --ipv6-block-confirmed >/dev/null
ip netns exec client wg-quick up "$work/wgclient.conf"
ip netns exec client ping -c 3 -W 2 198.51.100.2
# Exit has no route to 10.77.0.0/24: a successful reply requires gateway NAT.
ip netns exec gateway wg show wggw latest-handshakes | awk '{ if ($2 > 0) found=1 } END {exit !found}'
ip netns exec gateway wg show wggw transfer | awk '{ if ($2 > 0 && $3 > 0) found=1 } END {exit !found}'
gw doctor >"$work/doctor.json"
# Exercise actual native parser and wg-quick extension stripping.
ip netns exec gateway wg setconf wggw "$work/state/runtime.conf"
ip netns exec client wg-quick strip "$work/wgclient.conf" >"$work/client-native.conf"
ip netns exec client wg setconf wgclient "$work/client-native.conf"
gw down >/dev/null
gw up >/dev/null
reconnected=false
for attempt in {1..10}; do
  if ip netns exec client ping -c 1 -W 2 198.51.100.2; then reconnected=true; break; fi
  sleep 1
done
"$reconnected"
gw peer revoke test >/dev/null
gw reconcile >/dev/null
if ip netns exec client ping -c 1 -W 2 198.51.100.2; then echo 'Revoked peer still carries traffic' >&2; exit 1; fi
[[ -z $(ip netns exec gateway wg show wggw peers) ]]
! grep -Fq "$public" "$work/state/wggw.conf"
! grep -Fq "$public" "$work/state/runtime.conf"
gw down >/dev/null
gw up >/dev/null
[[ -z $(ip netns exec gateway wg show wggw peers) ]]
ip netns exec gateway sh "$work/firewall.sh" remove
ip netns exec gateway sh "$work/firewall.sh" remove
ip netns exec gateway nft list table inet unrelated_test >/dev/null
printf 'PASS: native parsing, handshake, encrypted routed traffic, NAT, restart, revocation, firewall repeat/reversal\n'
uname -r
wg --version
ip -Version
nft --version
"$VPN_CONFIG_KIT_BIN" --version

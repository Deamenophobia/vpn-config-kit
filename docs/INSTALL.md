# Linux installation and reversal

Target: a dedicated Linux gateway with kernel WireGuard support, wireguard-tools, iproute2, nftables, root/CAP_NET_ADMIN and systemd if boot persistence is wanted. For Xray, follow the separate [backend guide](XRAY.md).

Build with a current stable Rust toolchain and a C compiler, then install the binary and an editable configuration:

```sh
cargo build --locked --release
sudo install -m 755 target/release/vpn-config-kit /usr/local/bin/vpn-config-kit
sudo install -d -m 700 /etc/vpn-config-kit
sudo install -m 600 examples/gateway.toml /etc/vpn-config-kit/gateway.toml
```

Edit the endpoint, egress interface and address pool in `gateway.toml` before continuing.

1. Select an unused interface and non-overlapping RFC1918 pool. Check the real egress interface with `ip route`; the example is illustrative.
2. Run `sudo vpn-config-kit check`, then `sudo vpn-config-kit init`. Save the displayed gateway public key for client identity verification. `init` does not start an interface or forward traffic.
3. Save the previous `net.ipv4.ip_forward` value in a protected operator record. Review the consequences for existing forwarding services. Enable IPv4 forwarding with `sudo sysctl -w net.ipv4.ip_forward=1`. For reboot persistence, create a dedicated `/etc/sysctl.d/90-vpn-config-kit.conf` with that one setting. Keep IPv6 forwarding disabled unless separately managed for another purpose; this project does not implement IPv6 gateway service.
4. Generate `sudo vpn-config-kit firewall-plan --out /etc/vpn-config-kit/gateway-firewall.sh`. Review it alongside `sudo nft list ruleset`. The script owns only `inet vpn_config_kit_<interface>`, allows tunnel-to-egress forwarding and established return traffic, drops other traffic to/from the tunnel, and masquerades only the configured IPv4 pool on the selected egress. Confirm the reserved table name is unused before first application. Apply explicitly with `sudo sh /etc/vpn-config-kit/gateway-firewall.sh apply`. Reapplying replaces only that table atomically. No ruleset flush, default-policy changes or SSH rule changes are performed.
5. Existing host/cloud firewalls may still drop the WireGuard UDP port or forwarded traffic: an nftables accept in one base chain cannot override a later drop. Integrate narrowly scoped allows into your existing firewall policy as needed. Open only the selected UDP port in the cloud firewall. Do not expose a management port; there is none. The generated input rule does not implement a general host firewall.
6. Run `sudo vpn-config-kit up`, [enroll a peer and export its profile](USAGE.md), then securely deliver it. Run `sudo vpn-config-kit doctor`. Retain access through your existing administrator connection during setup.

Server `<interface>.conf` is a wg-quick boot file with addresses but no shell hooks or `SaveConfig`. `runtime.conf` contains only native wg settings. Do not copy either into a second active config location. This avoids a stale `/etc/wireguard` copy resurrecting revoked peers after restart.

For service persistence, install the example unit and use the matching config filename:

```sh
sudo install -m 644 examples/vpn-config-kit@.service /etc/systemd/system/vpn-config-kit@.service
sudo install -m 644 examples/vpn-config-kit-firewall@.service /etc/systemd/system/vpn-config-kit-firewall@.service
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-config-kit@gateway.service
sudo systemctl reload vpn-config-kit@gateway.service
```

The example gateway unit requires the matching firewall unit, which applies `/etc/vpn-config-kit/gateway-firewall.sh` before startup and removes its table when stopped. For an existing firewall manager, integrate the owned rules there and adjust this dependency deliberately. Do not overwrite a system-wide `/etc/nftables.conf` maintained by another firewall. Test both firewall and gateway restoration after reboot; the generated script must exist before enabling the service pair.

To reverse: disable/stop `vpn-config-kit@gateway.service` (or run `vpn-config-kit down`), stop `vpn-config-kit-firewall@gateway.service` if installed, run `sh /etc/vpn-config-kit/gateway-firewall.sh remove`, remove only the dedicated unit/drop-ins and owned sysctl file, and restore the recorded forwarding value **only if no other service needs it**. Remove the cloud UDP rule you added. Keep the private state backup or explicitly destroy it; do not leave old boot configs enabled. Repeated firewall removal is safe. Changing interface names requires removing the old owned table as well as setting up the new one.

Troubleshooting:

| Symptom | Next check |
| --- | --- |
| Pending/revoking with last_error | Correct the named persistence/runtime prerequisite, then `up` or `reconcile`; keep the database and key |
| Another operation is running | Wait for that process; locks release on process exit; do not delete operation.lock |
| Interface ownership/key mismatch | Inspect local managers; use an unused interface or restore the matching key/state; do not force adoption |
| No handshake | Client/server public keys, endpoint IPv4 resolution, UDP port and both host/cloud firewall |
| Handshake but no internet | Forwarding sysctl, egress interface, NAT and all filter chains; then DNS |
| DNS failure | Resolver reachable through client routes; client DNS integration; Linux wg-quick DNS requires resolvconf-compatible tooling |
| Pool overlap | Choose unused space before initialization; include client LAN/VPC/container networks in excluded_subnets |
| Timeout | Inspect the owned interface, then retry `up` for incomplete link setup or `reconcile` for peer synchronization |
| Private-path error | Correct ownership/0600 files/0700 directories or Windows ACL; symlinks are deliberately rejected |

WireGuard format references: [wg manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8), [wg-quick manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8), [quickstart](https://www.wireguard.com/quickstart/).

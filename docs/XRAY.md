# Xray backend

VPN Config Kit manages one dedicated Xray service using VLESS, REALITY and the `xtls-rprx-vision` flow over RAW/TCP. WireGuard remains the default backend. Choose Xray explicitly with `--backend xray-reality`; each backend has its own configuration and state directory. They can run on the same server independently.

The supported engine is upstream Xray **26.10.21**, x86_64. The manager checks its exact artifact digest before use. Engine upgrades require a matching toolkit update. Native client JSON targets the same engine version; connection links require a client that supports this protocol/security/flow combination.

## Install and configure

Install the toolkit as `/usr/local/bin/vpn-config-kit`, then install the external engine:

```sh
sudo sh scripts/install-xray.sh
sudo install -d -m 700 /etc/vpn-config-kit
sudo install -m 600 examples/xray.toml /etc/vpn-config-kit/xray.toml
```

Edit `endpoint`, `server_name`, `target`, and the listening address/port. Example hostnames are placeholders. Choose a suitable TLS 1.3 target whose hostname matches `server_name`; configure the server's actual public endpoint separately. Avoid ports already owned by another service. WireGuard commonly uses UDP while this preset uses TCP.

| Setting | Default / meaning |
| --- | --- |
| version / backend | `1` / `xray-reality`; strict schema |
| listen / listen_port | `0.0.0.0` / `443`; TCP listener, configured with an IPv4 address |
| endpoint | Required IPv4 address or hostname and port used by clients |
| server_name | Required TLS hostname used by REALITY |
| target | Required target host:port |
| state_dir | `/var/lib/vpn-config-kit-xray`; dedicated private directory |
| engine_path | `/usr/local/lib/vpn-config-kit/xray` |
| manager_path | `/usr/local/bin/vpn-config-kit` |
| command_timeout_secs | `30`; range 10–120 |
| allow_private_destinations | `false`; blocks clients from reaching local/private/reserved IPv4 ranges and IPv6 destinations |

Paths in generated systemd units must use letters, digits, `/`, `_`, `.` or `-`. Use `--set 'field=TOML_VALUE'` for overrides. Applied settings are saved to protected `managed.toml`; the service uses that snapshot after reboot. Edit your main TOML and run `reconcile` to apply changes.

Reserve the TCP port exclusively for this service. Wildcard listening can use a dual-stack socket on the host; use an explicit IPv4 listen address and host/cloud firewall rules to constrain ingress. The default outbound policy blocks IPv6 destinations.

```sh
sudo vpn-config-kit --backend xray-reality check
sudo vpn-config-kit --backend xray-reality init
sudo vpn-config-kit --backend xray-reality service-plan --out /etc/vpn-config-kit/xray.service
```

`init` prints a public `service` name, such as `vpn-config-kit-xray-<instance>.service`. Install the generated file using **that exact name**:

```sh
sudo install -m 644 /etc/vpn-config-kit/xray.service /etc/systemd/system/NAME_FROM_OUTPUT
sudo systemctl daemon-reload
sudo vpn-config-kit --backend xray-reality firewall-plan --out /etc/vpn-config-kit/xray-firewall.sh
sudo sh /etc/vpn-config-kit/xray-firewall.sh apply
sudo vpn-config-kit --backend xray-reality up
sudo systemctl enable NAME_FROM_OUTPUT
```

The firewall script changes only the instance's dedicated nftables table. Integrate its TCP allow with your host/cloud firewall. An accept in this table does not override a drop elsewhere. Arrange reboot persistence through your existing firewall manager. Xray's user-space proxy needs no IP forwarding or WireGuard NAT. Generated service definitions are owned exactly by the toolkit: regenerate units for path changes; arbitrary systemd drop-ins are rejected.

## Devices and exports

```sh
sudo vpn-config-kit --backend xray-reality peer add --name phone
sudo vpn-config-kit --backend xray-reality peer export phone --out /absolute/private/phone.json
sudo vpn-config-kit --backend xray-reality peer export phone \
  --format link --out /absolute/private/phone.txt --qr /absolute/private/phone.svg
sudo vpn-config-kit --backend xray-reality peer list
sudo vpn-config-kit --backend xray-reality doctor
```

JSON profiles start a **loopback SOCKS proxy** at `127.0.0.1:10808`; `--socks-port` changes that port. Run with `xray run -config phone.json`, then point applications at it. Use remote DNS where supported. A SOCKS proxy only carries configured applications. Full-device routing, IPv6 blocking, DNS handling and disconnect policy belong to the chosen client's TUN/VPN mode. The toolkit does not configure a client kill switch.

The selected Vision flow intercepts proxied UDP port 443, so QUIC applications need TCP fallback. Other UDP traffic can use SOCKS UDP association. See the upstream [flow modes](https://xtls.github.io/en/config/outbounds/vless.html#outboundconfigurationobject).

Links and QR images support clients that accept `type=tcp`, `security=reality`, `flow=xtls-rprx-vision`, SNI, public key and short ID. UUIDs, full links, profiles and QR images are credentials. Exports refuse overwrites. Status output excludes UUIDs and full profiles.

```sh
sudo vpn-config-kit --backend xray-reality peer rotate phone
sudo vpn-config-kit --backend xray-reality peer revoke phone
sudo vpn-config-kit --backend xray-reality reconcile
sudo vpn-config-kit --backend xray-reality down
```

Rotation requires a new export for that device. `rotate-server-key` rotates the REALITY key and requires new exports for **every** Xray device. Add `--defer` to enrollment, rotation or revocation to save intent offline, then apply it with `up` or `reconcile`.

Applying credentials stops and restarts the dedicated Xray service, interrupting **all** its sessions. WireGuard is unaffected. Intent is recorded first; completion requires agreement between the owned process, listening socket and persisted configuration. Failures retain retry state. Revoked names remain reserved as tombstones. Startup refuses a saved configuration that differs from current desired state, preventing an interrupted edit from silently reusing stale credentials at boot.

`peer revoke` affects only the selected backend. Revoke each profile separately when a device has both WireGuard and Xray access.

## Recovery and removal

Keep `xray-state.json`, `managed.toml`, `xray.json`, and your main TOML in a protected backup. State includes the server private key and device credentials. `candidate.json` is private staging material. Stop managers and the service before backing up; restore matching files together. Reapply subsequent revocations before restarting an older backup.

Correct the reported prerequisite and run `reconcile` after an interruption. Do not replace missing state with new keys over an existing runtime configuration. Re-export profiles after changing endpoints, server names or keys.

To remove Xray, run `down`, disable its exact service, remove only that unit and run `systemctl daemon-reload`. Run `sh /etc/vpn-config-kit/xray-firewall.sh remove`, remove its entry from your firewall manager and remove the corresponding cloud TCP rule. Retain or deliberately destroy private backups and exports. Remove the standalone engine only if nothing else uses it.

References: [VLESS](https://xtls.github.io/en/config/inbounds/vless.html), [REALITY](https://xtls.github.io/en/config/transports/reality.html), [engine release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21).

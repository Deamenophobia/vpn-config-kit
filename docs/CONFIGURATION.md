# Configuration and CLI reference

WireGuard is the default backend; this reference describes its version-1 schema. Select the optional backend with `--backend xray-reality` and use the separate [Xray settings and commands](XRAY.md). Existing WireGuard TOML files need no migration. Each backend has its own versioned file and protected state; adding Xray does not convert WireGuard peers or credentials.

Use a versioned TOML file (`--config`, default `/etc/vpn-config-kit/gateway.toml`). Unknown fields and unsupported versions are errors. Precedence is explicit `--set 'field=TOML_VALUE'` assignments (last wins), file values, then defaults. No environment settings override configuration. Error messages suppress TOML source lines because they could contain accidentally pasted secrets.

```sh
vpn-config-kit --config /etc/vpn-config-kit/gateway.toml --set 'keepalive=25' check
vpn-config-kit --set 'endpoint="vpn.example.net:51820"' peer list
```

| Field | Default | Rules and meaning |
| --- | --- | --- |
| version | 1 | Only version 1 supported |
| interface | wg0 | Dedicated interface; letter first, then letters/digits/underscore; at most 15 characters |
| endpoint | required | Public IPv4 or DNS hostname and nonzero port; example uses reserved `example.com`; IPv6 endpoint literals unsupported |
| listen_port | 51820 | Nonzero UDP port; external endpoint port may differ with explicit upstream NAT |
| pool | 10.77.0.0/24 | Canonical RFC1918 IPv4 network, /16 through /30 |
| gateway_address | 10.77.0.1 | Inside pool; network/broadcast excluded from allocation |
| egress_interface | required | Explicit interface carrying internet traffic; must differ from tunnel |
| routing | full | `full` routes all IPv4 destinations; `split` requires split_routes |
| split_routes | [] | Canonical IPv4 destination networks, no /0; these are client routes, not server peer AllowedIPs |
| dns_policy | tunnel | `tunnel` emits DNS; `preserve` requires empty dns and leaves client's existing resolver policy |
| dns | [1.1.1.1] | IPv4 resolver addresses; must be covered by client destination routes |
| ipv6_policy | block-on-client | Only supported policy; requires explicit acknowledgment on export |
| excluded_subnets | [] | Known LAN, VPC, container and client LAN ranges; rejects any overlap with pool |
| keepalive | 0 | Off, matching WireGuard default; 25 is a common NAT traversal choice |
| mtu | omitted | Let wg-quick choose; explicit 1280..9000 accepted |
| state_dir | /var/lib/vpn-config-kit | Absolute, private, dedicated directory; parent must exist; no symlink/reparse components |
| command_timeout_secs | 15 | 1..120 per system command; timeouts terminate and reap subprocesses |

Do not use the example egress interface without checking `ip route`. `up` rejects overlapping IPv4 routes in all tables on other interfaces; this cannot discover remote/client LAN overlap. Configure `excluded_subnets` accordingly. A hostname endpoint must resolve to reachable IPv4 when client IPv6 is blocked.

Split example, tunneling only the gateway network and using a resolver reachable within that network:

```toml
routing = "split"
split_routes = ["10.77.0.0/24"]
dns_policy = "preserve"
dns = []
```

Split mode deliberately leaves destinations outside the listed networks on the client's ordinary connection. `preserve` can send DNS outside the tunnel. Even `tunnel` depends on the client honoring its DNS setting (browser encrypted DNS may differ).

`--quiet` suppresses successful output; errors remain on stderr. The default output is JSON with public metadata. Logging is intentionally limited to command results and sanitized errors; there is no key/profile debug log mode. No optional feature is required. `peer export --qr PATH` adds an SVG QR file; it is as sensitive as the profile.

| Command | Behavior |
| --- | --- |
| example / check | Print documented example / validate settings only |
| keygen --out PATH / pubkey --key PATH | Local protected key generation / public derivation; neither requires a gateway config |
| init | Initialize key, SQLite schema and desired boot/native files; no runtime change |
| prepare | Rewrite boot/native files from current intent; no lifecycle completion |
| up / down | Claim/start or stop this dedicated interface; preserve desired peers |
| peer add --name N --public-key K [--defer] | Atomically reserve address and intent; sync unless deferred |
| peer list / peer show N | Public identifiers, address, lifecycle, attempts and sanitized retry reason |
| peer revoke N [--defer] | Commit removal intent before any runtime action; retain tombstone forever |
| peer export N --private-key-file P --out P --ipv6-block-confirmed [--qr P] | Require matching client key; never print secret profile contents |
| reconcile | Rewrite desired files, sync runtime, verify both, then complete |
| doctor | Public handshake/counter and prerequisite report; missing prerequisites produce nonzero exit |
| firewall-plan --out PATH | Write apply/remove script for review; no firewall changes |

State contains `gateway.key`, `peers.db`, `operation.lock`, an `interface.claim` marker after first startup, `<interface>.conf` (wg-quick), and `runtime.conf` (native wg). Database identity binds the server public key, pool, gateway address and interface. Changing those requires a deliberate new gateway migration; normal config editing will fail closed. Changing endpoint, DNS, routing or keepalive requires fresh client exports; changing egress/port requires review and regeneration of firewall rules. MTU changes on an existing interface require `down` then `up`.

On Windows use an absolute Windows `state_dir` override. Existing private folders must have ACLs granting access only to the current user, SYSTEM and Administrators; newly created private folders/files are restricted automatically. Linux state requires current-user ownership and no group/other permissions. The active gateway runtime is Linux-only.

use crate::{
    config::{Config, DnsPolicy},
    keys::Secret,
    storage::Peer,
};
use anyhow::{Result, ensure};
use qrcode::{QrCode, render::svg};
use zeroize::Zeroizing;

pub fn server(config: &Config, key: &Secret, peers: &[Peer], quick: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\n",
        key.expose(),
        config.listen_port
    ));
    if quick {
        out.push_str(&format!(
            "Address = {}/{}\n",
            config.gateway_address,
            config.pool.prefix_len()
        ));
        if let Some(mtu) = config.mtu {
            out.push_str(&format!("MTU = {mtu}\n"));
        }
        // Never use SaveConfig: runtime drift must not overwrite persisted desired state.
    }
    for peer in peers.iter().filter(|p| p.desired()) {
        out.push_str(&format!(
            "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
            peer.public_key, peer.address
        ));
    }
    out
}
pub fn client(
    config: &Config,
    gateway_public: &str,
    peer: &Peer,
    key: &Secret,
    ipv6_block_confirmed: bool,
) -> Result<Zeroizing<String>> {
    config.validate()?;
    crate::keys::decode(gateway_public)?;
    ensure!(peer.desired(), "cannot export a revoking or revoked peer");
    ensure!(
        key.public_key()? == peer.public_key,
        "private key does not match enrolled peer"
    );
    ensure!(
        ipv6_block_confirmed,
        "block IPv6 on the client first, then pass --ipv6-block-confirmed; this profile only tunnels IPv4"
    );
    let mut out = Zeroizing::new(format!(
        "# IPv4 only. Client IPv6 blocking is required. No kill switch is installed.\n[Interface]\nPrivateKey = {}\nAddress = {}/32\n",
        key.expose(),
        peer.address
    ));
    if config.dns_policy == DnsPolicy::Tunnel {
        out.push_str(&format!(
            "DNS = {}\n",
            config
                .dns
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(mtu) = config.mtu {
        out.push_str(&format!("MTU = {mtu}\n"));
    }
    out.push_str(&format!(
        "\n[Peer]\nPublicKey = {gateway_public}\nEndpoint = {}\nAllowedIPs = {}\n",
        config.endpoint,
        config
            .client_routes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if config.keepalive > 0 {
        out.push_str(&format!("PersistentKeepalive = {}\n", config.keepalive));
    }
    Ok(out)
}
pub fn qr(profile: &str) -> Result<Zeroizing<String>> {
    let code = QrCode::new(profile.as_bytes())?;
    Ok(Zeroizing::new(
        code.render::<svg::Color>().min_dimensions(320, 320).build(),
    ))
}
/// A scoped, reversible script. All substituted values have strict validation.
/// The user applies it explicitly; the CLI never changes the host firewall.
pub fn firewall(config: &Config) -> Result<String> {
    config.validate()?;
    Ok(format!(
        r#"#!/bin/sh
set -eu
# Reserved table for this dedicated gateway. Review existing firewall policy first.
table='vpn_config_kit_{iface}'
case "${{1:-}}" in
  apply)
    {{
      if nft list table inet "$table" >/dev/null 2>&1; then
        printf 'delete table inet %s\n' "$table"
      fi
      cat <<'RULES'
table inet vpn_config_kit_{iface} {{
  comment "vpn-config-kit managed gateway rules"
  chain input {{
    type filter hook input priority 0; policy accept;
    iifname "{egress}" udp dport {port} accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
    iifname "{iface}" oifname "{egress}" ip saddr {pool} accept
    iifname "{egress}" oifname "{iface}" ip daddr {pool} ct state established,related accept
    iifname "{iface}" drop
    oifname "{iface}" drop
  }}
  chain nat {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{egress}" ip saddr {pool} masquerade
  }}
}}
RULES
    }} | nft -f -
    ;;
  remove)
    if nft list table inet "$table" >/dev/null 2>&1; then
      nft delete table inet "$table"
    fi
    ;;
  *) echo 'usage: sh firewall.sh apply|remove' >&2; exit 2 ;;
esac
"#,
        iface = config.interface,
        egress = config.egress_interface,
        port = config.listen_port,
        pool = config.pool
    ))
}

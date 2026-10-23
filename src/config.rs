use anyhow::{Result, bail, ensure};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub interface: String,
    pub endpoint: String,
    pub listen_port: u16,
    pub pool: Ipv4Net,
    pub gateway_address: Ipv4Addr,
    pub egress_interface: String,
    pub routing: Routing,
    pub split_routes: Vec<Ipv4Net>,
    pub dns_policy: DnsPolicy,
    pub dns: Vec<Ipv4Addr>,
    pub ipv6_policy: Ipv6Policy,
    pub excluded_subnets: Vec<Ipv4Net>,
    pub keepalive: u16,
    pub mtu: Option<u16>,
    pub state_dir: PathBuf,
    pub command_timeout_secs: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Routing {
    Full,
    Split,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsPolicy {
    Preserve,
    Tunnel,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Policy {
    BlockOnClient,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            interface: "wg0".into(),
            endpoint: String::new(),
            listen_port: 51820,
            pool: "10.77.0.0/24".parse().unwrap(),
            gateway_address: "10.77.0.1".parse().unwrap(),
            egress_interface: String::new(),
            routing: Routing::Full,
            split_routes: vec![],
            dns_policy: DnsPolicy::Tunnel,
            dns: vec!["1.1.1.1".parse().unwrap()],
            ipv6_policy: Ipv6Policy::BlockOnClient,
            excluded_subnets: vec![],
            keepalive: 0,
            mtu: None,
            state_dir: "/var/lib/vpn-config-kit".into(),
            command_timeout_secs: 15,
        }
    }
}
impl Config {
    pub fn with_overrides(text: &str, overrides: &[String]) -> Result<Self> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid TOML configuration"))?;
        for value in overrides {
            let replacement: toml::Table = toml::from_str(value)
                .map_err(|_| anyhow::anyhow!("--set requires one TOML key=value assignment"))?;
            ensure!(replacement.len() == 1, "--set requires exactly one field");
            table.extend(replacement);
        }
        table.try_into().map_err(|_| {
            anyhow::anyhow!("invalid configuration: check types, field names, and version")
        })
    }
    pub fn parse(text: &str) -> Result<Self> {
        // TOML's default errors include source lines, which may contain pasted secrets.
        toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid configuration: check types, field names, and version")
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported configuration version");
        interface_name(&self.interface)?;
        interface_name(&self.egress_interface)?;
        ensure!(
            self.interface != self.egress_interface,
            "egress must differ from tunnel interface"
        );
        endpoint(&self.endpoint)?;
        ensure!(self.listen_port > 0, "listen_port must be nonzero");
        ensure!(
            (16..=30).contains(&self.pool.prefix_len()) && self.pool.addr() == self.pool.network(),
            "pool must be a canonical IPv4 network with prefix /16 through /30"
        );
        ensure!(
            self.pool.network().is_private() && self.pool.broadcast().is_private(),
            "pool must use RFC1918 private space"
        );
        ensure!(
            self.pool.contains(&self.gateway_address)
                && self.gateway_address != self.pool.network()
                && self.gateway_address != self.pool.broadcast(),
            "gateway_address must be a usable pool address"
        );
        for n in &self.excluded_subnets {
            ensure!(!overlaps(&self.pool, n), "pool overlaps an excluded subnet");
        }
        match self.routing {
            Routing::Full => ensure!(
                self.split_routes.is_empty(),
                "full routing cannot have split_routes"
            ),
            Routing::Split => {
                ensure!(
                    !self.split_routes.is_empty(),
                    "split routing requires split_routes"
                );
                for n in &self.split_routes {
                    ensure!(
                        n.prefix_len() > 0 && n.addr() == n.network(),
                        "split routes must be canonical and cannot contain a default route"
                    );
                }
            }
        }
        match self.dns_policy {
            DnsPolicy::Preserve => ensure!(
                self.dns.is_empty(),
                "preserve DNS requires an empty dns list"
            ),
            DnsPolicy::Tunnel => {
                ensure!(
                    !self.dns.is_empty(),
                    "tunnel DNS requires resolver addresses"
                );
                for ip in &self.dns {
                    ensure!(
                        !ip.is_unspecified()
                            && !ip.is_multicast()
                            && !ip.is_loopback()
                            && *ip != Ipv4Addr::BROADCAST,
                        "invalid DNS resolver address"
                    );
                    ensure!(
                        self.client_routes().iter().any(|n| n.contains(ip)),
                        "DNS resolver is outside client routes"
                    );
                }
            }
        }
        ensure!(
            self.mtu.is_none_or(|m| (1280..=9000).contains(&m)),
            "MTU must be 1280..9000"
        );
        ensure!(
            (1..=120).contains(&self.command_timeout_secs),
            "command timeout must be 1..120 seconds"
        );
        ensure!(self.state_dir.is_absolute(), "state_dir must be absolute");
        ensure!(
            !self
                .state_dir
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "state_dir cannot contain parent traversal"
        );
        Ok(())
    }
    pub fn client_routes(&self) -> Vec<Ipv4Net> {
        match self.routing {
            Routing::Full => vec!["0.0.0.0/0".parse().unwrap()],
            Routing::Split => self.split_routes.clone(),
        }
    }
    pub fn quick_path(&self) -> PathBuf {
        self.state_dir.join(format!("{}.conf", self.interface))
    }
    pub fn native_path(&self) -> PathBuf {
        self.state_dir.join("runtime.conf")
    }
    pub fn key_path(&self) -> PathBuf {
        self.state_dir.join("gateway.key")
    }
    pub fn identity(&self, public_key: &str) -> String {
        format!(
            "{}|{}|{}|{}",
            self.interface, self.pool, self.gateway_address, public_key
        )
    }
}
pub fn overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}
pub fn interface_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 15
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "interface must start with a letter and contain 1..15 ASCII letters, digits or underscores"
    );
    Ok(())
}
pub(crate) fn endpoint(value: &str) -> Result<()> {
    let Some((host, port)) = value.rsplit_once(':') else {
        bail!("endpoint must be host:port");
    };
    ensure!(
        port.parse::<u16>().is_ok_and(|p| p > 0),
        "invalid endpoint port"
    );
    ensure!(
        host.len() <= 253 && !host.is_empty(),
        "invalid endpoint host"
    );
    // IPv4 or DNS transport endpoints only: clients must block IPv6 in this release.
    ensure!(
        host.split('.').all(|p| !p.is_empty()
            && p.len() <= 63
            && p.as_bytes()[0].is_ascii_alphanumeric()
            && p.as_bytes()[p.len() - 1].is_ascii_alphanumeric()
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "endpoint must be an IPv4 address or DNS hostname"
    );
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ip: Ipv4Addr = host
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid endpoint IPv4 address"))?;
        ensure!(
            !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
            "invalid endpoint address"
        );
    }
    Ok(())
}

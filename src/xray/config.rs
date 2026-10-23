use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

pub const ENGINE_VERSION: &str = "26.10.21";
pub const LINUX_SHA256: &str = "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e";
pub const WINDOWS_SHA256: &str = "c77a00eb84fb93ae044c2d771a1cabcc033b81e487253fbc35b12df6879c1e15";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub backend: String,
    pub listen: Ipv4Addr,
    pub listen_port: u16,
    pub endpoint: String,
    pub server_name: String,
    pub target: String,
    pub state_dir: PathBuf,
    pub engine_path: PathBuf,
    pub manager_path: PathBuf,
    pub command_timeout_secs: u64,
    pub allow_private_destinations: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            backend: "xray-reality".into(),
            listen: Ipv4Addr::UNSPECIFIED,
            listen_port: 443,
            endpoint: String::new(),
            server_name: String::new(),
            target: String::new(),
            state_dir: "/var/lib/vpn-config-kit-xray".into(),
            engine_path: "/usr/local/lib/vpn-config-kit/xray".into(),
            manager_path: "/usr/local/bin/vpn-config-kit".into(),
            command_timeout_secs: 30,
            allow_private_destinations: false,
        }
    }
}
impl Config {
    pub fn parse(text: &str, overrides: &[String]) -> Result<Self> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid Xray TOML configuration"))?;
        for value in overrides {
            let replacement: toml::Table = toml::from_str(value)
                .map_err(|_| anyhow::anyhow!("--set requires one TOML key=value assignment"))?;
            ensure!(replacement.len() == 1, "--set requires exactly one field");
            table.extend(replacement);
        }
        let config: Self = table
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Xray configuration fields or types"))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.backend == "xray-reality",
            "unsupported Xray configuration version or backend"
        );
        crate::config::endpoint(&self.endpoint)?;
        crate::config::endpoint(&self.target)?;
        ensure!(
            !self.server_name.contains(':'),
            "server_name must be a DNS hostname"
        );
        crate::config::endpoint(&format!("{}:443", self.server_name))?;
        ensure!(
            self.server_name.parse::<Ipv4Addr>().is_err(),
            "server_name must be a DNS hostname"
        );
        ensure!(
            self.listen_port != 0
                && !self.listen.is_multicast()
                && self.listen != Ipv4Addr::BROADCAST,
            "invalid Xray listener"
        );
        ensure!(
            (10..=120).contains(&self.command_timeout_secs),
            "command timeout must be 10..120 seconds"
        );
        for path in [&self.state_dir, &self.engine_path, &self.manager_path] {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|p| matches!(p, std::path::Component::ParentDir)),
                "Xray paths must be absolute without parent traversal"
            );
        }
        Ok(())
    }
    pub fn runtime_path(&self) -> PathBuf {
        self.state_dir.join("xray.json")
    }
    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("xray-state.json")
    }
}
pub fn linux_path(path: &Path) -> Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid service path"))?;
    ensure!(
        value.starts_with('/')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b)),
        "service paths must be absolute Linux paths using letters, digits, /, _, . or -"
    );
    Ok(value)
}

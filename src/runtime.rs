use crate::config::{Config, overlaps};
use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub public_key: String,
    pub listen_port: u16,
    pub peers: BTreeMap<String, String>,
}
pub trait WireGuard {
    fn sync(&mut self, native_path: &Path) -> Result<()>;
    fn snapshot(&mut self) -> Result<Snapshot>;
}
#[derive(Clone)]
pub struct Linux {
    pub config: Config,
}
impl Linux {
    pub fn claim(&self) -> Result<()> {
        let path = self.config.state_dir.join("interface.claim");
        let public = crate::secure::read_secret(&self.config.key_path())?.public_key()?;
        if path.exists() {
            crate::secure::check_mode(&path, false)?;
            ensure!(
                std::fs::read_to_string(path)? == public,
                "invalid interface ownership marker"
            );
        } else {
            ensure!(
                !self.is_up()?,
                "interface already exists without an ownership marker; choose an unused interface"
            );
            crate::secure::create(&path, public.as_bytes())?;
        }
        Ok(())
    }
    pub fn verify_owner(&self, allow_unconfigured: bool) -> Result<()> {
        let path = self.config.state_dir.join("interface.claim");
        crate::secure::check_mode(&path, false)
            .context("interface is not claimed; start it with up first")?;
        let public = crate::secure::read_secret(&self.config.key_path())?.public_key()?;
        ensure!(
            std::fs::read_to_string(path)? == public,
            "invalid interface ownership marker"
        );
        let actual = self.wg(&["show", &self.config.interface, "public-key"])?;
        ensure!(
            actual.trim() == public || (allow_unconfigured && actual.trim() == "(none)"),
            "existing interface has another key; refusing to modify it"
        );
        Ok(())
    }
    pub fn link_ready(&self) -> Result<bool> {
        let raw = run(
            "ip",
            &["-j", "address", "show", "dev", &self.config.interface],
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )?;
        let data: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
        Ok(data.iter().any(|link| {
            link["flags"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "UP"))
                && link["addr_info"].as_array().is_some_and(|a| {
                    a.iter().any(|v| {
                        v["local"] == self.config.gateway_address.to_string()
                            && v["prefixlen"] == self.config.pool.prefix_len()
                    })
                })
        }))
    }
    fn wg(&self, args: &[&str]) -> Result<String> {
        ensure!(
            cfg!(target_os = "linux"),
            "runtime management requires Linux with wireguard-tools and CAP_NET_ADMIN/root"
        );
        run(
            "wg",
            args,
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )
    }
    pub fn is_up(&self) -> Result<bool> {
        Ok(self
            .wg(&["show", "interfaces"])?
            .split_whitespace()
            .any(|i| i == self.config.interface))
    }
    pub fn quick(&self, action: &str) -> Result<()> {
        ensure!(cfg!(target_os = "linux"), "interface setup requires Linux");
        ensure!(
            action == "up" || action == "down",
            "invalid interface action"
        );
        run(
            "wg-quick",
            &[
                action,
                self.config
                    .quick_path()
                    .to_str()
                    .context("invalid configuration path")?,
            ],
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )?;
        Ok(())
    }
    pub fn check_routes(&self) -> Result<()> {
        let raw = run(
            "ip",
            &["-j", "-4", "route", "show", "table", "all"],
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )?;
        let routes: Vec<serde_json::Value> =
            serde_json::from_str(&raw).context("cannot parse IPv4 routes")?;
        for route in routes {
            if route["dev"].as_str() == Some(&self.config.interface) {
                continue;
            }
            let Some(dst) = route["dst"].as_str() else {
                continue;
            };
            if dst == "default" {
                continue;
            }
            let dst = if dst.contains('/') {
                dst.to_owned()
            } else {
                format!("{dst}/32")
            };
            let net: Ipv4Net = dst.parse().context("unrecognized IPv4 route")?;
            ensure!(
                !overlaps(&self.config.pool, &net),
                "address pool overlaps an existing route on another interface"
            );
        }
        Ok(())
    }
    pub fn diagnostics(&mut self) -> Result<serde_json::Value> {
        let snapshot = self.snapshot()?;
        let iface = &self.config.interface;
        let handshakes = self.wg(&["show", iface, "latest-handshakes"])?;
        let transfer = self.wg(&["show", iface, "transfer"])?;
        // These explicit wg fields contain public identifiers/counters only; never use dump/showconf.
        let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_default()
            .trim()
            == "1";
        let egress = run(
            "ip",
            &["-j", "link", "show", "dev", &self.config.egress_interface],
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )
        .is_ok();
        Ok(
            serde_json::json!({"runtime":snapshot,"latest_handshakes":handshakes.trim(),"transfer_bytes":transfer.trim(),"ipv4_forwarding":forwarding,"egress_exists":egress,"link_ready":self.link_ready().unwrap_or(false),"pool_route_overlap_check":self.check_routes().is_ok(),"ipv6":"must be blocked on client","firewall":"inspect owned nft table and all host/cloud policies manually"}),
        )
    }
}
impl WireGuard for Linux {
    fn sync(&mut self, path: &Path) -> Result<()> {
        self.verify_owner(false)?;
        self.wg(&[
            "syncconf",
            &self.config.interface,
            path.to_str().context("invalid configuration path")?,
        ])?;
        Ok(())
    }
    fn snapshot(&mut self) -> Result<Snapshot> {
        let iface = &self.config.interface;
        let public_key = self.wg(&["show", iface, "public-key"])?.trim().to_owned();
        let listen_port = self
            .wg(&["show", iface, "listen-port"])?
            .trim()
            .parse()
            .context("invalid runtime listen port")?;
        let raw = self.wg(&["show", iface, "allowed-ips"])?;
        let mut peers = BTreeMap::new();
        for line in raw.lines().filter(|l| !l.is_empty()) {
            let (key, ips) = line
                .split_once('\t')
                .context("invalid runtime peer listing")?;
            crate::keys::decode(key)?;
            peers.insert(
                key.into(),
                ips.split_whitespace().collect::<Vec<_>>().join(""),
            );
        }
        Ok(Snapshot {
            public_key,
            listen_port,
            peers,
        })
    }
}
/// Bounded capture, no stderr reflection, timeout kills/reaps the child and its Unix process group.
pub fn run(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(command, input, timeout)
}

pub(crate) fn run_command(
    mut command: Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<String> {
    ensure!(
        input.is_none_or(|b| b.len() <= 1024),
        "system tool input exceeds small-input limit"
    );
    let started = Instant::now();
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW for helper tools.
    }
    let mut child = command.spawn().map_err(|_| {
        anyhow::anyhow!("cannot start required system tool; check installation and privileges")
    })?;
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            let mut result = Vec::new();
            let mut reader = stdout;
            let mut buffer = [0u8; 8192];
            let mut overflow = false;
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                if result.len() + n <= 1024 * 1024 {
                    result.extend_from_slice(&buffer[..n]);
                } else {
                    overflow = true;
                }
            }
            Ok::<_, std::io::Error>((result, overflow))
        })();
        let _ = send.send(result);
    });
    let written = if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes)
    } else {
        Ok(())
    };
    let waited = child.wait_timeout(timeout.saturating_sub(started.elapsed()));
    let mut captured = None;
    if matches!(waited, Ok(Some(_))) {
        captured = receive
            .recv_timeout(timeout.saturating_sub(started.elapsed()))
            .ok();
    }
    let timed_out = captured.is_none();
    if timed_out || !matches!(waited,Ok(Some(s)) if s.success()) || written.is_err() {
        #[cfg(unix)]
        {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    ensure!(
        !timed_out,
        "system tool timed out or wait failed; process terminated; inspect interface and reconcile"
    );
    ensure!(
        waited?.unwrap().success(),
        "system tool failed; check privileges, configuration and interface; output suppressed"
    );
    written.context("system tool input failed")?;
    let (bytes, overflow) = captured.unwrap()?;
    ensure!(!overflow, "system tool output exceeded limit");
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("system tool returned non-UTF8 output"))
}

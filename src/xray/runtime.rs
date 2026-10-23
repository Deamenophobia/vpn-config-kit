use super::{
    config::{self, Config, linux_path},
    render,
    state::State,
};
use crate::{runtime::run_command, secure};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Running {
    pub running: bool,
    pub invocation: String,
}
pub trait Runtime {
    fn validate(&mut self, config: &Path) -> Result<()>;
    fn status(&mut self, unit: &str) -> Result<Running>;
    /// Existing service identity need not match newly selected listener settings.
    fn before_restart(&mut self, unit: &str) -> Result<Running> {
        self.status(unit)
    }
    fn restart(&mut self, unit: &str) -> Result<Running>;
    fn stop(&mut self, unit: &str) -> Result<()>;
}
pub struct Native {
    pub config: Config,
}
pub fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
impl Native {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    pub fn check_engine(&self) -> Result<()> {
        let expected = if cfg!(windows) {
            config::WINDOWS_SHA256
        } else {
            config::LINUX_SHA256
        };
        ensure!(
            cfg!(target_arch = "x86_64"),
            "the pinned engine currently supports x86_64 hosts"
        );
        ensure!(
            digest(&self.config.engine_path)? == expected,
            "Xray binary differs from the pinned upstream artifact"
        );
        let mut command = Command::new(&self.config.engine_path);
        command.arg("version");
        let result = run_command(
            command,
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )?;
        ensure!(
            result.starts_with(&format!("Xray {} (", config::ENGINE_VERSION)),
            "unsupported Xray version"
        );
        Ok(())
    }
    fn systemctl(&self, args: &[&str]) -> Result<String> {
        ensure!(
            cfg!(target_os = "linux"),
            "Xray service management requires Linux with systemd"
        );
        let mut command = Command::new("systemctl");
        command.args(args);
        run_command(
            command,
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )
    }
    fn property(&self, unit: &str, property: &str) -> Result<String> {
        Ok(self
            .systemctl(&["show", unit, "--property", property, "--value"])?
            .trim()
            .to_string())
    }
    fn owned(&self, unit: &str) -> Result<()> {
        valid_unit(unit)?;
        ensure!(
            self.property(unit, "LoadState")? == "loaded",
            "install the generated Xray service first"
        );
        ensure!(
            self.property(unit, "DropInPaths")?.is_empty(),
            "Xray service drop-ins are not supported"
        );
        let path = self.property(unit, "FragmentPath")?;
        ensure!(
            path == format!("/etc/systemd/system/{unit}"),
            "Xray unit must be installed in /etc/systemd/system"
        );
        let actual = std::fs::read_to_string(path)?;
        ensure!(
            actual == service(&self.config)?,
            "Xray service definition differs from the generated unit"
        );
        Ok(())
    }
}
impl Runtime for Native {
    fn before_restart(&mut self, unit: &str) -> Result<Running> {
        self.owned(unit)?;
        let active = self.property(unit, "ActiveState")?;
        let pid = self.property(unit, "MainPID")?;
        if matches!(active.as_str(), "inactive" | "failed") {
            ensure!(pid == "0", "inactive Xray unit still has a process");
            return Ok(Running {
                running: false,
                invocation: String::new(),
            });
        }
        let invocation = self.property(unit, "InvocationID")?;
        ensure!(
            active == "active"
                && pid.parse::<u32>().is_ok_and(|p| p > 0)
                && invocation.len() == 32
                && invocation.bytes().all(|b| b.is_ascii_hexdigit()),
            "Xray service is transitioning"
        );
        Ok(Running {
            running: true,
            invocation: format!("{invocation}:{pid}"),
        })
    }
    fn validate(&mut self, path: &Path) -> Result<()> {
        self.check_engine()?;
        secure::check_mode(path, false)?;
        let mut command = Command::new(&self.config.engine_path);
        command.arg("run").arg("-test").arg("-config").arg(path);
        run_command(
            command,
            None,
            Duration::from_secs(self.config.command_timeout_secs),
        )
        .map_err(|_| {
            anyhow::anyhow!("Xray rejected the configuration; native output suppressed")
        })?;
        Ok(())
    }
    fn status(&mut self, unit: &str) -> Result<Running> {
        self.owned(unit)?;
        let active = self.property(unit, "ActiveState")?;
        let pid = self.property(unit, "MainPID")?;
        if matches!(active.as_str(), "inactive" | "failed") {
            ensure!(pid == "0", "inactive Xray unit still has a process");
            return Ok(Running {
                running: false,
                invocation: String::new(),
            });
        }
        ensure!(
            active == "active" && pid.parse::<u32>().is_ok_and(|n| n > 0),
            "Xray service is transitioning"
        );
        let invocation = self.property(unit, "InvocationID")?;
        ensure!(
            invocation.len() == 32 && invocation.bytes().all(|b| b.is_ascii_hexdigit()),
            "missing Xray invocation identity"
        );
        let actual = std::fs::read(format!("/proc/{pid}/cmdline"))?;
        let args: Vec<_> = actual
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .collect();
        let engine = self
            .config
            .engine_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid engine path"))?;
        let runtime_path = self.config.runtime_path();
        let config = runtime_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid config path"))?;
        ensure!(
            args == vec![engine.as_bytes(), b"run", b"-config", config.as_bytes()],
            "service is not running the expected Xray command"
        );
        ensure!(
            digest(Path::new(&format!("/proc/{pid}/exe")))? == config::LINUX_SHA256,
            "unexpected running Xray binary"
        );
        let sockets: std::collections::HashSet<String> =
            std::fs::read_dir(format!("/proc/{pid}/fd"))?
                .filter_map(|e| e.ok())
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .filter_map(|p| {
                    p.to_str()
                        .and_then(|s| s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')))
                        .map(str::to_owned)
                })
                .collect();
        let bind = format!(
            "{:08X}:{:04X}",
            u32::from_le_bytes(self.config.listen.octets()),
            self.config.listen_port
        );
        let listeners = listening_sockets(self.config.listen_port)?;
        let wildcard_v6 = format!("{}:{:04X}", "0".repeat(32), self.config.listen_port);
        ensure!(
            listeners.iter().any(|(address, inode)| {
                (address == &bind
                    || (self.config.listen.is_unspecified() && address == &wildcard_v6))
                    && sockets.contains(inode)
            }) && listeners.iter().all(|(_, inode)| sockets.contains(inode)),
            "Xray does not own the configured listening socket"
        );
        ensure!(
            self.property(unit, "MainPID")? == pid
                && self.property(unit, "InvocationID")? == invocation,
            "Xray process changed during inspection"
        );
        Ok(Running {
            running: true,
            invocation: format!("{invocation}:{pid}"),
        })
    }
    fn restart(&mut self, unit: &str) -> Result<Running> {
        self.check_engine()?;
        self.stop(unit)?;
        ensure!(
            listening_sockets(self.config.listen_port)?.is_empty(),
            "Xray TCP port is already in use"
        );
        self.systemctl(&["start", unit])?;
        let deadline = Instant::now() + Duration::from_secs(self.config.command_timeout_secs);
        while Instant::now() < deadline {
            if let Ok(running) = self.status(unit) {
                if running.running {
                    return Ok(running);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::bail!("Xray did not become ready")
    }
    fn stop(&mut self, unit: &str) -> Result<()> {
        self.owned(unit)?;
        self.systemctl(&["stop", unit])?;
        ensure!(!self.status(unit)?.running, "Xray did not stop");
        Ok(())
    }
}
fn listening_sockets(port: u16) -> Result<Vec<(String, String)>> {
    let mut result = vec![];
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error)
                if path.ends_with("tcp6") && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        for line in text.lines().skip(1) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() > 9
                && columns[3] == "0A"
                && columns[1].ends_with(&format!(":{port:04X}"))
            {
                result.push((columns[1].to_owned(), columns[9].to_owned()));
            }
        }
    }
    Ok(result)
}
fn valid_unit(unit: &str) -> Result<()> {
    let middle = unit
        .strip_prefix("vpn-config-kit-xray-")
        .and_then(|s| s.strip_suffix(".service"))
        .ok_or_else(|| anyhow::anyhow!("invalid owned service name"))?;
    ensure!(
        middle.len() == 32 && middle.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid owned service name"
    );
    Ok(())
}
pub fn service(config: &Config) -> Result<String> {
    let manager = linux_path(&config.manager_path)?;
    let state = linux_path(&config.state_dir)?;
    linux_path(&config.engine_path)?;
    Ok(format!(
        "[Unit]\nDescription=VPN Config Kit Xray gateway\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart={manager} --backend xray-reality --config {state}/managed.toml xray-serve\nKillMode=control-group\nSendSIGKILL=yes\nTimeoutStopSec=10\nRestart=no\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n"
    ))
}
/// Called by the owned unit on every boot. Refuse stale config after interrupted intent.
pub fn check_startup(config: &Config) -> Result<()> {
    config.validate()?;
    secure::check_mode(&config.state_dir.join("managed.toml"), false)?;
    let state = State::read(config)?;
    let expected = render::server(config, &state)?;
    secure::check_mode(&config.runtime_path(), false)?;
    let saved = Zeroizing::new(std::fs::read_to_string(config.runtime_path())?);
    ensure!(
        *saved == *expected,
        "Xray intent differs from persisted configuration; run reconcile before starting"
    );
    Ok(())
}
pub fn serve(config: &Config) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "Xray service startup requires Linux"
    );
    check_startup(config)?;
    let mut native = Native::new(config.clone());
    native.validate(&config.runtime_path())?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let _error = Command::new(&config.engine_path)
            .arg("run")
            .arg("-config")
            .arg(config.runtime_path())
            .exec();
        anyhow::bail!("cannot execute pinned Xray engine");
    }
    #[cfg(not(unix))]
    anyhow::bail!("Xray service startup requires Linux");
}
pub fn firewall(config: &Config, state: &State) -> Result<String> {
    config.validate()?;
    let table = format!("vpn_config_kit_xray_{}", state.instance);
    ensure!(
        state.instance.len() == 32 && state.instance.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid instance"
    );
    let listen = if config.listen.is_unspecified() {
        String::new()
    } else {
        format!("ip daddr {} ", config.listen)
    };
    Ok(format!(
        "#!/bin/sh\nset -eu\ntable='{table}'\ncase \"$1\" in\napply)\n  {{\n    if nft list table inet \"$table\" >/dev/null 2>&1; then printf 'delete table inet %s\\n' \"$table\"; fi\n    cat <<'RULES'\ntable inet {table} {{\n  chain input {{\n    type filter hook input priority 0; policy accept;\n    {listen}tcp dport {port} accept\n  }}\n}}\nRULES\n  }} | nft -f -\n  ;;\nremove)\n  if nft list table inet \"$table\" >/dev/null 2>&1; then nft delete table inet \"$table\"; fi\n  ;;\n*) echo 'usage: sh firewall.sh apply|remove' >&2; exit 2 ;;\nesac\n",
        port = config.listen_port
    ))
}

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use vpn_config_kit::{
    app::Gateway, config::Config, export, keys::Secret, runtime::Linux, secure, xray,
};

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Backend {
    Wireguard,
    XrayReality,
}
#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum ExportFormat {
    Json,
    Link,
}

#[derive(Parser)]
#[command(version, about = "VPN Config Kit: a single-gateway management toolkit")]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "wireguard")]
    backend: Backend,
    /// Settings file; defaults to gateway.toml or xray.toml under /etc/vpn-config-kit.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override any configuration field with one TOML key=value assignment.
    #[arg(long = "set", global = true)]
    overrides: Vec<String>,
    /// Suppress successful command output; errors still go to stderr.
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Print an example containing documentation-only endpoint values.
    Example,
    /// Validate settings without touching state or networking.
    Check,
    /// Generate a local client key file; prints its public key only.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Derive a public key from a protected local private key file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Initialize private state/key and write boot/native configuration, without networking.
    Init,
    /// Write current desired boot/native configuration without completing pending work.
    Prepare,
    /// Start the dedicated interface, then synchronize and verify all peers.
    Up,
    /// Stop the dedicated interface, preserving desired state for a later up.
    Down,
    /// Retry pending operations and repair runtime drift from the database.
    Reconcile,
    /// Inspect public runtime counters and routing prerequisites.
    Doctor,
    /// Write a reviewed, scoped firewall apply/remove script; does not apply it.
    FirewallPlan {
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the dedicated Xray systemd unit; prints its required installation name.
    ServicePlan {
        #[arg(long)]
        out: PathBuf,
    },
    /// Rotate the REALITY server key; all Xray profiles must be exported again.
    RotateServerKey {
        #[arg(long)]
        defer: bool,
    },
    /// Internal service entrypoint; refuses stale persisted credentials on startup.
    #[command(hide = true)]
    XrayServe,
    #[command(subcommand)]
    Peer(PeerAction),
}
#[derive(Subcommand)]
enum PeerAction {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        defer: bool,
    },
    List,
    Show {
        name: String,
    },
    Revoke {
        name: String,
        #[arg(long)]
        defer: bool,
    },
    Rotate {
        name: String,
        #[arg(long)]
        defer: bool,
    },
    Export {
        name: String,
        #[arg(long)]
        private_key_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        qr: Option<PathBuf>,
        #[arg(long)]
        ipv6_block_confirmed: bool,
        /// Xray export format (default json); optional QR always contains the connection link.
        #[arg(long, value_enum)]
        format: Option<ExportFormat>,
        /// Loopback SOCKS port in an exported Xray JSON profile.
        #[arg(long, default_value_t = 10808)]
        socks_port: u16,
    },
}
fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}
fn output(cli: &Cli, value: impl serde::Serialize) -> Result<()> {
    if !cli.quiet {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}
fn settings(cli: &Cli) -> Result<Config> {
    let text = std::fs::read_to_string(config_path(cli)?).context("read configuration file")?;
    Config::with_overrides(&text, &cli.overrides)
}
fn config_path(cli: &Cli) -> Result<PathBuf> {
    absolute(cli.config.as_deref().unwrap_or_else(|| {
        Path::new(if cli.backend == Backend::Wireguard {
            "/etc/vpn-config-kit/gateway.toml"
        } else {
            "/etc/vpn-config-kit/xray.toml"
        })
    }))
}
fn execute(cli: &Cli) -> Result<()> {
    if cli.backend == Backend::XrayReality {
        return execute_xray(cli);
    }
    ensure!(
        !matches!(
            cli.command,
            Action::ServicePlan { .. }
                | Action::RotateServerKey { .. }
                | Action::XrayServe
                | Action::Peer(PeerAction::Rotate { .. })
        ),
        "this command requires --backend xray-reality"
    );
    match &cli.command {
        Action::Example => {
            if !cli.quiet {
                print!("{}", include_str!("../examples/gateway.toml"));
            }
            return Ok(());
        }
        Action::Keygen { out } => {
            let key = Secret::generate();
            secure::create(&absolute(out)?, key.expose().as_bytes())?;
            return output(
                cli,
                serde_json::json!({"public_key":key.public_key()?,"retention":"private key saved only to requested file; keep it for re-export"}),
            );
        }
        Action::Pubkey { key } => {
            return output(
                cli,
                serde_json::json!({"public_key":secure::read_secret(&absolute(key)?)?.public_key()?}),
            );
        }
        _ => (),
    }
    let config = settings(cli)?;
    config.validate()?;
    if matches!(cli.command, Action::Check) {
        return output(cli, serde_json::json!({"valid":true}));
    }
    if let Action::FirewallPlan { out } = &cli.command {
        secure::create(&absolute(out)?, export::firewall(&config)?.as_bytes())?;
        return output(cli, serde_json::json!({"written":true,"applied":false}));
    }
    let runtime = Linux {
        config: config.clone(),
    };
    let mut gateway = Gateway::open(config, runtime, matches!(cli.command, Action::Init))?;
    match &cli.command {
        Action::Init | Action::Prepare => {
            gateway.prepare()?;
            output(
                cli,
                serde_json::json!({"gateway_public_key":gateway.public_key()?,"runtime_changed":false,"sqlite_version":rusqlite::version()}),
            )
        }
        Action::Up => {
            gateway.runtime.check_routes()?;
            gateway.prepare()?;
            gateway.runtime.claim()?;
            if gateway.runtime.is_up()? {
                gateway.runtime.verify_owner(true)?;
                if !gateway.runtime.link_ready()? {
                    gateway.runtime.quick("down")?;
                }
            }
            if !gateway.runtime.is_up()? {
                gateway.runtime.quick("up")?;
            }
            gateway.reconcile()?;
            output(cli, serde_json::json!({"up":true}))
        }
        Action::Down => {
            if gateway.runtime.is_up()? {
                gateway.runtime.verify_owner(true)?;
                gateway.prepare()?;
                gateway.runtime.quick("down")?;
            }
            output(cli, serde_json::json!({"up":false}))
        }
        Action::Reconcile => {
            gateway.reconcile()?;
            output(cli, serde_json::json!({"reconciled":true}))
        }
        Action::Doctor => {
            let mut diagnostics = gateway.runtime.diagnostics()?;
            let audit = gateway.audit()?;
            diagnostics["consistency"] = audit.clone();
            output(cli, &diagnostics)?;
            ensure!(
                diagnostics["ipv4_forwarding"] == true
                    && diagnostics["egress_exists"] == true
                    && diagnostics["pool_route_overlap_check"] == true
                    && diagnostics["link_ready"] == true
                    && audit["runtime_matches_desired"] == true
                    && audit["persisted_matches_desired"] == true
                    && audit["unsettled_peers"] == 0,
                "gateway prerequisites failed; inspect doctor output"
            );
            Ok(())
        }
        Action::Peer(action) => match action {
            PeerAction::Add {
                name,
                public_key,
                defer,
            } => output(
                cli,
                gateway.enroll(
                    name,
                    public_key
                        .as_deref()
                        .context("WireGuard enrollment requires --public-key")?,
                    *defer,
                )?,
            ),
            PeerAction::List => output(cli, gateway.peers()?),
            PeerAction::Show { name } => output(cli, gateway.peer(name)?),
            PeerAction::Revoke { name, defer } => {
                gateway.revoke(name, *defer)?;
                output(cli, gateway.peer(name)?)
            }
            PeerAction::Export {
                name,
                private_key_file,
                out,
                qr,
                ipv6_block_confirmed,
                format,
                socks_port,
            } => {
                ensure!(
                    format.is_none() && *socks_port == 10808,
                    "Xray export options require --backend xray-reality"
                );
                let key = secure::read_secret(&absolute(
                    private_key_file
                        .as_deref()
                        .context("WireGuard export requires --private-key-file")?,
                )?)?;
                let profile = gateway.export(name, &key, *ipv6_block_confirmed)?;
                let qr_data = qr.as_ref().map(|_| export::qr(&profile)).transpose()?;
                if let Some(q) = qr {
                    ensure!(!absolute(q)?.exists(), "QR destination already exists");
                    ensure!(
                        absolute(q)? != absolute(out)?,
                        "profile and QR paths must differ"
                    );
                }
                secure::create(&absolute(out)?, profile.as_bytes())?;
                if let (Some(path), Some(data)) = (qr, qr_data) {
                    secure::create(&absolute(path)?, data.as_bytes())?;
                }
                output(
                    cli,
                    serde_json::json!({"written":true,"state":gateway.peer(name)?.state,"retention":"profile and optional QR contain a private key; retained until you remove them; database contains public keys only"}),
                )
            }
            PeerAction::Rotate { .. } => unreachable!(),
        },
        _ => unreachable!(),
    }
}
fn execute_xray(cli: &Cli) -> Result<()> {
    use xray::Runtime;
    if matches!(cli.command, Action::Example) {
        if !cli.quiet {
            print!("{}", include_str!("../examples/xray.toml"));
        }
        return Ok(());
    }
    ensure!(
        !matches!(cli.command, Action::Keygen { .. } | Action::Pubkey { .. }),
        "Xray generates credentials during init/enrollment"
    );
    let text =
        std::fs::read_to_string(config_path(cli)?).context("read Xray configuration file")?;
    let config = xray::Config::parse(&text, &cli.overrides)?;
    if matches!(cli.command, Action::Check) {
        return output(
            cli,
            serde_json::json!({"valid":true,"backend":"xray-reality"}),
        );
    }
    if matches!(cli.command, Action::XrayServe) {
        ensure!(
            cli.overrides.is_empty(),
            "service startup does not accept overrides"
        );
        return xray::runtime::serve(&config);
    }
    let runtime = xray::Native::new(config.clone());
    let mut gateway = xray::Gateway::open(config, runtime, matches!(cli.command, Action::Init))?;
    match &cli.command {
        Action::Init | Action::Prepare => {
            gateway.prepare()?;
        }
        Action::Up | Action::Reconcile => {
            gateway.reconcile()?;
        }
        Action::Down => {
            gateway.runtime.stop(&gateway.state.unit())?;
        }
        Action::Doctor => {
            let running = gateway.runtime.status(&gateway.state.unit())?;
            let saved =
                zeroize::Zeroizing::new(std::fs::read_to_string(gateway.config.runtime_path())?);
            ensure!(
                running.running
                    && *saved == *xray::render::server(&gateway.config, &gateway.state)?
                    && gateway.state.applied_revision == Some(gateway.state.revision)
                    && gateway.state.last_error.is_none(),
                "Xray is stopped or has unsettled changes; run up or reconcile"
            );
        }
        Action::FirewallPlan { out } => secure::create(
            &absolute(out)?,
            xray::runtime::firewall(&gateway.config, &gateway.state)?.as_bytes(),
        )?,
        Action::ServicePlan { out } => secure::create(
            &absolute(out)?,
            xray::runtime::service(&gateway.config)?.as_bytes(),
        )?,
        Action::RotateServerKey { defer } => {
            gateway.rotate_server_key()?;
            if !defer {
                gateway.reconcile()?;
            }
        }
        Action::Peer(action) => match action {
            PeerAction::Add {
                name,
                public_key,
                defer,
            } => {
                ensure!(
                    public_key.is_none(),
                    "Xray enrollment generates its own credential; omit --public-key"
                );
                gateway.enroll(name)?;
                if !defer {
                    gateway.reconcile()?;
                }
            }
            PeerAction::Revoke { name, defer } => {
                gateway.revoke(name)?;
                if !defer {
                    gateway.reconcile()?;
                }
            }
            PeerAction::Rotate { name, defer } => {
                gateway.rotate(name)?;
                if !defer {
                    gateway.reconcile()?;
                }
            }
            PeerAction::List => (),
            PeerAction::Show { name } => {
                let peer = gateway.peer(name)?;
                return output(
                    cli,
                    serde_json::json!({"name":peer.name,"state":peer.state,"backend":"xray-reality"}),
                );
            }
            PeerAction::Export {
                name,
                private_key_file,
                out,
                qr,
                ipv6_block_confirmed,
                format,
                socks_port,
            } => {
                ensure!(
                    private_key_file.is_none(),
                    "Xray exports use its protected credential store; omit --private-key-file"
                );
                ensure!(
                    !ipv6_block_confirmed,
                    "the WireGuard IPv6 acknowledgment does not apply to an application proxy"
                );
                let out = absolute(out)?;
                ensure!(!out.exists(), "export destination already exists");
                if let Some(path) = qr {
                    let path = absolute(path)?;
                    ensure!(
                        path != out && !path.exists(),
                        "QR destination exists or matches profile"
                    );
                }
                let peer = gateway.peer(name)?;
                let link = xray::render::link(&gateway.config, &gateway.state, peer)?;
                let body = if *format == Some(ExportFormat::Link) {
                    zeroize::Zeroizing::new(format!("{}\n", link.as_str()))
                } else {
                    xray::render::client(&gateway.config, &gateway.state, peer, *socks_port)?
                };
                let qr_data = qr.as_ref().map(|_| export::qr(&link)).transpose()?;
                // Native parsing happens before exposing a JSON profile to a client.
                if *format != Some(ExportFormat::Link) {
                    let candidate = tempfile::Builder::new()
                        .suffix(".json")
                        .tempfile_in(&gateway.config.state_dir)?
                        .into_temp_path();
                    secure::atomic_write(&candidate, body.as_bytes())?;
                    gateway.runtime.validate(&candidate)?;
                }
                secure::create(&out, body.as_bytes())?;
                if let (Some(path), Some(data)) = (qr, qr_data) {
                    secure::create(&absolute(path)?, data.as_bytes())?;
                }
                return output(
                    cli,
                    serde_json::json!({"written":true,"backend":"xray-reality","state":gateway.peer(name)?.state,
                    "retention":"profiles, connection links and QR images are credentials; retained until removed"}),
                );
            }
        },
        _ => unreachable!(),
    }
    output(cli, gateway.state.public())
}
fn main() {
    if let Err(error) = execute(&Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

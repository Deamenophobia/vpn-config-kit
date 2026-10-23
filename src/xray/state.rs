use super::{Config, render, runtime::Runtime};
use crate::secure;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs::File};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub name: String,
    pub(crate) id: String,
    pub(crate) short_id: String,
    pub state: String,
}
impl Credential {
    pub fn desired(&self) -> bool {
        self.state == "pending" || self.state == "active"
    }
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.id.zeroize();
        self.short_id.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub instance: String,
    pub(crate) private_key: String,
    pub revision: u64,
    pub applied_revision: Option<u64>,
    pub attempts: u64,
    pub last_error: Option<String>,
    pub credentials: Vec<Credential>,
}
impl Drop for State {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn random_hex(size: usize) -> String {
    let mut bytes = Zeroizing::new(vec![0u8; size]);
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}
fn uuid() -> String {
    let mut bytes = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(bytes.as_mut());
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..])
    )
}
fn private_key() -> String {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    URL_SAFE_NO_PAD.encode(secret.to_bytes())
}
pub fn name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "name must contain 1..64 ASCII letters, digits, hyphens or underscores"
    );
    Ok(())
}
fn is_hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
impl State {
    pub fn read(config: &Config) -> Result<Self> {
        let path = config.state_path();
        secure::check_mode(&path, false)?;
        ensure!(
            std::fs::metadata(&path)?.len() <= 8 * 1024 * 1024,
            "Xray state is too large"
        );
        let raw = Zeroizing::new(std::fs::read_to_string(path)?);
        let state: Self =
            serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("invalid Xray state"))?;
        ensure!(
            state.schema == 1 && is_hex(&state.instance, 32),
            "unsupported or invalid Xray state"
        );
        render::public_key(&state)?;
        ensure!(
            state.applied_revision.is_none_or(|r| r <= state.revision),
            "invalid Xray revision"
        );
        let mut names = HashSet::new();
        let mut ids = HashSet::new();
        let mut shorts = HashSet::new();
        for p in &state.credentials {
            name(&p.name)?;
            ensure!(
                matches!(
                    p.state.as_str(),
                    "pending" | "active" | "revoking" | "revoked"
                ),
                "invalid credential state"
            );
            ensure!(
                p.id.len() == 36
                    && p.id
                        .bytes()
                        .enumerate()
                        .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit()
                        }),
                "invalid stored credential"
            );
            ensure!(
                is_hex(&p.short_id, 16)
                    && names.insert(&p.name)
                    && ids.insert(&p.id)
                    && shorts.insert(&p.short_id),
                "duplicate or invalid stored credential"
            );
        }
        Ok(state)
    }
    fn save(&self, config: &Config) -> Result<()> {
        let text = Zeroizing::new(serde_json::to_string(self)?);
        secure::atomic_write(&config.state_path(), text.as_bytes())
    }
    pub fn unit(&self) -> String {
        format!("vpn-config-kit-xray-{}.service", self.instance)
    }
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({"backend":"xray-reality","service":self.unit(),"revision":self.revision,
            "applied_revision":self.applied_revision,"attempts":self.attempts,
            "last_error":self.last_error,"peers":self.credentials.iter().map(|p|
                serde_json::json!({"name":p.name,"state":p.state})).collect::<Vec<_>>()})
    }
}
pub struct Gateway<R: Runtime> {
    pub config: Config,
    pub state: State,
    pub runtime: R,
    _lock: File,
}
impl<R: Runtime> Gateway<R> {
    pub fn open(config: Config, runtime: R, initialize: bool) -> Result<Self> {
        config.validate()?;
        let lock = secure::lock(&config.state_dir)?;
        ensure!(
            !config.state_dir.join("peers.db").exists()
                && !config.state_dir.join("gateway.key").exists(),
            "Xray requires a separate state directory"
        );
        let state = if config.state_path().exists() {
            State::read(&config)?
        } else {
            ensure!(
                initialize && !config.runtime_path().exists(),
                "Xray state missing; initialize a new directory or restore its matching backup"
            );
            let state = State {
                schema: 1,
                instance: random_hex(16),
                private_key: private_key(),
                revision: 0,
                applied_revision: None,
                attempts: 0,
                last_error: None,
                credentials: vec![],
            };
            state.save(&config)?;
            state
        };
        Ok(Self {
            config,
            state,
            runtime,
            _lock: lock,
        })
    }
    pub fn peer(&self, name: &str) -> Result<&Credential> {
        self.state
            .credentials
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("peer not found"))
    }
    fn changed(&mut self) -> Result<()> {
        self.state.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("revision exhausted"))?;
        self.state.last_error = Some("pending reconciliation".into());
        self.state.save(&self.config)
    }
    pub fn enroll(&mut self, peer_name: &str) -> Result<()> {
        name(peer_name)?;
        ensure!(
            self.state.credentials.len() < 10000,
            "credential limit reached"
        );
        ensure!(
            !self.state.credentials.iter().any(|p| p.name == peer_name),
            "peer name already recorded, including revoked tombstones"
        );
        let id = uuid();
        let short_id = random_hex(8);
        ensure!(
            !self
                .state
                .credentials
                .iter()
                .any(|p| p.id == id || p.short_id == short_id),
            "credential collision; retry"
        );
        self.state.credentials.push(Credential {
            name: peer_name.into(),
            id,
            short_id,
            state: "pending".into(),
        });
        self.changed()
    }
    pub fn revoke(&mut self, name: &str) -> Result<()> {
        let peer = self
            .state
            .credentials
            .iter_mut()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("peer not found"))?;
        if peer.state == "revoked" || peer.state == "revoking" {
            return Ok(());
        }
        peer.state = "revoking".into();
        self.changed()
    }
    pub fn rotate(&mut self, name: &str) -> Result<()> {
        let new_id = uuid();
        let new_short = random_hex(8);
        ensure!(
            !self
                .state
                .credentials
                .iter()
                .any(|p| p.id == new_id || p.short_id == new_short),
            "credential collision; retry"
        );
        let peer = self
            .state
            .credentials
            .iter_mut()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("peer not found"))?;
        ensure!(peer.desired(), "cannot rotate revoked credentials");
        peer.id.zeroize();
        peer.short_id.zeroize();
        peer.id = new_id;
        peer.short_id = new_short;
        peer.state = "pending".into();
        self.changed()
    }
    pub fn rotate_server_key(&mut self) -> Result<()> {
        self.state.private_key.zeroize();
        self.state.private_key = private_key();
        for p in &mut self.state.credentials {
            if p.desired() {
                p.state = "pending".into();
            }
        }
        self.changed()
    }
    pub fn prepare(&mut self) -> Result<()> {
        let text = render::server(&self.config, &self.state)?;
        let candidate = self.config.state_dir.join("candidate.json");
        secure::atomic_write(&candidate, text.as_bytes())?;
        self.runtime.validate(&candidate)?;
        secure::atomic_write(
            &self.config.state_dir.join("managed.toml"),
            toml::to_string(&self.config)?.as_bytes(),
        )?;
        secure::atomic_write(&self.config.runtime_path(), text.as_bytes())?;
        // Candidate may contain a now-revoked credential after a crash; refresh on every prepare.
        Ok(())
    }
    pub fn reconcile(&mut self) -> Result<()> {
        self.state.attempts = self
            .state
            .attempts
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("attempt counter exhausted"))?;
        self.state.last_error = Some("reconciliation interrupted; retry required".into());
        self.state.save(&self.config)?;
        let result = (|| {
            self.prepare()?;
            let before = self.runtime.before_restart(&self.state.unit())?;
            let started = self.runtime.restart(&self.state.unit())?;
            ensure!(
                started.running && !started.invocation.is_empty(),
                "Xray did not start"
            );
            ensure!(
                !before.running || before.invocation != started.invocation,
                "old Xray process was not replaced"
            );
            secure::check_mode(&self.config.runtime_path(), false)?;
            let saved = Zeroizing::new(std::fs::read_to_string(self.config.runtime_path())?);
            ensure!(
                *saved == *render::server(&self.config, &self.state)?,
                "persisted Xray configuration differs"
            );
            ensure!(
                self.runtime.status(&self.state.unit())? == started,
                "Xray service changed during operation"
            );
            for p in &mut self.state.credentials {
                match p.state.as_str() {
                    "pending" => p.state = "active".into(),
                    "revoking" => p.state = "revoked".into(),
                    _ => (),
                }
            }
            self.state.applied_revision = Some(self.state.revision);
            self.state.last_error = None;
            self.state.save(&self.config)
        })();
        if result.is_err() {
            // Runtime output, native config errors and credentials must never escape.
            self.state.last_error =
                Some("Xray reconciliation failed; fix prerequisites and retry".into());
            let _ = self.state.save(&self.config);
            anyhow::bail!(
                "Xray reconciliation failed; intent retained; fix prerequisites and retry"
            );
        }
        Ok(())
    }
}

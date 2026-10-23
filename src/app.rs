use crate::{
    config::Config,
    export,
    keys::Secret,
    runtime::{Snapshot, WireGuard},
    secure,
    storage::{Peer, Sqlite, Store},
};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, fs::File};

/// The process lock spans reading desired state, all runtime work and final commit.
/// All managers for an interface must use this single state directory.
pub struct Gateway<R: WireGuard> {
    pub config: Config,
    pub runtime: R,
    store: Sqlite,
    key: Secret,
    _lock: File,
}
impl<R: WireGuard> Gateway<R> {
    pub fn open(config: Config, runtime: R, initialize: bool) -> Result<Self> {
        config.validate()?;
        let lock = secure::lock(&config.state_dir)?;
        ensure!(
            !config.state_dir.join("xray-state.json").exists(),
            "WireGuard requires a separate state directory from Xray"
        );
        if initialize && !config.key_path().exists() {
            ensure!(
                !config.state_dir.join("peers.db").exists(),
                "gateway key missing from existing state; restore original key, do not regenerate it"
            );
            let key = Secret::generate();
            secure::create(&config.key_path(), key.expose().as_bytes())?;
        }
        let key = secure::read_secret(&config.key_path())?;
        let store = Sqlite::open(
            &config.state_dir.join("peers.db"),
            &config.identity(&key.public_key()?),
        )?;
        Ok(Self {
            config,
            runtime,
            store,
            key,
            _lock: lock,
        })
    }
    pub fn public_key(&self) -> Result<String> {
        self.key.public_key()
    }
    pub fn audit(&mut self) -> Result<serde_json::Value> {
        let peers = self.peers()?;
        let expected = Snapshot {
            public_key: self.public_key()?,
            listen_port: self.config.listen_port,
            peers: peers
                .iter()
                .filter(|p| p.desired())
                .map(|p| (p.public_key.clone(), format!("{}/32", p.address)))
                .collect(),
        };
        let runtime_matches = self.runtime.snapshot()? == expected;
        let persisted_matches = [
            (self.config.quick_path(), true),
            (self.config.native_path(), false),
        ]
        .iter()
        .all(|(path, quick)| {
            secure::check_mode(path, false).is_ok()
                && std::fs::read(path)
                    .map(zeroize::Zeroizing::new)
                    .is_ok_and(|data| {
                        data.as_slice()
                            == export::server(&self.config, &self.key, &peers, *quick).as_bytes()
                    })
        });
        Ok(
            serde_json::json!({"runtime_matches_desired":runtime_matches,"persisted_matches_desired":persisted_matches,"unsettled_peers":peers.iter().filter(|p|p.state=="pending" || p.state=="revoking" || p.last_error.is_some()).count()}),
        )
    }
    pub fn peers(&self) -> Result<Vec<Peer>> {
        self.store.peers()
    }
    pub fn peer(&self, name: &str) -> Result<Peer> {
        self.peers()?
            .into_iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow::anyhow!("peer not found"))
    }
    pub fn enroll(&mut self, name: &str, public_key: &str, defer: bool) -> Result<Peer> {
        ensure!(
            public_key != self.public_key()?,
            "peer key must differ from gateway key"
        );
        self.store.reserve(&self.config, name, public_key)?;
        if !defer {
            self.reconcile()?;
        }
        self.peer(name)
    }
    pub fn revoke(&mut self, name: &str, defer: bool) -> Result<()> {
        self.store.revoke_intent(name)?;
        if !defer {
            self.reconcile()?;
        }
        Ok(())
    }
    /// Offline persistence never marks enrollment/revocation complete.
    pub fn prepare(&self) -> Result<()> {
        let peers = self.peers()?;
        secure::atomic_write(
            &self.config.quick_path(),
            export::server(&self.config, &self.key, &peers, true).as_bytes(),
        )?;
        secure::atomic_write(
            &self.config.native_path(),
            export::server(&self.config, &self.key, &peers, false).as_bytes(),
        )?;
        Ok(())
    }
    pub fn reconcile(&mut self) -> Result<()> {
        self.store.attempt()?;
        let mut phase = "persist configuration failed";
        let result = (|| {
            self.prepare()?;
            phase = "runtime synchronization failed";
            self.runtime.sync(&self.config.native_path())?;
            phase = "runtime verification failed";
            let peers = self.peers()?;
            let expected = Snapshot {
                public_key: self.key.public_key()?,
                listen_port: self.config.listen_port,
                peers: peers
                    .iter()
                    .filter(|p| p.desired())
                    .map(|p| (p.public_key.clone(), format!("{}/32", p.address)))
                    .collect::<BTreeMap<_, _>>(),
            };
            ensure!(
                self.runtime.snapshot()? == expected,
                "runtime state does not match desired configuration"
            );
            phase = "persisted configuration verification failed";
            for (path, quick) in [
                (self.config.quick_path(), true),
                (self.config.native_path(), false),
            ] {
                secure::check_mode(&path, false)?;
                let actual = zeroize::Zeroizing::new(std::fs::read(path)?);
                ensure!(
                    actual.as_slice()
                        == export::server(&self.config, &self.key, &peers, quick).as_bytes(),
                    "persisted configuration changed during operation"
                );
            }
            phase = "completion commit failed";
            self.store.complete()?;
            Ok(())
        })();
        if result.is_err() {
            self.store.failed(phase)?;
            // Adapter errors are untrusted and may contain a secret; persist/return only a phase.
            anyhow::bail!(
                "{phase}; intent and address reservations retained; fix prerequisite and run reconcile"
            );
        }
        result
    }
    pub fn export(
        &self,
        name: &str,
        key: &Secret,
        ipv6_block_confirmed: bool,
    ) -> Result<zeroize::Zeroizing<String>> {
        export::client(
            &self.config,
            &self.public_key()?,
            &self.peer(name)?,
            key,
            ipv6_block_confirmed,
        )
    }
}

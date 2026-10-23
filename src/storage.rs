use crate::{config::Config, keys, secure};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use std::{collections::HashSet, net::Ipv4Addr, path::Path, time::Duration};

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub address: Ipv4Addr,
    pub state: String,
    pub attempts: u64,
    pub last_error: Option<String>,
}
impl Peer {
    pub fn desired(&self) -> bool {
        self.state == "pending" || self.state == "active"
    }
}
pub trait Store {
    fn peers(&self) -> Result<Vec<Peer>>;
    fn reserve(&mut self, config: &Config, name: &str, public_key: &str) -> Result<Peer>;
    fn revoke_intent(&mut self, name: &str) -> Result<()>;
    fn attempt(&mut self) -> Result<()>;
    fn failed(&mut self, phase: &str) -> Result<()>;
    fn complete(&mut self) -> Result<()>;
}
pub struct Sqlite {
    connection: Connection,
}
impl Sqlite {
    pub fn open(path: &Path, identity: &str) -> Result<Self> {
        secure::directory(path.parent().context("database parent missing")?)?;
        if !path.exists() {
            match secure::create(path, b"") {
                Ok(()) => (),
                Err(_) if path.exists() => (),
                Err(e) => return Err(e),
            }
        }
        secure::check_mode(path, false)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        // Rollback journal is sufficient for this single writer; it lives in the private directory.
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(
            version <= 1,
            "database schema is newer than this program; use the matching binary"
        );
        if version == 0 {
            tx.execute_batch(
                "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE peers (
                    name TEXT PRIMARY KEY NOT NULL,
                    public_key TEXT UNIQUE NOT NULL,
                    address TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','active','revoking','revoked')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE UNIQUE INDEX reserved_address ON peers(address) WHERE state != 'revoked';
                PRAGMA user_version=1;",
            )?;
            tx.execute("INSERT INTO identity VALUES(1, ?1)", [identity])?;
        }
        let saved: String =
            tx.query_row("SELECT value FROM identity WHERE id=1", [], |r| r.get(0))?;
        ensure!(
            saved == identity,
            "gateway identity changed; do not reuse this database with a different key, pool, address or interface"
        );
        tx.commit()?;
        Ok(Self { connection })
    }
    pub fn version(&self) -> &'static str {
        rusqlite::version()
    }
}
impl Store for Sqlite {
    fn peers(&self) -> Result<Vec<Peer>> {
        let mut s = self.connection.prepare(
            "SELECT name,public_key,address,state,attempts,last_error FROM peers ORDER BY name",
        )?;
        let rows = s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (name, public_key, address, state, attempts, last_error) = row?;
            out.push(Peer {
                name,
                public_key,
                address: address.parse().context("corrupt stored address")?,
                state,
                attempts,
                last_error,
            });
        }
        Ok(out)
    }
    fn reserve(&mut self, config: &Config, name: &str, public_key: &str) -> Result<Peer> {
        config.validate()?;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "peer name must contain 1..64 ASCII letters, digits, hyphens or underscores"
        );
        keys::decode(public_key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM peers WHERE name=?1 OR public_key=?2)",
            params![name, public_key],
            |r| r.get(0),
        )?;
        ensure!(
            !exists,
            "peer name or public key already recorded (including revoked tombstones)"
        );
        let used: HashSet<String> = {
            let mut q = tx.prepare("SELECT address FROM peers WHERE state != 'revoked'")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let address = config
            .pool
            .hosts()
            .find(|ip| *ip != config.gateway_address && !used.contains(&ip.to_string()))
            .context("address pool exhausted; no reservation created")?;
        tx.execute(
            "INSERT INTO peers(name,public_key,address,state) VALUES(?1,?2,?3,'pending')",
            params![name, public_key, address.to_string()],
        )?;
        tx.commit()?;
        Ok(Peer {
            name: name.into(),
            public_key: public_key.into(),
            address,
            state: "pending".into(),
            attempts: 0,
            last_error: None,
        })
    }
    fn revoke_intent(&mut self, name: &str) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row("SELECT state FROM peers WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(state) = state else {
            bail!("peer not found");
        };
        if state != "revoked" {
            tx.execute("UPDATE peers SET state='revoking',last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE name=?1", [name])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn attempt(&mut self) -> Result<()> {
        self.connection.execute("UPDATE peers SET attempts=attempts+1,last_error='operation interrupted; reconcile required',updated_at=CURRENT_TIMESTAMP WHERE state != 'revoked'", [])?;
        Ok(())
    }
    fn failed(&mut self, phase: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE peers SET last_error=?1,updated_at=CURRENT_TIMESTAMP WHERE state != 'revoked'",
            [phase],
        )?;
        Ok(())
    }
    fn complete(&mut self) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE peers SET state=CASE WHEN state='pending' THEN 'active' WHEN state='revoking' THEN 'revoked' ELSE state END,last_error=NULL,updated_at=CURRENT_TIMESTAMP", [])?;
        tx.commit()?;
        Ok(())
    }
}

use anyhow::Result;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier, Mutex},
    thread,
};
use vpn_config_kit::{
    app::Gateway,
    config::Config,
    keys::Secret,
    runtime::{Snapshot, WireGuard},
    secure,
    storage::{Sqlite, Store},
};

#[derive(Clone, Default)]
struct Fake {
    inner: Arc<Mutex<RuntimeState>>,
}
#[derive(Default)]
struct RuntimeState {
    snapshot: Option<Snapshot>,
    fail_before: bool,
    fail_after: bool,
    tamper: bool,
    skip_sync: bool,
}
impl WireGuard for Fake {
    fn sync(&mut self, path: &Path) -> Result<()> {
        let mut s = self.inner.lock().unwrap();
        if s.fail_before {
            anyhow::bail!("PRIVATE-ERROR-SENTINEL");
        }
        if s.skip_sync {
            return Ok(());
        }
        let data = fs::read_to_string(path)?;
        let key = data
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey = "))
            .unwrap();
        let port = data
            .lines()
            .find_map(|l| l.strip_prefix("ListenPort = "))
            .unwrap()
            .parse()?;
        let mut peers = BTreeMap::new();
        let mut current = None;
        for line in data.lines() {
            if let Some(key) = line.strip_prefix("PublicKey = ") {
                current = Some(key.to_owned());
            }
            if let Some(ip) = line.strip_prefix("AllowedIPs = ") {
                peers.insert(current.take().unwrap(), ip.to_owned());
            }
        }
        s.snapshot = Some(Snapshot {
            public_key: Secret::parse(key.into())?.public_key()?,
            listen_port: port,
            peers,
        });
        if s.tamper {
            fs::write(path, b"changed")?;
        }
        if s.fail_after {
            anyhow::bail!("PRIVATE-ERROR-SENTINEL");
        }
        Ok(())
    }
    fn snapshot(&mut self) -> Result<Snapshot> {
        Ok(self.inner.lock().unwrap().snapshot.clone().unwrap())
    }
}
fn fixture() -> (tempfile::TempDir, Config, Fake) {
    let dir = tempfile::tempdir().unwrap();
    let c = Config {
        state_dir: dir.path().join("private"),
        endpoint: "vpn.example.com:51820".into(),
        egress_interface: "eth0".into(),
        ..Config::default()
    };
    (dir, c, Fake::default())
}
fn db_path(c: &Config) -> PathBuf {
    c.state_dir.join("peers.db")
}

#[test]
fn successful_command_without_runtime_removal_cannot_release_address() {
    let (_dir, mut c, r) = fixture();
    c.pool = "10.77.0.0/30".parse().unwrap();
    let mut g = Gateway::open(c, r.clone(), true).unwrap();
    g.enroll("old", &Secret::generate().public_key().unwrap(), false)
        .unwrap();
    r.inner.lock().unwrap().skip_sync = true;
    let error = g.revoke("old", false).unwrap_err().to_string();
    assert!(error.contains("runtime verification failed"));
    assert_eq!(g.peer("old").unwrap().state, "revoking");
    assert!(
        g.enroll("new", &Secret::generate().public_key().unwrap(), true)
            .is_err()
    );
    r.inner.lock().unwrap().skip_sync = false;
    g.reconcile().unwrap();
    assert_eq!(g.peer("old").unwrap().state, "revoked");
}

#[test]
fn interrupted_enrollment_survives_restart_and_redacts_failures() {
    let (_dir, c, r) = fixture();
    let key = Secret::generate();
    {
        let mut g = Gateway::open(c.clone(), r.clone(), true).unwrap();
        r.inner.lock().unwrap().fail_after = true;
        let error = g
            .enroll("phone", &key.public_key().unwrap(), false)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SENTINEL"));
        let peer = g.peer("phone").unwrap();
        assert_eq!(peer.state, "pending");
        assert_eq!(peer.attempts, 1);
        assert!(peer.last_error.is_some());
    }
    r.inner.lock().unwrap().fail_after = false;
    let mut g = Gateway::open(c, r.clone(), false).unwrap();
    g.reconcile().unwrap();
    g.reconcile().unwrap();
    assert_eq!(g.audit().unwrap()["runtime_matches_desired"], true);
    assert_eq!(g.audit().unwrap()["persisted_matches_desired"], true);
    let p = g.peer("phone").unwrap();
    assert_eq!(p.state, "active");
    assert!(p.last_error.is_none());
    assert_eq!(
        r.inner
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .len(),
        1
    );
}

#[test]
fn failed_revocation_keeps_address_until_both_copies_and_runtime_are_clean() {
    let (_dir, mut c, r) = fixture();
    c.pool = "10.77.0.0/30".parse().unwrap();
    let mut g = Gateway::open(c.clone(), r.clone(), true).unwrap();
    let a = Secret::generate();
    let b = Secret::generate();
    let original = g.enroll("old", &a.public_key().unwrap(), false).unwrap();
    r.inner.lock().unwrap().fail_before = true;
    assert!(g.revoke("old", false).is_err());
    assert_eq!(g.peer("old").unwrap().state, "revoking");
    assert!(g.enroll("new", &b.public_key().unwrap(), true).is_err());
    assert!(
        r.inner
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .contains_key(&a.public_key().unwrap())
    );
    r.inner.lock().unwrap().fail_before = false;
    g.reconcile().unwrap();
    assert_eq!(g.peer("old").unwrap().state, "revoked");
    for path in [c.quick_path(), c.native_path()] {
        assert!(
            !fs::read_to_string(path)
                .unwrap()
                .contains(&a.public_key().unwrap())
        );
    }
    let new = g.enroll("new", &b.public_key().unwrap(), false).unwrap();
    assert_eq!(original.address, new.address);
    assert!(g.enroll("another", &a.public_key().unwrap(), true).is_err());
    g.revoke("old", false).unwrap();
    assert_eq!(g.peer("new").unwrap().state, "active");
    assert_eq!(
        r.inner
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .len(),
        1
    );
}

#[test]
fn offline_intents_cannot_be_reactivated_and_runtime_drift_is_removed() {
    let (_dir, c, r) = fixture();
    let a = Secret::generate();
    let alien = Secret::generate();
    {
        let mut g = Gateway::open(c.clone(), r.clone(), true).unwrap();
        g.enroll("pending", &a.public_key().unwrap(), true).unwrap();
        g.revoke("pending", true).unwrap();
        g.prepare().unwrap();
        assert_eq!(g.peer("pending").unwrap().state, "revoking");
    }
    let mut g = Gateway::open(c, r.clone(), false).unwrap();
    g.reconcile().unwrap();
    r.inner
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .peers
        .insert(alien.public_key().unwrap(), "10.77.0.2/32".into());
    g.reconcile().unwrap();
    assert!(
        r.inner
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .is_empty()
    );
}

#[test]
fn persistence_failure_and_verification_failure_never_complete() {
    let (_dir, c, r) = fixture();
    let mut g = Gateway::open(c.clone(), r.clone(), true).unwrap();
    fs::create_dir(c.quick_path()).unwrap();
    let key = Secret::generate();
    assert!(g.enroll("one", &key.public_key().unwrap(), false).is_err());
    assert!(r.inner.lock().unwrap().snapshot.is_none());
    fs::remove_dir(c.quick_path()).unwrap();
    r.inner.lock().unwrap().tamper = true;
    assert!(g.reconcile().is_err());
    assert_eq!(g.peer("one").unwrap().state, "pending");
    r.inner.lock().unwrap().tamper = false;
    g.reconcile().unwrap();
}

#[test]
fn process_lock_blocks_conflicting_manager_and_identity_changes_fail_closed() {
    let (_dir, c, r) = fixture();
    let g = Gateway::open(c.clone(), r.clone(), true).unwrap();
    assert!(Gateway::open(c.clone(), r.clone(), false).is_err());
    drop(g);
    let mut other = c.clone();
    other.interface = "wg1".into();
    assert!(Gateway::open(other, r.clone(), false).is_err());
    fs::remove_file(c.key_path()).unwrap();
    assert!(Gateway::open(c, r, true).is_err());
}

#[test]
fn database_has_no_private_key_column_or_client_secret() {
    let (_dir, c, r) = fixture();
    let key = Secret::generate();
    let mut g = Gateway::open(c.clone(), r, true).unwrap();
    g.enroll("one", &key.public_key().unwrap(), true).unwrap();
    drop(g);
    let bytes = fs::read(db_path(&c)).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(key.expose()));
    let db = rusqlite::Connection::open(db_path(&c)).unwrap();
    let sql: String = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='peers'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!sql.contains("private"));
}

#[test]
fn concurrent_allocators_reserve_distinct_addresses_and_enforce_constraints() {
    let (_dir, mut c, _r) = fixture();
    c.pool = "10.77.0.0/28".parse().unwrap();
    secure::directory(&c.state_dir).unwrap();
    drop(Sqlite::open(&db_path(&c), "test-identity").unwrap());
    let barrier = Arc::new(Barrier::new(12));
    let threads: Vec<_> = (0..12)
        .map(|i| {
            let c = c.clone();
            let b = barrier.clone();
            thread::spawn(move || {
                let mut db = Sqlite::open(&db_path(&c), "test-identity").unwrap();
                let key = Secret::generate();
                b.wait();
                db.reserve(&c, &format!("peer{i}"), &key.public_key().unwrap())
                    .unwrap()
                    .address
            })
        })
        .collect();
    let ips: std::collections::HashSet<_> =
        threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(ips.len(), 12);
    let mut db = Sqlite::open(&db_path(&c), "test-identity").unwrap();
    db.reserve(&c, "last", &Secret::generate().public_key().unwrap())
        .unwrap();
    assert!(
        db.reserve(&c, "overflow", &Secret::generate().public_key().unwrap())
            .is_err()
    );
    let first = db.peers().unwrap()[0].clone();
    assert!(db.reserve(&c, "duplicate", &first.public_key).is_err());
    let raw = rusqlite::Connection::open(db_path(&c)).unwrap();
    assert!(raw.execute("INSERT INTO peers(name,public_key,address,state) VALUES('rogue','unique',?1,'pending')",[first.address.to_string()]).is_err());
}

#[test]
fn interrupted_sql_transaction_does_not_leak_a_reservation_and_newer_schema_is_rejected() {
    let (_dir, c, _r) = fixture();
    secure::directory(&c.state_dir).unwrap();
    drop(Sqlite::open(&db_path(&c), "test").unwrap());
    {
        let conn = rusqlite::Connection::open(db_path(&c)).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE; INSERT INTO peers(name,public_key,address,state) VALUES('uncommitted','key','10.77.0.2','pending');").unwrap();
    }
    let mut db = Sqlite::open(&db_path(&c), "test").unwrap();
    let p = db
        .reserve(&c, "valid", &Secret::generate().public_key().unwrap())
        .unwrap();
    assert_eq!(p.address.to_string(), "10.77.0.2");
    drop(db);
    let conn = rusqlite::Connection::open(db_path(&c)).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    assert!(Sqlite::open(&db_path(&c), "test").is_err());
}

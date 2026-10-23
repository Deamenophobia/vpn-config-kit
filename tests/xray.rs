use anyhow::{Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};
use vpn_config_kit::{
    secure,
    xray::{self, Config, Gateway, Running, Runtime},
};

#[derive(Default)]
struct Fake {
    invocation: u32,
    running: bool,
    fail: bool,
    ineffective: bool,
    corrupt: Option<PathBuf>,
}
impl Runtime for Fake {
    fn validate(&mut self, path: &Path) -> Result<()> {
        let _: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        Ok(())
    }
    fn status(&mut self, _: &str) -> Result<Running> {
        Ok(Running {
            running: self.running,
            invocation: if self.running {
                self.invocation.to_string()
            } else {
                String::new()
            },
        })
    }
    fn restart(&mut self, unit: &str) -> Result<Running> {
        if self.fail {
            bail!("SECRET_FROM_UNTRUSTED_ENGINE");
        }
        if !self.ineffective {
            self.invocation += 1;
        }
        self.running = true;
        if let Some(path) = &self.corrupt {
            secure::atomic_write(path, b"{}")?;
        }
        self.status(unit)
    }
    fn stop(&mut self, _: &str) -> Result<()> {
        self.running = false;
        Ok(())
    }
}
fn config(dir: &Path) -> Config {
    Config {
        state_dir: dir.join("xray"),
        endpoint: "vpn.example.com:443".into(),
        target: "www.example.com:443".into(),
        server_name: "www.example.com".into(),
        engine_path: dir.join("xray-engine"),
        manager_path: dir.join("manager"),
        ..Config::default()
    }
}
#[test]
fn xray_settings_and_exports_reject_injection_and_keep_secrets_out_of_status() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    c.validate().unwrap();
    let mut bad = c.clone();
    bad.server_name = "example.com&sid=secret".into();
    assert!(bad.validate().is_err());
    bad = c.clone();
    bad.backend = "wireguard".into();
    assert!(bad.validate().is_err());
    assert!(
        Config::parse("secret='DO_NOT_ECHO'", &[])
            .unwrap_err()
            .to_string()
            .find("DO_NOT_ECHO")
            .is_none()
    );
    let mut g = Gateway::open(c, Fake::default(), true).unwrap();
    g.enroll("phone").unwrap();
    assert!(g.enroll("phone").is_err());
    assert!(g.enroll("unsafe#name").is_err());
    let server = xray::render::server(&g.config, &g.state).unwrap();
    let v: serde_json::Value = serde_json::from_str(&server).unwrap();
    assert_eq!(
        v["outbounds"][0]["settings"]["finalRules"][0]["ip"][0],
        "::/0"
    );
    assert_eq!(
        v["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        "ForceIPv4"
    );
    let id = v["inbounds"][0]["settings"]["users"][0]["id"]
        .as_str()
        .unwrap();
    let private = v["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
        .as_str()
        .unwrap();
    let status = g.state.public().to_string();
    assert!(!status.contains(id) && !status.contains(private));
    let client =
        xray::render::client(&g.config, &g.state, g.peer("phone").unwrap(), 10808).unwrap();
    assert!(client.contains(id) && !client.contains(private));
    let uri = xray::render::link(&g.config, &g.state, g.peer("phone").unwrap()).unwrap();
    assert!(
        uri.starts_with("vless://")
            && uri.contains("flow=xtls-rprx-vision")
            && !uri.contains(private)
    );
    let v: serde_json::Value = serde_json::from_str(&client).unwrap();
    assert_eq!(v["inbounds"][0]["listen"], "127.0.0.1");
    assert!(!g.config.state_dir.join("peers.db").exists());
    let mut allowed = g.config.clone();
    allowed.allow_private_destinations = true;
    let data = xray::render::server(&allowed, &g.state).unwrap();
    let data: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        data["outbounds"][0]["settings"]["finalRules"][1]["action"],
        "allow"
    );
    let mut unit = g.config.clone();
    unit.state_dir = "/var/lib/vpn-config-kit-xray".into();
    unit.engine_path = "/usr/local/lib/vpn-config-kit/xray".into();
    unit.manager_path = "/usr/local/bin/vpn-config-kit".into();
    let service = xray::runtime::service(&unit).unwrap();
    assert!(
        service.contains("KillMode=control-group") && service.contains("managed.toml xray-serve")
    );
    unit.manager_path = "/usr/local/bin/unsafe%name".into();
    assert!(xray::runtime::service(&unit).is_err());
}
#[test]
fn xray_revocation_rotation_and_restart_intent_survive_failure() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut g = Gateway::open(c.clone(), Fake::default(), true).unwrap();
    g.enroll("phone").unwrap();
    g.reconcile().unwrap();
    assert_eq!(g.peer("phone").unwrap().state, "active");
    let old = xray::render::link(&g.config, &g.state, g.peer("phone").unwrap()).unwrap();
    g.rotate("phone").unwrap();
    let new = xray::render::link(&g.config, &g.state, g.peer("phone").unwrap()).unwrap();
    assert_ne!(*old, *new);
    assert!(xray::runtime::check_startup(&g.config).is_err());
    g.runtime.fail = true;
    let error = g.reconcile().unwrap_err().to_string();
    assert!(!error.contains("SECRET_FROM_UNTRUSTED_ENGINE"));
    let invocation = g.runtime.invocation;
    drop(g);
    let mut g = Gateway::open(
        c,
        Fake {
            running: true,
            invocation,
            ..Fake::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(g.peer("phone").unwrap().state, "pending");
    g.reconcile().unwrap();
    xray::runtime::check_startup(&g.config).unwrap();
    g.revoke("phone").unwrap();
    assert!(xray::runtime::check_startup(&g.config).is_err());
    g.runtime.ineffective = true;
    assert!(g.reconcile().is_err());
    assert_eq!(g.peer("phone").unwrap().state, "revoking");
    g.runtime.ineffective = false;
    g.reconcile().unwrap();
    g.revoke("phone").unwrap();
    g.reconcile().unwrap();
    assert_eq!(g.peer("phone").unwrap().state, "revoked");
    assert!(g.enroll("phone").is_err());
    assert!(g.rotate("phone").is_err());
    assert!(xray::render::link(&g.config, &g.state, g.peer("phone").unwrap()).is_err());
    let native = fs::read_to_string(g.config.runtime_path()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&native).unwrap();
    assert_eq!(
        v["inbounds"][0]["settings"]["users"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}
#[test]
fn xray_lock_persistence_tampering_and_server_key_rotation_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut g = Gateway::open(c.clone(), Fake::default(), true).unwrap();
    assert!(Gateway::open(c, Fake::default(), false).is_err());
    g.enroll("tablet").unwrap();
    g.reconcile().unwrap();
    let public = xray::render::public_key(&g.state).unwrap();
    g.rotate_server_key().unwrap();
    assert_ne!(public, xray::render::public_key(&g.state).unwrap());
    g.runtime.corrupt = Some(g.config.runtime_path());
    assert!(g.reconcile().is_err());
    assert_eq!(g.peer("tablet").unwrap().state, "pending");
    g.runtime.corrupt = None;
    g.reconcile().unwrap();
    secure::check_mode(&g.config.state_path(), false).unwrap();
    let rules = xray::runtime::firewall(&g.config, &g.state).unwrap();
    assert!(rules.contains("tcp dport 443") && !rules.contains("flush ruleset"));
}
#[test]
fn xray_refuses_wireguard_state_and_unknown_schema() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let g = Gateway::open(c.clone(), Fake::default(), true).unwrap();
    drop(g);
    let mut wg =
        vpn_config_kit::config::Config::parse(include_str!("../examples/gateway.toml")).unwrap();
    wg.state_dir = c.state_dir.clone();
    let error = vpn_config_kit::app::Gateway::open(
        wg.clone(),
        vpn_config_kit::runtime::Linux { config: wg },
        true,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("separate state directory"));
    assert!(!c.state_dir.join("gateway.key").exists());
    secure::create(&c.state_dir.join("peers.db"), b"").unwrap();
    assert!(Gateway::open(c.clone(), Fake::default(), false).is_err());
    fs::remove_file(c.state_dir.join("peers.db")).unwrap();
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(c.state_path()).unwrap()).unwrap();
    state["schema"] = 999.into();
    secure::atomic_write(
        &c.state_path(),
        serde_json::to_string(&state).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(Gateway::open(c, Fake::default(), false).is_err());
}
/// Opt in with VPN_CONFIG_KIT_XRAY_BIN pointing at the pinned native engine.
#[test]
#[ignore = "requires separately downloaded pinned Xray engine"]
fn pinned_native_engine_accepts_generated_server_and_client() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    c.engine_path = std::env::var_os("VPN_CONFIG_KIT_XRAY_BIN")
        .expect("set VPN_CONFIG_KIT_XRAY_BIN")
        .into();
    let runtime = xray::Native::new(c.clone());
    let mut g = Gateway::open(c, runtime, true).unwrap();
    g.enroll("native").unwrap();
    g.prepare().unwrap();
    let path = g.config.state_dir.join("client.json");
    let client =
        xray::render::client(&g.config, &g.state, g.peer("native").unwrap(), 10808).unwrap();
    secure::create(&path, client.as_bytes()).unwrap();
    g.runtime.validate(&path).unwrap();
    g.revoke("native").unwrap();
    g.prepare().unwrap();
    g.config.engine_path = dir.path().join("fake-engine");
    fs::write(&g.config.engine_path, b"not the pinned engine").unwrap();
    assert!(xray::Native::new(g.config.clone()).check_engine().is_err());
}

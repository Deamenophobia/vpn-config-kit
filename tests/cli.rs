use std::{
    fs,
    process::{Command, Output},
};
use vpn_config_kit::{config::Config, secure};
fn command(config: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vpn-config-kit"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn offline_cli_key_enrollment_export_and_failure_recovery_intent() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("private");
    secure::directory(&private).unwrap();
    let c = Config {
        state_dir: private.join("gateway"),
        endpoint: "vpn.example.com:51820".into(),
        egress_interface: "eth0".into(),
        ..Config::default()
    };
    let file = private.join("gateway.toml");
    fs::write(&file, toml::to_string(&c).unwrap()).unwrap();
    assert!(command(&file, &["check"]).status.success());
    let initialized = command(&file, &["init"]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let keypath = private.join("phone.key");
    let keypath = keypath.to_str().unwrap();
    let generated = command(&file, &["keygen", "--out", keypath]);
    assert!(generated.status.success());
    let json: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
    let public = json["public_key"].as_str().unwrap();
    let added = command(
        &file,
        &[
            "peer",
            "add",
            "--name",
            "phone",
            "--public-key",
            public,
            "--defer",
        ],
    );
    assert!(added.status.success());
    let profile = private.join("phone.conf");
    let exported = command(
        &file,
        &[
            "peer",
            "export",
            "phone",
            "--private-key-file",
            keypath,
            "--out",
            profile.to_str().unwrap(),
            "--ipv6-block-confirmed",
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let privatekey = fs::read_to_string(keypath).unwrap();
    for bytes in [&generated.stdout, &added.stdout, &exported.stdout] {
        assert!(!String::from_utf8_lossy(bytes).contains(&privatekey));
    }
    assert!(fs::read_to_string(profile).unwrap().contains(&privatekey));
    let reconciled = command(&file, &["reconcile"]);
    assert!(!reconciled.status.success()); // No interface created by this test.
    let listed = command(&file, &["peer", "list"]);
    let peers: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(peers[0]["state"], "pending");
    assert!(peers[0]["last_error"].is_string());
    let lock = secure::lock(&c.state_dir).unwrap();
    let conflicted = command(&file, &["peer", "revoke", "phone", "--defer"]);
    assert!(!conflicted.status.success());
    assert!(String::from_utf8_lossy(&conflicted.stderr).contains("another gateway operation"));
    drop(lock);
    assert!(
        command(&file, &["peer", "revoke", "phone", "--defer"])
            .status
            .success()
    );
}

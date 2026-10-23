use std::{
    fs,
    time::{Duration, Instant},
};
use vpn_config_kit::{
    config::{Config, DnsPolicy, Routing},
    export,
    keys::{Secret, decode},
    runtime, secure,
    storage::Peer,
};

fn valid() -> Config {
    let mut c = Config::parse(include_str!("../examples/gateway.toml")).unwrap();
    c.state_dir = std::env::temp_dir().join("vpn-config-kit-config-test");
    c
}
#[test]
fn invalid_configuration_and_injection_are_rejected_without_source_echo() {
    let c = valid();
    c.validate().unwrap();
    let mut bad = Vec::new();
    let mut x = c.clone();
    x.version = 2;
    bad.push(x);
    let mut x = c.clone();
    x.interface = "wg0;id".into();
    bad.push(x);
    let mut x = c.clone();
    x.endpoint = "example.com:123\nPrivateKey = SECRET".into();
    bad.push(x);
    let mut x = c.clone();
    x.pool = "10.77.0.1/24".parse().unwrap();
    bad.push(x);
    let mut x = c.clone();
    x.pool = "8.8.0.0/16".parse().unwrap();
    bad.push(x);
    let mut x = c.clone();
    x.gateway_address = "10.77.1.1".parse().unwrap();
    bad.push(x);
    let mut x = c.clone();
    x.excluded_subnets = vec!["10.0.0.0/8".parse().unwrap()];
    bad.push(x);
    let mut x = c.clone();
    x.listen_port = 0;
    bad.push(x);
    let mut x = c.clone();
    x.routing = Routing::Split;
    bad.push(x);
    let mut x = c.clone();
    x.routing = Routing::Split;
    x.split_routes = vec!["10.77.0.0/24".parse().unwrap()];
    bad.push(x);
    let mut x = c.clone();
    x.dns_policy = DnsPolicy::Preserve;
    bad.push(x);
    let mut x = c.clone();
    x.command_timeout_secs = 0;
    bad.push(x);
    let mut x = c.clone();
    x.state_dir = "relative".into();
    bad.push(x);
    for item in bad {
        let error = item.validate().unwrap_err().to_string();
        assert!(!error.contains("SECRET"));
    }
    let error = Config::parse("private_key='PRIVATE_SENTINEL'")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE_SENTINEL"));
    assert!(Config::parse("ipv6_policy='ignore'").is_err());
}
#[test]
fn overrides_take_precedence_without_ignoring_unknown_fields() {
    let c = Config::with_overrides(
        include_str!("../examples/gateway.toml"),
        &["listen_port=12345".into(), "keepalive=25".into()],
    )
    .unwrap();
    assert_eq!(c.listen_port, 12345);
    assert_eq!(c.keepalive, 25);
    assert!(Config::with_overrides("unknown=1", &["listen_port=12345".into()]).is_err());
}
#[test]
fn wireguard_key_generation_matches_rfc7748_public_vector_and_debug_is_redacted() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let key = Secret::parse(STANDARD.encode(bytes)).unwrap();
    let public = STANDARD.decode(key.public_key().unwrap()).unwrap();
    let public_hex = public
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        public_hex,
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(format!("{key:?}"), "Secret([REDACTED])");
    assert!(decode(&STANDARD.encode([0u8; 32])).is_err());
    assert!(decode("SECRET").is_err());
}
#[test]
fn exports_separate_native_and_quick_fields_and_check_client_identity() {
    let mut c = valid();
    c.keepalive = 25;
    c.mtu = Some(1420);
    let gateway = Secret::generate();
    let key = Secret::generate();
    let peer = Peer {
        name: "phone".into(),
        public_key: key.public_key().unwrap(),
        address: "10.77.0.2".parse().unwrap(),
        state: "pending".into(),
        attempts: 0,
        last_error: None,
    };
    let native = export::server(&c, &gateway, std::slice::from_ref(&peer), false);
    assert!(!native.contains("Address ="));
    assert!(!native.contains("DNS"));
    assert!(!native.contains("SaveConfig"));
    assert!(native.contains("AllowedIPs = 10.77.0.2/32"));
    let quick = export::server(&c, &gateway, std::slice::from_ref(&peer), true);
    assert!(quick.contains("Address = 10.77.0.1/24"));
    assert!(export::client(&c, &gateway.public_key().unwrap(), &peer, &key, false).is_err());
    assert!(
        export::client(
            &c,
            &gateway.public_key().unwrap(),
            &peer,
            &Secret::generate(),
            true
        )
        .is_err()
    );
    let client = export::client(&c, &gateway.public_key().unwrap(), &peer, &key, true).unwrap();
    assert!(client.contains("AllowedIPs = 0.0.0.0/0"));
    assert!(!client.contains("::/0"));
    assert!(client.contains("PersistentKeepalive = 25"));
    assert!(!client.contains(gateway.expose()));
    assert!(export::qr(&client).unwrap().contains("<svg"));
    c.routing = Routing::Split;
    c.split_routes = vec!["10.77.0.0/24".parse().unwrap()];
    c.dns_policy = DnsPolicy::Preserve;
    c.dns.clear();
    let client = export::client(&c, &gateway.public_key().unwrap(), &peer, &key, true).unwrap();
    assert!(client.contains("AllowedIPs = 10.77.0.0/24"));
    assert!(!client.contains("DNS ="));
}
#[test]
fn private_exports_refuse_overwrite_and_permissions_are_restrictive() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("private");
    secure::directory(&folder).unwrap();
    let file = folder.join("client.conf");
    secure::create(&file, b"secret").unwrap();
    assert!(secure::create(&file, b"replacement").is_err());
    assert_eq!(fs::read(&file).unwrap(), b"secret");
    secure::atomic_write(&file, b"new secret").unwrap();
    secure::check_mode(&file, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn firewall_script_is_scoped_to_owned_table_and_has_reversal() {
    let script = export::firewall(&valid()).unwrap();
    assert!(!script.contains("flush ruleset"));
    assert!(script.contains("delete table inet"));
    assert!(script.contains("vpn_config_kit_wg0"));
    assert!(script.contains("ip saddr 10.77.0.0/24 masquerade"));
}
#[test]
fn failing_subprocess_output_is_redacted_and_timeout_is_bounded() {
    #[cfg(windows)]
    let (program, args) = (
        "powershell.exe",
        vec![
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Write-Error PRIVATE_SENTINEL; exit 1",
        ],
    );
    #[cfg(unix)]
    let (program, args) = ("sh", vec!["-c", "echo PRIVATE_SENTINEL >&2; exit 1"]);
    let error = runtime::run(program, &args, None, Duration::from_secs(5))
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE_SENTINEL"));
    #[cfg(windows)]
    let args = vec![
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Start-Sleep -Seconds 30",
    ];
    #[cfg(unix)]
    let args = vec!["-c", "sleep 30"];
    let now = Instant::now();
    assert!(runtime::run(program, &args, None, Duration::from_millis(250)).is_err());
    assert!(now.elapsed() < Duration::from_secs(5));
}
#[cfg(unix)]
#[test]
fn exited_parent_cannot_leave_a_child_holding_stdout_forever() {
    let now = Instant::now();
    assert!(
        runtime::run(
            "sh",
            &["-c", "sleep 30 & exit 0"],
            None,
            Duration::from_millis(200)
        )
        .is_err()
    );
    assert!(now.elapsed() < Duration::from_secs(3));
}
#[cfg(unix)]
#[test]
fn symlinks_hardlinks_and_broad_permissions_are_rejected() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("private");
    secure::directory(&private).unwrap();
    let key = private.join("key");
    secure::create(&key, b"secret").unwrap();
    let alias = private.join("alias");
    symlink(&key, &alias).unwrap();
    assert!(secure::check_mode(&alias, false).is_err());
    fs::hard_link(&key, private.join("hard")).unwrap();
    assert!(secure::check_mode(&key, false).is_err());
    fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(secure::directory(&private).is_err());
}

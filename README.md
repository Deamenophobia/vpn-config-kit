# VPN Config Kit

A single-gateway management toolkit in Rust for WireGuard and optional Xray.

Evolved from [kokoro-vpn](https://gitlab.com/kokoro-tech/infra/kokoro-vpn), with an independently rewritten implementation. Access to the original repository is required.

```sh
cargo build --locked --release
```

Gateway services run on Linux. Windows supports local configuration and exports.

[Setup](docs/INSTALL.md) · [Usage](docs/USAGE.md) · [Xray](docs/XRAY.md) · [Configuration](docs/CONFIGURATION.md) · [Security](docs/SECURITY.md) · [Notices](THIRD_PARTY_NOTICES.md)

If you run into a problem, please contact me by opening an issue in this repository. Do not include credentials or client profiles.

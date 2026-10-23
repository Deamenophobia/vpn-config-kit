# Provenance and licensing

VPN Config Kit is an independently written Rust implementation. No legacy implementation files, snippets, migrations, tests, deployment files, assets or Git history were imported. Detailed source mapping, revision references and private migration findings remain outside this repository. This is not a claim of a legal clean-room process.

The project evolved from [kokoro-vpn](https://gitlab.com/kokoro-tech/infra/kokoro-vpn), whose source requires repository access. WireGuard support uses standard tooling and independently rendered profiles. The optional Xray backend uses new management code around a separately installed upstream engine; no legacy transport implementation was copied.

`Cargo.lock` pins Rust dependencies. [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and `notices/` retain their license inventory and available license/author texts. Regenerate them with `python scripts/dependency-notices.py` after dependency changes. The Xray installer retains its upstream license alongside the external engine.

The owner has left the project license undecided. Dependency notices do not assign a license to VPN Config Kit. Cargo package publication remains disabled.

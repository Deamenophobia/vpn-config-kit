# Usage

Complete the [gateway setup](INSTALL.md) first. WireGuard is the default backend. For the optional Xray backend, use its separate [setup and commands](XRAY.md).

## WireGuard devices

Generate a client key in a private directory, then enroll its public key on the gateway:

```sh
mkdir -m 700 client-secrets
vpn-config-kit keygen --out "$PWD/client-secrets/phone.key"
sudo vpn-config-kit peer add --name phone --public-key PUBLIC_KEY_FROM_KEYGEN
```

With a protected local copy of the client key, export a profile:

```sh
sudo vpn-config-kit peer export phone \
  --private-key-file /absolute/private/phone.key \
  --out /absolute/private/phone.conf --qr /absolute/private/phone.svg \
  --ipv6-block-confirmed
```

WireGuard profiles tunnel IPv4. The export flag acknowledges that you have blocked IPv6 independently on the client. Client DNS and disconnect behavior remain controlled by the client application.

## Manage access

```sh
sudo vpn-config-kit peer list
sudo vpn-config-kit doctor
sudo vpn-config-kit peer revoke phone
sudo vpn-config-kit reconcile
```

Add `--backend xray-reality` for Xray. Revocation affects the selected backend; revoke both profiles if a device uses both. Xray credential changes restart its dedicated service and interrupt active sessions.

Use `--config /absolute/path/gateway.toml` to select settings and `--help` for command options. Profiles, links and QR images contain credentials: store them privately, transfer them securely and remove temporary copies after delivery. WireGuard client private keys remain outside the peer database; Xray credentials reside in its separate protected state directory.

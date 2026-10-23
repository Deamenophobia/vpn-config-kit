#!/bin/sh
# Installs only the pinned external engine and its license; does not start a service.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'Linux x86_64 required.' >&2; exit 1; }
for tool in curl unzip sha256sum install mktemp; do command -v "$tool" >/dev/null; done
umask 077
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 --max-time 180 \
  https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip \
  -o "$work/engine.zip"
printf '%s  %s\n' 0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978 "$work/engine.zip" | sha256sum -c -
unzip -q "$work/engine.zip" -d "$work/extracted"
printf '%s  %s\n' a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e "$work/extracted/xray" | sha256sum -c -
install -d -m 755 /usr/local/lib/vpn-config-kit /usr/local/share/doc/vpn-config-kit/xray
install -m 755 "$work/extracted/xray" /usr/local/lib/vpn-config-kit/xray
install -m 644 "$work/extracted/LICENSE" /usr/local/share/doc/vpn-config-kit/xray/LICENSE
echo 'Installed Xray 26.10.21. No service was started.'

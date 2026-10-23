"""Local native Xray exercise using only loopback TCP/UDP and a temporary TLS target.

Requires Python 3, OpenSSL, a built toolkit, and the pinned native Xray engine.
Does not manage systemd, interfaces, host routes, or firewalls.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time


def exact(stream, count):
    data = b""
    while len(data) < count:
        part = stream.recv(count - len(data))
        if not part:
            raise ConnectionError("connection closed")
        data += part
    return data


def socks(port, destination, command=1):
    stream = socket.create_connection(("127.0.0.1", port), timeout=4)
    try:
        stream.sendall(b"\x05\x01\x00")
        assert exact(stream, 2) == b"\x05\x00"
        stream.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", destination))
        head = exact(stream, 4)
        assert head[:3] == b"\x05\x00\x00"
        length = {1: 4, 4: 16}.get(head[3])
        if length is None:
            length = exact(stream, 1)[0]
        address = exact(stream, length)
        bind_port = struct.unpack("!H", exact(stream, 2))[0]
        return stream, bind_port
    except BaseException:
        stream.close()
        raise


class TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    def handle_error(self, *_):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(120)
        while data := self.request.recv(4096):
            self.request.sendall(data)


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TLS(socketserver.BaseRequestHandler):
    context = None
    def handle(self):
        self.request.settimeout(4)
        with self.context.wrap_socket(self.request, server_side=True) as stream:
            stream.recv(1024)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--keep-work", action="store_true", help="retain private diagnostic files under --scratch")
    args = parser.parse_args()
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    processes = []
    servers = []
    def run(command):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=90, creationflags=flags)
        if result.returncode:
            if Path(str(command[0])).resolve() == args.toolkit.resolve():
                raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
            raise RuntimeError("command failed: " + Path(str(command[0])).name + " (output suppressed)")
        return result.stdout
    def start(config):
        if args.keep_work:
            data = json.loads(config.read_text(encoding="utf-8"))
            data["log"] = {"loglevel": "debug", "access": "none", "error": str(config.parent / f"native-{len(processes)}.log")}
            config = config.parent / f"native-{len(processes)}.json"
            config.write_text(json.dumps(data), encoding="utf-8")
        process = subprocess.Popen([str(args.engine), "run", "-config", str(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        processes.append(process)
        return process
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    def ready(port, process):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError("native engine did not open its loopback listener")
    directory = (contextlib.nullcontext(tempfile.mkdtemp(prefix="vpn-config-kit-loopback-", dir=args.scratch))
                 if args.keep_work else tempfile.TemporaryDirectory(prefix="vpn-config-kit-loopback-", dir=args.scratch))
    with directory as tmp:
        work = Path(tmp)
        if args.keep_work:
            print("Private diagnostic directory: " + str(work), flush=True)
        try:
            cert, key = work / "target.pem", work / "target.key"
            run([args.openssl, "req", "-newkey", "rsa:2048", "-nodes", "-x509", "-sha256",
                 "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                 "-keyout", str(key), "-out", str(cert)])
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            context.set_alpn_protocols(["h2", "http/1.1"])
            TLS.context = context
            for server in (TCP(("127.0.0.1", 0), TLS), TCP(("127.0.0.1", 0), Echo),
                           socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPEcho)):
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
            tls_port, echo_port, udp_port = [s.server_address[1] for s in servers]
            server_port, client_port = free_port(), free_port()
            state = work / "state"
            values = dict(version=1, backend="xray-reality", listen="127.0.0.1",
                          listen_port=server_port, endpoint=f"127.0.0.1:{server_port}",
                          target=f"127.0.0.1:{tls_port}", server_name="localhost",
                          state_dir=str(state), engine_path=str(args.engine.resolve()),
                          manager_path=str(args.toolkit.resolve()), allow_private_destinations=True)
            config = work / "gateway.toml"
            config.write_text("\n".join(f"{k} = {json.dumps(v)}" for k, v in values.items()), encoding="utf-8")
            def cli(*arguments):
                return run([str(args.toolkit), "--backend", "xray-reality", "--config", str(config), *map(str, arguments)])
            cli("init")
            cli("peer", "add", "--name", "phone", "--defer")
            cli("prepare")
            profile = state / "client.json"
            cli("peer", "export", "phone", "--out", profile, "--socks-port", client_port)
            cli("peer", "export", "phone", "--format", "link", "--out", state / "client.txt", "--qr", state / "client.svg")
            server = start(state / "xray.json")
            client = start(profile)
            ready(server_port, server)
            ready(client_port, client)
            session, _ = socks(client_port, echo_port)
            with contextlib.closing(session):
                session.sendall(b"authenticated-tcp")
                assert exact(session, 17) == b"authenticated-tcp"
                association, udp_proxy = socks(client_port, 0, command=3)
                with contextlib.closing(association), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(5)
                    packet = b"\0\0\0\1" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port) + b"authenticated-udp"
                    udp.sendto(packet, ("127.0.0.1", udp_proxy))
                    reply = udp.recv(4096)
                    assert reply.endswith(b"authenticated-udp")
                cli("peer", "rotate", "phone", "--defer")
                cli("prepare")
                stop(server)
                server = start(state / "xray.json")
                ready(server_port, server)
                try:
                    session.sendall(b"old-session")
                    assert session.recv(4096) == b""
                except (ConnectionError, OSError):
                    pass
            def rejected():
                try:
                    stream, _ = socks(client_port, echo_port)
                    with stream:
                        stream.sendall(b"must-not-pass")
                        return exact(stream, 13) != b"must-not-pass"
                except (ConnectionError, OSError, AssertionError):
                    return True
            assert rejected(), "old credentials still pass traffic"
            stop(client)
            profile = state / "rotated.json"
            cli("peer", "export", "phone", "--out", profile, "--socks-port", client_port)
            client = start(profile)
            ready(client_port, client)
            stream, _ = socks(client_port, echo_port)
            with stream:
                stream.sendall(b"rotated")
                assert exact(stream, 7) == b"rotated"
            cli("peer", "revoke", "phone", "--defer")
            cli("prepare")
            stop(server)
            server = start(state / "xray.json")
            ready(server_port, server)
            assert rejected(), "revoked credentials still pass traffic"
            print("PASS: native REALITY/Vision TCP, UDP, credential rotation, old-session termination and revocation")
        finally:
            for process in reversed(processes):
                stop(process)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()

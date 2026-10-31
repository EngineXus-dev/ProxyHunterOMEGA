"""OpenVPN plus a local SOCKS5 gateway, isolated inside its Docker network."""
import ipaddress
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import threading
import time


def run(*args):
    subprocess.run(args, check=True, capture_output=True)


def exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise ConnectionError("SOCKS client disconnected")
        value += chunk
    return value


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(15)
        upstream = None
        try:
            version, count = exact(client, 2)
            methods = exact(client, count)
            if version != 5 or 0 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")
            version, command, _, kind = exact(client, 4)
            if version != 5 or command != 1:
                raise ValueError("Only SOCKS5 CONNECT is supported")
            if kind == 1:
                host = socket.inet_ntop(socket.AF_INET, exact(client, 4))
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, exact(client, 16))
            elif kind == 3:
                host = exact(client, exact(client, 1)[0]).decode("idna")
            else:
                raise ValueError("Unknown SOCKS address type")
            port = struct.unpack("!H", exact(client, 2))[0]
            upstream = socket.create_connection((host, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.settimeout(None)
            upstream.settimeout(None)
            while True:
                ready, _, _ = select.select([client, upstream], [], [], 60)
                if not ready:
                    break
                for stream in ready:
                    data = stream.recv(65536)
                    if not data:
                        return
                    (upstream if stream is client else client).sendall(data)
        except (OSError, ValueError, ConnectionError):
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            if upstream:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    remote = str(ipaddress.ip_address(os.environ["VPN_REMOTE_IP"]))
    port = str(int(os.environ["VPN_REMOTE_PORT"]))
    protocol = os.environ.get("VPN_REMOTE_PROTO", "tcp")
    if protocol not in ("tcp", "udp"):
        raise ValueError("Invalid VPN protocol")
    # Container-only fail-closed egress policy. Host routes are never modified.
    run("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
    run("iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    run("iptables", "-A", "OUTPUT", "-d", remote, "-p", protocol, "--dport", port, "-j", "ACCEPT")
    run("iptables", "-A", "OUTPUT", "-o", "tun0", "-j", "ACCEPT")
    run("iptables", "-P", "OUTPUT", "DROP")
    run("ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
    run("ip6tables", "-A", "OUTPUT", "-o", "tun0", "-j", "ACCEPT")
    run("ip6tables", "-P", "OUTPUT", "DROP")
    Path("/tmp/vpn-auth").write_text("vpn\nvpn\n")
    log = Path("/tmp/openvpn.log")
    process = subprocess.Popen(["openvpn", "--config", "/vpn/client.ovpn", "--auth-user-pass", "/tmp/vpn-auth",
        "--connect-retry-max", "1", "--connect-timeout", "10", "--resolv-retry", "5", "--log", str(log)])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        if log.exists() and "Initialization Sequence Completed" in log.read_text(errors="replace"):
            route = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout
            if "dev tun0" in route:
                # Docker Desktop's private DNS resolver is not reachable through
                # a remote VPN. Resolve via public DNS inside the encrypted tunnel.
                Path("/etc/resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n")
                with Server(("0.0.0.0", 1080), Proxy) as server:
                    print("VPN_READY", flush=True)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    process.wait()
                    server.shutdown()
                return
        time.sleep(0.25)
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    print("VPN_FAILED", flush=True)
    if log.exists():
        print("\n".join(log.read_text(errors="replace").splitlines()[-12:]), flush=True)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

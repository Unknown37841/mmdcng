#!/usr/bin/env python3
"""
Sub merger + health-checker for VLESS subscriptions.

- Reads a list of subscription URLs from subs.txt
- For each sub: downloads it, decodes it (base64), extracts vless:// configs
- Tests every config's server:port with a raw TCP connect (measures latency)
- If ALL configs of a sub fail -> that whole sub is dropped (as requested)
- Otherwise keeps the TOP_N fastest configs from that sub
- Writes the combined result (base64-encoded, ready to use as a subscription)
  into output_sub.txt, plus a human-readable report.txt

Note: a TCP connect test only proves the server:port is reachable/open.
It does NOT run a full VLESS handshake. This is intentional so the whole
thing can run on a free GitHub Actions runner with zero extra binaries.
See the README for how to upgrade to a real xray-core based test later.
"""

import base64
import re
import socket
import ssl
import time
import sys
import os
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

INPUT_FILE = "subs.txt"
OUTPUT_FILE = "output_sub.txt"
REPORT_FILE = "report.txt"

TOP_N = 3          # how many fastest configs to keep per sub (no limit on number of subs in subs.txt)
TIMEOUT = 5         # seconds, per connection attempt (TLS+WS handshake needs a bit more than plain TCP)
RETRIES = 2         # attempts per config (keeps the best result)


def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except Exception as e:
        print(f"  fetch failed: {e}")
        return None


def decode_sub(raw):
    text = raw.decode("utf-8", errors="ignore").strip()
    # subscriptions are usually base64 of a newline-separated config list
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if "vless://" in decoded:
            text = decoded
    except Exception:
        pass
    return [l.strip() for l in text.splitlines() if l.strip().startswith("vless://")]


def parse_vless(uri):
    """Parse a vless:// URI into its connection parameters."""
    try:
        u = urlparse(uri)
        address = u.hostname
        port = u.port
        if not address or not port:
            return None
        params = parse_qs(u.query)

        def g(key, default=None):
            v = params.get(key)
            return v[0] if v else default

        security = (g("security", "none") or "none").lower()
        net_type = (g("type", "tcp") or "tcp").lower()
        host_header = g("host", address)
        sni = g("sni", host_header) or address
        path = unquote(g("path", "/") or "/")
        return {
            "address": address,
            "port": port,
            "security": security,
            "type": net_type,
            "host": host_header,
            "sni": sni,
            "path": path,
        }
    except Exception:
        return None


def _probe_once(cfg, timeout):
    """
    One real connectivity attempt.
    - For type=ws: opens TCP (+TLS with correct SNI if security=tls), then
      sends a real WebSocket upgrade request with the correct Host/path and
      only counts it alive if the server answers "101 Switching Protocols".
      This matters a lot for CDN-fronted configs (e.g. Cloudflare) where the
      IP itself is basically always reachable even if the backend worker/
      token behind it is dead - a plain TCP check would wrongly say "alive".
    - For other transport types (tcp/grpc/etc.): falls back to a TCP
      connect (+TLS handshake if security=tls) as a reachability check.
    """
    start = time.time()
    address, port = cfg["address"], cfg["port"]
    raw_sock = socket.create_connection((address, port), timeout=timeout)
    sock = raw_sock
    try:
        if cfg["security"] == "tls":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=cfg["sni"])

        if cfg["type"] == "ws":
            key = base64.b64encode(os.urandom(16)).decode()
            path = cfg["path"] if cfg["path"].startswith("/") else "/" + cfg["path"]
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {cfg['host']}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            )
            sock.sendall(req.encode())
            sock.settimeout(timeout)
            resp = sock.recv(512)
            status_line = resp.split(b"\r\n", 1)[0]
            if b" 101 " not in (b" " + status_line):
                return None
        # for non-ws types, a successful TCP(+TLS) connect is our signal

        return (time.time() - start) * 1000
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe(cfg, timeout=TIMEOUT, retries=RETRIES):
    best = None
    for _ in range(retries):
        try:
            elapsed = _probe_once(cfg, timeout)
        except Exception:
            elapsed = None
        if elapsed is not None and (best is None or elapsed < best):
            best = elapsed
    return best  # None => unreachable


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"{INPUT_FILE} not found")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        sub_urls = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

    all_selected = []
    report_lines = []

    for idx, sub_url in enumerate(sub_urls, 1):
        print(f"[{idx}/{len(sub_urls)}] {sub_url}")
        raw = fetch(sub_url)
        if raw is None:
            report_lines.append(f"SUB#{idx} DROPPED (fetch failed): {sub_url}")
            continue

        configs = decode_sub(raw)
        if not configs:
            report_lines.append(f"SUB#{idx} DROPPED (no vless configs found): {sub_url}")
            continue

        results = []
        for cfg_uri in configs:
            cfg = parse_vless(cfg_uri)
            if not cfg:
                continue
            latency = probe(cfg)
            status = f"{latency:.0f}ms" if latency is not None else "DEAD"
            print(f"    {cfg['address']}:{cfg['port']} ({cfg['type']}/{cfg['security']}) -> {status}")
            if latency is not None:
                results.append((latency, cfg_uri))

        if not results:
            report_lines.append(
                f"SUB#{idx} DROPPED (all {len(configs)} configs unreachable): {sub_url}"
            )
            continue

        results.sort(key=lambda x: x[0])
        top = results[:TOP_N]
        report_lines.append(
            f"SUB#{idx} OK: {len(results)}/{len(configs)} reachable, kept {len(top)}: {sub_url}"
        )
        all_selected.extend(cfg for _, cfg in top)

    output_text = "\n".join(all_selected)
    output_b64 = base64.b64encode(output_text.encode("utf-8")).decode("utf-8")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output_b64)

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print("\n--- REPORT ---")
    print("\n".join(report_lines))
    print(f"\nTotal selected configs: {len(all_selected)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Sub merger + health-checker for VLESS subscriptions.

- Reads settings from config.json (top_n_per_sub, timeout, retries, workers...)
- Reads a list of subscription URLs from subs.txt (optionally with a
  per-line override for how many configs to keep from that specific sub)
- For each sub: downloads it, decodes it (base64), extracts vless:// configs
- Tests every config with a real connectivity probe (see _probe_once) in
  parallel threads for speed
- If ALL configs of a sub fail -> that whole sub is dropped
- Otherwise keeps the N fastest configs from that sub (N = top_n_per_sub,
  unless overridden for that sub in subs.txt)
- Writes the combined result (base64-encoded, ready to use as a subscription)
  into output_sub.txt, plus a human-readable report.txt

Note: for type=ws configs this does a real WebSocket upgrade handshake
(with TLS+SNI+Host+Path) and only accepts a "101 Switching Protocols"
response as alive - a plain TCP check is not enough for CDN-fronted
(e.g. Cloudflare) configs, since the shared IP is basically always up
even if the backend behind it is dead. For other transport types it
falls back to a TCP(+TLS) connect check.
"""

import base64
import json
import socket
import ssl
import sys
import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote

CONFIG_FILE = "config.json"
INPUT_FILE = "subs.txt"
OUTPUT_FILE = "output_sub.txt"
REPORT_FILE = "report.txt"

DEFAULT_CONFIG = {
    "top_n_per_sub": 3,       # how many fastest configs to keep per sub, by default
    "timeout_seconds": 5,     # seconds, per connection attempt
    "retries": 2,             # attempts per config (best result is kept)
    "max_workers": 20,        # how many configs to test in parallel at once
    "tag_configs_with_source": False,  # append "| subN" to each config's name
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            cfg.update({k: v for k, v in user_cfg.items() if k in DEFAULT_CONFIG})
        except Exception as e:
            print(f"WARNING: could not read {CONFIG_FILE}, using defaults ({e})")
    return cfg


def load_subs(cfg):
    """
    Each line in subs.txt is either:
        https://.../sub1
    or, to override top_n just for that sub:
        https://.../sub1, 5
    Lines starting with # are ignored. Any number of lines is supported.
    """
    if not os.path.exists(INPUT_FILE):
        print(f"{INPUT_FILE} not found")
        sys.exit(1)

    subs = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                url, override = line.split(",", 1)
                url = url.strip()
                try:
                    top_n = int(override.strip())
                except ValueError:
                    top_n = cfg["top_n_per_sub"]
            else:
                url = line
                top_n = cfg["top_n_per_sub"]
            subs.append((url, top_n))
    return subs


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


def probe(cfg, timeout, retries):
    best = None
    for _ in range(retries):
        try:
            elapsed = _probe_once(cfg, timeout)
        except Exception:
            elapsed = None
        if elapsed is not None and (best is None or elapsed < best):
            best = elapsed
    return best  # None => unreachable


def test_one_config(args):
    sub_idx, cfg_uri, timeout, retries = args
    parsed = parse_vless(cfg_uri)
    if not parsed:
        return sub_idx, cfg_uri, None
    latency = probe(parsed, timeout, retries)
    label = f"{parsed['address']}:{parsed['port']} ({parsed['type']}/{parsed['security']})"
    status = f"{latency:.0f}ms" if latency is not None else "DEAD"
    print(f"  [sub {sub_idx}] {label} -> {status}")
    return sub_idx, cfg_uri, latency


def main():
    cfg = load_config()
    print(f"Config: {cfg}")

    subs = load_subs(cfg)
    print(f"Loaded {len(subs)} sub(s) from {INPUT_FILE}")

    # Step 1: fetch + decode every sub (cheap, sequential is fine)
    sub_configs = {}   # sub_idx -> list of config URIs
    sub_meta = {}       # sub_idx -> (url, top_n)
    for idx, (url, top_n) in enumerate(subs, 1):
        print(f"[{idx}/{len(subs)}] fetching {url}")
        raw = fetch(url)
        sub_meta[idx] = (url, top_n)
        if raw is None:
            sub_configs[idx] = []
            continue
        configs = decode_sub(raw)
        sub_configs[idx] = configs
        print(f"  found {len(configs)} vless config(s)")

    # Step 2: test every config from every sub in parallel
    tasks = [
        (idx, cfg_uri, cfg["timeout_seconds"], cfg["retries"])
        for idx, configs in sub_configs.items()
        for cfg_uri in configs
    ]
    print(f"\nTesting {len(tasks)} config(s) with {cfg['max_workers']} parallel workers...")

    results_by_sub = {idx: [] for idx in sub_configs}
    if tasks:
        with ThreadPoolExecutor(max_workers=cfg["max_workers"]) as pool:
            for sub_idx, cfg_uri, latency in pool.map(test_one_config, tasks):
                if latency is not None:
                    results_by_sub[sub_idx].append((latency, cfg_uri))

    # Step 3: pick top N per sub, drop subs with zero alive configs
    all_selected = []
    report_lines = []
    for idx in sorted(sub_meta):
        url, top_n = sub_meta[idx]
        total = len(sub_configs.get(idx, []))
        alive = results_by_sub.get(idx, [])

        if total == 0:
            report_lines.append(f"SUB#{idx} DROPPED (fetch failed or no configs found): {url}")
            continue
        if not alive:
            report_lines.append(f"SUB#{idx} DROPPED (all {total} configs unreachable): {url}")
            continue

        alive.sort(key=lambda x: x[0])
        top = alive[:top_n]
        report_lines.append(
            f"SUB#{idx} OK: {len(alive)}/{total} reachable, kept {len(top)} (top_n={top_n}): {url}"
        )

        for latency, cfg_uri in top:
            if cfg["tag_configs_with_source"]:
                base, frag = (cfg_uri.split("#", 1) + [""])[:2]
                tag = f"sub{idx}"
                cfg_uri = f"{base}#{unquote(frag)} | {tag}" if frag else f"{base}#{tag}"
            all_selected.append(cfg_uri)

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

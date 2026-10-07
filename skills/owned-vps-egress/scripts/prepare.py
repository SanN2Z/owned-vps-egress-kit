"""Generate a NEW recipient-owned deployment; no network or active-system changes."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import urlencode, quote
import uuid

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parents[3]
PROTECTED = ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
             "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"]
LOCAL4 = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
LOCAL6 = ["::1/128", "fc00::/7", "fe80::/10"]
TEST_NETS = [ipaddress.ip_network(s) for s in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def domain(value: str) -> str:
    value = value.lower().rstrip(".")
    if len(value) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise ValueError("Expected a DNS hostname, without URL, wildcard or port")
    return value


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as f:
        f.write(text)
    path.chmod(0o600)


def write_json(path: Path, value: object) -> None:
    write_private(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def profile(node: dict, platform: str, domains: list[str], allow_lan: bool) -> dict:
    rules = []
    if allow_lan:
        rules += [f"IP-CIDR6,{x},DIRECT,no-resolve" for x in LOCAL6]
    rules += ["IP-CIDR6,::/0,REJECT,no-resolve"]
    rules += [f"DOMAIN-SUFFIX,{x},PROXY" for x in PROTECTED]
    # Portable profiles intentionally do not add broad per-process DIRECT rules.
    if allow_lan:
        rules += [f"IP-CIDR,{x},DIRECT,no-resolve" for x in LOCAL4]
    rules += [f"DOMAIN-SUFFIX,{x},DIRECT" for x in domains]
    rules += ["MATCH,PROXY"]
    return {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
        "mode": "rule", "log-level": "warning", "ipv6": True,
        "external-controller": "", "find-process-mode": "off",
        "tun": {"enable": True, "stack": "gvisor", "auto-route": True,
                "auto-detect-interface": True, "strict-route": True,
                "device": "utun123" if platform == "macos" else "Mihomo",
                "mtu": 1500, "dns-hijack": ["any:53", "tcp://any:53"],
                "inet6-address": ["fdfe:dcba:9876::1/126"]},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "respect-rules": True,
                "default-nameserver": ["https://1.1.1.1/dns-query"],
                "nameserver": ["https://1.1.1.1/dns-query#PROXY",
                               "https://8.8.8.8/dns-query#PROXY"],
                # Nodes are literal IPs; this bootstrap resolver isn't needed
                # for the generated endpoint. It is not a general DNS fallback.
                "proxy-server-nameserver": ["https://1.1.1.1/dns-query#DIRECT"],
                "direct-nameserver": ["https://1.1.1.1/dns-query#PROXY"],
                "fake-ip-filter": ["*.lan", "localhost"]},
        "proxies": [node],
        "proxy-groups": [{"name": "GLOBAL", "type": "select", "proxies": ["PROXY"]},
                         {"name": "PROXY", "type": "select", "proxies": [node["name"]]}],
        "rules": rules,
    }


def guard(config: dict) -> str:
    return "// PRIVATE: bind only to this recipient's profile, never globally.\n" + \
        "const approved = " + json.dumps(config, ensure_ascii=True) + ";\n" + r'''
function main(config) {
  const clone = x => JSON.parse(JSON.stringify(x));
  const t = config.tun || {};
  const node = (config.proxies || []).find(p => p.name === approved.proxies[0].name);
  const expected = approved.proxies[0];
  const identity = node && ["type", "server", "port", "uuid", "flow", "tls", "servername"]
    .every(k => node[k] === expected[k]) && !node["dialer-proxy"] &&
    node["skip-cert-verify"] !== true &&
    JSON.stringify(node["reality-opts"]) === JSON.stringify(expected["reality-opts"]);
  const capture = config.ipv6 === true && t.enable === true &&
    t["auto-route"] === true && t["strict-route"] === true &&
    (t["inet6-address"] || []).length > 0 &&
    ["any:53", "tcp://any:53"].every(x => (t["dns-hijack"] || []).includes(x)) &&
    !["route-exclude-address", "route-exclude-address-set", "route-address", "route-address-set",
      "include-interface", "exclude-interface", "include-uid", "exclude-uid",
      "include-uid-range", "exclude-uid-range", "include-package", "exclude-package",
      "inet4-route-exclude-address", "inet6-route-exclude-address"]
      .some(k => (t[k] || []).length);
  config.mode = "rule";
  config["proxy-providers"] = {};
  config["rule-providers"] = {};
  config["sub-rules"] = {};
  config.listeners = [];
  config.tunnels = [];
  config["allow-lan"] = false;
  config["bind-address"] = "127.0.0.1";
  config["external-controller"] = "";
  config.dns = clone(approved.dns);
  config["find-process-mode"] = "off";
  config.proxies = identity && capture ? clone(approved.proxies) : [];
  config["proxy-groups"] = identity && capture ? clone(approved["proxy-groups"]) :
    [{name: "GLOBAL", type: "select", proxies: ["PROXY"]},
     {name: "PROXY", type: "select", proxies: ["REJECT"]}];
  config.rules = identity && capture ? clone(approved.rules) : ["MATCH,REJECT"];
  // When TUN itself is absent, only the separately installed OS guard protects
  // native traffic. Reject rules cannot capture traffic outside the process.
  return config;
}
'''


def create(args: argparse.Namespace) -> dict:
    addr = ipaddress.ip_address(args.new_vps_ip)
    if addr.version != 4:
        raise ValueError("This initial deployment recipe requires a public IPv4 endpoint")
    fixture = bool(args.test_fixture)
    if fixture:
        if not any(addr in n for n in TEST_NETS):
            raise ValueError("Test fixtures may use only RFC 5737 documentation addresses")
    elif not addr.is_global:
        raise ValueError("A newly rented public IPv4 is required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.recipient):
        raise ValueError("Recipient must be a short ASCII label")
    if not 1024 <= args.port <= 65535 or not 1 <= args.clients <= 100:
        raise ValueError("Port must be 1024..65535; clients must be 1..100")
    sni = domain(args.sni)
    domains = sorted(set(domain(x) for x in args.direct_domain))
    for d in domains:
        if any(d == p or d.endswith("." + p) or p.endswith("." + d) for p in PROTECTED):
            raise ValueError("DIRECT exception overlaps protected domain policy")
    output = Path(args.output).expanduser().resolve()
    if output == REPO or REPO in output.parents:
        raise ValueError("Private output must be outside the public repository")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if os.name != "nt":
        output.chmod(0o700)
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
    public = b64(private.public_key().public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw))
    short_id = secrets.token_hex(8)
    users = [{"name": f"client{i:02}", "uuid": str(uuid.uuid4()),
              "flow": "xtls-rprx-vision"} for i in range(1, args.clients + 1)]
    server = {"log": {"level": "warn", "timestamp": True},
              "inbounds": [{"type": "vless", "tag": "owned-in", "listen": "0.0.0.0",
                            "listen_port": args.port, "users": users,
                            "tls": {"enabled": True, "server_name": sni,
                                    "reality": {"enabled": True,
                                                "handshake": {"server": sni, "server_port": 443},
                                                "private_key": b64(private_raw),
                                                "short_id": [short_id]}}}],
              "outbounds": [{"type": "direct", "tag": "direct"}],
              "route": {"rules": [{"ip_is_private": True, "action": "reject"}],
                        "final": "direct"}}
    write_json(output / "server" / "server.private.json", server)
    for user in users:
        client = output / "clients" / user["name"]
        node = {"name": "OWNED-VPS", "type": "vless", "server": str(addr),
                "port": args.port, "uuid": user["uuid"], "network": "tcp", "udp": True,
                "tls": True, "flow": "xtls-rprx-vision", "servername": sni,
                "client-fingerprint": "chrome", "skip-cert-verify": False,
                "reality-opts": {"public-key": public, "short-id": short_id}}
        for platform in args.platform:
            config = profile(node, platform, domains, args.allow_lan)
            write_private(client / f"mihomo-{platform}.private.yaml",
                          yaml.safe_dump(config, sort_keys=False, allow_unicode=True))
            write_private(client / f"guard-{platform}.private.js", guard(config))
        query = urlencode({"encryption": "none", "security": "reality", "type": "tcp",
                           "sni": sni, "fp": "chrome", "pbk": public, "sid": short_id,
                           "flow": "xtls-rprx-vision"})
        link = f"vless://{user['uuid']}@{addr}:{args.port}?{query}#" + quote(
            args.recipient + "-" + user["name"], safe="")
        write_private(client / "shadowrocket-node.private.txt", link + "\n")
        ios_rules = ["# Node import is separate; PROXY means the selected owned node.",
                     "# Verify DNS routing and tunnel options in this installed app.",
                     "[General]", "dns-server = https://1.1.1.1/dns-query", "ipv6 = true", "",
                     "[Rule]"]
        if args.allow_lan:
            ios_rules += [f"IP-CIDR6,{x},DIRECT,no-resolve" for x in LOCAL6]
        ios_rules += ["IP-CIDR6,::/0,REJECT,no-resolve"]
        ios_rules += [f"DOMAIN-SUFFIX,{x},PROXY" for x in PROTECTED]
        if args.allow_lan:
            ios_rules += [f"IP-CIDR,{x},DIRECT,no-resolve" for x in LOCAL4]
        ios_rules += [f"DOMAIN-SUFFIX,{x},DIRECT" for x in domains]
        ios_rules += ["FINAL,PROXY", ""]
        write_private(client / "shadowrocket-rules.private.conf", "\n".join(ios_rules))
        if args.qr:
            import qrcode
            qr_path = client / "shadowrocket-node.private.png"
            qrcode.make(link).save(qr_path)
            qr_path.chmod(0o600)
        write_private(client / "IMPORT.txt", "PRIVATE: contains this device's credential.\n"
                      "Desktop: import the matching Mihomo YAML; do not activate an existing "
                      "client without permission. Import alone does not install an OS guard.\n"
                      "iOS: import node link/QR AND rule file; select only this owned node; "
                      "use configuration routing. Check DNS-through-proxy, full tunnel and "
                      "on-demand options in the installed version, then test on device.\n"
                      "Do not install a root CA or enable HTTPS decryption.\n")
    manifest = {"schema": 1, "recipient": args.recipient, "new_vps_ip": str(addr),
                "port": args.port, "sni": sni, "clients": len(users),
                "platforms": args.platform, "test_fixture": fixture,
                "topology": "recipient-owned-direct", "direct_domains": domains,
                "allow_lan": args.allow_lan, "server_deployed": False,
                "os_guard_verified": False, "ios_device_verified": False,
                "files": {str(p.relative_to(output)).replace("\\", "/"):
                          hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in output.rglob("*") if p.is_file()}}
    write_json(output / "manifest.private.json", manifest)
    return {"generated": True, "recipient": args.recipient, "clients": len(users),
            "output": str(output), "test_fixture": fixture, "deployed": False}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--recipient", required=True)
    p.add_argument("--new-vps-ip", required=True)
    p.add_argument("--sni", required=True, help="REALITY target verified from the new VPS")
    p.add_argument("--output", required=True, help="New private folder outside this repository")
    p.add_argument("--port", type=int, default=9443)
    p.add_argument("--clients", type=int, default=1)
    p.add_argument("--platform", action="append", choices=["windows", "macos", "linux"])
    p.add_argument("--direct-domain", action="append", default=[])
    p.add_argument("--allow-lan", action="store_true")
    p.add_argument("--qr", action="store_true")
    p.add_argument("--test-fixture", action="store_true", help="Nondeployable RFC 5737 fixture")
    return p


if __name__ == "__main__":
    try:
        options = parser().parse_args()
        options.platform = sorted(set(options.platform or ["windows"]))
        print(json.dumps(create(options), indent=2))
    except Exception as exc:
        print(f"[fail] {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)

"""Offline cross-file validation; does not claim deployment or leak-test success."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlparse, parse_qs
import uuid

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import prepare

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def validate(folder: Path) -> dict:
    folder = folder.resolve()
    manifest = json.loads((folder / "manifest.private.json").read_text(encoding="utf-8"))
    require(manifest["topology"] == "recipient-owned-direct", "Unexpected topology")
    actual = {str(p.relative_to(folder)).replace("\\", "/") for p in folder.rglob("*")
              if p.is_file() and p.name != "manifest.private.json"}
    require(actual == set(manifest["files"]), "Unexpected or missing files")
    for name, sha in manifest["files"].items():
        p = (folder / name).resolve()
        require(folder in p.parents, "Manifest path escaped deployment folder")
        require(hashlib.sha256(p.read_bytes()).hexdigest() == sha, "Artifact hash mismatch")
    server = json.loads((folder / "server/server.private.json").read_text(encoding="utf-8"))
    inbound, = server["inbounds"]
    reality = inbound["tls"]["reality"]
    raw = base64.urlsafe_b64decode(reality["private_key"] + "=")
    private = X25519PrivateKey.from_private_bytes(raw)
    pub = prepare.b64(private.public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw))
    users = inbound["users"]
    require(len(users) == manifest["clients"], "Wrong client count")
    require(len({u["uuid"] for u in users}) == len(users), "Clients share credentials")
    require(inbound["listen_port"] == manifest["port"], "Server port mismatch")
    require(inbound["type"] == "vless" and inbound["tls"]["enabled"], "Unencrypted inbound")
    for user in users:
        uuid.UUID(user["uuid"])
        client = folder / "clients" / user["name"]
        for platform in manifest["platforms"]:
            p = yaml.safe_load((client / f"mihomo-{platform}.private.yaml").read_text(encoding="utf-8"))
            node, = p["proxies"]
            require(node["server"] == manifest["new_vps_ip"], "Foreign exit")
            require(node["uuid"] == user["uuid"], "Client/server credential mismatch")
            require(node["port"] == manifest["port"], "Client port mismatch")
            require(node["reality-opts"]["public-key"] == pub, "REALITY key mismatch")
            require(node["reality-opts"]["short-id"] in reality["short_id"], "Short ID mismatch")
            require(node["servername"] == inbound["tls"]["server_name"] == manifest["sni"],
                    "SNI mismatch")
            require(p == prepare.profile(node, platform, manifest["direct_domains"],
                                         manifest["allow_lan"]), "Routing/capture policy drift")
            require(not node.get("dialer-proxy") and not node.get("skip-cert-verify"),
                    "Unexpected transit or disabled certificate verification")
            require(node["flow"] == user["flow"] == "xtls-rprx-vision", "Flow mismatch")
            require((client / f"guard-{platform}.private.js").read_text(encoding="utf-8") ==
                    prepare.guard(p), "Profile guard drift")
        link = (client / "shadowrocket-node.private.txt").read_text(encoding="utf-8").strip()
        uri = urlparse(link)
        qs = parse_qs(uri.query)
        require(uri.scheme == "vless" and uri.username == user["uuid"], "Invalid node URI")
        require(uri.hostname == manifest["new_vps_ip"] and uri.port == manifest["port"],
                "URI endpoint mismatch")
        require(qs.get("pbk") == [pub] and qs.get("sni") == [manifest["sni"]] and
                qs.get("security") == ["reality"] and qs.get("flow") == ["xtls-rprx-vision"] and
                qs.get("sid") == reality["short_id"] and qs.get("type") == ["tcp"] and
                qs.get("encryption") == ["none"] and qs.get("fp") == ["chrome"],
                "URI security mismatch")
        conf = (client / "shadowrocket-rules.private.conf").read_text(encoding="utf-8")
        rules = conf.split("[Rule]\n", 1)[1].splitlines()
        require(rules[-1] == "FINAL,PROXY", "iOS default route is not protected")
        require("IP-CIDR6,::/0,REJECT,no-resolve" in rules, "iOS IPv6 rejection absent")
        for artifact in client.iterdir():
            if artifact.suffix == ".png":
                continue
            text = artifact.read_text(encoding="utf-8")
            require(reality["private_key"] not in text, "Server private key in client handoff")
            for other in users:
                if other != user:
                    require(other["uuid"] not in text, "Another client's credential in handoff")
    return {"offline_validation": "passed", "clients": len(users),
            "platforms": manifest["platforms"], "test_fixture": manifest["test_fixture"],
            "live_server": "not tested", "os_kill_switch": "not tested", "ios": "not device tested"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    try:
        print(json.dumps(validate(parser.parse_args().folder), indent=2))
    except Exception as exc:
        print(f"[fail] {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)

"""Fail on private artifacts, credentials and unapproved public IPv4s in a clean kit."""
from __future__ import annotations
import argparse
import ipaddress
from pathlib import Path
import re
import sys

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

ALLOWED_PUBLIC = {"1.1.1.1", "8.8.8.8"}  # Public DNS service examples only.
PATTERNS = {
    "private-key block": re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    "node credential": re.compile(r"(?:vless|vmess|trojan|ss)://[A-Za-z0-9+/=_-]{16,}"),
    "UUID credential": re.compile(r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", re.I),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{25,})"),
    "credential assignment": re.compile(r'''["'](?:private_key|uuid|password|token)["']\s*:\s*["'][A-Za-z0-9_+/=-]{20,}["']'''),
}
FORBIDDEN_SUFFIX = {".exe", ".zip", ".tgz", ".wfw", ".pem", ".key", ".p12", ".pfx", ".png"}


def scan(root: Path) -> tuple[list[str], list[str]]:
    problems, files = [], []
    for p in sorted(root.rglob("*")):
        relative = p.relative_to(root)
        if set(relative.parts) & {".git", ".venv", "__pycache__"}:
            continue
        if p.is_symlink():
            problems.append(f"{relative}: symlink outside the reviewed file set")
            continue
        if not p.is_file():
            continue
        files.append(str(relative))
        if ".private." in p.name or p.suffix.lower() in FORBIDDEN_SUFFIX or p.name.startswith("known_hosts"):
            problems.append(f"{relative}: private/binary artifact")
            continue
        try:
            text = p.read_text(encoding="utf-8-sig")
        except UnicodeError:
            problems.append(f"{relative}: unreviewed binary/non-UTF8 file")
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                problems.append(f"{relative}: {name}")
        for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
            if any(int(part) > 255 for part in token.split(".")):
                continue  # Version-number matches outside the IPv4 range.
            address = ipaddress.ip_address(token)
            if address.is_global and token not in ALLOWED_PUBLIC:
                problems.append(f"{relative}: unexpected public endpoint (value redacted)")
    return sorted(set(problems)), files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    issues, inventory = scan(args.repository.resolve())
    print("Reviewed candidate files:")
    print("\n".join(inventory))
    if issues:
        print("[fail] " + "\n[fail] ".join(issues), file=sys.stderr)
        raise SystemExit(1)
    print(f"PUBLISH_SCAN_PASS: {len(inventory)} files; manual review and history scan still required before push")

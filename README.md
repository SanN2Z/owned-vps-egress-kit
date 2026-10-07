# Owned VPS Egress Kit

An agent skill for recipient-owned VPS deployment, Mihomo/Clash Verge imports,
iOS Shadowrocket handoff, and layered TUN/DNS/egress audits.

**Every new recipient rents a new VPS.** No author's server, credential,
subscription, client export or fallback is included. The provider is configurable.
An optimized route may help reachability; it does not guarantee peak-hour speed.

## Use with Codex

Ask Codex to install the skill from this repository:

```text
Use $skill-installer to install https://github.com/SanN2Z/owned-vps-egress-kit/tree/main/skills/owned-vps-egress
```

Alternatively, copy `skills/owned-vps-egress` into your user-level
`~/.agents/skills/`, or into `.agents/skills/` in the repository where you want to
invoke it. See the [official skill documentation](https://learn.chatgpt.com/docs/build-skills).

Then invoke:

```text
Use $owned-vps-egress. I have rented a NEW VPS for this recipient.
Recipient: research-team-b. IP: <new IP>. OS: Ubuntu LTS, <architecture>.
SSH: <user>, <port>, local key path <path>; host fingerprint <verified value>.
Clients: Windows Clash Verge and iOS Shadowrocket, <device count>.
Prepare the deployment and imports. Keep the currently running VPN untouched.
```

The agent can perform authorized SSH deployment. A bare IP does not authorize
access and does not provide authentication. iOS still requires app installation,
VPN consent, import/selection and device verification. "One invocation" does not
mean a portable OS kill switch can be silently installed on every platform.

## Included automation

- `prepare.py`: fresh X25519 REALITY key, independent per-device UUIDs, sing-box
  server config, Mihomo YAML, profile-local guard, VLESS link, QR, iOS rule file.
- `validate.py`: cross-check credential isolation, key agreement and routing.
- `install_server.sh`: fresh systemd installation from a checksum-verified local
  binary; check-only by default, explicit `--apply` for an authorized fresh VPS.
- `windows_audit.ps1`: read-only firewall/adapter audit with app-package scopes.
- `publish_check.py`: public-tree secret/artifact scan; not a substitute for review.

Create a project-local Python virtual environment and install `requirements.txt`.
Use `python skills/owned-vps-egress/scripts/prepare.py --help`. Generated outputs
must go **outside this repository**. Each client's subfolder is its private handoff;
never send the entire deployment folder to an ordinary client.

## Scope and status

The initial protocol is VLESS + REALITY + XTLS Vision, TCP transport. Its UDP
application traffic uses the proxy protocol; the server listener is TCP.
Linux systemd server install is supplied. Windows/macOS/Linux Mihomo exports are
generated; OS-level guards need platform-specific preparation and validation.
Shadowrocket receives a separate node import and rule file, not Windows settings.

See [the full Chinese workflow](docs/WORKFLOW.zh-CN.md),
[verification record](docs/VALIDATION.md), and
[source references](skills/owned-vps-egress/references/sources.md).
No server purchase, remote deployment, live desktop change or GitHub publication
is performed merely by generating this kit.

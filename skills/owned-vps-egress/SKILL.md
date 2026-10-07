---
name: owned-vps-egress
description: Audit TUN, DNS and outbound leak protection, or deploy a newly rented recipient-owned VPS and prepare Mihomo/Clash Verge and iOS Shadowrocket imports. Use for owned VPN exit setup, migration and fail-closed checks.
---

# Owned VPS egress

Deliver a recipient-specific server and client bundle, with evidence for the protection actually tested. A working proxy, correct exit, fail-closed policy and OS-level kill switch are separate results.

## Ownership and operating constraints

- For another person, use a **new VPS rented for that recipient**, their authorized SSH identity and fresh per-device credentials. Never discover and reuse the author's machines, subscriptions, keys, fallback nodes or archived exports. No personal endpoints are bundled here.
- A provider selling an optimized VPS route is the infrastructure host; the recipient still administers the exit. A third-party proxy endpoint is a different trust boundary. Do not buy either without authorization.
- Default topology: `client -> recipient-owned optimized-route VPS -> destination`. Optional transit: `client -> supplier transit -> recipient-owned VPS -> destination`. Supplier nodes must never become final exits. All recipient-owned exits down means failure, never `DIRECT` or a raw supplier fallback.
- Read-only audit is the default when the user asks to inspect. Do not restart/kill a running Clash/Verge/Mihomo process. Do not switch profiles, groups, system proxy or TUN, reload configuration, modify firewall/adapter settings or break connections without authorization covering that action. Prepare reviewable artifacts first. Never execute an old recovery script merely to inspect state.
- Keep credentials and operational artifacts outside the repository. Do not print private keys, UUIDs, node URLs, QR payloads or subscriptions. A node QR is a bearer credential. Client bundles must not contain the server private key or another client's UUID.

## Route the task

**Audit an existing machine:** read [audit.md](references/audit.md). Identify saved GUI settings, source profile, global/profile scripts, generated configuration, live controller and OS firewall separately. Use GET-only controller calls. Report discrepancies; don't silently repair them. The bundled `windows_audit.ps1` only reads state.

**New deployment or migration:** read [deployment.md](references/deployment.md), then the appropriate client reference. Collect only missing facts:

1. Recipient/deployment label; newly rented IP; OS/architecture; provider/region and expected transfer budget.
2. SSH user/port and local key path or existing SSH alias; host-key fingerprint verified through the provider console. IP alone is insufficient. Do not request private key contents in chat.
3. Client platforms/versions, device count, explicitly desired DIRECT domains/LAN access, and whether an OS-level guard is requested.
4. A REALITY handshake hostname tested from this server. Never disable certificate checking to hide an unsuitable target.

Use `scripts/prepare.py` to generate fresh server/clients locally, then `scripts/validate.py`. Fetch an official sing-box release for the server architecture, pin its version and verify its checksum before executing it. `scripts/install_server.sh` installs a new, separate systemd service only; it refuses an existing deployment and never resets the firewall or SSH. Its apply step requires the user-authorized new server, not a personal fallback. Explain missing firewall/security-group access before testing connectivity.

For multiple new recipient-owned VPSs, provision each independently; merge only after verifying ownership, and use only those owned exits in fallback groups. The generator deliberately emits one exit and no hidden fallback.

## Clients and verification

- [Desktop](references/desktop.md): Mihomo-capable client required, not every historical Clash build. Generate platform-appropriate TUN device settings. Validate the final GUI-generated runtime as well as the import. `guard-<platform>.private.js` is a profile-local safeguard; it must not be installed as a global script over unrelated profiles.
- [Windows guard](references/windows-guard.md): discover the actual service executable and interfaces. Make a backup and concrete change plan before applying an OS kill switch. A YAML import cannot install it. Do not claim kill-switch protection from TUN alone.
- [iOS](references/ios.md): import the VLESS URI/QR **and** the rule configuration, select only the recipient's node, check DNS/tunnel settings in the installed app, and complete device tests. Never translate Windows process rules or firewall commands into imaginary iOS support. An iOS device is a client; running this skill needs an agent environment with Python/SSH, usually a computer.
- Follow [verification.md](references/verification.md). Keep production unchanged while running isolated parser/protocol tests. Tag checks as static, isolated, device-tested or not tested. Do not call a Linux install or iOS import tested merely because generation succeeded.

## Handoff and publishing

Return server status, the recipient's private import paths, version/hash evidence, DIRECT exceptions, revocation steps and unresolved limits. Never enable MITM, install a root CA or use an online subscription converter for this workflow.

For GitHub, publish only this clean kit. Run `scripts/publish_check.py` on the repository and inspect the exact candidate file list. Never publish the surrounding workspace, generated bundles, SSH material or local audit reports. Creating this kit does not authorize a push or release. Installation/invocation and the end-user flow are in the repository README and `docs/WORKFLOW.zh-CN.md`.

# New recipient deployment

Use a newly rented recipient-owned Linux systemd VPS. Prefer a supported Ubuntu
LTS/Debian release and a provider/region with demonstrated reachability from that
recipient's access network. The original user's preferred category is an
optimized-route VPS; do not hard-code a provider, existing IP or commercial claim.
Check monthly transfer, whether both directions count, shaping, port limits,
peak-hour routes and cancellation terms. A port advertised as 1 Gbps is not a
guaranteed end-to-end rate. For a lab, size concurrency and monthly TB separately.

## Inputs and server preflight

Record recipient, new IP, provider, region, OS, architecture, SSH user/port/key
path, console-verified SSH host fingerprint and client count in a **private**
deployment record. A public IP without SSH access is not enough. If only a
password is initially available, use a protected interactive entry or SSH agent;
do not place it in command arguments, source code, chat logs or GitHub.

Pin the host key to a dedicated known_hosts file after independently comparing
the provider-console fingerprint. `ssh-keyscan` only collects a key; it does not
authenticate it. Use `StrictHostKeyChecking=yes`. Do not adopt AutoAddPolicy or
`StrictHostKeyChecking=no`. Do not reuse the author's SSH identity for others.

Read-only server checks: `cat /etc/os-release`, `uname -m`, `id`, `date -u`,
`ss -lntup`, existing service list, disk/RAM, `systemctl --version`, firewall and
provider security-group state. Check clock synchronization. Test the selected
REALITY handshake hostname from that VPS with SNI and certificate verification,
for example `openssl s_client -connect HOST:443 -servername HOST -tls1_3 -verify_return_error`.
Review target suitability using current sing-box documentation; successful TLS
alone is not a substitute for the actual REALITY client test.

## Generate and stage

In a local virtual environment with this kit's requirements:

```text
python skills/owned-vps-egress/scripts/prepare.py --recipient team-b --new-vps-ip <NEW_IP> --sni <VERIFIED_HOSTNAME> --clients 3 --platform windows --platform macos --platform linux --qr --output <PRIVATE_DIRECTORY_OUTSIDE_REPOSITORY>
python skills/owned-vps-egress/scripts/validate.py <PRIVATE_DIRECTORY_OUTSIDE_REPOSITORY>
```

The default has no public DIRECT exception and no LAN bypass. Add `--allow-lan`
or repeated `--direct-domain domain.example` only when wanted by this recipient.
All application DNS stays on the owned route, including explicitly direct domains;
this means those domain connections may also lose resolution when the VPS fails.
Changing to direct DNS for exceptions is a separate documented policy choice.

POSIX files use private modes. On Windows, POSIX chmod does not establish a full
ACL: place output in a private user directory and inspect/restrict inherited ACLs
before treating it as secret storage. Do not put artifacts in a synced/public repo.

Download the selected stable **official** SagerNet/sing-box release for the
server architecture. Record exact version, asset URL, archive SHA256, published
checksum source and extracted binary SHA256. Verify archive before extraction;
verify publisher signatures/attestations when available. Never execute an
unverified download or pipe an internet script into a shell. Installers and schema
must match that version; run `sing-box check` before install.

Over pinned SSH, create a private staging directory on the NEW VPS. Copy only:
the verified Linux binary, `server/server.private.json`, `manifest.private.json`
and `scripts/install_server.sh`. Never send every client bundle to every recipient.
Using a root SSH session or reviewed sudo wrapper, run:

```sh
bash install_server.sh ./sing-box ./server.private.json <BINARY_SHA256> ./manifest.private.json
# After the concrete deployment is authorized:
bash install_server.sh ./sing-box ./server.private.json <BINARY_SHA256> ./manifest.private.json --apply
```

The installer requires systemd with LoadCredential support (247+), an unused TCP
port >=1024, a fresh namespace, and root for apply. It runs sing-box with a dynamic
unprivileged user. Config remains root-only and is handed to the service through
systemd credentials. It refuses fixtures and existing installations. If a step
fails, inspect partial state and journal before retrying; do not delete directories
or stop unrelated services automatically.

Open only the selected TCP listener in the provider firewall and the existing
host firewall when authorized. Preserve working SSH access and existing rules;
do not reset UFW/nftables or enable a default-deny policy blindly. REALITY over
TCP carries proxied UDP internally; opening the same UDP server port is not needed
for this recipe. Keep SSH hardening a separate step after a second key-authenticated
session succeeds. Do not disable password access or change SSH ports prematurely.

## Verify and hand off

Read service status, the listener and bounded journal output; redact credentials.
Check a disposable client with TUN disabled and a unique localhost port. Verify
HTTPS, the recipient-owned exit, DNS and any needed UDP feature. No production
client restart is needed. Run the normal/transport-failure/all-owned-failure
matrix in verification.md before declaring the profile ready.

Import/activation on a live client needs authorization for the affected device.
Deliver only the assigned `clients/clientNN` directory. The full server/admin
bundle belongs to the recipient's administrator. If a node link is compromised,
remove that UUID from the server users list, validate a candidate configuration,
and schedule the server reload/restart with the owner; other users may be affected.

## Optional transit or owned fallback

The bundled generator implements direct optimized-route access. Do not pretend
its one-node selector performs automatic fallback. For optional transit, create
an owned VLESS node with Mihomo `dialer-proxy` pointing to a supplier-only entry
group; user-facing groups contain owned direct/owned-via-entry nodes exclusively.
Keep supplier credentials private. Test entry failure, all-owned failure and
subscription replacement. Existing global relay scripts may wrap a new owned
node unless the owned inventory or a profile-specific bypass is updated.
Inspect the generated graph rather than trusting names or the source YAML.

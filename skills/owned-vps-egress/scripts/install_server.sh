#!/usr/bin/env bash
# Fresh systemd VPS only. No downloads, firewall changes, SSH changes or restarts.
set -euo pipefail
umask 077
trap 'printf "[fail] server installer stopped at line %s; inspect partial state before retrying\n" "$LINENO" >&2' ERR

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo 'Usage: install_server.sh VERIFIED_SING_BOX_BINARY SERVER_CONFIG SHA256 MANIFEST [--apply]' >&2
  exit 2
fi
source_bin=$(realpath -- "$1")
source_config=$(realpath -- "$2")
expected_sha=$3
manifest=$(realpath -- "$4")
mode=${5:---check}
[[ $mode == --check || $mode == --apply ]] || { echo '[fail] Invalid mode' >&2; exit 2; }
[[ $expected_sha =~ ^[a-fA-F0-9]{64}$ ]] || { echo '[fail] Invalid SHA256' >&2; exit 2; }
[[ -f $source_bin && -f $source_config ]] || { echo '[fail] Missing input' >&2; exit 1; }
printf '%s  %s\n' "$expected_sha" "$source_bin" | sha256sum --check --status
command -v python3 >/dev/null
command -v systemctl >/dev/null
command -v ss >/dev/null

# Reject malformed server config; never infer a recipient from an old archive.
listen_port=$(python3 - "$source_config" "$manifest" <<'PY'
import hashlib, ipaddress, json, sys
def require(condition, message):
    if not condition:
        raise ValueError(message)
c = json.load(open(sys.argv[1], encoding='utf-8'))
m = json.load(open(sys.argv[2], encoding='utf-8'))
require(m['test_fixture'] is False, 'Test fixtures must never be deployed')
require(ipaddress.ip_address(m['new_vps_ip']).is_global, 'Expected a new public endpoint')
require(m['files']['server/server.private.json'] == hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest(), 'Server config hash mismatch')
i, = c['inbounds']
require(i['type'] == 'vless' and i['tls']['reality']['enabled'], 'Expected REALITY inbound')
require(1024 <= i['listen_port'] <= 65535 and i['listen_port'] == m['port'], 'Invalid port')
require(i['users'] and len({u['uuid'] for u in i['users']}) == len(i['users']), 'Nonunique users')
require(all(u['flow'] == 'xtls-rprx-vision' for u in i['users']), 'Unexpected flow')
print(i['listen_port'])
PY
)
binary=/usr/local/lib/owned-vps-egress/sing-box
config=/etc/owned-vps-egress/config.json
unit=/etc/systemd/system/owned-vps-egress.service
for path in "$binary" "$config" "$unit" /usr/local/lib/owned-vps-egress /etc/owned-vps-egress; do
  [[ ! -e $path ]] || { echo '[fail] Existing deployment: use reviewed migration, not overwrite' >&2; exit 1; }
done
[[ -z $(ss -H -lnt "sport = :$listen_port") ]] || { echo '[fail] Port occupied' >&2; exit 1; }
"$source_bin" check -c "$source_config"
echo "CHECK_PASS: new service; TCP port $listen_port; firewall and SSH unchanged"
[[ $mode == --apply ]] || exit 0
[[ $EUID -eq 0 ]] || { echo '[fail] Apply requires root on the authorized NEW VPS' >&2; exit 1; }

install -d -m 0755 /usr/local/lib/owned-vps-egress
install -d -m 0750 /etc/owned-vps-egress
install -m 0755 "$source_bin" "$binary"
install -m 0600 "$source_config" "$config"
cat > "$unit" <<'UNIT'
[Unit]
Description=Recipient-owned VLESS REALITY exit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
LoadCredential=config.json:/etc/owned-vps-egress/config.json
ExecStart=/usr/local/lib/owned-vps-egress/sing-box run -c ${CREDENTIALS_DIRECTORY}/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now owned-vps-egress.service
systemctl is-active --quiet owned-vps-egress.service
echo 'INSTALL_PASS: new service started; still verify provider firewall and end-to-end exit'

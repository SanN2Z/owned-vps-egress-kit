# Mihomo desktop clients

Use a current Mihomo-compatible client. Original/legacy Clash implementations
may not support VLESS REALITY or the TUN/DNS fields in this kit. Validate with the
actual destination core (`mihomo -t -d ISOLATED_DIRECTORY -f CONFIG`) before import.

Choose the generated Windows, macOS or Linux YAML. macOS requires a `utun` device
name; if the generated name is in use, choose an unused one and regenerate/review
the profile guard. Linux auto-redirect is not enabled by this portable profile.
TUN privileges and platform integration remain client-specific.

The profile captures IPv4 and IPv6, suppresses AAAA DNS answers and rejects public
IPv6. These are complementary controls: `dns.ipv6: false` alone does not block
literal IPv6 or an OS route. Capture UDP/TCP port 53 and route application DoH
through PROXY. Bootstrap is IP-addressed and separate from application DNS.
No default rule allows an application to fall back to public DIRECT.

Before activating, back up source, GUI/base settings and enhancement scripts.
Inspect global modifications: an older supplier relay script may misclassify a
new owned VPS, and a GUI may overwrite TUN/DNS values. Bind the generated private
guard to this profile only if the client supports profile scripts. It canonicalizes
rules/DNS/owned selectors and rejects the proxy path when identity or capture
checks fail. It cannot protect native traffic when TUN/the core is absent.

Verify after import/regeneration:

- Rule mode, TUN on, strict-route, both DNS hijacks, IPv6 TUN address, no unexpected
  route/interface/process exclusions; listener is local-only.
- PROXY has only the new recipient-owned node; GLOBAL exposes PROXY; no supplier
  node or DIRECT is a fallback. Compare full identity and REALITY keys privately.
- Protected domains precede any explicit DIRECT exceptions; final MATCH is PROXY.
- Actual selection and native app HTTPS/UDP/DNS exit match the recipient's server.

The Windows OS guard is described separately. On macOS, the application firewall
is not an equivalent outbound kill switch; a reviewed PF/network-extension policy
is needed. On Linux, use an audited nftables/firewalld design that permits tunnel
transport and required link services while denying bypass; account for service
UID/marks, network namespaces, Docker and NetworkManager. Do not paste Windows
commands or claim these guards are installed by this YAML. If no OS guard has
been implemented and crash-tested, label protection "TUN only; crash bypass not verified".

# iOS / Shadowrocket

Install the genuine Shadowrocket app from the App Store (app ID 932747118;
developer website shadowlaunch.com). It is a client, not a server subscription.
Record the actual app and iOS versions. No iOS device was available to validate
this kit initially; do not promote generated artifacts to a device-tested result.

## Import sequence

1. Transfer only the assigned client directory using a private channel. Import
   `shadowrocket-node.private.txt` through its VLESS URL or scan its QR inside
   Shadowrocket. Do not use a web QR service or public subscription converter.
2. Check host/port, VLESS, REALITY, Vision, SNI, public key, short ID and fingerprint
   against the assigned artifact. Leave certificate verification enabled. Never
   import the server's REALITY private key. Check the app recognizes every URI field.
3. Import `shadowrocket-rules.private.conf` through Files/iCloud Drive or another
   supported private file import. This is a separate operation from node import.
   Select it and configuration/rule routing. The built-in PROXY policy must use
   the assigned owned node. Do not select an old supplier/airport profile or a
   fallback group containing DIRECT. The minimal rule file has no MITM or scripts.
4. Inspect the parsed rules and DNS settings. FINAL must be PROXY; public IPv6 must
   be captured/rejected; approved LAN/domestic exceptions are intentional DIRECT.
   Enable DNS through the proxy in the installed app where supported. The file's
   DoH resolver URL alone does not prove its transport is proxied. If the app cannot
   enforce the intended DNS path, report the limitation instead of asserting safety.
5. Review the app's current full-tunnel/route-enforcement and on-demand settings.
   UI labels and configuration keys vary. Do not invent or silently assume a
   `include-all-networks` config key is supported by this installed version. Use
   the actual UI/help, then test. iOS VPN consent and switching an active VPN are
   user actions. An agent on a computer cannot silently grant that consent.

## What is different from Windows

- Windows `PROCESS-NAME` exceptions, firewall policy, physical-adapter settings and
  Clash Verge enhancement JavaScript do not transfer to Shadowrocket.
- Apple exposes includeAllNetworks/enforceRoutes APIs with configurable system
  exceptions; this does not prove which flags an installed client uses. On-demand
  reconnect is not proof of a persistent OS kill switch when VPN is disabled.
- A VPN icon or matching website IP alone does not verify DNS, UDP, IPv6 or all
  applications. User-disabled VPN, boot-before-connect and system exceptions must
  not be described as protected without evidence.
- Do not enable HTTPS decryption or install a root CA for this setup.

## Device acceptance

Test on both Wi-Fi and cellular: HTTPS exit, protected site traffic, DNS route,
IPv6 literal destination rejection and required UDP/STUN behavior. Check DNS
logs or a controlled resolver/packet capture; a DNS leak website's resolver
location by itself is not conclusive evidence. Test switching Wi-Fi/cellular,
sleep/wake and an unreachable **test copy** of the node while keeping the VPN on.
Protected requests must fail instead of using the access-network IP. Separately,
with consent and a nonsensitive test app, assess what happens when the VPN is off;
normal direct connectivity must be reported honestly. Record results per version.

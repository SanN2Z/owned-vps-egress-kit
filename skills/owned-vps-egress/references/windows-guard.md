# Windows outbound guard

This is an agent-executed, machine-specific procedure, not a blindly portable
firewall installer. Preparing a plan or running windows_audit.ps1 is read-only.
Applying these controls can interrupt other applications and requires authorization
covering the exact changes. Never restart or kill a running proxy to test them.

1. Run `windows_audit.ps1`; enumerate active physical/virtual adapters and the
   actual service-core executable. The running path can differ from Program Files.
   Inventory effective rules from all stores, including app-package scopes,
   third-party security, domain policy and Hyper-V. Stop if managed policy cannot
   be reconciled. Explicitly account for multiple uplinks and overlay exit nodes.
2. Prepare a concrete change list: enable all firewall profiles; set outbound
   default Block; retain only approved allowances. A block default does not override
   explicit Allow rules. Identify precisely which unrelated outbound allows would
   be disabled. Do not indiscriminately disable inbound, corporate or sandbox rules.
3. Define transport exceptions for the verified core executable and recipient-owned
   endpoint/port where practical; optional transit adds its approved transport only.
   If a broad core allowance is required for intentional DIRECT rules, document it:
   the core is trusted and its routing policy becomes part of enforcement.
4. Allow application traffic on the exact TUN interface, loopback and required
   DHCP/link services. LAN/overlay ranges are opt-in, not inherently harmless:
   allowing them can expose a LAN proxy or another VPN as a bypass. Physical DNS
   port 53 blocks must not also block the TUN DNS path. Inspect actual interfaces
   rather than relying on one English adapter name.
5. Choose IPv6 capture-and-reject and, when intended, disable physical adapter IPv6
   bindings. Explain impact and back up original bindings. Do not change IPv6 blindly
   on IPv6-only networks. WSL/Hyper-V/Docker/other VPNs require separate enforcement;
   host defaults alone are insufficient evidence.
6. Export the existing firewall (`netsh advfirewall export <PRIVATE_BACKUP.wfw>`),
   save original profiles, changed rule IDs, bindings and browser settings. Arrange
   local/console recovery before changing a remote machine. Apply the approved
   narrow plan; retain a private mutation ledger and fail loudly on any error.
7. Verify effective policy, TUN/native traffic, deliberate physical-interface TCP
   and UDP bypass attempts, DNS and IPv6. Never treat a TCP failure as UDP proof.
   Real core-crash/TUN-off tests require a separate controlled session authorized
   by the owner; they must not be induced on an active work connection here.

Browser WebRTC policies can reduce non-proxied UDP behavior but do not replace
network enforcement. Review browser effective policy rather than assuming registry
writes are already active; do not restart the browser automatically.

After a client/core or Store-app update, new NIC/VPN/WSL installation, reboot or
firewall change, compare effective allowances with the approved baseline. Report
new allowances before claiming full fail-closed protection. Do not silently install
scheduled jobs or background monitors.

Safe recovery keeps the guard active and tests only this recipient's owned exits.
If none work, protected/default traffic stays rejected. Restoring a pre-guard
firewall backup may remove protection: treat it as an explicit emergency rollback,
not the default "repair internet" action. Never insert DIRECT to conceal failure.

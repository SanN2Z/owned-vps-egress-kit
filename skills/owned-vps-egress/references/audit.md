# Read-only audit

Collect the installed client/core version and process identities. Preserve a
baseline hash of any configuration or script read. Do not enumerate unrelated
secrets or print complete credentials. Keep machine-specific evidence local.

Inspect these layers separately:

1. GUI settings: Rule vs Global/Direct, TUN, system proxy, DNS overrides and
   profile-specific enhancements. A GUI with stale cached state can regenerate
   an older policy even after the disk/runtime files were fixed.
2. Source profile and global/profile scripts: ordered rules, owned node identity,
   transit transformations, provider expansions, duplicated nodes, direct bypasses.
3. Generated runtime and GET-only controller: actual TUN enable/strict-route,
   UDP and TCP 53 capture, IPv6 TUN address, current selection, expanded group
   graph and active connection chains. Configuration on disk is not live proof.
   Never issue PATCH/PUT/DELETE, change selectors, or close connections in audit mode.
4. DNS: default application resolvers, resolver bootstrap, proxy-host resolution,
   direct-domain exceptions, OS/browser encrypted DNS and IPv6. Encrypted DNS can
   still leave through the physical network. DNS interception alone does not
   capture all DoH/DoT or every OS-local DNS path.
5. OS enforcement: default outbound, every effective allowance including app
   package/PolicyAppId scope, physical adapters, virtual adapters, WSL/Hyper-V,
   browser WebRTC policies, core executable path after an update. A rule with
   Program=Any can still be limited by PackageFamilyName; inspect the full scope.

Separate intentional DIRECT rules from leakage. An allowlisted application can
open embedded pages or new hostnames not covered by the protected domain list;
avoid broad process DIRECT defaults in portable profiles. DNS policy ordering
and routing-rule ordering are separate checks.

Report three categories: observed current state, historical test evidence with
date, and unverified behavior. Read-only checks do not prove crash/reboot/network
handoff fail-closed behavior. If local sandbox blocks the controller/CIM query,
retry only the same read-only operation with appropriate permission; don't disable
security or treat permission failure as an empty/pass result.

Capture process identities and file hashes again at the end. GUI/core restarts,
new background services, recovery execution and automatic firewall fixes are
outside a read-only audit.

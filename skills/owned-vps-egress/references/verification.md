# Verification and evidence

Use a new private test directory. Never use a production port/controller/TUN
device. For parser checks, `mihomo -t -d <isolated> -f <candidate>` exits by itself;
do not run a candidate TUN configuration as a second active VPN. For protocol tests
copy the candidate, set TUN disabled, DNS listener to a unique localhost port or
disabled, and mixed/controller ports to unused loopback ports. Do not modify the
original client artifact. Retain the exact test configuration hash privately.

Minimum results:

| Check | Required observable result |
|---|---|
| Fresh recipient generation | New REALITY key and distinct UUID per device; no personal endpoint |
| Cross-file consistency | Server user, client URI, YAML and REALITY public key agree |
| Normal owned exit | HTTPS and required UDP emerge from this recipient's owned server |
| Supplier transit down (if used) | Only recipient-owned direct/alternate exit works, or connection fails |
| All owned exits unreachable | Protected/default request fails; no supplier/raw DIRECT success |
| DNS resolver unavailable | No silent system/plain-DNS fallback for protected names |
| Profile regeneration | Final runtime still has the intended capture/DNS/group graph |
| IPv6 literal access | Owned IPv6 route if explicitly implemented, otherwise rejection |
| OS guard | Physical TCP/UDP/DNS attempts denied outside approved exceptions |
| Core/TUN unavailable | Only claim tested OS protection; schedule disruptive testing separately |
| iOS | Actual import + Wi-Fi/cellular/DNS/IPv6/handoff/outage checks on the target device |

A direct-only deployment has no supplier: mark its supplier-failure case N/A,
not passed. For optional transit, test all three path conditions before enabling.
An offline group-graph check or a local mock cannot prove real-network DNS or
physical-interface enforcement. Name each evidence level in the handoff.

Do not stop existing processes or connections. Isolated test processes may be
launched only without TUN/system-proxy effects and with bounded lifetime. Never
kill by process name: if cleanup is authorized, target only the exact disposable
process created for that test. A parse-only invocation needs no termination.

Use source IP and path tests together: geographic labels alone are not ownership
proof. Record version, date, access network and expected exit privately. Avoid
recording sensitive URL paths or other users' traffic contents.

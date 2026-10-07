# Initial validation — 2026-10-07

This is a local release candidate, not a production deployment certification.

| Check | Result | Scope |
|---|---|---|
| Skill creator validator | PASS | Required metadata and skill structure |
| Python regression suite | 12/12 PASS | Fresh identity, recipient/device isolation, path safety, tamper detection, explicit exceptions, URI/key agreement, private-artifact scanning |
| JavaScript guard execution | PASS | Normal policy canonicalization; six identity/capture/transit faults yield REJECT |
| QR generation | PASS | Image generated locally from assigned node URI; no iOS scan performed |
| Mihomo parser | 3/3 PASS | Windows, macOS and Linux YAML variants parsed by Windows Mihomo v1.19.31; not native macOS/Linux runtime testing |
| Bash installer syntax | PASS | `bash -n`; no service installed |
| PowerShell syntax and audit | PASS | Parsed by Windows PowerShell; helper executed read-only |
| Public-tree scan | PASS | No private artifact, credential or unexpected public IPv4 found; candidate file list reviewed |
| Personal identity comparison | PASS | Public kit does not contain the author's current node endpoint/UUID/secret values |
| Linux sing-box service deployment | NOT RUN | Requires a new recipient-owned server and authorized SSH access |
| New server end-to-end protocol/failure tests | NOT RUN | Parser/unit checks do not prove a network path |
| New OS kill switch installation/crash tests | NOT RUN | Platform procedures supplied; no live network changes made |
| Shadowrocket import/DNS/IPv6/network handoff | NOT RUN | Requires the actual iOS device and app version |

Reproduce offline tests from the repository root:

```text
python -B -m unittest discover -s tests -v
python -B skills/owned-vps-egress/scripts/publish_check.py .
```

Requirements: Python 3.10+, the packages in requirements.txt, and Node.js for the
JavaScript behavior test. Temporary directories hold only newly generated test
credentials and documentation IP addresses. On a restricted Windows agent sandbox,
private-directory ACLs or Git Bash shared-memory access can require a permitted
unsandboxed test execution. This is not permission to weaken filesystem/network
controls or run the server installer against an existing machine.

The real-machine audit is stored outside this public kit. No active profile,
selector, TUN, system proxy, firewall, browser or running proxy process was changed.

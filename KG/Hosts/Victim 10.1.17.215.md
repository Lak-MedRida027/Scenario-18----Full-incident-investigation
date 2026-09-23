---
tags: [victim, ioc]
---

# Victim - 10.1.17.215

The **only** compromised host; sole source of malicious activity across all five phases.

| Field | Value |
|---|---|
| IP | 10.1.17.215 |
| Hostname | DESKTOP-L8C5GSJ |
| Domain | BLUEMOONTUESDAY |
| OS | Windows |
| MAC | 00:D0:B7:26:4A:74 (Intel Corporation) |
| Bytes sent | 2,470,879 (~2.4 MB) |
| Bytes received | 23,007,609 (~23 MB) |
| Outgoing sessions | 405 |

## Role in the attack
- Downloaded [[TeamViewer.exe]], [[Teamvie.dll]], [[TV.dll]] and [[29842.ps1]] from [[C2 5.252.153.241]].
- Beaconed to the C2 ([[C2 beacon URI 1517096937]]) and pulled payloads ([[C2 payload URI get-file]]).
- Abused Kerberos against [[DC 10.1.17.2]] to steal [[shutchenson]].
- **Top talker**: 1,830,702 bytes outbound (455x the next host) -> [[T1041 Exfiltration Over C2]].

Seen in: [[Phase 1 - Detection]], [[Phase 2 - Behavioral Analysis]], [[Phase 3 - Forensics]],
[[Phase 4 - NetFlow]], [[Phase 5 - Deep Packet Inspection]].

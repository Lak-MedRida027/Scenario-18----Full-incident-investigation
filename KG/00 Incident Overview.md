---
tags: [overview]
---

# Incident Overview - Report 18 (Zui Golden Scenario)

> Data Exfiltration + Internal Compromise via a **fake TeamViewer trojan**.
> Reconstructed from a single PCAP (`traffic_analysis.pcap`, 2025-01-22).

## One-line story
[[Victim 10.1.17.215]] downloaded a fake TeamViewer trojan from [[C2 5.252.153.241]] over
cleartext HTTP, ran an obfuscated PowerShell payload in memory, stole the domain account
[[shutchenson]] from [[DC 10.1.17.2]] via Kerberos, and exfiltrated ~1.75 MB back to the C2.

## Key entities
- Victim host: [[Victim 10.1.17.215]]
- Attacker C2: [[C2 5.252.153.241]]
- Domain controller: [[DC 10.1.17.2]]
- Stolen account: [[shutchenson]]

## Payloads
[[TeamViewer.exe]] · [[Teamvie.dll]] · [[TV.dll]] · [[29842.ps1]]

## Attacker infrastructure
[[master16.teamviewer.com]] · [[C2 beacon URI 1517096937]] · [[C2 payload URI get-file]]

## Investigation phases
[[Phase 1 - Detection]] -> [[Phase 2 - Behavioral Analysis]] -> [[Phase 3 - Forensics]]
-> [[Phase 4 - NetFlow]] -> [[Phase 5 - Deep Packet Inspection]]

## Tools
[[Zui (Brim)]] · [[NetworkMiner]] · [[Wireshark]] · [[NetFlow]]

## MITRE ATT&CK
[[T1105 Ingress Tool Transfer]] · [[T1036 Masquerading]] · [[T1055 Process Injection]]
· [[T1071.001 Web Protocols]] · [[T1059.001 PowerShell]] · [[T1027 Obfuscated Files]]
· [[T1558 Kerberos Tickets]] · [[T1041 Exfiltration Over C2]]

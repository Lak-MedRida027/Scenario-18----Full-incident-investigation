---
tags: [phase]
---

# Phase 2 - Behavioral Analysis (Zeek Logs)

Tool: [[Zui (Brim)]].

- `conn` longest session: 43m12s [[Victim 10.1.17.215]] -> [[C2 5.252.153.241]]:80.
- `conn | sum(orig_bytes) by id.orig_h`: victim is top talker (1,830,702 bytes).
- `dns | count() by query`: rare [[master16.teamviewer.com]] (queried once).
- `http`: 594 GETs -> [[C2 beacon URI 1517096937]] and [[C2 payload URI get-file]].
- Rare ports: 88 (Kerberos), 2917 (suspicious).

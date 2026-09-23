---
tags: [infra, ioc]
---

# master16.teamviewer.com

DNS lookup queried **exactly once** - a single-use C2 registration domain tied to the fake
TeamViewer lure.

- Queried by [[Victim 10.1.17.215]]; associated with [[C2 5.252.153.241]].
- Reinforces the TeamViewer-themed masquerade -> [[T1036 Masquerading]].
- Found in [[Phase 2 - Behavioral Analysis]] (dns.log rare-query hunt).

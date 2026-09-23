---
tags: [tool]
---

# Wireshark

Deep packet inspection and stream reconstruction.

- Powered [[Phase 5 - Deep Packet Inspection]].
- Filter `ip.addr == 10.1.17.215 && ip.addr == 5.252.153.241` isolated the C2 session;
  Follow HTTP Stream revealed [[29842.ps1]] and the Express.js server fingerprint.

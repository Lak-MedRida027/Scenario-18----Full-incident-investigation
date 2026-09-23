---
tags: [phase]
---

# Phase 1 - Detection (Suricata Alert Triage)

Tool: [[Zui (Brim)]]. Queries: `event_type=="alert" | sort severity desc` then
`event_type=="alert" alert.severity==1 | cut ts, src_ip, dest_ip, alert.signature`.

- 28 alert rows; 4 severity-1 signatures all part of one infection chain.
- Identified [[C2 5.252.153.241]] and [[Victim 10.1.17.215]] as the key IPs.
- Signatures point to [[TeamViewer.exe]] download and C2 callbacks.

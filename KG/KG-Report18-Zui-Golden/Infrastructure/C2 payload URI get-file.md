---
tags: [infra, ioc]
---

# C2 Payload URI - /api/file/get-file/<id>

Structured REST path used to deliver every payload (all returned **200**).

| URI | Payload |
|---|---|
| `/api/file/get-file/TeamViewer` | main trojan ([[TeamViewer.exe]]) |
| `/api/file/get-file/TeamViewer_Resource_fr...` | resource file |
| `/api/file/get-file/29842.ps1` | [[29842.ps1]] |
| `/api/file/get-file/264872` | additional binary |

- Hosted on [[C2 5.252.153.241]]; requested by [[Victim 10.1.17.215]].
- MITRE: [[T1105 Ingress Tool Transfer]]. 594 total HTTP GETs observed.

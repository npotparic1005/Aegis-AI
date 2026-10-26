# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-02T06:50:45.821100+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, 10.10.10.0/24
- **In-scope domains:** localhost, dvwa.local

## Summary

- Actions executed: **2**
- Findings recorded: **4**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-02T06:49:03.949126+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-02T06:50:16.330652+00:00 | cve_lookup | 127.0.0.1 | allow | yes |

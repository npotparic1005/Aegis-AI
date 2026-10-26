# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-08-31T14:35:54.407962+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, 10.10.10.0/24
- **In-scope domains:** localhost, dvwa.local

## Summary

- Actions executed: **4**
- Findings recorded: **8**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open iss-realsecure |
| 127.0.0.1 | 912/tcp open apex-mesh |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-08-31T14:14:59.054630+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-08-31T14:16:10.112491+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-08-31T14:17:02.284208+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-08-31T14:17:38.441859+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-08-31T14:19:37.269476+00:00 | cve_lookup | 127.0.0.1 | allow | no |

# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-14T11:00:52.357906+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** localhost

## Summary

- Actions executed: **2**
- Findings recorded: **14**

## Findings

| Host | Detail |
|------|--------|
| 127.0.0.1 | 135/tcp open msrpc |
| 127.0.0.1 | 445/tcp open microsoft-ds |
| 127.0.0.1 | 902/tcp open vmware-auth 1.10 |
| 127.0.0.1 | 912/tcp open vmware-auth 1.0 |
| 127.0.0.1 | Buffer overflow in the RPC Locator service for Microsoft Windows NT 4.0, Windows NT 4.0 Terminal Server Edition, Windows 2000, and Windows XP allows local users to execute arbitrar… |
| 127.0.0.1 | Buffer overflow in a certain DCOM interface for RPC in Microsoft Windows NT 4.0, 2000, XP, and Server 2003 allows remote attackers to execute arbitrary code via a malformed message… |
| 127.0.0.1 | The RPC Runtime Library for Microsoft Windows NT 4.0 allows remote attackers to read active memory or cause a denial of service (system crash) via a malicious message, possibly rel… |
| 127.0.0.1 | Vulnerabilities in RPC servers in (1) Microsoft Exchange Server 2000 and earlier, (2) Microsoft SQL Server 2000 and earlier, (3) Windows NT 4.0, and (4) Windows 2000 allow remote a… |
| 127.0.0.1 | The Sun Microsystems RPC library Services for Unix 3.0 Interix SD, as implemented on Microsoft Windows NT4, 2000, and XP, allows remote attackers to cause a denial of service (serv… |
| 127.0.0.1 | An input validation error in the Sun Microsystems RPC library Services for Unix 3.0 Interix SD, as implemented on Microsoft Windows NT4, 2000, and XP, allows remote attackers to ca… |
| 127.0.0.1 | Buffer overflow in the COM Internet Services and in the RPC over HTTP Proxy components for Microsoft Windows NT Server 4.0, NT 4.0 Terminal Server Edition, 2000, XP, and Server 200… |
| 127.0.0.1 | An Activation function in the RPCSS Service involved with DCOM activation for Microsoft Windows 2000, XP, and 2003 allows remote attackers to cause a denial of service (memory cons… |
| 127.0.0.1 | Microsoft Windows 2000 allows local users to cause a denial of service by corrupting the local security policy via malformed RPC traffic, aka the "Local Security Policy Corruption"… |
| 127.0.0.1 | The DCOM RPC interface for Microsoft Windows NT 4.0, 2000, XP, and Server 2003 allows remote attackers to cause network communications via an "alter context" call that contains add… |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-14T10:54:07.016630+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-14T10:54:49.759017+00:00 | cve_lookup | 127.0.0.1 | allow | yes |

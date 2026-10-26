# Penetration Test Report — Local Lab — DVWA

*Generated: 2026-09-14T06:50:39.674455+00:00*

## Engagement

- **Client:** self
- **Authorization:** personal-lab-owned-hardware
- **Window:** 2025-01-01 → 2030-12-31
- **In-scope hosts:** 127.0.0.1, scanme.nmap.org
- **In-scope domains:** localhost

## Summary

- Actions executed: **9**
- Findings recorded: **20**

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
| 127.0.0.1 | VMware Authentication Daemon 1.0 in vmware-authd.exe in the VMware Authorization Service in VMware Workstation 7.0 before 7.0.1 build 227600 and 6.5.x before 6.5.4 build 246459, VM… |
| 127.0.0.1 | VMware Authentication Daemon 1.0 in vmware-authd.exe in the VMware Authorization Service in VMware Workstation 7.0 before 7.0.1 build 227600 and 6.5.x before 6.5.4 build 246459, VM… |
| 127.0.0.1 | flowd in Juniper Junos 10.4 before 10.4R11 on SRX devices, when the MSRPC Application Layer Gateway (ALG) is enabled, allows remote attackers to cause a denial of service (daemon c… |
| 127.0.0.1 | Microsoft Exchange 2000, when used with Microsoft Remote Procedure Call (MSRPC), allows remote attackers to cause a denial of service (crash or memory consumption) via malformed MS… |
| 127.0.0.1 | http://127.0.0.1:80/: curl: (7) Failed to connect to 127.0.0.1:80 after 2047 ms: Could not connect to server |
| 127.0.0.1 | https://127.0.0.1:443/: curl: (7) Failed to connect to 127.0.0.1:443 after 2036 ms: Could not connect to server |

## Action Log (audit)

| Time | Tool | Target | Policy | Executed |
|------|------|--------|--------|----------|
| 2026-09-14T06:05:47.011797+00:00 | nmap | 127.0.0.1 | allow | yes |
| 2026-09-14T06:07:12.952647+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-14T06:07:20.719821+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-14T06:07:27.810086+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-14T06:08:43.571962+00:00 | cve_lookup | 127.0.0.1 | allow | yes |
| 2026-09-14T06:16:22.101538+00:00 | whois | example.com | DENY | no |
| 2026-09-14T06:22:19.239281+00:00 | dns_lookup | 127.0.0.1 | allow | yes |
| 2026-09-14T06:23:15.845073+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-09-14T06:24:29.703726+00:00 | http_headers | 127.0.0.1 | allow | yes |
| 2026-09-14T06:37:40.938054+00:00 | whois | 127.0.0.1 | allow | yes |

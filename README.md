# Azure-security-labs

Security operations lab series building cloud security capabilities on Azure.

## Mission 01: Azure SIEM Setup & Log Monitoring

**Focus:** Setting up a complete SIEM (Security Information and Event Management) infrastructure on Azure to monitor a Windows 10 workstation.

**Tech Stack:** Azure Monitor, Microsoft Sentinel, Azure Arc, KQL (Kusto Query Language)

### Mission Files

- **runbook.md** — Complete setup documentation from Steps 0-5b with all troubleshooting
- **queries.kql** — 7 KQL queries for log analysis and security monitoring
- **detection.md** — Step 6 anomalous activity detection template and analysis framework

## Project Alignment

This lab covers **BeCode Project 1: IAM & Log Monitoring Lab** - cloud security foundation with log monitoring and SIEM setup.

## Current Setup

### Mission 01: Azure SIEM Setup ✅

**Completed:**
- ✅ Tailscale VPN connectivity
- ✅ Remote Desktop connection to Windows 10 workstation (WKS-L57)
- ✅ Azure for Students account activation
- ✅ Resource group and Log Analytics workspace creation
- ✅ Microsoft Sentinel enablement (free trial)
- ✅ Azure Arc machine registration
- ✅ Data Collection Rules for Windows events
- ✅ Log data verification and KQL queries
- ⏳ Step 6: Anomalous activity detection (pending coach execution)

**Key Learnings:**
- Allowed regions ≠ available regions in service dropdowns
- MFA required for Azure resource creation (device code flow)
- Always check Heartbeat first for connectivity issues
- Two data collection chains: unstructured (Event) and structured (SecurityEvent)

---

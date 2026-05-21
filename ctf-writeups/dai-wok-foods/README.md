# Dai Wok Foods

A comprehensive digital forensics investigation analyzing a multi-stage phishing campaign and ransomware attack targeting a food services company through email-based social engineering and malicious Office documents.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Medium-yellow?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-Digital%20Forensics%20%7C%20Threat%20Hunting-purple?style=flat-square)

---

## Challenge Overview

| **Attribute** | **Details** |
|---------------|-------------|
| **Challenge Name** | Dai Wok Foods: A Challenging Culinary Mystery |
| **Author** | David Brown |
| **Platform** | KC7 Cyber (kc7001.eastus) |
| **Category** | Digital Forensics, Threat Hunting, Email Security |
| **Difficulty** | Medium |
| **Tools Used** | KQL (Kusto Query Language), VirusTotal, MaxMind GeoIP, PassiveDNS Analysis |
| **Target Environment** | Dai Wok Foods corporate network |

**Scenario:**

Dai Wok Foods, a restaurant company, experienced a sophisticated multi-stage cyber attack beginning in early April 2023. The incident started when employee Delphia Evans received a phishing email with subject "[EXTERNAL] Formal action on food poisoning." The threat actor, later identified as FIN7/CarbonSpider, deployed a phishing campaign using multiple spoofed sender addresses and typosquatted domains mimicking legal and food administration services. Employee John Garcia clicked a malicious link leading to the download of "large_order.xlsx," which triggered the execution of PowerShell-based malware. The attack culminated in the deployment of BabLock ransomware using DLL side-loading techniques, affecting multiple restaurant locations and locking users out of their systems.

## Attack Timeline

| **Date/Time** | **Event** |
|---------------|-----------|
| 2023-04-02T20:40:54Z | Initial phishing email sent to delphia_evans@daiwokfoods[.]com from county.county[@]yahoo[.]com |
| 2023-04-03T18:04:56Z | Phishing email delivered to john_garcia@daiwokfoods[.]com from official[@]verizon[.]com with reply-to service_official[@]yandex[.]com |
| 2023-04-03T18:38:38Z | John Garcia clicked malicious link to complaints-cityofficialsfood[.]com |
| 2023-04-03T18:39:12Z | File large_order.xlsx created on LVJW-LAPTOP at C:\Users\jogarcia\Downloads\ |
| 2023-04-03T19:28:46Z | PowerShell script c5k3fsys.3bp[.]ps1 executed with execution policy bypass from \\share1\Admin\ |
| 2023-04-04T10:14:35Z | Security alert generated - employee deevans reported suspicious email |
| 2023-04-09T16:09:54Z | Threat actor IP 179.58.169[.]157 performed reconnaissance search for "store managers" on daiwokfoods[.]com |
| 2023-05-08T09:19:01Z | Config.ini file created on compromised host VORT-DESKTOP |
| 2023-05-08T09:21:51Z | cy[.]exe (SHA256: 4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d) deployed on S3XE-DESKTOP |
| 2023-05-11T10:03:33Z | Volume Shadow Copy deletion executed: vssadmin[.]exe delete shadows /All /Quiet |
| 2023-05-12T09:22:48Z | Second phishing wave: Local_County_Updates.xlsx campaign begins targeting multiple employees |
| 2023-05-12T10:00:55Z | First employee clicked link to operations-management[.]hk hosting Local_County_Updates.xlsx |

## Solution Walkthrough

### Step 1 — Identify Compromised Employee

**Objective:** Determine which employee clicked the initial phishing link.

```kql
// Query: Find employee by IP address who accessed the malicious content
Employees
| where ip_addr == "192.168.3.86"
```
// Result: John Garcia (jogarcia), Logistics Coordinator, hostname LVJW-LAPTOP

**Key Findings:**
- **Employee Name:** John Garcia
- **Username:** jogarcia
- **Email:** john_garcia@daiwokfoods[.]com
- **IP Address:** 192.168.3[.]86
- **Hostname:** LVJW-LAPTOP
- **Role:** Logistics Coordinator

---

### Step 2 — Analyze Phishing Email

**Objective:** Examine the suspicious email delivered to John Garcia.

```kql
// Query: Locate email sent to John Garcia from known malicious senders
Email
| where recipient == "john_garcia@daiwokfoods.com"
| where sender has_any ("county.county@yahoo.com", "complaint_county@gmail.com", "official@verizon")
```
// Result: Email from official@verizon[.]com sent 2023-04-03T18:04:56Z with reply-to service_official[@]yandex[.]com

**Key Findings:**
- **Timestamp:** 2023-04-03T18:04:56Z
- **Sender:** official[@]verizon[.]com (spoofed)
- **Reply-to:** service_official[@]yandex[.]com
- **Subject:** [EXTERNAL] Legal notice of customer complaint
- **Verdict:** SUSPICIOUS
- **Link:** hxxps://complaints-cityofficialsfood[.]com/search/published/images/images/large_order.xlsx

---

### Step 3 — Investigate Reply-To Infrastructure

**Objective:** Determine the geolocation of the reply-to email domain.

OSINT research on yandex[.]com domain revealed the email service provider is based in Russia, indicating likely threat actor infrastructure location.

**Key Findings:**
- **Domain:** yandex[.]com
- **Country of Origin:** Russia
- **Technique:** Email spoofing with Russian-based reply-to address to evade detection

---

### Step 4 — PassiveDNS Analysis

**Objective:** Identify IP addresses associated with the malicious domain.

```kql
// Query: Find all DNS resolution records for the phishing domain
PassiveDns
| where domain contains "complaints-cityofficialsfood.com"
```
// Result: 9 DNS records found with multiple IP addresses over time

**Key Findings:**
- **Record Count:** 9 PassiveDNS entries
- **IP Addresses Identified:**
  - 134.173.137[.]45
  - 177.43.27[.]137
  - 188.216.230[.]252
  - 131.162.160[.]193
  - 179.58.169[.]157
  - 77.112.237[.]13
  - 189.100.73[.]140

**IP Resolution at Time of Email:** 179.58.169[.]157 (closest to 2023-04-03T18:04:56Z)

---

### Step 5 — GeoIP Lookup

**Objective:** Determine geographic location of threat actor infrastructure.

Using MaxMind GeoIP service on IP 179.58.169[.]157:

**Key Findings:**
- **IP Address:** 179.58.169[.]157
- **Location:** La Paz, Bolivia
- **Hostname:** mobile-179-58-169-157.vnet[.]bo
- **ASN:** AS28024 (Nuevatel PCS de Bolivia S.A.)
- **Organization:** Nuevatel PCS de Bolivia (mobile network)

---

### Step 6 — Reconnaissance Activity Detection

**Objective:** Identify attacker's post-compromise reconnaissance.

```kql
// Query: Search for inbound connections from threat actor IP
InboundNetworkEvents
| where src_ip == "179.58.169.157"
```
// Result: GET request to hxxp://daiwokfoods[.]com/search?query=store%20managers on 2023-04-09T16:09:54

**Key Findings:**
- **Earliest Search Query:** "store managers" (URL-decoded from %20)
- **Technique:** Reconnaissance of organizational structure via web search
- **Total Records from Threat IPs:** 49 inbound network events
- **Earliest Activity:** 2023-03-26T01:20:14Z

---

### Step 7 — Analyze Malicious File Download

**Objective:** Track the creation and location of the weaponized Excel file.

```kql
// Query: Locate file creation event for malicious Excel file
FileCreationEvents
| where filename == "large_order.xlsx"
```
// Result: File created on LVJW-LAPTOP by jogarcia on 2023-04-03T18:39:12Z

**Key Findings:**
- **Filename:** large_order.xlsx
- **Path:** C:\Users\jogarcia\Downloads\large_order.xlsx
- **SHA256:** b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501
- **Timestamp:** 2023-04-03T18:39:12Z
- **Process:** chrome[.]exe (download via browser)
- **Host Count:** 1 machine affected initially

---

### Step 8 — VirusTotal Hash Analysis

**Objective:** Verify if the malicious file is known to threat intelligence.

Searched SHA256 hash on VirusTotal: b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501

**Key Findings:**
- **VirusTotal Result:** No results found
- **Implication:** Zero-day or targeted malware not previously submitted to public repositories

---

### Step 9 — Identify Malicious PowerShell Execution

**Objective:** Detect post-exploitation PowerShell activity.

```kql
// Query: Find process events after initial file download
ProcessEvents
| where hostname == "LVJW-LAPTOP"
| where timestamp >= datetime(2023-04-03T18:39:12Z)
```
// Result: PowerShell script execution with bypass flags detected

**Key Findings:**
- **Script Name:** c5k3fsys.3bp[.]ps1
- **Location:** \\share1\Admin\c5k3fsys.3bp[.]ps1 (network share)
- **Command Line:** `cmd.exe /c start %SYSTEMROOT%\system32\WindowsPowerShell\v1.0\powershell.exe -noni -nop -exe bypass -f \\share1\Admin\c5k3fsys.3bp.ps1`
- **Parent Process:** ClearTemp[.]ps1
- **Parent Hash:** 662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779
- **Execution Time:** 2023-04-03T19:28:46Z

---

### Step 10 — Malware Family Attribution

**Objective:** Identify the malware family and associated threat actor.

VirusTotal analysis of parent_process_hash 662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779:

**Key Findings:**
- **Detection:** 37/62 vendors flagged as malicious
- **Popular Threat Label:** trojan.powershell/malgent
- **Associated Malware:** FIN7 Diceloader
- **Threat Actor:** FIN7 / CarbonSpider
- **File Size:** 322.51 KB
- **Behavior Tags:** idle, detect-debug-environment, direct-cpu-clock-access, runtime-modules, long-sleeps
- **MD5 Hash:** d405909fd2fd02137244b7b36a3b806

**Threat Intelligence:**
According to public threat reporting, FIN7 has shifted operations to ransomware deployment campaigns.

---

### Step 11 — DLL Side-Loading Analysis

**Objective:** Identify DLL hijacking technique used by the threat actor.

Research from Group-IB blog post referenced on VirusTotal community page identified the technique:

```kql
// Query: Find legitimate process being abused
ProcessEvents
| where process_commandline contains 'cy.exe'
```
// Result: notepad[.]exe abused via cy[.]exe to load winutils.dll

**Key Findings:**
- **MITRE Technique:** T1574.002 (Hijack Execution Flow: DLL Side-Loading)
- **Legitimate Process:** notepad[.]exe
- **Malicious DLL:** winutils.dll (no longer present on systems)
- **Loader Binary:** cy[.]exe
- **SHA256 (cy[.]exe):** 4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d
- **Command Line:** `cy.exe --run=3308 --pt=C:\Users\Public\Documents\winutils.dll`
- **Affected Hostname:** JP9Y-DESKTOP

**VirusTotal Analysis of cy[.]exe:**
- **Detection:** 52/72 vendors flagged as malicious
- **File Size:** 79.50 KB
- **Popular Threat Label:** trojan.dllhijack/doina
- **Threat Categories:** trojan, ransomware
- **Family Labels:** dllhijack, doina, darkloader, BabLock ransomware
- **SHA256:** 21ff279ba30d227e32e63cb388bf8c2d21c4fd7e935b3087088579b29e56d81d

---

### Step 12 — Ransomware Deployment Detection

**Objective:** Identify ransomware execution and anti-forensics activity.

```kql
// Query: Search for shadow copy deletion commands
ProcessEvents
| where hostname == '1FK7-MACHINE'
| where process_commandline contains "delete"
```
// Result: Volume Shadow Copy deletion command executed

**Key Findings:**
- **Attack Type:** Ransomware (BabLock)
- **Anti-Forensics Command:** `vssadmin.exe delete shadows /All /Quiet`
- **Purpose:** Prevent system restoration from shadow copies
- **Timestamp:** 2023-05-11T10:03:33Z
- **Affected Host:** 1FK7-MACHINE

---

### Step 13 — Identify Targeted Roles

**Objective:** Determine organizational roles targeted by the phishing campaign.

```kql
// Query: Find distinct roles of employees who received phishing emails
let TA_emails =
Email
| where sender has_any ("county.county@yahoo.com", "complaint_county@gmail.com",
"official@gmail.com", "service_official@yandex.com", "official@verizon.com")
| distinct recipient;
Employees
| where email_addr in (TA_emails)
| distinct role
| count
```
// Result: 15 distinct roles targeted

**Key Findings:**
- **Roles Targeted:** 15 unique job functions
- **Phishing Email Count:** 13 emails containing large_order.xlsx link
- **Campaign Scale:** Multi-employee targeting across organizational structure

---

### Step 14 — Second Wave Analysis

**Objective:** Investigate the subsequent ransomware campaign.

```kql
// Query: Analyze Local_County_Updates.xlsx campaign
Email
| where link contains "Local_County_Updates.xlsx"
```
// Result: Second phishing wave identified starting 2023-05-12T09:22:48Z

**Key Findings:**
- **Malicious File:** Local_County_Updates.xlsx
- **Sender:** restaurant[@]verizon[.]com
- **Reply-to:** miguel_waters[@]hoisumsupplies[.]com
- **First Sent:** 2023-05-12T09:22:48Z
- **First Click:** 2023-05-12T10:00:55Z
- **Malicious Domain:** operations-management[.]hk
- **Full URL:** hxxp://operations-management[.]hk/published/share/share/modules/Local_County_Updates.xlsx
- **Victim IP:** 192.168.1[.]176
- **Victim Role:** Ingredient Procurement

---

### Step 15 — Authentication Analysis

**Objective:** Detect unauthorized access from compromised credentials.

```kql
// Query: Identify login sources for compromised user
AuthenticationEvents
| where username == "jogarcia"
| distinct src_ip
```
// Result: 2 distinct source IPs - internal and suspicious external IP

**Key Findings:**
- **Username:** jogarcia (compromised account)
- **Login IP 1:** 192.168.3[.]86 (internal/legitimate)
- **Login IP 2:** 2.20.114[.]29 (external/suspicious)
- **External IP Location:** Palermo, Sicily, Italy (Akamai infrastructure)
- **Authentication Records from External IP:** 12 events
- **Affected Host:** MAIL-SERVER01

## IOC Table

| **Type** | **Indicator** | **Context** | **Threat Actor** |
|----------|---------------|-------------|------------------|
| Email | official[@]verizon[.]com | Spoofed sender address in phishing campaign | FIN7/CarbonSpider |
| Email | service_official[@]yandex[.]com | Reply-to address (Russia-based) | FIN7/CarbonSpider |
| Email | county.county[@]yahoo[.]com | Phishing campaign sender | FIN7/CarbonSpider |
| Email | complaint_county[@]gmail[.]com | Phishing campaign sender/reply-to | FIN7/CarbonSpider |
| Email | restaurant[@]verizon[.]com | Second wave phishing sender | FIN7/CarbonSpider |
| Email | miguel_waters[@]hoisumsupplies[.]com | Second wave reply-to address | FIN7/CarbonSpider |
| Domain | complaints-cityofficialsfood[.]com | Malicious phishing domain hosting large_order.xlsx | FIN7/CarbonSpider |
| Domain | operations-management[.]hk | Second wave phishing domain hosting Local_County_Updates.xlsx | FIN7/CarbonSpider |
| Domain | foodadministration-legal-services[.]com | Typosquatted domain in phishing campaign | FIN7/CarbonSpider |
| IPv4 | 179.58.169[.]157 | Threat actor C2 infrastructure (Bolivia mobile network) | FIN7/CarbonSpider |
| IPv4 | 134.173.137[.]45 | PassiveDNS resolution for phishing domain | FIN7/CarbonSpider |
| IPv4 | 177.43.27[.]137 | PassiveDNS resolution for phishing domain | FIN7/CarbonSpider |
| IPv4 | 188.216.230[.]252 | PassiveDNS resolution for phishing domain | FIN7/CarbonSpider |
| IPv4 | 131.162.160[.]193 | PassiveDNS resolution for phishing domain | FIN7/CarbonSpider |
| IPv4 | 2.20.114[.]29 | Unauthorized login source (Italy, Akamai) | FIN7/CarbonSpider |
| SHA256 | b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501 | large_order.xlsx (initial payload) | FIN7/CarbonSpider |
| SHA256 | 662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779 | c5k3fsys.3bp[.]ps1 parent process (FIN7 Diceloader) | FIN7/CarbonSpider |
| SHA256 | 4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d | cy[.]exe (DLL side-loading binary) | FIN7/CarbonSpider |
| SHA256 | 21ff279ba30d227e32e63cb388bf8c2d21c4fd7e935b3087088579b29e56d81d | cy[.]exe alternate hash (BabLock ransomware component) | FIN7/CarbonSpider |
| MD5 | d405909fd2fd02137244b7b36a3b806 | FIN7 Diceloader malware | FIN7/CarbonSpider |
| Filename | large_order.xlsx | Weaponized Excel document | FIN7/CarbonSpider |
| Filename | Local_County_Updates.xlsx | Second wave weaponized Excel document | FIN7/CarbonSpider |
| Filename | c5k3fsys.3bp[.]ps1 | Malicious PowerShell script (FIN7 Diceloader) | FIN7/CarbonSpider |
| Filename | winutils.dll | Malicious DLL for side-loading (deleted post-execution) | FIN7/CarbonSpider |
| Filename | cy[.]exe | Legitimate-appearing binary for DLL hijacking | FIN7/CarbonSpider |
| File Path | \\share1\Admin\c5k3fsys.3bp[.]ps1 | Network share hosting malicious PowerShell | FIN7/CarbonSpider |
| File Path | C:\Users\Public\Documents\winutils.dll | Malicious DLL staging location | FIN7/CarbonSpider |

## MITRE ATT&CK Mapping

| **Tactic** | **Technique ID** | **Technique Name** | **Evidence from Investigation** |
|------------|------------------|--------------------|---------------------------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Delivery of large_order.xlsx and Local_County_Updates.xlsx via phishing emails to multiple employees |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Malicious links in emails directing to complaints-cityofficialsfood[.]com and operations-management[.]hk |
| Execution | T1204.002 | User Execution: Malicious File | John Garcia downloaded and opened large_order.xlsx from phishing link |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution of c5k3fsys.3bp[.]ps1 with bypass flags: -noni -nop -exe bypass |
| Persistence | T1547 | Boot or Logon Autostart Execution | Configuration files (config.ini) created in C:\Users\Public\Documents\ |
| Defense Evasion | T1027 | Obfuscated Files or Information | PowerShell script names obfuscated (c5k3fsys.3bp[.]ps1), malware employing anti-debug techniques |
| Defense Evasion | T1070.001 | Indicator Removal on Host: Clear Windows Event Logs | Parent process masquerading as ClearTemp[.]ps1 |
| Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 | Abuse of notepad[.]exe to load malicious winutils.dll |
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | cy[.]exe loading malicious winutils.dll via DLL side-loading technique targeting notepad[.]exe |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Volume Shadow Copy deletion to prevent recovery: vssadmin[.]exe delete shadows /All /Quiet |
| Credential Access | T1078 | Valid Accounts | Unauthorized authentication from 2.20.114[.]29 (Italy) using compromised jogarcia credentials |
| Discovery | T1087 | Account Discovery | Reconnaissance search for "store managers" on daiwokfoods[.]com by threat actor |
| Discovery | T1083 | File and Directory Discovery | Enumeration of network shares (\\share1\Admin\) for malware staging |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Use of network share \\share1\Admin\ to host and execute PowerShell payload |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP/HTTPS communication to phishing domains for payload delivery |
| Command and Control | T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Fast-flux DNS observed with 9 IP resolutions for single domain over short timeframe |
| Impact | T1486 | Data Encrypted for Impact | BabLock ransomware deployment affecting multiple restaurant locations |
| Impact | T1490 | Inhibit System Recovery | Deletion of Volume Shadow Copies to prevent restoration: vssadmin[.]exe delete shadows /All /Quiet |

## Tools Used

- **Kusto Query Language (KQL)** — Primary query language for log analysis across Employees, Email, PassiveDns, InboundNetworkEvents, OutboundNetworkEvents, FileCreationEvents, ProcessEvents, AuthenticationEvents, and SecurityAlerts tables
- **VirusTotal** — Malware hash analysis and threat intelligence lookup for file hashes (b9d3c96..., 662124b..., 4874d33..., 21ff279...)
- **MaxMind GeoIP** — Geolocation of threat actor IP addresses (179.58.169[.]157 in Bolivia, 2.20.114[.]29 in Italy)
- **ipgeolocation[.]com** — Secondary GeoIP verification and ASN lookup
- **PassiveDNS Analysis** — Historical DNS resolution tracking for malicious domains
- **OSINT (Open Source Intelligence)** — Domain registration research and threat actor infrastructure profiling
- **Group-IB Blog Post** — Malware technique research (BabLock ransomware DLL side-loading methodology)
- **MITRE ATT&CK Framework** — Technique mapping and adversary behavior categorization
- **YARA Rules** — Malware signature matching (MAL_Bablock_DLL_Apr23 rule detected on VirusTotal)

## Key Takeaways

1. **Email Spoofing Detection** — Reply-to address mismatches are critical indicators of phishing campaigns. The discrepancy between sender (official[@]verizon[.]com) and reply-to (service_official[@]yandex[.]com) addresses revealed the true attacker infrastructure in Russia, demonstrating the importance of inspecting full email headers rather than relying solely on sender fields.

2. **Fast-Flux DNS Infrastructure** — The threat actor employed dynamic DNS resolution with 9 different IP addresses across multiple countries (Bolivia, various other locations) over a short timeframe, making static blocklists ineffective. Defenders should implement PassiveDNS monitoring and query frequency analysis to detect infrastructure rotation patterns.

3. **Living-Off-The-Land Techniques** — FIN7 abused legitimate Windows processes (notepad[.]exe) via DLL side-loading (T1574.002) to evade application whitelisting and behavioral detection. Organizations must implement DLL integrity verification and monitor for unexpected parent-child process relationships to detect this technique.

4. **PowerShell Execution Policy Bypass** — The flags `-noni -nop -exe bypass` allowed malicious script execution despite Group Policy restrictions. Implement PowerShell Constrained Language Mode, ScriptBlock logging, and Module logging to detect bypass attempts and capture full command-line arguments for forensic analysis.

5. **Multi-Stage Attack Correlation** — The investigation required correlating data across 8+ log sources (Email, Network Events, File Creation, Process Execution, Authentication, DNS) over a 6-week timeline. Security teams should implement SIEM correlation rules that link initial phishing indicators to downstream execution events, enabling earlier detection of multi-stage campaigns.

6. **Ransomware Pre-Encryption Indicators** — The execution of `vssadmin.exe delete shadows /All /Quiet` provides a critical detection opportunity before encryption occurs. Organizations should implement real-time alerting on Volume Shadow Copy deletion commands and block vssadmin[.]exe execution for standard users through application control policies.

## References

- [MITRE ATT&CK T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1574.002 - Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [Group-IB BabLock Ransomware Analysis](hxxps://www.group-ib[.]com/blog/bablock-ransomware/)
- [VirusTotal File Analysis Platform](https://www.virustotal.com/)
- [MaxMind GeoIP Demo](hxxps://www.maxmind[.]com/en/geoip-demo)
- [YARA Rule: MAL_Bablock_DLL_Apr23 - Valhalla](hxxps://valhalla.nextron-systems[.]com/info/rule/MAL_Bablock_DLL_Apr23)
- [FIN7 Threat Group Profile - MITRE ATT&CK](https://attack.mitre.org/groups/G0046/)
- [KC7 Cyber Platform](hxxps://kc7cyber[.]com/)

---

*Author: David Brown | Platform: KC7 Cyber | Date: 2026-05-15*
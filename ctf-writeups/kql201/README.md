# Kql201

A KQL (Kusto Query Language) training challenge covering intermediate techniques for security log analysis, aggregation, data transformation, and threat hunting.

![Difficulty](hxxps://img.shields[.]io/badge/Difficulty-Beginner-green?style=flat-square) ![Platform](hxxps://img.shields[.]io/badge/Platform-KC7-blue?style=flat-square) ![Category](hxxps://img.shields[.]io/badge/Category-DFIR%20%7C%20Log%20Analysis-purple?style=flat-square)

---

## Challenge Overview

| **Attribute**       | **Detail**                                                                 |
|---------------------|---------------------------------------------------------------------------|
| **Challenge Name**  | Kql201                                                                    |
| **Author**          | David Brown                                                               |
| **Platform**        | KC7                                                                       |
| **Category**        | DFIR / Log Analysis                                                       |
| **Difficulty**      | Beginner                                                                  |
| **Tools Used**      | Azure Data Explorer (KQL), KC7 Training Platform                          |
| **Target/Box**      | kc7001.eastus (JoJosHospital, TitanShield, OwlRecords)                   |

**Scenario:**

This is an intermediate KQL training course focused on analyzing security events in a healthcare environment. Participants investigate authentication logs, email activity, file creation events, and process execution to identify suspicious patterns including password spray attacks, phishing campaigns, and off-hours access. The challenge teaches time-based filtering, aggregation functions, data transformation, and advanced query operators essential for security operations and threat hunting.

---

## Attack Timeline

| **Date/Time**            | **Event**                                                                 |
|--------------------------|---------------------------------------------------------------------------|
| 2024-05-01 07:31:56 AM   | First observed docs[.]google[.]com link sent by raul_wilson[@]jojoshospital[.]org |
| 2024-05-01 – 2024-05-07  | 2,050 unique passwords used in failed login attempts across environment   |
| 2024-05-01 – 2024-05-07  | Password hash `1623d9ed4415a2715b958c45bd634969` used 4 times in failed logins |
| 2024-05-12 2:00:00 PM    | Spike of 105 failed login attempts in single hour (peak activity)         |
| 2024-06-01 – 2024-06-07  | 2,259 failed login attempts recorded during first week of June            |
| 2024-06-17 2:49:30 PM    | Encrypted files (`.encrypted` extension) first observed on ENRQ-LAPTOP    |
| 2024-06-19               | Cumulative 17,884 failed login attempts recorded by end of investigation  |

---

## Solution Walkthrough

### Step 1 — Enumerate Distinct Process Names

**Objective:** Count unique process names executing on the system to baseline normal activity.

```kql
ProcessEvents
| summarize process_events = count() by process_name
```

**Key findings:**
- **Answer:** 98 distinct process names
- **Top processes:** runtimebroker[.]exe (2,520 events), searchhost[.]exe (1,402), services[.]exe (1,340)

// Result: 98 unique process names identified across all process execution events

---

### Step 2 — Identify Password Spray Activity (Failed Logins)

**Objective:** Detect source IPs attempting to authenticate to multiple accounts (password spray indicator).

```kql
AuthenticationEvents
| where result == "Failed Login"
| summarize unique_accounts = dcount(username) by src_ip
| where unique_accounts > 1
```

**Key findings:**
- **Source IPs with spray behavior:** 6 IPs total
- **Top offender:** 10[.]10[.]0[.]2 (21 unique accounts targeted)
- **Attack pattern:** Multiple IPs targeting 18-21 unique accounts each

// Result: 6 IP addresses exhibited password spray behavior (>1 account targeted)

---

### Step 3 — Analyze Successful Multi-Account Logins

**Objective:** Identify IPs that successfully authenticated to multiple accounts (potential credential reuse).

```kql
AuthenticationEvents
| where result == "Successful Login"
| summarize unique_accounts = dcount(username) by src_ip
| where unique_accounts > 1
```

**Key findings:**
- **Most suspicious IP:** 10[.]10[.]0[.]75 (23 successful logins to unique accounts)
- **Runner-up IPs:** 10[.]10[.]0[.]2 and 10[.]10[.]0[.]42 (21 accounts each)

// Result: 10.10.0.75 successfully logged into the most unique accounts (23 total)

---

### Step 4 — Count Unique Passwords in Failed Logins (May 1-7, 2024)

**Objective:** Determine the breadth of password spray campaign.

```kql
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize count() by password_hash
```

**Key findings:**
- **Total unique passwords:** 2,050
- **Most common password hash:** `1623d9ed4415a2715b958c45bd634969` (used 4 times)

// Result: 2,050 distinct passwords attempted during May 1-7 timeframe

---

### Step 5 — Identify Targeted Host (48NM-LAPTOP)

**Objective:** Analyze failed logins against specific hostname to detect targeted attacks.

```kql
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where hostname == "48NM-LAPTOP"
| where result == "Failed Login"
| summarize count() by password_hash
```

**Key findings:**
- **Hostname:** 48NM-LAPTOP
- **Unique passwords attempted:** 2
- **Password hashes:** `1bb9a35daa6aa0ab824e85702a222dba`, `436b0eec37df52c760c6b3730ba4019c`

// Result: 2 unique passwords used against 48NM-LAPTOP during investigation period

---

### Step 6 — Find Commonly Used Passwords (>=10 Attempts)

**Objective:** Identify passwords used repeatedly in brute force attempts.

```kql
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize count() by password_hash
| where count_ >= 10
| sort by count_ desc
```

**Key findings:**
- **Passwords used 10+ times:** 5 total
- **Most common:** `f85e4614d9bd4f19ad00eb6a6a5a0a15` (15 attempts)
- **Detection value:** Indicates automated password spraying

// Result: 5 passwords were reused 10 or more times (indicator of automated attack)

---

### Step 7 — Identify One-Time Passwords (Anomaly Detection)

**Objective:** Count passwords attempted only once to gauge attack sophistication.

```kql
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize count() by password_hash
| where count_ == 1
| sort by count_ desc
```

**Key findings:**
- **Single-use passwords:** 2,018
- **Conclusion:** No password spray detected (attack pattern would show few passwords against many accounts)

// Result: 2,018 passwords used only once; pattern does not match password spray signature

---

### Step 8 — Validate Password Spray Detection

**Objective:** Confirm whether passwords are being reused across multiple accounts.

```kql
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize unique_accounts = dcount(username) by password_hash
| sort by unique_accounts desc
| where unique_accounts > 10
```

**Key findings:**
- **Passwords used against >10 accounts:** 0
- **Verdict:** No password spray attack confirmed

// Result: 0 passwords targeted more than 10 accounts; investigation confirms no spray attack

---

### Step 9 — Analyze Email Sender Activity

**Objective:** Identify users sending the most emails to detect potential phishing campaigns.

```kql
Email
| summarize
    total_emails_sent = count(),
    unique_recipiants = dcount(recipient)
by sender
| sort by total_emails_sent desc
| take 6
```

**Key findings:**
- **Sixth-highest sender:** jamie_baydal[@]jojoshospital[.]org (42 emails to 42 unique recipients)
- **Pattern:** High email volume with nearly 1:1 sender-to-recipient ratio (potential mass mailing)

// Result: jamie_baydal[@]jojoshospital[.]org sent the sixth-most emails (42 total)

---

### Step 10 — Timeline Analysis of Malicious Links

**Objective:** Determine when suspicious links were first distributed.

```kql
Email
| where link has "docs.google.com"
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by sender
```

**Key findings:**
- **Sender:** raul_wilson[@]jojoshospital[.]org
- **First observed:** 2024-05-01 07:31:56 AM
- **Last observed:** 2024-05-29 01:24:34 PM

// Result: First docs.google.com link sent at 2024-05-01 07:31:56 by raul_wilson

---

### Step 11 — Detect Ransomware Activity (Encrypted Files)

**Objective:** Identify file encryption events indicating ransomware.

```kql
FileCreationEvents
| where hostname == "ENRQ-LAPTOP"
| where filename contains ".encrypted"
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by filename
```

**Key findings:**
- **Hostname:** ENRQ-LAPTOP
- **Username:** caross
- **First encrypted file:** 2024-06-17 2:49:30 PM
- **Hash:** 2c44c24535c7f55b7248ddbaa2a0c7828bb5

// Result: Encrypted files first appeared on ENRQ-LAPTOP at 2024-06-17 14:49:30

---

### Step 12 — Investigate Malicious Tool Downloads

**Objective:** Identify tools downloaded from malicious domains.

```kql
OutboundNetworkEvents
| where url has "nothing-to-see-here.net"
| summarize make_set(url) by src_ip
```

**Key findings:**
- **Tool downloaded:** advanced-ip-scanner[.]exe
- **Malicious domain:** nothing-to-see-here[.]net
- **Redirect chain:** freerainsigkanes[.]net → raisinkanes[.]com → nothing-to-see-here[.]net
- **Affected IPs:** 14 internal hosts (10[.]10[.]0[.]0/24 and 10[.]10[.]1[.]0/24)

// Result: 14 internal IPs downloaded tools from nothing-to-see-here[.]net via redirect chain

---

### Step 13 — Detect Off-Hours Authentication

**Objective:** Find suspicious logins outside normal business hours (before 6 AM or after 6 PM).

```kql
AuthenticationEvents
| extend hour = hourofday(timestamp)
| where hour < 6 or hour >= 18
| count
```

**Key findings:**
- **Off-hours logins:** 3 events
- **Risk indicator:** Authentication activity outside business hours

// Result: 3 authentication events occurred during off-hours (before 6 AM or after 6 PM)

---

### Step 14 — Enumerate External Email Domains

**Objective:** Identify email senders from domains outside the organization.

```kql
Email
| extend sender_domain = tostring(split(sender, "@")[-1])
| where sender_domain !in ("jojoshospital.org", "kentuckypharmasupply.com")
| distinct sender_domain
```

**Key findings:**
- **External domains:** 10 total
- **Notable domains:** gmail[.]com, yahoo[.]com, protonmail[.]com, yandex[.]com
- **Risk:** Free email providers and privacy-focused services (protonmail)

// Result: 10 unique sender domains observed outside whitelisted organizations

---

### Step 15 — Hunt for Suspicious Process Commands

**Objective:** Detect potentially malicious process execution using command-line analysis.

```kql
ProcessEvents
| where process_commandline has_any ("regedit", "spotify", "cobaltstrike")
```

**Key findings:**
- **Total matches:** 6,020 processes
- **Suspicious indicator:** "cobaltstrike" mentioned (adversary simulation tool)
- **Parent processes:** explorer[.]exe, cmd[.]exe, powershell[.]exe, sc[.]exe

// Result: 6,020 processes contained regedit, spotify, or cobaltstrike in command line

---

### Step 16 — Identify Accounts with Multiple Login IPs (Lateral Movement)

**Objective:** Detect accounts logging in from more than 5 unique IPs (credential theft indicator).

```kql
AuthenticationEvents
| where result == "Successful Login"
| summarize
    ip_list = make_set(src_ip),
    unique_ip_count = dcount(src_ip)
by username
| where unique_ip_count > 5
```

**Key findings:**
- **Suspicious accounts:** 15 total
- **Local admin accounts affected:** physassi_local_admin, nursprac_local_admin, regidoct_local_admin, volu_local_admin
- **IP count per account:** 6 unique IPs
- **Common IPs:** 10[.]10[.]0[.]1, 10[.]10[.]0[.]2, 10[.]10[.]0[.]10, 10[.]10[.]0[.]34, 10[.]10[.]0[.]42, 10[.]10[.]0[.]75

// Result: 15 accounts logged in from more than 5 unique IPs (lateral movement indicator)

---

## IOC Table

| **Type**        | **Indicator**                                      | **Context**                                      | **Threat Actor** |
|-----------------|---------------------------------------------------|--------------------------------------------------|------------------|
| IP Address      | 10[.]10[.]0[.]75                                   | Most successful multi-account logins (23 accounts) | Unknown          |
| IP Address      | 10[.]10[.]0[.]2                                    | Password spray attempts (21 unique accounts)      | Unknown          |
| IP Address      | 10[.]10[.]0[.]42                                   | Failed/successful logins to 21 accounts           | Unknown          |
| Domain          | nothing-to-see-here[.]net                         | Malicious tool hosting (advanced-ip-scanner[.]exe) | Unknown          |
| Domain          | freerainsigkanes[.]net                            | Redirect domain used in watering hole attack      | Unknown          |
| Domain          | raisinkanes[.]com                                 | Typosquatting/redirect domain                     | Unknown          |
| File Hash (SHA256) | 2c44c24535c7f55b7248ddbaa2a0c7828bb5          | Encrypted file on ENRQ-LAPTOP (ransomware)       | Unknown          |
| Password Hash   | 1623d9ed4415a2715b958c45bd634969                 | Most common failed login password (4 attempts)    | Unknown          |
| Password Hash   | f85e4614d9bd4f19ad00eb6a6a5a0a15                 | Password used 15 times in spray attempts          | Unknown          |
| Hostname        | ENRQ-LAPTOP                                       | Ransomware encryption victim                      | Unknown          |
| Hostname        | 48NM-LAPTOP                                       | Targeted in password spray (2 passwords)          | Unknown          |
| Email           | raul_wilson[@]jojoshospital[.]org                 | First to send docs[.]google[.]com phishing link  | Unknown          |
| Email           | jamie_baydal[@]jojoshospital[.]org                | Sixth-highest email volume (42 emails)            | Unknown          |
| Process         | advanced-ip-scanner[.]exe                           | Reconnaissance tool downloaded from malicious domain | Unknown       |
| Process         | cobaltstrike                                      | Adversary simulation tool detected in command lines | Unknown        |

---

## MITRE ATT&CK Mapping

| **Tactic**              | **Technique ID** | **Technique Name**                     | **Evidence from Investigation**                                      |
|-------------------------|------------------|----------------------------------------|----------------------------------------------------------------------|
| Reconnaissance          | T1595.002        | Active Scanning: Vulnerability Scanning| advanced-ip-scanner[.]exe downloaded from nothing-to-see-here[.]net   |
| Initial Access          | T1566.001        | Phishing: Spearphishing Attachment     | 273 emails with .docx links sent; docs[.]google[.]com links distributed |
| Credential Access       | T1110.003        | Brute Force: Password Spraying         | 2,050 unique passwords attempted; 6 IPs targeting 18-21 accounts each |
| Defense Evasion         | T1070.006        | Indicator Removal: Timestomp           | Timeline analysis revealed off-hours activity (3 events)             |
| Lateral Movement        | T1021            | Remote Services                        | 15 accounts logged in from >5 unique IPs; admin accounts compromised |
| Impact                  | T1486            | Data Encrypted for Impact              | .encrypted files created on ENRQ-LAPTOP starting 2024-06-17 14:49:30 |

---

## Tools Used

- **Azure Data Explorer (KQL)** — Primary query language for log analysis, filtering, aggregation, and threat hunting across authentication, email, file, and process events
- **KC7 Training Platform** — Interactive cybersecurity training environment simulating real-world SOC investigations in healthcare sector

---

## Key Takeaways

1. **Time-based filtering is critical** — Using `datetime()`, `between`, `ago()`, and `bin()` functions enables precise timeline reconstruction and identification of attack windows (e.g., off-hours activity, hourly spikes).

2. **Aggregation reveals attack patterns** — Functions like `count()`, `dcount()`, `min()`, `max()`, and `make_set()` transform raw logs into actionable intelligence, distinguishing password spray attacks from normal failed logins.

3. **Data transformation enhances detection** — The `project` and `extend` operators enable field extraction (e.g., sender domains, hour-of-day) and conditional logic (`iff()`, `case()`) for risk scoring.

4. **Advanced filtering improves efficiency** — Operators like `startswith`, `endswith`, `in`, `!in`, and `has_any` reduce query complexity and enable hunting for IOCs, suspicious commands, and malicious domains.

5. **Multi-source correlation is essential** — Cross-referencing AuthenticationEvents, Email, FileCreationEvents, and ProcessEvents reveals full attack chains (phishing → credential theft → lateral movement → ransomware).

6. **Behavioral baselines detect anomalies** — Identifying accounts with >5 login IPs, emails with 1:1 sender-recipient ratios, and processes with suspicious command-line arguments uncovers deviations from normal activity.

---

## References

- [MITRE ATT&CK T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [Azure Data Explorer (Kusto) Query Language Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [KC7 Cybersecurity Training Platform](hxxps://kc7cyber[.]com/)

---

*Author: David Brown | Platform: KC7 | Date: 2024*
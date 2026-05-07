# Crosstalk CTF Writeup
A digital forensics and incident response (DFIR) analysis focusing on persistence mechanisms and suspicious file activity.

![Difficulty](https://img.shields.io/badge/Difficulty-[FILL%20IN]-blue)
![Category](https://img.shields.io/badge/Category-DFIR-red)
![Platform](https://img.shields.io/badge/Platform-[FILL%20IN]-orange)

## Challenge Details

| Detail | Value |
| :--- | :--- |
| **Challenge Name** | Crosstalk |
| **Author** | David Brown |
| **Category** | Digital Forensics / Incident Response |
| **Points** | [FILL IN] |
| **Difficulty** | [FILL IN] |

## Solution Walkthrough

### 1. Initial Evidence Triage
The investigation began with the analysis of system logs and file creation events on the host `sys1-dept`. Reviewing the event logs revealed suspicious file activity within a user's directory.

Two compressed archives were identified as being created in rapid succession:
*   `C:\Users\5y51-D3p7\Documents\export_stage.zip` (Created: 2025-12-03, 6:27:10 AM UTC)
*   `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip` (Created: 2025-12-03, 7:26:03 AM UTC)

The naming convention suggests a staging process, likely used for data exfiltration or the delivery of malicious payloads.

### 2. Persistence Analysis
Further inspection of command-line execution logs revealed an attempt to establish persistence on the system. A scheduled task was created using `schtasks.exe` to ensure the execution of a PowerShell script on a recurring basis.

**Command identified:**
```cmd
"schtasks.exe" /Create /SC DAILY /TN BonusReviewAssist /TR "powershell.exe [FILL IN]"
```

**Analysis of the command:**
*   `/SC DAILY`: Sets the schedule to run every day.
*   `/TN BonusReviewAssist`: Names the task "BonusReviewAssist" to blend in with legitimate business processes (Masquerading).
*   `/TR "powershell.exe..."`: Specifies the task run action, invoking PowerShell to execute a payload.

### 3. Timeline Correlation
By correlating the file creation events with the command execution logs, the following timeline was established:

| Timestamp (UTC) | Event | Detail |
| :--- | :--- | :--- |
| 2025-12-03 06:27:10 | File Created | `export_stage.zip` dropped in Documents folder. |
| 2025-12-03 07:26:00 | Command Executed | Persistence established via `BonusReviewAssist` scheduled task. |
| 2025-12-03 07:26:03 | File Created | `Q4Candidate_Pack.zip` dropped in Documents folder. |

## Tools Used

*   **Log Analysis Tool:** [FILL IN] (e.g., Event Viewer, ELK Stack, or Splunk)
*   **Timeline Analysis:** Manual correlation of UTC timestamps.

## Key Takeaways

*   **Persistence via Scheduled Tasks:** The use of `schtasks.exe` is a common technique (MITRE ATT&CK T1053.005) used by adversaries to maintain access across reboots.
*   **Masquerading:** Naming malicious tasks with business-centric terms (e.g., "BonusReviewAssist") is a tactic used to evade detection by system administrators during manual audits.
*   **Staging Indicators:** The creation of multiple `.zip` files in user directories often indicates the staging phase of an attack, where data is collected and compressed before being exfiltrated from the network.
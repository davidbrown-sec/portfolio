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
| **Points** | [FILL IN] |

---

## Scenario

This challenge investigates a supply chain compromise affecting Industrial Control Systems (ICS) infrastructure. The scenario involves analyzing how adversaries leveraged third-party vendor relationships to gain unauthorized access to critical industrial systems, following the MITRE ATT&CK for ICS framework.

**Investigation Objectives:**
- Identify compromised supply chain components
- Trace lateral movement into ICS networks
- Determine impact on operational technology (OT) systems
- Document indicators of compromise (IOCs)

---

## Solution Walkthrough

### 1. Initial Reconnaissance

[FILL IN: Initial steps taken to understand the scope of the supply chain compromise]

```bash
# Example initial enumeration commands
[FILL IN]
```

### 2. Supply Chain Analysis

Investigation of the third-party vendor infrastructure and trust relationships.

```bash
# Identify vendor connections and trust boundaries
[FILL IN]
```

**Key Findings:**
- [FILL IN: Compromised vendor components]
- [FILL IN: Attack vector details]
- [FILL IN: Initial access method]

### 3. ICS Network Enumeration

Mapping the industrial control system environment and identifying affected components.

```bash
# ICS protocol analysis
[FILL IN]
```

**Critical Assets Identified:**
- [FILL IN: PLCs, RTUs, HMIs, or other ICS devices]
- [FILL IN: Industrial protocols in use]
- [FILL IN: Network segmentation details]

### 4. Lateral Movement Tracking

Analyzing how the attacker moved from IT infrastructure into OT networks.

```python
# Example log analysis script
[FILL IN]
```

**MITRE ATT&CK for ICS Techniques Observed:**
- [FILL IN: T0XXX - Technique name]
- [FILL IN: T0XXX - Technique name]
- [FILL IN: T0XXX - Technique name]

### 5. Impact Assessment

Determining the operational impact on industrial processes.

```bash
# Assess system modifications or control changes
[FILL IN]
```

**Compromise Indicators:**
- [FILL IN: Unauthorized configuration changes]
- [FILL IN: Abnormal process behavior]
- [FILL IN: Safety system impacts]

### 6. Flag Capture

[FILL IN: Final steps to retrieve the flag]

```bash
# Flag retrieval
[FILL IN]
```

**Flag:** `[FILL IN]`

---

## Tools Used

- **[FILL IN]** - Network traffic analysis
- **[FILL IN]** - ICS protocol decoder
- **[FILL IN]** - Log analysis and correlation
- **[FILL IN]** - SCADA/ICS enumeration tool
- **Wireshark** - Packet capture analysis (if applicable)
- **nmap** with NSE scripts - ICS service detection (if applicable)

---

## Technical Analysis

### Supply Chain Attack Vector

The compromise followed a classic supply chain attack pattern:

1. **Initial Compromise:** [FILL IN: How the vendor was compromised]
2. **Trust Exploitation:** [FILL IN: How trust relationships were abused]
3. **Persistence Mechanism:** [FILL IN: How access was maintained]
4. **ICS Infiltration:** [FILL IN: How OT networks were accessed]

### Network Architecture

```
[FILL IN: Network diagram or description showing:]
- IT/OT boundary
- Compromised vendor systems
- Affected ICS components
- Attack path
```

### Indicators of Compromise (IOCs)

**Network Indicators:**
- [FILL IN: Malicious IP addresses]
- [FILL IN: Suspicious domains]
- [FILL IN: Anomalous network traffic patterns]

**File Indicators:**
- [FILL IN: Malicious file hashes]
- [FILL IN: Modified configuration files]

**Behavioral Indicators:**
- [FILL IN: Unusual process execution]
- [FILL IN: Abnormal authentication patterns]

---

## Defensive Recommendations

Based on this investigation, the following security controls should be implemented:

### Supply Chain Security
1. **Vendor Risk Management:** Implement third-party security assessments and continuous monitoring
2. **Trust Boundaries:** Enforce strict network segmentation between vendor access and critical ICS zones
3. **Multi-Factor Authentication:** Require MFA for all vendor remote access

### ICS-Specific Controls
1. **Network Segmentation:** Deploy defense-in-depth architecture separating IT and OT networks
2. **Protocol Monitoring:** Implement ICS protocol anomaly detection (Modbus, DNP3, etc.)
3. **Asset Inventory:** Maintain comprehensive inventory of all ICS devices and firmware versions
4. **Change Management:** Enforce strict change control for ICS configurations

### Detection and Response
1. **Behavioral Analytics:** Monitor for anomalous ICS commands and process deviations
2. **Log Aggregation:** Centralize logs from IT, OT, and vendor access points
3. **Incident Response:** Develop ICS-specific incident response procedures

---

## References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [NIST SP 800-82 Rev. 3: Guide to Operational Technology (OT) Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [ICS-CERT Recommended Practices](https://www.cisa.gov/uscert/ics/recommended-practices)
- [CISA Supply Chain Risk Management Guidelines](https://www.cisa.gov/supply-chain)

---

## Key Takeaways

1. **Supply Chain as Attack Surface:** Third-party vendors with privileged access represent significant risk to critical infrastructure, requiring robust vendor risk management programs.

2. **IT/OT Convergence Risks:** The blending of information technology and operational technology networks creates new attack paths that must be carefully managed through segmentation and monitoring.

3. **ICS Protocol Awareness:** Understanding industrial protocols (Modbus, DNP3, OPC, etc.) is essential for detecting anomalous behavior in OT environments.

4. **Defense in Depth for ICS:** Multiple layers of security controls are necessary, including network segmentation, protocol whitelisting, and anomaly detection specific to industrial processes.

5. **Trust Verification:** "Trust but verify" is insufficient for ICS environments—continuous validation of vendor access and activities is critical for operational security.

6. **Incident Response Planning:** ICS incidents require specialized response procedures that balance cybersecurity with safety and operational continuity considerations.

---

**Author's Note:** This challenge effectively demonstrates the complexities of securing industrial control systems against supply chain attacks, highlighting the importance of understanding both cybersecurity principles and operational technology architectures.

---

*Challenge Author: David Brown*  
*Writeup Date: [FILL IN]*  
*Contact: [FILL IN]*
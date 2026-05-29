# Domain Controller - condef.local

![Platform](hxxps://img.shields[.]io/badge/platform-Windows%20Server%202019-0078D6?logo=windows&logoColor=white)
![Environment](hxxps://img.shields[.]io/badge/environment-Proxmox-E57000?logo=proxmox&logoColor=white)
![Category](hxxps://img.shields[.]io/badge/category-Active%20Directory-4B275F)
![Status](hxxps://img.shields[.]io/badge/status-Production%20Ready-success)

A virtualized Windows Server 2019 Domain Controller serving as the primary authentication and directory services infrastructure for the `condef.local` lab environment. Configured with Active Directory Domain Services (AD DS), DNS, and Global Catalog services for comprehensive testing of Windows domain security scenarios.

---

## What It Does

This Domain Controller provides centralized identity management and authentication services for a security testing lab environment. It serves as the authoritative source for:

- **Active Directory Domain Services**: User, computer, and group object management for the `condef.local` domain
- **DNS Services**: Name resolution and service location records for domain-joined systems
- **Global Catalog**: Cross-domain object searches and universal group membership information
- **Kerberos Authentication**: Secure ticket-granting services for domain resources
- **Group Policy Management**: Centralized configuration enforcement across domain members

**Primary Use Cases:**
- Red team attack simulation (Kerberos attacks, LDAP exploitation, credential harvesting)
- Blue team detection engineering (Windows event log analysis, AD security monitoring)
- Security tool validation (BloodHound, Mimikatz, Impacket testing)
- Enterprise environment replication for security research

---

## Installation

### Infrastructure Specifications

| Component | Value |
|-----------|-------|
| **Hypervisor** | Proxmox VE (pve2) |
| **VM ID** | 103 |
| **Operating System** | Windows Server 2019 |
| **IP Address** | 192.168.1.50 |
| **Domain** | condef.local |
| **NetBIOS Name** | CONDEF |
| **Forest Functional Level** | Windows Server 2016 |
| **Domain Functional Level** | Windows Server 2016 |

### Prerequisites

- Proxmox Virtual Environment 7.x or higher
- VirtIO drivers for Windows (for optimized disk and network I/O)
- Network configuration with static IP addressing on 192.168.1.0/24 subnet
- Windows Server 2019 Standard/Datacenter ISO

### Deployment Steps

```powershell
# 1. Install AD DS Role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 2. Promote server to Domain Controller
Install-ADDSForest `
    -DomainName "condef.local" `
    -DomainNetbiosName "CONDEF" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString -String '[DSRM_PASSWORD]' -AsPlainText -Force) `
    -Force:$true

# 3. Verify installation
Get-ADDomain
Get-ADForest
Get-DnsServerZone
```

### Post-Installation Configuration

```powershell
# Configure DNS forwarders (example)
Add-DnsServerForwarder -IPAddress "8.8.8.8"
Add-DnsServerForwarder -IPAddress "8.8.4.4"

# Enable Active Directory Recycle Bin
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
    -Scope ForestOrConfigurationSet `
    -Target 'condef.local'

# Configure time synchronization (critical for Kerberos)
w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:YES /update
Restart-Service w32time
```

---

## Usage Examples

### Common Administrative Tasks

```powershell
# Create organizational units
New-ADOrganizationalUnit -Name "Lab Users" -Path "DC=condef,DC=local"
New-ADOrganizationalUnit -Name "Lab Computers" -Path "DC=condef,DC=local"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=condef,DC=local"

# Create test user account
New-ADUser -Name "Test User" `
    -SamAccountName "tuser" `
    -UserPrincipalName "tuser@condef.local" `
    -Path "OU=Lab Users,DC=condef,DC=local" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true

# Create security group
New-ADGroup -Name "Security Analysts" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Lab Users,DC=condef,DC=local"

# Add user to group
Add-ADGroupMember -Identity "Security Analysts" -Members "tuser"
```

### Security Testing Setup

```powershell
# Create vulnerable service account (for Kerberoasting testing)
New-ADUser -Name "SQL Service" `
    -SamAccountName "svc_sql" `
    -UserPrincipalName "svc_sql@condef.local" `
    -Path "OU=Service Accounts,DC=condef,DC=local" `
    -AccountPassword (ConvertTo-SecureString "MyS3rv1ceP@ss!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

# Register SPN (creates Kerberoasting target)
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/sql.condef.local:1433"}

# Configure user with constrained delegation (for testing privilege escalation)
Set-ADUser -Identity "tuser" -Add @{'msDS-AllowedToDelegateTo'="CIFS/fileserver.condef.local"}
```

### Monitoring and Logging

```powershell
# Enable advanced auditing for security research
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable

# Query recent Kerberos ticket requests (Event ID 4769)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 50 | 
    Select-Object TimeCreated, Message | 
    Format-List

# Export AD structure for BloodHound analysis
# (Requires SharpHound from domain-joined system)
```

### Snapshot Management

```bash
# From Proxmox host (pve2)
# Create pre-testing snapshot
qm snapshot 103 pre_test_$(date +%Y%m%d_%H%M%S)

# List snapshots
qm listsnapshot 103

# Rollback to clean state
qm rollback 103 [SNAPSHOT_NAME]
```

---

## Key Options Table

### Active Directory Configuration

| Parameter | Value | Purpose |
|-----------|-------|---------|
| **Domain FQDN** | condef.local | Full domain name |
| **NetBIOS Name** | CONDEF | Legacy domain identifier |
| **Forest Functional Level** | Windows Server 2016 | Enables modern AD features |
| **Domain Functional Level** | Windows Server 2016 | Controls available domain features |
| **DSRM Password** | [CONFIGURED] | Directory Services Restore Mode recovery |
| **Global Catalog** | Enabled | Supports cross-domain queries |

### Network Configuration

| Parameter | Value | Purpose |
|-----------|-------|---------|
| **IP Address** | 192.168.1.50 | Static IPv4 address |
| **Subnet Mask** | 255.255[.]255[.]0 | /24 network |
| **DNS Server** | 192.168.1.50 (self) | Points to local DNS service |
| **Default Gateway** | [FILL IN] | Network egress point |

### Service Roles

| Service | Status | Port(s) | Purpose |
|---------|--------|---------|---------|
| **Active Directory DS** | Running | 389 (LDAP), 636 (LDAPS), 3268 (GC) | Directory services |
| **DNS** | Running | 53 | Name resolution |
| **Kerberos KDC** | Running | 88 | Authentication |
| **SMB** | Running | 445 | File sharing / SYSVOL |
| **RPC** | Running | 135 + dynamic | Remote management |

---

## Real-World Use Cases

### 1. **Kerberos Attack Simulation**
Test detection and prevention of Kerberoasting, AS-REP roasting, and Golden/Silver ticket attacks against a controlled domain environment.

```powershell
# Blue Team: Monitor for Kerberoasting attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | 
    Where-Object {$_.Properties[8].Value -eq '0x17'} |  # RC4 encryption
    Select-Object @{Name='User';Expression={$_.Properties[0].Value}},
                  @{Name='Service';Expression={$_.Properties[1].Value}},
                  TimeCreated
```

### 2. **LDAP Enumeration Detection**
Validate SIEM rules for detecting reconnaissance tools like BloodHound, ADRecon, or SharpHound.

```powershell
# Blue Team: Audit unusual LDAP queries
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} -MaxEvents 1000 | 
    Group-Object {$_.Properties[1].Value} |  # Group by account
    Where-Object Count -gt 50 |
    Sort-Object Count -Descending
```

### 3. **Privilege Escalation Lab**
Create intentionally vulnerable configurations to practice detection of DCSync, DCShadow, and delegation abuse.

```powershell
# Red Team: Test DCSync capability (requires DA privileges)
# Using Mimikatz syntax:
# lsadump::dcsync /domain:condef.local /user:Administrator

# Blue Team: Alert on replication requests from non-DC systems
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} | 
    Where-Object {$_.Message -like "*Replicating Directory Changes*"}
```

### 4. **Group Policy Attack Testing**
Test immediate scheduled task deployment via GPO (T1484.001) and detection mechanisms.

```powershell
# Red Team: Create malicious GPO (simulated)
New-GPO -Name "Malicious Update" | 
    New-GPLink -Target "OU=Lab Computers,DC=condef,DC=local"

# Blue Team: Monitor GPO modifications
Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 100
```

### 5. **Snapshot-Based Forensics Training**
Use clean snapshots to teach investigators AD attack artifact analysis without impacting production systems.

```bash
# Workflow:
# 1. Take clean snapshot
# 2. Execute simulated attack
# 3. Capture forensic evidence
# 4. Rollback to clean state
# 5. Repeat with different attack vector
```

---

## Key Takeaways

✅ **Purpose-Built Testing Environment** — Isolated domain controller optimized for security research without production impact

✅ **MITRE ATT&CK Coverage** — Supports testing of techniques including T1558 (Steal/Forge Kerberos Tickets), T1003 (OS Credential Dumping), T1484 (Domain Policy Modification), and T1087 (Account Discovery)

✅ **Snapshot Recovery** — Proxmox VM snapshots enable rapid rollback to known-good state after destructive testing

✅ **Functional Level Selection** — Windows Server 2016 level balances modern AD features with broad compatibility for legacy attack tools

✅ **Network Isolation** — Dedicated 192.168.1.0/24 lab subnet prevents accidental interaction with production networks

✅ **Logging Infrastructure** — Pre-configured auditing enables blue team detection engineering and SIEM rule validation

✅ **Service Account Targets** — Intentional creation of SPNs and constrained delegation provides Kerberoasting and privilege escalation practice opportunities

✅ **VirtIO Optimization** — Paravirtualized drivers ensure minimal performance overhead during high-volume security tool execution

⚠️ **Security Note** — This system intentionally contains vulnerable configurations. Never expose to untrusted networks or reuse passwords in production environments.

---

**Maintained by:** [FILL IN]  
**Last Updated:** [FILL IN]  
**License:** [FILL IN]
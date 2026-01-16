### SITUATION: 
It's been a week since the initial compromise. You arrive Monday morning to find ransom notes across every system. The threat actors weren't just stealing data - they were preparing for total devastation.

Your CEO needs answers:

  - How did they get to our backup infrastructure?

  - What exactly did they destroy?

  - How did the ransomware spread so fast?

  - Can we recover?

#### FLAG 1: LATERAL MOVEMENT - Remote Access
Attackers pivot to critical infrastructure to eliminate recovery options before deploying ransomware.
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ProcessCommandLine has_any ("ssh", "@")
| where AccountName !in ("system", "local service", "")
| where AccountDomain != " "
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, ProcessCreationTime

```
Result
![image alt](De1)

Question: What remote access command was executed from the compromised workstation?

```
"ssh.exe" backup-admin@10.1.0.189
```

#### FLAG 2: LATERAL MOVEMENT - Attack Source
Identifying the attack source enables network segmentation and containment.

```
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where RemoteIP == "10.1.0.189"
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessVersionInfoFileDescription, LocalIP

```
Result
![image alt](De2)

Question: What IP address initiated the connection to the backup server?

```
10.1.0.108
```

#### FLAG 3: CREDENTIAL ACCESS - Compromised Account

Administrative accounts with backup privileges provide access to critical recovery infrastructure.

```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ProcessCommandLine has_any ("ssh", "@")
| where AccountName !in ("system", "local service", "")
| where AccountDomain != " "
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, ProcessCreationTime

```
Result
![image alt](De3)

Question: What account was used to access the backup server?
```
backup-admin
```

#### FLAG 4: DISCOVERY - Directory Enumeration
File system enumeration reveals backup locations and valuable targets for destruction.

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where AccountName == "backup-admin"
| where FileName == "ls"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessCreationTime
| order by TimeGenerated asc  
```
Result
![image alt](De4)

Question: What command listed the backup directory contents?

```
ls --color=auto -la /backups/
```

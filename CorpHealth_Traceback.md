## Scenario
Your organization recently completed a phased deployment of an internal platform known as CorpHealth — a lightweight system monitoring and maintenance framework designed to: 
 
  - Track endpoint stability and performance
  - Run automated post-patch health checks
  - Collect system diagnostics during maintenance windows
  - Reduce manual workload for operations teams 

CorpHealth operates using a mix of scheduled tasks, background services, and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account.

This account was granted local administrator privileges on specific systems to: 

  - Register scheduled maintenance tasks
  - Install and remove system services
  - Write diagnostic and configuration data to protected system locations
  - Perform controlled cleanup and telemetry operations

It was designed to be used only through approved automation frameworks, not through interactive sign-ins.

### Anomalous Activity 

In mid-November, routine monitoring began surfacing unusual activity tied to a workstation in the operations environment.

At first glance, the activity appeared consistent with normal system maintenance tasks:
 health checks, scheduled runs, configuration updates, and inventory synchronization.

However, a closer review raised concerns:

  - Activity occurred outside normal maintenance windows
  - Script execution patterns deviated from approved baselines
  - Diagnostic processes were launched manually rather than through automation
  - Some actions resembled behaviors often associated with credential compromise or script misuse

Much of this activity was associated with an account that normally runs silently in the background.

### Your Role 

You are taking over as the lead analyst assigned to review historical telemetry captured by: 

  - Microsoft Defender for Endpoint
  - Azure diagnostic and device logs
  - Supporting endpoint event artifacts 

You will not have live access to the machine — only its recorded activity.

Your task is to determine: 

- What system was affected?
- When suspicious activity occurred?
- How the activity progressed across different stages?
- Whether the behavior represents authorized automation or misuse of a privileged account?

---





### Flag 0: Identify the device

Your first step is confirming which workstation generated the unusual telemetry.
Initial log clustering shows that all suspicious events originated from a single endpoint active during an off-hours window in the middle of November.  
During your initial sweep, look for a workstation that shows:

A small cluster of events during an unusual maintenance window 

Activity between Mid November to Early December.

Multiple entries with sources tied to Process Events, Network Events, File Events, and Script-based operations

Query Used
````
DeviceInfo
| where TimeGenerated  between (datetime(2025-11-15) .. datetime(2025-12-05))
| where DeviceName matches regex @"(?i)^[a-z]{2}-"
| project TimeGenerated, DeviceName, PublicIP, OSDistribution

````
Result 
![image alt](1)

Query 
````
DeviceInfo
| where TimeGenerated  between (datetime(2025-11-15) .. datetime(2025-12-05))
| where DeviceName matches regex @"(?i)^[a-z]{2}-"
| where DeviceName startswith "c"
| project TimeGenerated, DeviceName, PublicIP, OSDistribution

````
Result
![image alt](1a)

*Question: What is the compromised Device Name?*
```
ch-ops-wks02
```

#### Severity Indicators
**Severity:** 🔴 Critical
**Severity:** 🟠 Medium
**Severity:** ⚪ Low














































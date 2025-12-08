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
  












































  

  

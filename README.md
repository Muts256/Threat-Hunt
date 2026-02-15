### Introduction

This repository illustrates hands-on CTF-style threat hunting, focusing on detecting, analyzing, and responding to real-world attacker techniques. It includes hypothesis-driven hunts, log analysis, KQL queries, MITRE ATT&CK mappings, and documented findings. The goal is to demonstrate practical threat hunting skills, analytical thinking, and a structured approach to uncovering stealthy threats in modern environments.

### Threat Hunt Challenges

The Threat hunting challenges mimic real-world attacker activity and require analysts to proactively search for hidden or suspicious behaviour in systems and networks.

Technology used in the investigations:

- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
  
| Threat Hunt | Description |
|-------| ---------- |
| [Azuki Cargo Hold](https://github.com/Muts256/Threat-Hunt/blob/main/Azuki-Cargo-Hold.md) | Suspicious lateral movement |
| [Azuki Bridge Takeover](https://github.com/Muts256/Threat-Hunt/blob/main/Azuki_Bridge_Takeover.md) | Persistent backdoors and exfiltrating sensitive business data |
| [Azuki Dead in the Water](https://github.com/Muts256/Threat-Hunt/blob/main/Azuki_Dead_in_the_Water.md) | Ransomware intrusion |
| [CorpHealth Traceback](https://github.com/Muts256/Threat-Hunt/blob/main/CorpHealth_Traceback.md) | Maintenance Script Intrusion |

Navigation Tip: Each hunt title is clickable and will take you directly to the detailed investigation.

### Objective
Develop the ability to proactively detect advanced threats by analysing the system and network.

Achieved by:
  - Analysing logs, telemetry, and system artifacts.

  - Identifying abnormal patterns (e.g., beaconing, lateral movement, persistence).

  - Forming and testing hypotheses (e.g., “Is this C2 traffic?”).

  - Using tools like SIEM, EDR, packet captures, and scripts.

  - Mapping findings to MITRE ATT&CK.
  - Documenting reports.

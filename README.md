# mdr-triage-lab
# MDR Alert Triage and Auto-Resolution Lab

A home SOC lab that mirrors an MDR analyst workflow: generate attacker telemetry, detect it in Splunk, triage and escalate true positives, and auto-resolve known-benign alerts with a Trusted Behavior Registry-style allowlist.

**Result: 16 alerts triaged, 11 auto-resolved (69% noise reduction), 5 escalated. Every real attack was escalated and none were suppressed.**

## Architecture
Windows 11 VM (Sysmon + Splunk Universal Forwarder) -> Splunk Enterprise on host (index `win`) -> alerts.csv export -> Python allowlist engine -> resolved.csv / escalated.csv

## Lab setup
- VirtualBox Windows 11 VM on NAT, Sysmon with the SwiftOnSecurity config
- Splunk Universal Forwarder sending Security and Sysmon logs to Splunk Enterprise (port 9997)
- Sysmon events arrive as XML, so fields (Image, CommandLine, ParentImage, User) are extracted with `rex`
- Telemetry generated with Atomic Red Team plus simulated benign IT activity
  
<img width="1743" height="382" alt="image" src="https://github.com/user-attachments/assets/df239021-639a-44b2-bda4-35d933bc4976" />


## Detections
| ATT&CK | Detection | Logic |
|---|---|---|
| T1059.001 | Encoded PowerShell | Sysmon EventCode 1, powershell.exe with -enc or -EncodedCommand |
| T1110 | Brute force | 10 or more Windows 4625 failed logons in 5 minutes |
| T1053.005 | Scheduled task persistence | Sysmon EventCode 1, schtasks.exe with /create |

![Encoded PowerShell](screenshots/02-detection-encoded-powershell.png)
<img width="1568" height="780" alt="image" src="https://github.com/user-attachments/assets/d677cd7b-1cd6-4c0c-a7b6-6e7d907c9865" />

![Brute force](screenshots/03-detection-brute-force.png)
<img width="1568" height="387" alt="image" src="https://github.com/user-attachments/assets/f022059d-6645-47d4-a436-243be331094d" />

![Scheduled task](screenshots/04-detection-scheduled-task.png)
<img width="1568" height="771" alt="image" src="https://github.com/user-attachments/assets/7f00e894-0edd-40ca-9992-0ff1b531e70d" />

![Saved alerts](screenshots/05-saved-alerts.png)
<img width="1743" height="537" alt="image" src="https://github.com/user-attachments/assets/1623dbe7-6043-4638-b29e-b31789496677" />


## Auto-resolution (mini Trusted Behavior Registry)
`auto_resolve.py` compares each alert to `allowlist.json`. Every entry has an ID, a narrow match, and a documented reason, so it cannot suppress a real attack.

| ID | Rule | Match | Reason |
|---|---|---|---|
| TBR-001 | Encoded PowerShell | parent image inventory_agent.exe | Approved IT inventory agent |
| TBR-002 | Scheduled Task | command line BackupNightly | Approved nightly backup job |

![Auto-resolve output](screenshots/06-auto-resolve-output.png)

Validation: all Atomic Red Test activity landed in `escalated.csv`.

## Escalation reports
See the `reports/` folder: In the files

## Lessons learned
- Forwarder access to the Sysmon log needed Event Log Readers permission (errorCode=5)
- VM clock drift after a saved-state resume stopped log forwarding
- Allowlist entries must be narrow and documented, then validated against true positives

## Next steps
T1105 ingress tool transfer detection, SOAR-style playbook, Sentinel/KQL version.

## Files
alerts.csv, allowlist.json, auto_resolve.py, resolved.csv, escalated.csv

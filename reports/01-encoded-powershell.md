# Escalation Report: Encoded PowerShell Execution (T1059.001)

| Field | Detail |
|---|---|
| Severity | High |
| Verdict | True positive (simulated adversary activity, Atomic Red Team) |
| Detected | 2026-10-29 11:38 (VM local time) |
| Host / User | sanjananuguri / sanjananuguri\sanja |
| Source | Sysmon EventCode 1, Splunk detection "T1059.001 - Encoded PowerShell" |

## Summary
Two PowerShell processes ran with encoded-argument parameters, a common technique for hiding commands from casual inspection. Neither matches any approved IT activity in the allowlist, so both were escalated.

## Evidence
- Process: powershell.exe launched by powershell.exe (parent and child are both PowerShell)
- Command line 1: `-EncodedCommandParamVariation E -UseEncodedArguments`
- Command line 2: `-CommandParamVariation C -UseEncodedArguments`
- Both ran within about 8 seconds, under the same user session
- Context: five benign encoded-PowerShell runs from C:\ITTools\inventory_agent.exe in the same period were auto-resolved by TBR-001, so these two are distinguishable by parent process

## Impact
Encoded commands can hide download cradles, credential theft, or lateral movement tooling. In this lab the commands only exercised parameter handling, so no further compromise was observed.

## Recommended actions
1. Isolate the host and review the full PowerShell Operational log (Event 4104) for decoded script content.
2. Review other processes started by the same session and any outbound connections.
3. Reset the user's credentials if the decoded content is malicious.
4. Block or alert on encoded PowerShell launched by non-approved parents.

## MITRE ATT&CK
T1059.001 Command and Scripting Interpreter: PowerShell

# Escalation Report: Scheduled Task Persistence (T1053.005)

| Field | Detail |
|---|---|
| Severity | High |
| Verdict | True positive (simulated adversary activity, Atomic Red Team) |
| Detected | 2026-10-28 14:44 (VM local time) |
| Host / User | sanjananuguri / sanjananuguri\sanja |
| Source | Sysmon EventCode 1, Splunk detection "T1053.005 - Scheduled Task Persistence" |

## Summary
Two scheduled tasks were created via schtasks.exe launched from cmd.exe, set to run at system startup and at user logon. The startup task runs as SYSTEM. Neither matches an approved job in the allowlist, so both were escalated.

## Evidence
- Task 1: `schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"`
- Task 2: `schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"`
- Both created within about a second of each other, with cmd.exe as the parent
- Context: BackupNightly tasks created from PowerShell in the same environment were auto-resolved by TBR-002

## Impact
Startup and logon triggers survive reboots, giving an attacker persistent code execution, and /ru system means that code runs with the highest local privileges. Here the payload was calc.exe, a harmless stand-in.

## Recommended actions
1. Delete both tasks and confirm with `schtasks /query`.
2. Identify how the creating process was launched and review activity before 14:44.
3. Alert on schtasks /create with /ru system from non-admin tooling.
4. Review other persistence locations (Run keys, services).

## MITRE ATT&CK
T1053.005 Scheduled Task/Job: Scheduled Task

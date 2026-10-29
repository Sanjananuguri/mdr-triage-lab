# Escalation Report: Brute Force Logon Attempts (T1110)

| Field | Detail |
|---|---|
| Severity | Medium |
| Verdict | True positive (simulated adversary activity) |
| Detected | 2026-10-28, 5-minute window starting 14:40 (VM local time) |
| Host / Account | sanjananuguri / fakeadmin (non-existent account) |
| Source | Windows Security EventCode 4625, Splunk detection "T1110 - Brute Force" |

## Summary
15 failed logon attempts against a non-existent account occurred within 5 minutes, exceeding the detection threshold of 10. The pattern matches password guessing.

## Evidence
- 15 events with EventCode 4625 in one 5-minute window
- Single target account: fakeadmin
- Attempts generated with repeated `net use` requests to the local IPC$ share using incorrect passwords
- No successful logon (4624) for this account followed

## Impact
Without a successful logon, no access was gained. With a valid account name, the same pattern could lead to credential compromise.

## Recommended actions
1. Confirm no 4624 followed the failures for this account.
2. Identify the source address and block it if external.
3. Enforce account lockout and MFA on exposed services.
4. Tune the threshold if an authorized scanner is the source, and document it as an allowlist entry.

## MITRE ATT&CK
T1110 Brute Force

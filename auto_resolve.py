import csv, json
from collections import Counter

alerts = list(csv.DictReader(open("alerts.csv", encoding="utf-8-sig")))
registry = json.load(open("allowlist.json"))
resolved, escalated = [], []

for a in alerts:
    m = next((r for r in registry if r["rule"] == a["rule"] and r["contains"].lower() in a.get(r["field"], "").lower()), None)
    if m:
        a["resolution"] = f"Auto-resolved by {m['id']}: {m['reason']}"
        resolved.append(a)
    else:
        a["resolution"] = "Escalate to analyst"
        escalated.append(a)

for name, rows in (("resolved.csv", resolved), ("escalated.csv", escalated)):
    with open(name, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(alerts[0].keys()) + ["resolution"])
        w.writeheader(); w.writerows(rows)

total = len(alerts)
print(f"Total alerts: {total}")
print(f"Auto-resolved: {len(resolved)} ({len(resolved)/total:.0%} noise reduction)")
print(f"Escalated: {len(escalated)}  {dict(Counter(a['rule'] for a in escalated))}")

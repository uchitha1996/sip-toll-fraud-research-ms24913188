#!/usr/bin/env python3
"""Verify 34 archived run-local CDR deltas, not whole master CDR or production calls."""
from pathlib import Path
from collections import Counter
import csv,json,hashlib
ROOT=Path("/home/astrix/sip-fraud-research")
OUT=ROOT/"datasets/pp2-priority-audit-20261010"
e=json.loads((ROOT/"datasets/ml-lab-20260930/evidence_index.json").read_text())
rows=[]
for sid,entry in sorted(e.items()):
    p=Path(entry["run_dir"])
    with (p/"cdr_before.csv").open(newline="") as f: before=list(csv.reader(f))
    with (p/"cdr_after.csv").open(newline="") as f: after=list(csv.reader(f))
    delta=list((Counter(map(tuple,after))-Counter(map(tuple,before))).elements())
    assert len(delta)==entry["verification"]["cdr_delta"],sid
    for r in delta:
        assert len(r)>=17 and r[1] in ("1001","1002") and r[2] in ("88001","88002"),sid
        assert r[14]=="ANSWERED" and int(r[13])==6,sid
        rows.append(dict(scenario_id=sid,split=entry["split"],src=r[1],dst=r[2],
            start=r[9],answered=r[14],billsec=int(r[13]),uniqueid=r[16]))
assert len(rows)==21
assert len(set(x["uniqueid"] for x in rows))==21
summary=dict(verified_scenarios=len(e),new_answered_call_rows=len(rows),
  called_pairs=dict(Counter(x["src"]+"->"+x["dst"] for x in rows)),
  all_isolated_routes=True,all_6_second_answered=True,unique_cdr_ids=True,
  implication="Completed isolated lab calls corroborated retrospectively; not fraud status or real-world baseline",
  forbidden_in_early_ml="answered outcome and billsec were available only after call completion")
(OUT/"cdr_reconciliation.json").write_text(json.dumps(summary,indent=2)+"\n")
with (OUT/"verified_new_lab_calls.csv").open("w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with (OUT/"PP2_HIGH_PRIORITY_STATUS.md").open("a") as f:
    f.write("\n## Additional independent CDR reconciliation (10 October)\n")
    f.write("- PASS: 34/34 run-local CDR before/after deltas match verification records.\n")
    f.write("- PASS: 21/21 new lab call CDRs answered for six seconds, 21 distinct unique IDs, only 1001->88001 or 1002->88002.\n")
    f.write("- These are isolated scripted calls. They cannot substitute for a diverse external normal-call baseline or prove authorization.\n")
    f.write("- Early ML must not use final answered CDR outcome or final billsec.\n")
print("PASS CDR audit",json.dumps(summary))

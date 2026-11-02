#!/usr/bin/env python3
"""PP2 read-only audit of archived evidence; no new SIP traffic."""
from pathlib import Path
import json,csv,hashlib,datetime,collections
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"datasets"/"pp2-priority-audit-20261010"
OUT.mkdir(parents=True,exist_ok=True)
def j(p): return json.loads((ROOT/p).read_text())
def hashfile(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
    return h.hexdigest()
def metrics(records,key):
    t=collections.Counter((r["truth"],r[key]) for r in records)
    tp,fp,tn,fn=[t[k] for k in ((1,1),(0,1),(0,0),(1,0))]
    prec=tp/(tp+fp) if tp+fp else 0
    rec=tp/(tp+fn) if tp+fn else 0
    fpr=fp/(fp+tn) if fp+tn else 0
    spec=tn/(tn+fp) if tn+fp else 0
    return dict(TP=tp,FP=fp,TN=tn,FN=fn,precision=round(prec,4),
                recall=round(rec,4),FPR=round(fpr,4),
                balanced_accuracy=round((rec+spec)/2,4))
archive=j("datasets/ml-lab-20260930/evidence_index.json")
ml=j("datasets/ml-lab-20260930/heldout_results.json")
freeze=j("datasets/ml-lab-20260930/freeze_commit.json")
f=j("datasets/f-series-evaluation/20260930T094922Z/metrics.json")
causal=j("datasets/causal-ml-holdout-20261001/summary.json")
first=j("datasets/first-alert-comparison-20261002/summary.json")
dep=j("datasets/full-stage-deployment-comparison-20261002/descriptive_analysis.json")
checks=[]
for sid,e in sorted(archive.items()):
    p=Path(e["run_dir"])/"traffic.pcap"
    assert p.exists() and hashfile(p)==e["pcap_sha256"],"Capture integrity failed "+sid
    assert e["verification"]["verified"],"Verification failed "+sid
    checks.append({"id":sid,"split":e["split"],"pcap_sha256":e["pcap_sha256"],
                   "cdr_delta":e["verification"].get("cdr_delta")})
assert len(checks)==34
assert hashfile(ROOT/"datasets/ml-lab-20260930/model.joblib")==freeze["model_sha256"]
assert hashfile(ROOT/"datasets/ml-lab-20260930/freeze.json")==freeze["freeze_sha256"]
hrows=[]
for r in ml["individual"]:
    sid=r["scenario_id"];e=archive[sid]
    gt=list(csv.DictReader((Path(e["run_dir"])/"scenario_ground_truth.csv").open()))
    assert len(gt)==1 and gt[0]["label"]==r["truth"] and e["pcap_sha256"]==r["pcap_sha256"]
    hrows.append(dict(id=sid,label=r["truth"],truth=int(r["truth"]=="SIMULATED_ABUSE"),
      ML=r["ml_binary"],ML_decision=r["ml_decision"],ML_score=r["p_simulated_abuse"],
      V6_any=r["v6_any_alert"],V6_answered=r["v6_answered_stage"],
      answered_cdr=e["verification"]["cdr_delta"],stages="|".join(e["v6_stages"])))
assert len(hrows)==10
hm={k:metrics(hrows,k) for k in ["ML","V6_any","V6_answered"]}
for k,orig in [("ML","ml"),("V6_any","v6_any_stage"),("V6_answered","v6_answered_stage")]:
    for large,small in (("TP","tp"),("FP","fp"),("TN","tn"),("FN","fn")):
        assert hm[k][large]==ml[orig][small]
frows=list(csv.DictReader((ROOT/"datasets/f-series-evaluation/20260930T094922Z/scenario_results.csv").open()))
assert len(frows)==12
fm={}
for k in ("v3","v5","v6"):
    t=[{"truth":int(r["truth"]=="ATTACK"),"pred":int(r[k+"_alert"].lower()=="true")} for r in frows]
    fm[k.upper()]=metrics(t,"pred")
    for field in ("TP","FP","TN","FN"):
        assert fm[k.upper()][field]==f["binary_metrics"][k.upper()][field]
pairs=[]
for x,y in [("H003","H007"),("H004","H008")]:
    a,b=[next(r for r in hrows if r["id"]==sid) for sid in (x,y)]
    assert a["truth"]!=b["truth"] and a["ML_decision"]==b["ML_decision"] and a["V6_any"]==b["V6_any"]
    pairs.append(x+"/"+y)
cdr={g:sum(r["answered_cdr"] for r in hrows if r["label"]==g) for g in ("BENIGN","SIMULATED_ABUSE")}
assert len(dep["cases"])==7 and all(x["verified"] for x in dep["cases"])
priority=dict(collections.Counter(r["priority"] for r in causal["results"]))
comparable=[r for r in first["results"] if r.get("v3_first_alert_s") is not None and r.get("v6_first_alert_s") is not None]
cmp=dict(collections.Counter("earlier" if r["v6_first_alert_s"]<r["v3_first_alert_s"]-1e-6
    else "later" if r["v6_first_alert_s"]>r["v3_first_alert_s"]+1e-6 else "same" for r in comparable))
res={"timestamp_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "mode":"secondary offline archival re-analysis, NOT new model/holdout/traffic",
 "archive_pcap_hashes_verified":len(checks),"f_series":fm,"heldout":hm,
 "matched_opposite_intent_pairs":pairs,"cdr_answered_heldout":cdr,
 "f_first_alert_common_onset_comparisons":len(comparable),"v6_versus_v3_first_alert":cmp,
 "causal_ML_review_priorities":priority,"native_external_verified_cases":len(dep["cases"])}
(OUT/"audit_summary.json").write_text(json.dumps(res,indent=2)+"\n")
for name,rs in [("archive_integrity.csv",checks),("historical_heldout_comparison.csv",hrows)]:
    with (OUT/name).open("w",newline="") as fd:
        w=csv.DictWriter(fd,list(rs[0]));w.writeheader();w.writerows(rs)
def table(rows):
    s=["| Model | TP | FP | TN | FN | Precision | Recall | FPR | Balanced accuracy |",
       "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for k,v in rows.items():
        s.append("| "+k+" | "+" | ".join(str(v[f]) for f in
            ["TP","FP","TN","FN","precision","recall","FPR","balanced_accuracy"])+" |")
    return "\n".join(s)
report=[
"# PP2 High-Priority Research Validation",
"",
"## Audit status",
"- This is a READ-ONLY replication using previously inspected captures; not a new validation set.",
"- PASS: 34/34 archived PCAP SHA256 values match the saved evidence index.",
"- PASS: frozen retrospective ML model and freeze manifest hashes match.",
"- PASS: historical confusion matrices have been recalculated from per-case predictions.",
"- PASS: seven native/external live cases are independently marked verified in the existing archive.",
"",
"## Stage-detector development results on F01-F12",
table(fm),
"",
"## Retrospective ML comparison on previously held-out H001-H010",
table(hm),
"",
"**ML does not establish an improvement.** The ML endpoint uses retrospective CDR, while the V6 stage endpoint can alert online; the comparison is descriptive, not a matched prospective early-detection trial.",
"",
"## Research caveats and CDR",
"- Matched opposite-intent pairs with same ML decision and V6 alert outcome: "+", ".join(pairs)+".",
"- Independently verified lab CDR call counts across H scenarios: "+str(cdr)+". CDR verifies outcome, not authorization.",
"- Separate causal ML priority experiment on 10 archived cases: "+str(priority)+". Review priority is NOT fraudulent intent.",
"- Archived comparable first-alert cases V6 versus V3: "+str(cmp)+" over "+str(len(comparable))+" comparable cases. No universal earlier-detection claim.",
"",
"## Remaining high-priority experiments",
"1. Independent account/destination permission records created BEFORE new traffic; validate legitimate recovery versus simulated unauthorized action.",
"2. New legitimate multi-account NAT/proxy and mixed-session controls plus diversity probe tests.",
"3. Prospective fresh grouped sessions with frozen rules/model; evaluate the same early-time endpoint for simple baseline, stage rules, context checks and causal ML.",
"4. Larger normal CDR baseline with consent/anonymization. Never use future answered CDR as an input to an early detector.",
"5. Expand repeated native/external load and stability measurements only if time allows. The initial pilot is already complete.",
"",
"## Operational blocker",
"- SIPp generator (172.16.200.68) responds to ping, but the non-interactive SSH key for pi@172.16.200.68 is rejected; no new live tests attempted by this audit.",
"- Do not install modules, change PBX routes, dial PSTN or reuse the previously inspected heldout cases as if fresh.",
"",
"## PP2 takeaway",
"Stage-aware detection and five-stage native/external pilot work; independent attribution of unauthorized toll fraud, local ML improvement and generalized performance remain unproven.",
]
(OUT/"PP2_HIGH_PRIORITY_STATUS.md").write_text("\n".join(report)+"\n")
print("PASS: offline PP2 validation completed")
print("Archive PCAP integrity:",len(checks),"/34")
print("F-series metrics:",fm)
print("Historic heldout metrics:",hm)
print("CDR:",cdr,"Priority:",priority,"First-alert:",cmp)
print("REPORT:",OUT/"PP2_HIGH_PRIORITY_STATUS.md")

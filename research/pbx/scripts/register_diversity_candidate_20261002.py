#!/usr/bin/env python3
"""Development-only causal REGISTER target diversity; no malicious-intent decision."""
import csv,json,hashlib
from collections import defaultdict,deque
from pathlib import Path
ROOT=Path('/home/astrix/sip-fraud-research')
OUT=ROOT/'datasets/register-diversity-candidate-20261002'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def replay(path):
    queues=defaultdict(deque);seen=set();reported=set();alerts=[]
    with path.open(newline='') as f:rows=list(csv.DictReader(f))
    rows.sort(key=lambda p:float(p['frame.time_epoch']))
    for p in rows:
        if p['sip.Method']!='REGISTER' or p['ip.dst']!='172.16.200.81':continue
        target=p['sip.to.user'];source=p['ip.src'];cid=p['sip.Call-ID']
        if not source or not target or not cid:continue
        dialog=(source,cid,target)
        if dialog in seen:continue
        seen.add(dialog)
        now=float(p['frame.time_epoch']);q=queues[source]
        while q and q[0][0]<now-60:q.popleft()
        q.append((now,target))
        targets=sorted({t for _,t in q})
        if len(targets)>=5 and source not in reported:
            reported.add(source)
            alerts.append(dict(stage='REGISTER_TARGET_DIVERSITY_REVIEW',source=source,
                decisive_epoch=now,window_s=60,unique_targets=len(targets),targets=targets,
                elapsed_from_first_window_request_s=round(now-q[0][0],6),
                meaning='Many attempted REGISTER identities; not verified valid IDs or proven attack.'))
    return alerts
def main():
    assert not OUT.exists();OUT.mkdir(mode=0o700)
    inputs=list((ROOT/'datasets/register-enumeration-20261002').glob('RE*/sip_packets.csv'))
    inputs+=list((ROOT/'datasets/literature-development-20261002/development').glob('DL*/sip_packets.csv'))
    inputs+=list((ROOT/'datasets/ml-v2-development-20261002/development').glob('DV*/sip_packets.csv'))
    protocol=dict(script_sha256=sha(Path(__file__)),window_s=60,minimum_distinct_register_targets=5,
        status='Exploratory candidate after seeing development gap; not frozen prospective validation.',
        excludes='No use of scenario labels, response success, future CDRs, or existing ML scores.',
        limitation='Shared NAT/proxy sources may legitimately represent many accounts; such live benign controls pending.')
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    results=[]
    for p in sorted(inputs):
        a=replay(p);results.append(dict(case=p.parent.name,capture_fields_sha256=sha(p),alerts=a))
    (OUT/'results.json').write_text(json.dumps(dict(protocol=protocol,cases=results),indent=2)+'\n')
    print(json.dumps(dict(cases=len(results),alerts=[r for r in results if r['alerts']])),flush=True)
if __name__=='__main__':main()

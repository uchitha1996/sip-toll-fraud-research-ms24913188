#!/usr/bin/env python3
"""Predeclared literature-informed development only; preserve every old artifact."""
import csv, hashlib, json, os, sys
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path('/home/astrix/sip-fraud-research')
sys.path.insert(0,str(ROOT/'scripts'))
import lab_batch_runner as runner
import lab_process_batch as verifier
from adapt_checkpoint_events import adapt
from causal_review_score import load_model, MLProgression
BASE=ROOT/'datasets/literature-development-20261002'
MANIFEST=BASE/'manifest.json'
MODEL=ROOT/'datasets/causal-review-ml-20261001/frozen_model.json'
EXPECTED='ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def utc(): return datetime.now(timezone.utc).isoformat()
def main():
    os.umask(0o077)
    assert sha(MODEL)==EXPECTED
    assert not BASE.exists(), 'Never overwrite prior evidence'
    BASE.mkdir(mode=0o700)
    scenarios=[]
    profiles=[('slow_recovery',6,6,1,'1002','F13/F14/F18'),
              ('slow_no_success',10,6,0,'1001','F14'),
              ('paced_success',10,3,1,'1001','F13/F18'),
              ('gate_boundary',5,1,1,'1002','F13/F18')]
    for n,(profile,wrong,interval,success,account,family) in enumerate(profiles):
        for j,intent in enumerate(('AUTHORIZED','SIMULATED_ABUSE')):
            scenarios.append(dict(id=f'DL{n*2+j+1:03}',split='development',
              intent=intent,account=account,wrong=wrong,interval=interval,
              success=success,call=0,post_register_pause=0,
              profile_group=profile,session_group='literature20261002',
              proposed_family=family,
              label_basis='Experimenter-assigned role only; no credential theft. Same planned SIP stimulus across pair.'))
    manifest=dict(declared_utc=utc(),wrapper_sha256=sha(Path(__file__)),
      frozen_model_sha256=EXPECTED,
      sources=['https://doi.org/10.1007/978-3-319-60774-0_9'],
      purpose='Development variation of pacing/count/success, not new held-out accuracy.',
      limits='One generator/PBX session. Interval is a requested start spacing; actual packet timing is measured.',
      grouping='Matched profiles share group; entire session must remain together for cross-session evaluation.',
      stop_rule='First missing evidence or cleanup failure halts the batch.',
      scenarios=scenarios)
    MANIFEST.write_text(json.dumps(manifest,indent=2)+'\n')
    runner.OUT=BASE
    verifier.BASE=BASE
    verifier.MANIFEST=MANIFEST
    model=load_model(MODEL)
    summary=[]
    for row in scenarios:
        print('START',row['id'],flush=True)
        runner.run(row,sha(MANIFEST))
        verifier.process(row,execute=False)
        run=BASE/'development'/row['id']
        events=adapt(run)
        (run/'events.jsonl').write_text(''.join(json.dumps(e,sort_keys=True)+'\n' for e in events))
        engine=MLProgression(model)
        alerts=[]
        for event in events: alerts.extend(engine.accept(event))
        (run/'frozen_ml_replay.json').write_text(json.dumps(alerts,indent=2)+'\n')
        scored=[a for a in alerts if 'ml_priority' in a]
        verification=json.loads((run/'independent_verification.json').read_text())
        entry=dict(id=row['id'],intent=row['intent'],profile_group=row['profile_group'],
           session_group=row['session_group'],wrong=row['wrong'],interval=row['interval'],
           success=row['success'],verified=verification['verified'],
           v6_stages=verification['v6_stages'],eligible=bool(scored),
           score=scored[0]['ml_probability'] if scored else None,
           priority=scored[0]['ml_priority'] if scored else None,
           values=scored[0]['ml_feature_values'] if scored else None,
           pcap_sha256=verification['pcap_sha256'])
        summary.append(entry)
        (BASE/'summary.json').write_text(json.dumps(dict(status='in_progress',
           completed=len(summary),manifest_sha256=sha(MANIFEST),cases=summary),indent=2)+'\n')
        print('DONE',json.dumps(entry),flush=True)
    assert sha(MODEL)==EXPECTED
    with (BASE/'causal_features.csv').open('x',newline='') as f:
        names=['id','intent','profile_group','session_group','eligible','score','priority',
          'failures_120s','peak_failures_10s','failure_span_s','first_failure_to_success_s']
        w=csv.DictWriter(f,fieldnames=names); w.writeheader()
        for e in summary:
            d={k:e[k] for k in names[:7]}
            d.update(dict(zip(names[7:],e['values'] or ['']*4)))
            w.writerow(d)
    pairs=[]
    for i in range(0,len(summary),2):
        a,b=summary[i:i+2]
        pairs.append(dict(ids=[a['id'],b['id']],same_stages=a['v6_stages']==b['v6_stages'],
                          same_priority=a['priority']==b['priority']))
    postflight={key:runner.cmd(cmd).strip() for key,cmd in {
       'calls':['asterisk','-rx','core show channels count'],
       'route1001':['asterisk','-rx','dialplan show 88001@internal'],
       'route1002':['asterisk','-rx','dialplan show 88002@internal']}.items()}
    assert '0 active calls' in postflight['calls']
    assert all('no existence' in postflight[k] for k in ('route1001','route1002'))
    (BASE/'summary.json').write_text(json.dumps(dict(status='complete',completed=len(summary),
       finished_utc=utc(),manifest_sha256=sha(MANIFEST),wrapper_sha256=sha(Path(__file__)),
       frozen_model_sha256=EXPECTED,cases=summary,pairs=pairs,postflight=postflight,
       limitation='Live collection then offline replay. Assigned intent is unobservable in SIP; no new model or heldout result.',
       ),indent=2)+'\n')
    print('COMPLETE',len(summary),flush=True)
if __name__=='__main__': main()

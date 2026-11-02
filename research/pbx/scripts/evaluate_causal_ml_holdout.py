#!/usr/bin/env python3
"""One-time postfreeze evaluation of a new stage-time ML priority holdout."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

from adapt_checkpoint_events import adapt
from causal_review_score import MLProgression, load_model

ROOT=Path('/home/astrix/sip-fraud-research')
MANIFEST=ROOT/'datasets/causal_ml_holdout_manifest_20261001.json'
MODEL=ROOT/'datasets/causal-review-ml-20261001/frozen_model.json'
BASE=ROOT/'datasets/burst-lab-20261001/heldout'
OUT=ROOT/'datasets/causal-ml-holdout-20261001'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    plan=json.loads(MANIFEST.read_text())
    model=load_model(MODEL)
    assert sha(MODEL)==plan['frozen_model_sha256']
    assert len(plan['scenarios'])==10
    assert sum(r['intent']=='simulated_unauthorized' for r in plan['scenarios'])==5
    assert not OUT.exists()
    for row in plan['scenarios']:
        run=BASE/row['id']
        assert json.loads((run/'predeclared_protocol.json').read_text())['manifest_sha256']==sha(MANIFEST)
        check=json.loads((run/'independent_verification.json').read_text())
        assert check['verified'] and check['id']==row['id']
        status=json.loads((run/'run_status.json').read_text())
        assert sha(run/'traffic.pcap')==status['capture_sha256']
        v5=run/'v5_replay'
        assert not v5.exists()
        subprocess.run(['python3',str(ROOT/'scripts/candidate_v5_replay.py'),
                        str(run/'traffic.pcap'),str(v5),
                        '--observation-end-utc',status['end_utc']],
                       check=True,capture_output=True,text=True)
    OUT.mkdir(mode=0o700)
    results=[]
    for row in plan['scenarios']:
        run=BASE/row['id'];target=OUT/row['id'];target.mkdir(mode=0o700)
        events=adapt(run)
        for e in events:
            if e['kind']=='OUTBOUND_INVITE':
                e['destination_group']=row['destination_group'];e['trunk']=row['trunk']
        engine=MLProgression(model)
        for e in events:engine.accept(e)
        reviews=[a for a in engine.outputs if a['stage']=='SUSPECTED_COMPROMISE']
        bursts=[a for a in engine.outputs if a['stage']=='CALL_BURST']
        assert len(reviews)==len(bursts)==1
        assert reviews[0]['risk']=='REVIEW'
        assert reviews[0]['ml_model_sha256']==sha(MODEL)
        for name,data in (('events.jsonl',events),('alerts.jsonl',engine.outputs)):
            with (target/name).open('x') as h:
                for item in data:h.write(json.dumps(item,sort_keys=True)+'\n')
        result={'id':row['id'],'assigned_intent':row['intent'],
                'label':int(row['intent']=='simulated_unauthorized'),
                'probability':reviews[0]['ml_probability'],
                'priority':reviews[0]['ml_priority'],
                'features':reviews[0]['ml_feature_values'],
                'stages':[a['stage'] for a in engine.outputs],
                'answered_cdr_count_independently_verified':3,
                'pcap_sha256':sha(run/'traffic.pcap'),
                'events_sha256':sha(target/'events.jsonl'),
                'alerts_sha256':sha(target/'alerts.jsonl')}
        (target/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
        results.append(result)
        print(json.dumps(result),flush=True)
    assert len(results)==10
    pairs=[('B006','B011'),('B007','B012'),('B008','B013'),
           ('B009','B014'),('B010','B015')]
    for a,b in pairs:
        x,y=[next(r for r in results if r['id']==id) for id in (a,b)]
        assert x['label']!=y['label'] and x['stages']==y['stages']
    summary={'model_sha256':sha(MODEL),'manifest_sha256':sha(MANIFEST),
             'count':len(results),'positive':5,'negative':5,
             'higher_priority_tp':sum(r['label']==1 and r['priority']=='HIGHER' for r in results),
             'higher_priority_fp':sum(r['label']==0 and r['priority']=='HIGHER' for r in results),
             'lower_priority_benign':sum(r['label']==0 and r['priority']=='LOWER' for r in results),
             'lower_priority_abuse':sum(r['label']==1 and r['priority']=='LOWER' for r in results),
             'pairs':pairs,'results':results,
             'warning':'Single-generator assigned-intent lab holdout; no automated suppression or population accuracy claim.'}
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='results'}),flush=True)
    print('summary_sha256',sha(OUT/'summary.json'),flush=True)

if __name__=='__main__':main()

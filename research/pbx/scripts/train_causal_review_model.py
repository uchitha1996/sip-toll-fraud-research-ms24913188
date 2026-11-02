#!/usr/bin/env python3
"""Freeze a small stage-time risk-priority model from development episodes only."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT=Path('/home/astrix/sip-fraud-research')
DATA=ROOT/'datasets/ml-lab-20260930'
AUDIT=ROOT/'datasets/online-prototype-audit-20261001'
OUT=ROOT/'datasets/causal-review-ml-20261001'
NAMES=['failures_120s','peak_failures_10s','failure_span_s','first_failure_to_success_s']

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def epoch(t): return datetime.fromisoformat(t.replace('Z','+00:00')).timestamp()
def features(events):
    failures=[]
    for event in events:
        now=epoch(event['time_utc'])
        if event['kind']=='AUTH_REJECTION': failures.append(now)
        if event['kind']=='REGISTER_SUCCESS':
            recent=[t for t in failures if now-120<=t<=now]
            if len(recent)<5: return None
            peak=max((sum(t-10<=v<=t for v in recent) for t in recent),default=0)
            return [len(recent),peak,round(max(recent)-min(recent),4),
                    round(now-min(recent),4)]
    return None

def main():
    os.umask(0o077)
    assert not OUT.exists()
    manifest=json.loads((DATA/'ml_protocol_manifest.json').read_text())
    prior=pd.read_csv(DATA/'development_features.csv').set_index('scenario_id')
    rows=[]
    for item in manifest['scenarios']:
        if item['split']!='development':continue
        path=AUDIT/'development'/item['id']/'events.jsonl'
        events=[json.loads(line) for line in path.read_text().splitlines()]
        vector=features(events)
        if vector is None:continue
        old=prior.loc[item['id']]
        assert vector[:2]==[old.confirmed_rejections,old.max_rejections_10s]
        assert abs(vector[2]-old.rejection_span_s)<.002
        assert abs(vector[3]-old.rejection_to_success_s)<.002
        rows.append({'id':item['id'],'label':int(item['intent']=='SIMULATED_ABUSE'),
                     'group':old.profile_group,'values':vector,'events_sha256':sha(path)})
    assert len(rows)==10 and sum(r['label'] for r in rows)==5
    X=np.array([r['values'] for r in rows],dtype=float)
    y=np.array([r['label'] for r in rows],dtype=int)
    groups=np.array([r['group'] for r in rows])
    splitter=StratifiedGroupKFold(n_splits=2,shuffle=True,random_state=17)
    predictions=np.full(len(rows),np.nan)
    folds=[]
    for number,(train,test) in enumerate(splitter.split(X,y,groups)):
        assert len(set(y[train]))==2 and not set(groups[train])&set(groups[test])
        model=make_pipeline(StandardScaler(),LogisticRegression(C=.3,solver='liblinear',random_state=17))
        model.fit(X[train],y[train])
        predictions[test]=model.predict_proba(X[test])[:,1]
        folds.append({'fold':number,'train':[rows[i]['id'] for i in train],
                      'test':[rows[i]['id'] for i in test]})
    assert np.isfinite(predictions).all()
    final=make_pipeline(StandardScaler(),LogisticRegression(C=.3,solver='liblinear',random_state=17))
    final.fit(X,y)
    scale,reg=final.steps[0][1],final.steps[1][1]
    OUT.mkdir(mode=0o700)
    model={'frozen_utc':datetime.now(timezone.utc).isoformat(),
           'endpoint':'first REGISTER_SUCCESS after >=5 confirmed failures in 120s',
           'feature_names':NAMES,'mean':scale.mean_.tolist(),
           'scale':scale.scale_.tolist(),'coef':reg.coef_[0].tolist(),
           'intercept':float(reg.intercept_[0]),'priority_thresholds':[.4,.6],
           'priority_policy':'<0.4 lower; 0.4-0.6 review; >=0.6 higher; never suppress rule evidence',
           'training_ids':[r['id'] for r in rows],
           'manifest_sha256':sha(DATA/'ml_protocol_manifest.json'),
           'development_features_sha256':sha(DATA/'development_features.csv'),
           'audit_summary_sha256':sha(AUDIT/'summary.json'),
           'trainer_sha256':sha(Path(__file__)),
           'sklearn_version':sklearn.__version__,
           'limitations':'ten labelled development episodes; paired intent ambiguity; no holdout performance yet'}
    (OUT/'frozen_model.json').write_text(json.dumps(model,indent=2)+'\n')
    (OUT/'development_stage_rows.json').write_text(json.dumps(rows,indent=2)+'\n')
    report={'folds':folds,'out_of_fold':[{'id':r['id'],'label':r['label'],
                                        'probability':float(predictions[i])}
                                       for i,r in enumerate(rows)],
            'frozen_model_sha256':sha(OUT/'frozen_model.json')}
    (OUT/'development_cv.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'training_count':len(rows),'model_sha256':report['frozen_model_sha256'],
                      'out_of_fold':report['out_of_fold']}))

if __name__=='__main__':main()

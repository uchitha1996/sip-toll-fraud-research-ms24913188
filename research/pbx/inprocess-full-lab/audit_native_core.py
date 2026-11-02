#!/usr/bin/env python3
"""Compare C port against the frozen Python reference on saved events only."""
import hashlib,json,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/home/astrix/sip-fraud-research')
sys.path.insert(0,str(ROOT/'scripts'))
from causal_review_score import MLProgression,load_model
from native_core import NativeCore
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check(events):
 ref=MLProgression(load_model(ROOT/'datasets/causal-review-ml-20261001/frozen_model.json'))
 native=NativeCore(HERE/'libprogression_core.so');total=0
 try:
  for e in events:
   a=ref.accept(e);b=native.accept(e)
   assert [x['stage'] for x in a]==[x['stage'] for x in b],(e,a,b)
   for x,y in zip(a,b):
    for key in ['risk','source_ip','account','call_id','destination','policy']:
     assert x[key]==y[key],(key,x,y)
    if 'ml_probability' in x:
     assert abs(x['ml_probability']-y['ml_probability'])<1e-10,(x,y)
     assert x['ml_priority']==y['ml_priority']
     assert x['ml_feature_values']==y['ml_feature_values']
     assert x['ml_model_sha256']==y['ml_model_sha256']
   total+=len(a)
 finally:native.close()
 return total
def fixtures():
 events=[]
 def add(kind,t,account='1002',**kw):
  e=dict(kind=kind,event_id='fixture:'+str(len(events)),time_utc=datetime.fromtimestamp(1700000000+t,timezone.utc).isoformat(),source_ip='172.16.200.68',account=account,**kw)
  events.append(e)
 for i in range(5):add('OPTIONS_REQUEST',i,account='',target=str(9000+i))
 for i in range(10):add('AUTH_REJECTION',10+i*2,call_id='wrong'+str(i))
 add('REGISTER_SUCCESS',31,call_id='valid')
 add('REGISTER_SUCCESS',32,call_id='valid-retry')
 for i in range(3):
  add('OUTBOUND_INVITE',34+i*7,call_id='call'+str(i),destination='88002',destination_group='lab-uas',trunk='lab-trunk')
  add('OUTBOUND_INVITE',35+i*7,call_id='call'+str(i),destination='88002',destination_group='lab-uas',trunk='lab-trunk')
  add('CALL_SIP_COMPLETED',36+i*7,call_id='call'+str(i))
  add('CDR_ANSWERED',37+i*7,call_id='call'+str(i),destination='88002',billsec=6)
 events.append(dict(events[-1]))
 # Expiration and separate account; a new failure-set recovery may re-alert.
 for i in range(6):add('AUTH_REJECTION',160+i*2,account='1001',call_id='later'+str(i))
 add('REGISTER_SUCCESS',174,account='1001',call_id='later-success')
 return events
def main():
 assert sha(ROOT/'datasets/causal-review-ml-20261001/frozen_model.json')=='ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d'
 paths=sorted((ROOT/'datasets/online-prototype-audit-20261001').rglob('events.jsonl'))
 if not paths:paths=sorted((ROOT/'datasets/online-prototype-audit-20261001').rglob('*events.jsonl'))
 assert len(paths)==34, len(paths)
 rows=[]
 for p in paths:
  events=[json.loads(s) for s in p.read_text().splitlines() if s.strip()]
  rows.append({'path':str(p.relative_to(ROOT)),'events':len(events),'alerts':check(events),'sha256':sha(p)})
 test=fixtures();fixture_alerts=check(test)
 # Invalid order and bounded capacity must fail rather than silently alter evidence.
 n=NativeCore(HERE/'libprogression_core.so')
 try:
  n.accept(test[1])
  try:n.accept(test[0])
  except ValueError:pass
  else:raise AssertionError('Out-of-order event accepted')
 finally:n.close()
 summary={'scope':'Read-only regression, no fresh accuracy or live latency','runs_matched':len(rows),'events':sum(r['events'] for r in rows),'alerts':sum(r['alerts'] for r in rows),'fixtures':len(test),'fixture_alerts':fixture_alerts,'rows':rows,'sources':{p.name:sha(p) for p in HERE.glob('*') if p.suffix in ['.c','.h','.py','.so']}}
 out=ROOT/'datasets/full-stage-port-audit-20261002';out.mkdir(mode=0o700,exist_ok=False)
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({k:v for k,v in summary.items() if k not in ['rows','sources']}),flush=True)
if __name__=='__main__':main()

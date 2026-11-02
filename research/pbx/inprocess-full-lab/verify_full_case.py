#!/usr/bin/env python3
"""Independent raw-packet/reference check after unchanged SIP/CDR gate."""
import argparse,json,sys
from pathlib import Path
from audit_packet_adapter import decode
from packet_adapter import Adapter,GEN,PBX
from audit_native_core import check,ROOT
from causal_review_score import MLProgression,load_model
def verify(run,out,row):
 packets=decode(run/'traffic.pcap');adapter=Adapter();events=[]
 for p in packets:events.extend(adapter.feed(p,float(p['frame.time_epoch'])))
 events.extend(adapter.drain(float(packets[-1]['frame.time_epoch'])+2))
 check(events) # Exact C/Python parity on the same new packet events.
 ref=MLProgression(load_model(ROOT/'datasets/causal-review-ml-20261001/frozen_model.json'))
 expected=[a for e in events for a in ref.accept(e)]
 kinds={k:sum(e['kind']==k for e in events) for k in ['OPTIONS_REQUEST','AUTH_REJECTION','REGISTER_SUCCESS','OUTBOUND_INVITE']}
 assert kinds==dict(OPTIONS_REQUEST=5,AUTH_REJECTION=row['wrong'],REGISTER_SUCCESS=1,OUTBOUND_INVITE=3),kinds
 targets={e['target'] for e in events if e['kind']=='OPTIONS_REQUEST'}
 assert len(targets)==(5 if row['options_distinct'] else 1)
 planned=['CALL_BURST'] if not row['wrong'] else ['RECONNAISSANCE','AUTHENTICATION_ATTACK','SUSPECTED_COMPROMISE','SUSPECTED_OUTBOUND_ATTEMPT','SUSPECTED_OUTBOUND_ATTEMPT','SUSPECTED_OUTBOUND_ATTEMPT','CALL_BURST']
 assert [a['stage'] for a in expected]==planned
 independent=json.loads((run/'independent_verification.json').read_text());assert independent['verified']
 assert independent['billsec']==[6,6,6],independent['billsec']
 assert '0 packets dropped by kernel' in (run/'tcpdump.log').read_text()
 observed=[json.loads(s) for s in (out/'alerts.jsonl').read_text().splitlines() if s.strip()]
 if row['mode']=='OFF':assert not observed
 else:
  assert len(observed)==len(expected),(len(observed),len(expected))
  for a,b in zip(expected,observed):
   for k in ['stage','risk','source_ip','account','call_id','destination','policy']:assert a[k]==b[k],(k,a,b)
   if 'ml_probability' in a:
    assert a['ml_model_sha256']==b['ml_model_sha256'] and a['ml_priority']==b['ml_priority']
    tol=.005 if row['mode']=='INTERNAL' else 1e-8
    assert abs(a['ml_probability']-b['ml_probability'])<=tol
    assert a['ml_feature_values'][:2]==b['ml_feature_values'][:2]
    assert all(abs(x-y)<=(.050 if row['mode']=='INTERNAL' else 1e-4) for x,y in zip(a['ml_feature_values'][2:],b['ml_feature_values'][2:]))
  if row['mode']=='EXTERNAL':
   assert json.loads((out/'external/status.json').read_text())['error'] is None
   assert '0 packets dropped by kernel' in (out/'external/capture.log').read_text()
 timings=[]
 for a in observed:
  kind={'RECONNAISSANCE':'OPTIONS_REQUEST','AUTHENTICATION_ATTACK':'AUTH_REJECTION','SUSPECTED_COMPROMISE':'REGISTER_SUCCESS','SUSPECTED_OUTBOUND_ATTEMPT':'OUTBOUND_INVITE','CALL_BURST':'OUTBOUND_INVITE'}[a['stage']]
  e=next(e for e in events if e['kind']==kind and e['call_id']==a['call_id'])
  from stream_progression_prototype import epoch
  onset=epoch(e['time_utc'])
  if kind=='REGISTER_SUCCESS':
   # Actionable request timestamp: authenticated request receiving accepted 200.
   onset=max(float(p['frame.time_epoch']) for p in packets if p['ip.src']==GEN and p['sip.Method']=='REGISTER' and p['sip.Call-ID']==a['call_id'] and p['sip.auth.username'] and float(p['frame.time_epoch'])<=onset)
  delay=(a['decision_epoch']-onset)*1000
  assert delay>=0,('Negative delay',a,delay)
  timings.append({'stage':a['stage'],'call_id':a['call_id'],'packet_to_decision_ms':delay,'packet_to_observation_ms':(a['observed_epoch']-onset)*1000})
 setups=[]
 for cid in independent['call_ids']:
  leg=[p for p in packets if p['sip.Call-ID']==cid]
  start=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']==GEN and p['sip.Method']=='INVITE')
  answered=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']==PBX and p['sip.Status-Code']=='200' and p['sip.CSeq.method']=='INVITE')
  setups.append({'call_id':cid,'invite_to_200_ms':(answered-start)*1000})
 report={'id':row['id'],'mode':row['mode'],'verified':True,'event_counts':kinds,'expected_stages':planned,'timings':timings,'call_setup':setups,'scope':'Development delivery/overhead comparison; no new fraud accuracy or live CDR-stage claim'}
 with (out/'verification.json').open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
 return report
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('manifest',type=Path);ap.add_argument('id');ap.add_argument('out',type=Path);a=ap.parse_args()
 row=next(r for r in json.loads(a.manifest.read_text())['scenarios'] if r['id']==a.id)
 print(json.dumps(verify(ROOT/'datasets/burst-lab-20261001/development'/a.id,a.out,row)))

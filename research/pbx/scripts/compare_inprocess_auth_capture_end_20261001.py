#!/usr/bin/env python3
"""Read-only external-engine stage parity on fresh in-process auth captures."""
import csv,json,re,subprocess,hashlib,os
from datetime import datetime,timezone
from pathlib import Path
from stream_progression_prototype import Progression
R=Path('/home/astrix/sip-fraud-research')
B=R/'datasets/inprocess-auth-validation-20261001'
O=B/'external_auth_parity_capture_end'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 os.umask(0o077);O.mkdir(mode=0o700,exist_ok=False)
 source=R/'scripts/candidate_v5_replay.py'
 assert sha(source)=='e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004'
 results=[]
 for sid in ['A000','A001','A002']:
  run=B/sid;out=O/sid;out.mkdir()
  verification=json.loads((run/'verification.json').read_text());assert verification['verified']
  assert sha(run/'traffic.pcap')==verification['pcap_sha256']
  assert 'packets captured' in (run/'tcpdump.log').read_text()
  end=datetime.fromtimestamp((run/'tcpdump.log').stat().st_mtime,timezone.utc).isoformat()
  (out/'observation_end.json').write_text(json.dumps({'end_utc':end,'source':'tcpdump termination-log filesystem mtime; PCAP mtime is last flush, not capture stop'},indent=2)+'\n')
  subprocess.run(['python3',str(source),str(run/'traffic.pcap'),str(out/'v5_replay'),'--observation-end-utc',end],
                 capture_output=True,text=True,check=True)
  rows=list(csv.DictReader((out/'v5_replay/candidate_timeline.csv').open()))
  events=[]
  for x in rows:
   kind=('AUTH_REJECTION' if x['event_type']=='CONFIRMED_REJECTION' else
         'REGISTER_SUCCESS' if x['event_type']=='REGISTER_FINAL_RESPONSE' and x['status']=='200' else None)
   if kind:
    events.append({'event_id':'v5:'+x['event_number'],'time_utc':x['time_utc'],
                   'source_ip':x['entity'],'account':x['target'],'kind':kind,'call_id':x['call_id']})
  events.sort(key=lambda x:(x['time_utc'],x['event_id']))
  engine=Progression()
  for event in events:engine.accept(event)
  stages=[x['stage'] for x in engine.outputs]
  inprocess=[re.search(r'stage=(\S+)',x).group(1) for x in verification['module_events']]
  result={'id':sid,'events':len(events),'external_replay_stages':stages,
          'live_inprocess_stages':inprocess,'match':stages==inprocess,'pcap_sha256':sha(run/'traffic.pcap')}
  (out/'events.json').write_text(json.dumps(events,indent=2)+'\n')
  (out/'external_alerts.json').write_text(json.dumps(engine.outputs,indent=2)+'\n')
  results.append(result);print(json.dumps(result),flush=True)
  assert result['match']
 summary={'results':results,'all_match':all(x['match'] for x in results),
          'scope':'Auth stage subset only. External side is archived replay; not simultaneous live delivery or latency/overhead comparison.'}
 (O/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print('COMPLETE',sha(O/'summary.json'),flush=True)
if __name__=='__main__':main()


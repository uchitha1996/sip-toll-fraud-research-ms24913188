#!/usr/bin/env python3
"""Exercise protocol semantics and verify new adapter on existing lab PCAPs."""
import csv,io,json,subprocess,sys
from pathlib import Path
from packet_adapter import Adapter,FIELDS,GEN,PBX
from audit_native_core import check,ROOT,HERE,sha
def packet(method='',code='',seq='1',cid='auth',username='',stale=''):
 p={k:'' for k in FIELDS};p.update({'frame.time_epoch':'1700000000','ip.src':GEN if method else PBX,'ip.dst':PBX if method else GEN,'sip.Method':method,'sip.Status-Code':code,'sip.CSeq.method':'REGISTER','sip.CSeq.seq':seq,'sip.Call-ID':cid,'sip.from.user':'1002','sip.to.user':'1002','sip.auth.username':username,'sip.auth.stale':stale});return p
def fixtures():
 a=Adapter();assert not a.feed(packet(method='REGISTER'),0)
 assert not a.feed(packet(code='401'),.01)
 assert not a.feed(packet(method='REGISTER',seq='2',username='1002'),.1)
 assert not a.feed(packet(code='401',seq='2'),.2)
 assert not a.feed(packet(code='401',seq='2'),.3)
 assert not a.feed(packet(method='REGISTER',seq='3',username='1002'),.4)
 out=a.feed(packet(code='200',seq='3'),.5)
 assert [e['kind'] for e in out]==['REGISTER_SUCCESS']
 assert not a.drain(2)
 b=Adapter();b.feed(packet(method='REGISTER',seq='2',username='1002'),0)
 assert not b.feed(packet(code='401',seq='2',stale='true'),.1)
 assert not b.drain(2)
 c=Adapter();c.feed(packet(method='REGISTER',seq='2',username='1002'),0)
 assert not c.feed(packet(code='401',seq='2'),.1)
 assert not c.drain(.99)
 assert [e['kind'] for e in c.drain(1.1)]==['AUTH_REJECTION']
 return ['initial_challenge_ignored','digest_retry_success_cancels_rejection','response_retransmission_deduplicated','stale_challenge_ignored','one_second_grace']
def decode(path):
 cmd=['tshark','-r',str(path),'-Y','sip','-T','fields','-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=f']
 for field in FIELDS:cmd.extend(['-e',field])
 result=subprocess.run(cmd,capture_output=True,text=True,check=True)
 return list(csv.DictReader(io.StringIO(result.stdout)))
def main():
 tests=fixtures();rows=[]
 for sid in ['B005','B016','B021','B022','B023','B024','B027','B028','B029']:
  p=ROOT/'datasets/burst-lab-20261001/development'/sid/'traffic.pcap'
  packets=decode(p);adapter=Adapter();events=[]
  for packet in packets:events.extend(adapter.feed(packet,float(packet['frame.time_epoch'])))
  if packets:events.extend(adapter.drain(float(packets[-1]['frame.time_epoch'])+2))
  counts={kind:sum(e['kind']==kind for e in events) for kind in ['AUTH_REJECTION','REGISTER_SUCCESS','OUTBOUND_INVITE']}
  assert counts=={'AUTH_REJECTION':6,'REGISTER_SUCCESS':1,'OUTBOUND_INVITE':3},(sid,counts)
  rows.append({'id':sid,'counts':counts,'alerts':check(events),'pcap_sha256':sha(p),'scope':'Retained failed B024 remains excluded from pilot; adapter dedup regression only' if sid=='B024' else 'Archived protocol regression'})
 summary={'tests_passed':tests,'archived_cases':rows,'new_calls':0,'adapter_sha256':sha(HERE/'packet_adapter.py')}
 path=ROOT/'datasets/full-stage-port-audit-20261002/packet_adapter_verification.json'
 with path.open('x') as out:out.write(json.dumps(summary,indent=2)+'\n')
 print(json.dumps({'tests':tests,'archived_cases':len(rows),'new_calls':0}))
if __name__=='__main__':main()

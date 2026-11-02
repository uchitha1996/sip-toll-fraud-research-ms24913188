#!/usr/bin/env python3
"""Recalculate call setup from raw PCAP independently of batch summaries."""
import csv,hashlib,json,statistics,subprocess
from pathlib import Path
R=Path('/home/astrix/sip-fraud-research')
O=R/'datasets/deployment-call-comparison-20261002'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cli(s):return subprocess.run(['asterisk','-rx',s],capture_output=True,text=True,check=True).stdout
def main():
 summary=json.loads((O/'summary.json').read_text())
 manifest=json.loads((O/'manifest.json').read_text())
 assert sha(O/'manifest.json')==summary['manifest_sha256']
 out=[]
 fields=['frame.time_epoch','ip.src','sip.Method','sip.Status-Code','sip.CSeq.method','sip.Call-ID','sip.from.user','sip.r-uri.user']
 for result in summary['cases']:
  sid=result['id'];rd=R/'datasets/burst-lab-20261001/development'/sid
  protocol=json.loads((rd/'predeclared_protocol.json').read_text())
  assert protocol['manifest_sha256']==summary['manifest_sha256']
  assert sha(rd/'traffic.pcap')==result['pcap_sha256']
  assert '0 packets dropped by kernel' in (rd/'tcpdump.log').read_text()
  args=['tshark','-r',str(rd/'traffic.pcap'),'-Y','sip','-T','fields','-E','header=y','-E','separator=,','-E','quote=d']
  for field in fields:args+=['-e',field]
  table=O/sid/'audit_packets.csv'
  with table.open('x') as h:subprocess.run(args,stdout=h,check=True,timeout=25)
  with table.open() as h:packets=list(csv.DictReader(h))
  ids={p['sip.Call-ID'] for p in packets if p['ip.src']=='172.16.200.68' and p['sip.Method']=='INVITE' and p['sip.from.user']=='1002' and p['sip.r-uri.user']=='88002'}
  assert len(ids)==3
  samples=[]
  for cid in sorted(ids):
   leg=[p for p in packets if p['sip.Call-ID']==cid]
   start=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']=='172.16.200.68' and p['sip.Method']=='INVITE')
   end=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']=='172.16.200.81' and p['sip.Status-Code']=='200' and p['sip.CSeq.method']=='INVITE')
   assert any(p['sip.Method']=='ACK' for p in leg) and any(p['sip.Method']=='BYE' for p in leg)
   val=(end-start)*1000
   original=next(x for x in result['setup'] if x['call_id']==cid)['setup_ms']
   assert abs(val-original)<1e-7
   samples.append(val)
  with (rd/'cdr_before.csv').open() as h:before=list(csv.reader(h))
  with (rd/'cdr_after.csv').open() as h:after=list(csv.reader(h))
  assert after[:len(before)]==before
  delta=after[len(before):]
  assert len(delta)==3 and all(len(x)>=17 and x[1:3]==['1002','88002'] and x[14]=='ANSWERED' and int(x[13])==6 for x in delta)
  assert len((rd/'asterisk_failed_auth_evidence.txt').read_text().splitlines())==6
  if result['mode']=='EXTERNAL':
   status=json.loads((O/sid/'live/status.json').read_text())
   assert status['error'] is None and status['alerts']==['SUSPECTED_COMPROMISE']
   assert status['counts']=={'AUTH_REJECTION':6,'REGISTER_SUCCESS':1,'OUTBOUND_INVITE':0,'OPTIONS_REQUEST':0}
  assert result['verified']
  out.append({'id':sid,'mode':result['mode'],'raw_pcap_recalculated':True,'setup_ms':samples,'median_ms':statistics.median(samples),'three_six_second_answered_cdr':True,'six_auth_failures':True,'zero_capture_drops':True})
 assert '0 active calls' in cli('core show channels count')
 assert '0 modules loaded' in cli('module show like sipfraud')
 for d in ('88001','88002'):assert 'no existence' in cli(f'dialplan show {d}@internal')
 report={'all_checks_passed':True,'summary_sha256':sha(O/'summary.json'),'cases':out,
         'final_state':'Zero active calls, module unloaded, both temporary routes absent.'}
 (O/'independent_audit.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report),flush=True)
if __name__=='__main__':main()


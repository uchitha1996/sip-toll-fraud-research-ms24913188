#!/usr/bin/env python3
"""Matched call-setup pilot with shared auth observers, isolated lab only."""
import csv,json,os,signal,statistics,subprocess,threading,time
from datetime import datetime,timezone
from pathlib import Path
import measure_external_overhead_20261001 as perf
from measure_deployment_auth_20261002 import watcher,BIN,BINHASH
from lab_burst_runner import cmd,sha
R=Path('/home/astrix/sip-fraud-research')
O=R/'datasets/deployment-call-comparison-replacement-20261002'
FULL=Path('/var/log/asterisk/full')
EXPECTED_STAGES=['SUSPECTED_COMPROMISE']
def cli(s):return cmd(['asterisk','-rx',s])
def utc():return datetime.now(timezone.utc).isoformat()
def role(p):
 name=(p/'comm').read_text().strip()
 args=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
 if name=='asterisk':return 'pbx'
 if name.startswith('python') and 'overhead_collector_B' in args:return 'collector'
 if name.startswith('python') and 'external_event_service.py' in args:return 'service'
 if name=='tshark':return 'decoder'
 if name=='tcpdump':return 'capture'
 return None
perf.role=role
def monitor(stop,path,records):
 with path.open('x') as out:
  while not stop.is_set():
   snap={'epoch':time.time(),'monotonic':time.monotonic(),'processes':perf.sample()}
   records.append(snap);out.write(json.dumps(snap)+'\n');out.flush();stop.wait(.25)
def resources(records,onset,end):
 snaps=[x for x in records if onset<=x['epoch']<=end]
 assert len(snaps)>=2
 first={(x['pid'],x['start_ticks']):x['ticks'] for x in snaps[0]['processes']}
 last={};peaks={}
 for snap in snaps:
  sums={}
  for p in snap['processes']:
   last[p['pid'],p['start_ticks']]=p
   sums[p['role']]=sums.get(p['role'],0)+p['rss_kib']
  for k,v in sums.items():peaks[k]=max(peaks.get(k,0),v)
 cpu={}
 for key,p in last.items():
  cpu[p['role']]=cpu.get(p['role'],0)+max(0,p['ticks']-first.get(key,p['ticks']))/os.sysconf('SC_CLK_TCK')
 elapsed=snaps[-1]['monotonic']-snaps[0]['monotonic']
 return {'sample_count':len(snaps),'sampled_window_s':elapsed,'cpu_seconds_sampled':cpu,
         'cpu_core_percent':{k:v/elapsed*100 for k,v in cpu.items()},'peak_rss_kib_by_role':peaks}
def preflight():
 assert sha(BIN)==BINHASH
 assert '0 active calls' in cli('core show channels count')
 assert '0 modules loaded' in cli('module show like sipfraud')
 for d in ['88001','88002']:assert 'no existence' in cli(f'dialplan show {d}@internal')
def collector(sid):
 source=R/'scripts/overhead_collector_BT003.py'
 text=source.read_text()
 old="OUT = ROOT / 'datasets/deployment-auth-comparison-20261002/T003/live'"
 assert text.count(old)==1
 text=text.replace(old,f"OUT = ROOT / 'datasets/deployment-call-comparison-replacement-20261002/{sid}/live'")
 old="elif source == GEN and method=='INVITE'"
 assert text.count(old)==1
 text=text.replace(old,"elif False and source == GEN and method=='INVITE'")
 target=R/'scripts'/f'overhead_collector_{sid}.py'
 assert not target.exists();target.write_text(text)
 subprocess.run(['python3','-m','py_compile',str(target)],check=True)
 return target
def main():
 os.umask(0o077);preflight()
 rows=[{'id':f'B{i+27:03d}','mode':mode,'block':2,'split':'development',
        'intent':'authorized','account':'1002','wrong':6,'interval':2.1,'success':1,
        'call':3,'post_register_pause':1.0,'destination_group':'lab-uas','trunk':'lab-trunk'}
       for i,mode in enumerate(['EXTERNAL','INTERNAL','OFF'])]
 for row in rows:assert not (R/'datasets/burst-lab-20261001/development'/row['id']).exists()
 O.mkdir(mode=0o700,exist_ok=False)
 scripts={row['id']:collector(row['id']) for row in rows if row['mode']=='EXTERNAL'}
 plan={'replacement_for':'B024-B026; B024 had duplicate failed-auth log for first REGISTER Call-ID; strict original gate retained','declared_utc':utc(),'scenarios':rows,'script_sha256':sha(Path(__file__)),
       'runner_sha256':sha(R/'scripts/lab_burst_runner.py'),'module_sha256':BINHASH,
       'service_sha256':sha(R/'scripts/external_event_service.py'),
       'collector_sha256':{k:sha(v) for k,v in scripts.items()},
       'setup_endpoint':'First generator INVITE to first PBX 200 response for INVITE, same generator Call-ID; initial INVITE authentication is included.',
       'auth_scope':'INTERNAL module and EXTERNAL rule-only service receive shared authentication recovery stage. External collector decodes calls but does not forward INVITEs. No ML.',
       'order':'Replacement block EXTERNAL INTERNAL OFF, three sequential calls per case. Original B024 failed the exact auth-log-count gate; B025/B026 were not run. B021-B023 remain valid block 1. Original failed capture retained; no acceptance criteria changed.',
       'resource_window':'Samples with epoch between first generator REGISTER and last generator-leg BYE plus 0.5s. Excludes startup, preparation and offline PCAP extraction.',
       'sampling_interval_s':.25,'cpu_unit':'Percent of one core',
       'invalid_if':'Missing SIP/CDR/auth evidence, capture drops, alert mismatch, route cleanup or frozen hashes.',
       'limits':'Only two cases per mode; calls clustered within cases, one Pi/WLAN/account, no randomized order or load/stress control. No full-stage parity or precise causal overhead estimate. Different observation interfaces; sampled CPU may miss tails; summed RSS includes shared pages; native module memory not isolated.'}
 manifest=O/'manifest.json';manifest.write_text(json.dumps(plan,indent=2)+'\n')
 print('DECLARED',sha(manifest),flush=True);results=[]
 for row in rows:
  preflight();sid=row['id'];mode=row['mode'];p=O/sid;p.mkdir()
  stop=threading.Event();ready=threading.Event();events=[];records=[]
  watch=mon=live=None;log=None;loaded=False;error=None
  offset=FULL.stat().st_size
  try:
   if mode=='INTERNAL':
    assert 'Loaded' in cli('module load res_sipfraud_lab.so');loaded=True
    clean=cli('sipfraud lab status')
    assert 'account=1002 failures_window=0 auth_alerts=0 review_alerts=0' in clean
    (p/'module_before.txt').write_text(clean)
   if mode=='EXTERNAL':
    log=(p/'collector.log').open('x')
    live=subprocess.Popen(['python3','-u',str(scripts[sid])],stdout=log,stderr=subprocess.STDOUT)
    for _ in range(100):
     if live.poll() is not None:raise RuntimeError('Collector exited before traffic')
     err=p/'live/capture_stderr.log'
     if err.exists() and 'listening on wlan0' in err.read_text():break
     time.sleep(.1)
    else:raise RuntimeError('Collector not ready')
   watch=threading.Thread(target=watcher,args=(stop,offset,p/'module_observations.jsonl',events,ready))
   mon=threading.Thread(target=monitor,args=(stop,p/'resources.jsonl',records))
   watch.start();assert ready.wait(2);mon.start()
   run=subprocess.run(['python3','-u',str(R/'scripts/lab_burst_runner.py'),str(manifest),sid],
                      capture_output=True,text=True,timeout=140)
   (p/'runner.log').write_text(run.stdout+run.stderr)
   assert run.returncode==0,'Traffic runner failed'
   if loaded:(p/'module_after.txt').write_text(cli('sipfraud lab status'))
   if live:
    (p/'live/STOP').touch();assert live.wait(timeout=12)==0,'Collector failed'
  except Exception as exc:error=type(exc).__name__+': '+str(exc)
  finally:
   stop.set()
   for th in (watch,mon):
    if th:th.join(timeout=3)
   if live and live.poll() is None:
    live.terminate()
    try:live.wait(timeout=7)
    except subprocess.TimeoutExpired:live.kill();live.wait()
   if log:log.close()
   if loaded:cli('module unload res_sipfraud_lab.so')
   (p/'execution_status.json').write_text(json.dumps({'error':error,'finished_utc':utc()})+'\n')
  assert error is None,error
  rd=R/'datasets/burst-lab-20261001/development'/sid
  check=subprocess.run(['python3',str(R/'scripts/verify_burst_run.py'),str(rd)],
                       capture_output=True,text=True)
  (p/'verification.log').write_text(check.stdout+check.stderr)
  assert check.returncode==0,'Independent evidence gate failed'
  evidence=json.loads((rd/'independent_verification.json').read_text())
  packets=list(csv.DictReader((rd/'sip_packets.csv').open()))
  setup=[]
  for cid in evidence['call_ids']:
   leg=[x for x in packets if x['sip.Call-ID']==cid]
   starts=[float(x['frame.time_epoch']) for x in leg if x['ip.src']=='172.16.200.68' and x['sip.Method']=='INVITE']
   ends=[float(x['frame.time_epoch']) for x in leg if x['ip.src']=='172.16.200.81' and x['sip.Status-Code']=='200' and x['sip.CSeq.method']=='INVITE']
   assert starts and ends and min(ends)>=min(starts)
   setup.append({'call_id':cid,'first_invite_epoch':min(starts),'first_invite_200_epoch':min(ends),'setup_ms':(min(ends)-min(starts))*1000})
  onset=min(float(x['frame.time_epoch']) for x in packets if x['ip.src']=='172.16.200.68' and x['sip.Method']=='REGISTER')
  lastbye=max(float(x['frame.time_epoch']) for x in packets if x['sip.Call-ID'] in evidence['call_ids'] and x['sip.Method']=='BYE')
  checks={'independent_evidence':evidence['verified'],
          'capture_zero_drops':'0 packets dropped by kernel' in (rd/'tcpdump.log').read_text(),
          'three_setup_values':len(setup)==3,'module_unloaded':'0 modules loaded' in cli('module show like sipfraud')}
  reviews=[x for x in events if 'stage=SUSPECTED_COMPROMISE ' in x['line']]
  if mode=='INTERNAL':
   checks['one_native_review']=len(reviews)==1
   checks['native_counters']='account=1002 failures_window=6 auth_alerts=0 review_alerts=1' in (p/'module_after.txt').read_text()
  else:checks['no_native_alert']=len(events)==0
  if mode=='EXTERNAL':
   status=json.loads((p/'live/status.json').read_text())
   checks['external_auth_only']=not status['error'] and status['counts']=={'AUTH_REJECTION':6,'REGISTER_SUCCESS':1,'OUTBOUND_INVITE':0,'OPTIONS_REQUEST':0} and status['alerts']==EXPECTED_STAGES
   checks['external_capture_zero_drops']='0 packets dropped by kernel' in (p/'live/capture_stderr.log').read_text()
  result={'id':sid,'mode':mode,'block':row['block'],'setup':setup,
          'setup_ms_median':statistics.median(x['setup_ms'] for x in setup),'checks':checks,
          'verified':all(checks.values()),'pcap_sha256':sha(rd/'traffic.pcap'),
          'resource_onset_epoch':onset,'resource_end_epoch':lastbye+.5,
          'resources':resources(records,onset,lastbye+.5)}
  (p/'summary.json').write_text(json.dumps(result,indent=2)+'\n');results.append(result)
  print('CASE',json.dumps(result),flush=True)
  assert result['verified'],'Stop-on-failure gate'
 deltas=[]
 for block in (2,):
  off=next(x for x in results if x['block']==block and x['mode']=='OFF')
  for mode in ('INTERNAL','EXTERNAL'):
   on=next(x for x in results if x['block']==block and x['mode']==mode)
   deltas.append({'block':block,'mode':mode,'enabled_minus_off_median_ms':on['setup_ms_median']-off['setup_ms_median']})
 summary={'manifest_sha256':sha(manifest),'cases':results,'all_verified':all(x['verified'] for x in results),
          'within_block_setup_deltas':deltas,'scope':plan['auth_scope'],'limitations':plan['limits']}
 (O/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 preflight();print('COMPLETE',sha(O/'summary.json'),flush=True)
if __name__=='__main__':main()


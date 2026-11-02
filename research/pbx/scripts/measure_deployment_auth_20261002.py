#!/usr/bin/env python3
"""Shared auth-stage deployment observation: OFF/internal/external, two blocks."""
import csv,json,os,signal,subprocess,threading,time,statistics
from datetime import datetime,timezone
from pathlib import Path
from lab_burst_runner import cmd,ssh,sha,PREP,WRONG
from run_remote_sipp_challenges import ssh_sipp,FIELDS
import measure_external_overhead_20261001 as perf
R=Path('/home/astrix/sip-fraud-research')
O=R/'datasets/deployment-auth-comparison-20261002'
FULL=Path('/var/log/asterisk/full');CDR=Path('/var/log/asterisk/cdr-csv/Master.csv')
BIN=Path('/usr/lib/asterisk/modules/res_sipfraud_lab.so')
BINHASH='02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26'
def cli(s):return cmd(['asterisk','-rx',s])
def utc():return datetime.now(timezone.utc).isoformat()
def getrole(p):
 name=(p/'comm').read_text().strip()
 args=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
 if name=='asterisk':return 'pbx'
 if name.startswith('python') and 'overhead_collector_BT' in args:return 'collector'
 if name.startswith('python') and 'external_event_service.py' in args:return 'service'
 if name=='tshark':return 'decoder'
 if name=='tcpdump':return 'capture'
 return None
perf.role=getrole
def watcher(stop,offset,path,records,ready):
 with FULL.open(errors='replace') as h,path.open('x') as out:
  h.seek(offset);ready.set()
  while not stop.is_set():
   line=h.readline()
   if not line:stop.wait(.002);continue
   if 'SIPFRAUDLAB' in line:
    row={'observed_epoch':time.time(),'observed_monotonic_ns':time.perf_counter_ns(),'line':line.strip()}
    records.append(row);out.write(json.dumps(row)+'\n');out.flush()
def collector_script(sid):
 source=(R/'scripts/live_external_collector_ml.py').read_text()
 replacements=[
 ("OUT = ROOT / 'datasets/live-ml-20261001/B016'",f"OUT = ROOT / 'datasets/deployment-auth-comparison-20261002/{sid}/live'"),
 ("SERVICE = ROOT / 'scripts/external_event_service_ml.py'","SERVICE = ROOT / 'scripts/external_event_service.py'"),
 ("'--port',str(PORT),\n                                        '--ml-model',str(MODEL)","'--port',str(PORT)"),
 ("'model_sha256':sha(MODEL)","'model_scope':'No ML; shared auth-stage rule comparison'"),
 ("if results['OUTBOUND_INVITE'] >= 3 and now-last_packet > 10: break","if (OUT/'STOP').exists(): break"),
 ("flush_due(time.monotonic()+2)","flush_due(time.monotonic())")]
 for old,new in replacements:
  assert source.count(old)==1,old
  source=source.replace(old,new)
 start=source.index("    if error or results['AUTH_REJECTION']!=6")
 end=source.index("\nif __name__=='__main__':",start)
 source=source[:start]+"""    if error or results['AUTH_REJECTION']!=6 or results['REGISTER_SUCCESS']!=1 or results['OUTBOUND_INVITE']!=0 or status['alerts']!=['SUSPECTED_COMPROMISE']:
        raise SystemExit(1)
"""+source[end:]
 target=R/'scripts'/f'overhead_collector_B{sid}.py'
 assert not target.exists();target.write_text(source)
 subprocess.run(['python3','-m','py_compile',str(target)],check=True)
 return target
def main():
 os.umask(0o077)
 assert sha(BIN)==BINHASH
 assert '0 active calls' in cli('core show channels count')
 assert '0 modules loaded' in cli('module show like sipfraud')
 for dest in ['88001','88002']:assert 'no existence' in cli(f'dialplan show {dest}@internal')
 assert '172.16.200.68' in cmd(ssh('ip -4 -brief address show wlan0'))
 reg=R/'datasets/emulated-outbound-runs/.valid_register_1002.xml'
 inv=R/'datasets/emulated-outbound-runs/.valid_invite_1002.xml'
 assert not reg.exists() and not inv.exists()
 prep=R/'scripts/prepare_valid_register_1002.py'
 assert sha(prep)==PREP['1002']
 wrong=Path('/home/astrix/sipp-lab/failed_password_register_1002.xml')
 assert sha(wrong)==WRONG['1002'] and WRONG['1002'] in cmd(ssh('sha256sum /home/sipp/sip-fraud-lab/failed_password_register_1002.xml'))
 O.mkdir(mode=0o700,exist_ok=False)
 cases=[{'id':f'T{i+1:03d}','mode':mode,'block':1 if i<3 else 2}
        for i,mode in enumerate(['OFF','INTERNAL','EXTERNAL','EXTERNAL','INTERNAL','OFF'])]
 scripts={x['id']:collector_script(x['id']) for x in cases if x['mode']=='EXTERNAL'}
 plan={'declared_utc':utc(),'script_sha256':sha(Path(__file__)),'module_sha256':BINHASH,
       'cases':cases,'profile':{'account':'1002','wrong':6,'success':1,'paced_interval_s':2.1,'calls':0},
       'external_collector_hashes':{k:sha(v) for k,v in scripts.items()},
       'shared_endpoint':'SUSPECTED_COMPROMISE review after six failed registrations then valid registration',
       'timing_onset':'Authenticated REGISTER request matched to its successful 200 response using Call-ID and CSeq',
       'internal_endpoint':'Observer timestamps first matching Asterisk module log line; 2ms polling, logger delay included; not internal decision timestamp',
       'external_endpoint':'Collector timestamps service alert reply; capture/decoder/IPC delay included; no ML',
       'resource_window':'Traffic onset through 3s after valid REGISTER completes; startup and offline extraction excluded',
       'limits':'Two blocks, one account/device/PBX. Measured alert availability through different acquisition interfaces, not identical internal algorithms. Module-only memory not isolated. Sampled CPU can miss tails; summed RSS double-counts shared pages. No full-stage equivalence, stress or population claim.'}
 manifest=O/'manifest.json';manifest.write_text(json.dumps(plan,indent=2)+'\n')
 print('DECLARED',sha(manifest),flush=True);results=[]
 remote='/home/sipp/sip-fraud-lab/.valid_register_1002.xml'
 for row in cases:
  sid,mode=row['id'],row['mode'];p=O/sid;p.mkdir()
  assert '0 active calls' in cli('core show channels count')
  loaded=False;capture=live=None;caplog=livelog=None;stop=threading.Event()
  events=[];resources=[];watch=mon=None;error=None;codes=[]
  cdr_before=CDR.read_bytes();(p/'cdr_before.csv').write_bytes(cdr_before)
  offset=FULL.stat().st_size
  try:
   cmd(['python3',str(prep)])
   cmd(['scp','-p','-4','-i','/home/astrix/.ssh/sipp_lab_ed25519','-o','BatchMode=yes',
        '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',str(reg),'sipp@172.16.200.68:'+remote])
   cmd(ssh('chmod 600 '+remote))
   if mode=='INTERNAL':
    assert 'Loaded' in cli('module load res_sipfraud_lab.so');loaded=True
    clean=cli('sipfraud lab status');assert 'account=1002 failures_window=0 auth_alerts=0 review_alerts=0' in clean
    (p/'module_before.txt').write_text(clean)
   if mode=='EXTERNAL':
    livelog=(p/'collector.log').open('x')
    live=subprocess.Popen(['python3','-u',str(scripts[sid])],stdout=livelog,stderr=subprocess.STDOUT)
    for _ in range(100):
     if live.poll() is not None:raise RuntimeError('Collector exited before traffic')
     err=p/'live/capture_stderr.log'
     if err.exists() and 'listening on wlan0' in err.read_text():break
     time.sleep(.1)
    else:raise RuntimeError('Collector not ready')
   caplog=(p/'tcpdump.log').open('x')
   capture=subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0','-w',str(p/'traffic.pcap'),
                  'udp and host 172.16.200.68 and port 5060'],stdout=subprocess.DEVNULL,stderr=caplog)
   time.sleep(1);assert capture.poll() is None
   ready=threading.Event()
   watch=threading.Thread(target=watcher,args=(stop,offset,p/'module_observations.jsonl',events,ready))
   mon=threading.Thread(target=perf.monitor,args=(stop,p/'resources.jsonl',resources))
   watch.start();assert ready.wait(2);mon.start()
   start=time.monotonic();start_utc=utc()
   for i in range(6):
    time.sleep(max(0,start+2.1*i-time.monotonic()))
    result=ssh_sipp('failed_password_register_1002.xml',5134,1002)
    (p/f'wrong_{i+1:02d}.log').write_text(result.stdout+result.stderr)
    codes.append(result.returncode);assert result.returncode==0
   time.sleep(2.2)
   result=ssh_sipp(reg.name,5135,1002);codes.append(result.returncode)
   (p/'register.log').write_text(result.stdout+result.stderr);assert result.returncode==0
   time.sleep(3)
   end=time.monotonic();end_utc=utc()
   stop.set();watch.join();mon.join()
   if loaded:(p/'module_after.txt').write_text(cli('sipfraud lab status'))
   if live:
    (p/'live/STOP').touch();assert live.wait(timeout=12)==0,'Collector failed'
  except Exception as exc:error=type(exc).__name__+': '+str(exc)
  finally:
   stop.set()
   for th in (watch,mon):
    if th:th.join(timeout=3)
   if capture and capture.poll() is None:
    capture.send_signal(signal.SIGINT);capture.wait(timeout=8)
   stopped=utc();(p/'capture_stop.json').write_text(json.dumps({'stopped_utc':stopped})+'\n')
   if caplog:caplog.close()
   if live and live.poll() is None:
    live.terminate()
    try:live.wait(timeout=6)
    except subprocess.TimeoutExpired:live.kill();live.wait()
   if livelog:livelog.close()
   if loaded:cli('module unload res_sipfraud_lab.so')
   cmd(ssh('rm -f -- '+remote));reg.unlink(missing_ok=True);inv.unlink(missing_ok=True)
  with FULL.open(errors='replace') as h:h.seek(offset);lines=h.read().splitlines()
  failures=[x for x in lines if 'Failed to authenticate' in x and '172.16.200.68' in x]
  (p/'failed_auth.log').write_text('\n'.join(failures)+'\n')
  (p/'cdr_after.csv').write_bytes(CDR.read_bytes())
  args=['tshark','-r',str(p/'traffic.pcap'),'-Y','sip','-T','fields','-E','header=y','-E','separator=,','-E','quote=d']
  for f in list(FIELDS)+['sip.CSeq.seq']:args+=['-e',f]
  with (p/'sip_packets.csv').open('x') as h:subprocess.run(args,stdout=h,check=True,timeout=25)
  packets=list(csv.DictReader((p/'sip_packets.csv').open()))
  requests=[x for x in packets if x['ip.src']=='172.16.200.68' and x['sip.Method']=='REGISTER']
  rejects=[x for x in packets if x['ip.src']=='172.16.200.81' and x['sip.Status-Code']=='401' and x['sip.CSeq.method']=='REGISTER']
  successes=[x for x in packets if x['ip.src']=='172.16.200.81' and x['sip.Status-Code']=='200' and x['sip.CSeq.method']=='REGISTER']
  checks={'no_error':error is None,'requests_14':len(requests)==14,'challenges_rejections_13':len(rejects)==13,
   'one_success':len(successes)==1,'six_auth_logs':len(failures)==6,'no_cdr':CDR.read_bytes()==cdr_before,
   'no_invites':not any(x['sip.Method']=='INVITE' for x in packets),'zero_calls':'0 active calls' in cli('core show channels count')}
  latency=None;alert_count=0
  if len(successes)==1:
   success=successes[0]
   trigger=[x for x in requests if x['sip.Call-ID']==success['sip.Call-ID'] and x['sip.CSeq.seq']==success['sip.CSeq.seq']]
   checks['unique_trigger_request']=len(trigger)==1
   onset=float(trigger[0]['frame.time_epoch']) if len(trigger)==1 else None
   if mode=='INTERNAL':
    valid=[x for x in events if 'stage=SUSPECTED_COMPROMISE ' in x['line']]
    checks['one_review']=len(valid)==1;alert_count=len(valid)
    counters=(p/'module_after.txt').read_text()
    checks['native_counters']='account=1002 failures_window=6 auth_alerts=0 review_alerts=1' in counters
    if len(valid)==1 and onset is not None:latency=(valid[0]['observed_epoch']-onset)*1000
   elif mode=='EXTERNAL':
    status=json.loads((p/'live/status.json').read_text())
    alerts=[json.loads(x) for x in (p/'live/alerts.jsonl').read_text().splitlines()]
    checks['external_counts']=not status['error'] and status['counts']=={'AUTH_REJECTION':6,'REGISTER_SUCCESS':1,'OUTBOUND_INVITE':0,'OPTIONS_REQUEST':0}
    checks['one_review']=len(alerts)==1 and alerts[0]['stage']=='SUSPECTED_COMPROMISE';alert_count=len(alerts)
    if len(alerts)==1 and onset is not None:
     latency=(datetime.fromisoformat(alerts[0]['observed_decision_utc']).timestamp()-onset)*1000
   else:checks['no_native_alert']=len(events)==0
  if mode!='OFF':checks['nonnegative_latency']=latency is not None and latency>=0
  first={(x['pid'],x['start_ticks']):x['ticks'] for x in resources[0]['processes']} if resources else {}
  last={};peaks={}
  for snap in resources:
   sums={}
   for x in snap['processes']:
    last[x['pid'],x['start_ticks']]=x;sums[x['role']]=sums.get(x['role'],0)+x['rss_kib']
   for k,v in sums.items():peaks[k]=max(peaks.get(k,0),v)
  cpu={}
  for key,x in last.items():cpu[x['role']]=cpu.get(x['role'],0)+max(0,x['ticks']-first.get(key,x['ticks']))/os.sysconf('SC_CLK_TCK')
  elapsed=end-start if error is None else None
  result={'id':sid,'mode':mode,'block':row['block'],'checks':checks,'verified':all(checks.values()),'error':error,
   'alert_count':alert_count,'request_to_observed_alert_ms':latency,'resource_window_s':elapsed,
   'cpu_seconds_sampled':cpu,'cpu_core_percent':{k:v/elapsed*100 for k,v in cpu.items()} if elapsed else {},
   'peak_rss_kib_by_role':peaks,'pcap_sha256':sha(p/'traffic.pcap'),'capture_stop_utc':stopped,'sipp_exits':codes}
  (p/'verification.json').write_text(json.dumps(result,indent=2)+'\n');results.append(result)
  print('CASE',json.dumps(result),flush=True)
  assert result['verified'],'Verification failed; remaining cases stopped'
 summary={'manifest_sha256':sha(manifest),'cases':results,'all_verified':all(x['verified'] for x in results),
          'latency_ms_by_mode':{m:[x['request_to_observed_alert_ms'] for x in results if x['mode']==m] for m in ['INTERNAL','EXTERNAL']},
          'limitations':plan['limits'],'internal_endpoint':plan['internal_endpoint'],'external_endpoint':plan['external_endpoint']}
 (O/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 assert '0 modules loaded' in cli('module show like sipfraud')
 print('COMPLETE',sha(O/'summary.json'),flush=True)
if __name__=='__main__':main()


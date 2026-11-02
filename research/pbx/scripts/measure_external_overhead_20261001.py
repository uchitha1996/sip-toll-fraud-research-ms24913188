#!/usr/bin/env python3
"""Predeclared preliminary external-on/off comparison; isolated lab only."""
import csv, hashlib, json, os, statistics, subprocess, threading, time
from datetime import datetime, timezone
from pathlib import Path
R=Path('/home/astrix/sip-fraud-research')
O=R/'datasets/external-overhead-20261001'
MODEL=R/'datasets/causal-review-ml-20261001/frozen_model.json'
EXPECTED='ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def cli(s): return subprocess.run(['asterisk','-rx',s],capture_output=True,text=True,check=True).stdout
def role(p):
    name=(p/'comm').read_text().strip()
    cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
    if name=='asterisk': return 'pbx'
    if 'external_event_service_ml.py' in cmd: return 'service'
    if 'overhead_collector_B' in cmd and name.startswith('python'): return 'collector'
    if name=='tshark': return 'decoder'
    if name=='tcpdump': return 'capture'
    return None
def sample():
    rows=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            kind=role(p)
            if not kind: continue
            f=(p/'stat').read_text().rsplit(')',1)[1].split()
            rows.append({'pid':int(p.name),'role':kind,'ticks':int(f[11])+int(f[12]),
                         'start_ticks':int(f[19]),'rss_kib':int(f[21])*os.sysconf('SC_PAGE_SIZE')/1024})
        except (OSError,ValueError,IndexError): continue
    return rows
def monitor(stop,path,records):
    with path.open('x') as h:
        while not stop.is_set():
            row={'monotonic':time.monotonic(),'processes':sample()}
            records.append(row); h.write(json.dumps(row)+'\n');h.flush()
            stop.wait(.25)
def main():
    os.umask(0o077)
    assert sha(MODEL)==EXPECTED and '0 active calls' in cli('core show channels count')
    assert '0 modules loaded' in cli('module show like sipfraud')
    for d in ('88001','88002'): assert 'no existence' in cli(f'dialplan show {d}@internal')
    O.mkdir(mode=0o700,exist_ok=False)
    rows=[dict(id=s,split='development',intent='authorized',account='1002',wrong=6,
               interval=2.1,success=1,call=3,post_register_pause=1.0,
               destination_group='lab-uas',trunk='lab-trunk',detector_enabled=on,pair=pair)
          for s,on,pair in [('B017',False,1),('B018',True,1),('B019',True,2),('B020',False,2)]]
    plan={'created_utc':datetime.now(timezone.utc).isoformat(),'scenarios':rows,
          'frozen_model_sha256':EXPECTED,'runner_sha256':sha(R/'scripts/lab_burst_runner.py'),
          'collector_source_sha256':sha(R/'scripts/live_external_collector_ml.py'),
          'measurement':'First generator INVITE to first PBX INVITE 200 OK, per Call-ID; sampled process CPU/RSS during traffic runner only.',
          'order':'OFF ON ON OFF; two matched pairs; no significance/population claim.',
          'sampling_s':.25,'cpu_unit':'core-equivalent percent; 100% equals one busy core',
          'limits':'CPU counters sampled; short-lived process tails may be missed. RSS sum counts shared pages more than once. Same evidence capture in both arms; on adds detector capture and decoder. No in-process comparison.'}
    manifest=O/'manifest.json';manifest.write_text(json.dumps(plan,indent=2)+'\n')
    print('DECLARED',sha(manifest),flush=True)
    results=[]
    for row in rows:
        sid=row['id']; case=O/sid;case.mkdir()
        assert sha(MODEL)==EXPECTED and '0 active calls' in cli('core show channels count')
        live=None;log=None;records=[];stop=threading.Event()
        thread=threading.Thread(target=monitor,args=(stop,case/'resources.jsonl',records))
        begin=time.monotonic(); thread.start()
        try:
            if row['detector_enabled']:
                source=(R/'scripts/live_external_collector_ml.py').read_text()
                old="OUT = ROOT / 'datasets/live-ml-20261001/B016'"
                assert source.count(old)==1
                new=source.replace(old,f"OUT = ROOT / 'datasets/external-overhead-20261001/{sid}/live'")
                script=R/'scripts'/f'overhead_collector_{sid}.py';script.write_text(new)
                log=(case/'collector.log').open('x')
                live=subprocess.Popen(['python3','-u',str(script)],stdout=log,stderr=subprocess.STDOUT)
                for _ in range(100):
                    if live.poll() is not None: raise RuntimeError('Collector exited before traffic')
                    err=case/'live/capture_stderr.log'
                    if err.exists() and 'listening on wlan0' in err.read_text(): break
                    time.sleep(.1)
                else: raise RuntimeError('Collector not ready')
            run=subprocess.run(['python3','-u',str(R/'scripts/lab_burst_runner.py'),str(manifest),sid],
                               capture_output=True,text=True,timeout=110)
            (case/'runner.log').write_text(run.stdout+run.stderr)
            assert run.returncode==0, 'Traffic run failed'
        finally:
            stop.set();thread.join();elapsed=time.monotonic()-begin
        if live:
            assert live.wait(timeout=35)==0,'Live collector failed'
            log.close()
            status=json.loads((case/'live/status.json').read_text())
            assert not status['error'] and status['counts']['OUTBOUND_INVITE']==3
        rd=R/'datasets/burst-lab-20261001/development'/sid
        check=subprocess.run(['python3',str(R/'scripts/verify_burst_run.py'),str(rd)],
                             capture_output=True,text=True,check=True)
        (case/'verification.log').write_text(check.stdout+check.stderr)
        packets=list(csv.DictReader((rd/'sip_packets.csv').open()))
        ids=json.loads((rd/'independent_verification.json').read_text())['call_ids']
        setup=[]
        for cid in ids:
            leg=[p for p in packets if p['sip.Call-ID']==cid]
            t0=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']=='172.16.200.68' and p['sip.Method']=='INVITE')
            t1=min(float(p['frame.time_epoch']) for p in leg if p['ip.src']=='172.16.200.81' and p['sip.Status-Code']=='200' and p['sip.CSeq.method']=='INVITE')
            setup.append({'call_id':cid,'setup_ms':(t1-t0)*1000})
        first={(x['pid'],x['start_ticks']):x['ticks'] for x in records[0]['processes']}
        last={};peaks={}
        for snap in records:
            sums={}
            for p in snap['processes']:
                last[p['pid'],p['start_ticks']]=p
                sums[p['role']]=sums.get(p['role'],0)+p['rss_kib']
            for k,v in sums.items():peaks[k]=max(peaks.get(k,0),v)
        cpu={}
        for key,p in last.items():
            cpu[p['role']]=cpu.get(p['role'],0)+max(0,p['ticks']-first.get(key,0))/os.sysconf('SC_CLK_TCK')
        result={'id':sid,'detector_enabled':row['detector_enabled'],'pair':row['pair'],
                'runner_window_s':elapsed,'setup':setup,'setup_ms_median':statistics.median(x['setup_ms'] for x in setup),
                'sampled_cpu_seconds':cpu,'cpu_core_percent':{k:v/elapsed*100 for k,v in cpu.items()},
                'peak_summed_rss_kib_by_role':peaks,'verified':True,'pcap_sha256':sha(rd/'traffic.pcap')}
        (case/'summary.json').write_text(json.dumps(result,indent=2)+'\n');results.append(result)
        print('CASE',json.dumps(result),flush=True)
    pairs=[]
    for i in (1,2):
        off=next(x for x in results if x['pair']==i and not x['detector_enabled'])
        on=next(x for x in results if x['pair']==i and x['detector_enabled'])
        pairs.append({'pair':i,'on_minus_off_median_setup_ms':on['setup_ms_median']-off['setup_ms_median']})
    summary={'manifest_sha256':sha(manifest),'results':results,'paired_setup_deltas':pairs,'limitations':plan['limits']}
    (O/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    assert '0 active calls' in cli('core show channels count')
    for d in ('88001','88002'): assert 'no existence' in cli(f'dialplan show {d}@internal')
    print('COMPLETE',sha(O/'summary.json'),flush=True)
if __name__=='__main__':main()


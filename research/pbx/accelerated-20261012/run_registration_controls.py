#!/usr/bin/env python3
"""Fresh bounded repetitions; preserve original stopped P002 without editing it."""
import csv,hashlib,json,shlex,signal,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
import sys
sys.path.insert(0,str(PROJECT/'scripts'))
from run_remote_sipp_challenges import sip_packets
from register_diversity_candidate_20261002 import replay as diversity_replay
KEY=Path('/home/astrix/.ssh/sipp_lab_ed25519')
CDR=Path('/var/log/asterisk/cdr-csv/Master.csv')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.now(timezone.utc).isoformat()
def command(args,timeout=30,input=None):
    r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,input=input)
    if r.returncode:raise RuntimeError('Command failed: '+str(args[0])+' '+r.stderr[-400:])
    return r.stdout
def idle():
    assert '0 active calls' in command(['asterisk','-rx','core show channels count'])
    for d in ['88001','88002']:
        assert 'no existence' in command(['asterisk','-rx','dialplan show '+d+'@internal'])
def main():
    freeze=json.loads((ROOT/'evaluation_freeze.json').read_text())
    assert all(sha(ROOT/name)==digest for name,digest in freeze['sha256'].items())
    manifest=json.loads((ROOT/'prospective_manifest.json').read_text())
    out=ROOT/'registration_controls';out.mkdir(mode=0o700,exist_ok=False)
    results=[]
    idle()
    for case in manifest['registration_controls']:
        start=time.monotonic();idle()
        run=out/case['id'];run.mkdir(mode=0o700)
        before=CDR.read_bytes();(run/'cdr_before.csv').write_bytes(before)
        capture=None;error=None;responses=[]
        try:
            with (run/'tcpdump.log').open('x') as log:
                capture=subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0','-w',str(run/'traffic.pcap'),
                                          'udp and host 172.16.200.68 and port 5060'],stdout=subprocess.DEVNULL,stderr=log)
            time.sleep(1)
            assert capture.poll() is None
            remote='python3 - '+shlex.quote(json.dumps(case['targets']))
            cmd=['ssh','-T','-4','-i',str(KEY),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                 '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6','sipp@172.16.200.68',remote]
            responses=json.loads(command(cmd,input=(ROOT/'register_sender.py').read_text(),timeout=20))
            (run/'sender_records.json').write_text(json.dumps(responses,indent=2))
            time.sleep(1.5)
        except Exception as e:error=str(e)
        finally:
            if capture is not None:
                if capture.poll() is None:capture.send_signal(signal.SIGINT)
                capture.wait(timeout=8)
            (run/'cdr_after.csv').write_bytes(CDR.read_bytes())
        result=dict(id=case['id'],original_reference=case['original_reference'],end_utc=utc(),
                    error=error,verified=False,elapsed_seconds=round(time.monotonic()-start,3))
        try:
            assert error is None,error
            assert result['elapsed_seconds'] <= manifest['p002_troubleshooting_seconds']
            assert before==CDR.read_bytes(),'Unexpected CDR change'
            packets=sip_packets(run/'traffic.pcap',run/'sip_packets.csv')
            requests=[p for p in packets if p['ip.src']=='172.16.200.68' and p['sip.Method']=='REGISTER']
            replies=[p for p in packets if p['ip.src']=='172.16.200.81' and p['sip.CSeq.method']=='REGISTER' and p['sip.Status-Code']]
            sent_ids={r['call_id'] for r in responses}
            assert len(requests)==6 and len(sent_ids)==6 and {p['sip.Call-ID'] for p in requests}==sent_ids
            assert {p['sip.Call-ID'] for p in replies}==sent_ids,'Missing captured PBX response'
            assert sorted(p['sip.to.user'] for p in requests)==sorted(case['targets'])
            assert not any(p['sip.Method']=='INVITE' for p in packets)
            assert '0 packets dropped by kernel' in (run/'tcpdump.log').read_text()
            alerts=diversity_replay(run/'sip_packets.csv')
            result.update(verified=True,pcap_sha256=sha(run/'traffic.pcap'),requests=6,response_transactions=6,
                          unique_targets=len(set(case['targets'])),unknown_account_requests=sum(t not in ['1001','1002'] for t in case['targets']),
                          candidate_diversity_alerts=alerts,cdr_delta=0)
        except Exception as e:result['error']=str(e)
        (run/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
        results.append(result);print(json.dumps(result),flush=True)
        idle()
    summary=dict(cases=results,verified=sum(c['verified'] for c in results),total=4,
                 interpretation='REGISTER account diversity controls only; known/unknown identities do not establish fraud intent',
                 original_P002='Historical timeout retained unchanged; P102 is new traffic with revised observation boundary')
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('REGISTRATION CONTROLS COMPLETE',summary['verified'],'/4',flush=True)
if __name__=='__main__':main()

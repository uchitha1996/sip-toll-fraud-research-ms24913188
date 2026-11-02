#!/usr/bin/env python3
"""Bounded REGISTER target-diversity experiment; lab only; no authentication."""
import csv,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/home/astrix/sip-fraud-research')
sys.path.insert(0,str(ROOT/'scripts'))
import lab_batch_runner as runner
from run_remote_sipp_challenges import sip_packets
BASE=ROOT/'datasets/register-enumeration-20261002'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def main():
    os.umask(0o077)
    prior=ROOT/'datasets/literature-development-20261002/summary.json'
    assert json.loads(prior.read_text())['status']=='complete'
    assert '0 active calls' in runner.cmd(['asterisk','-rx','core show channels count'])
    for target in range(9001,9007):
        result=runner.cmd(['asterisk','-rx',f'pjsip show endpoint {target}'])
        assert 'Unable to find object' in result, 'Target must be unused'
    assert not BASE.exists()
    BASE.mkdir(mode=0o700)
    cases=[dict(id='RE001',targets=['9001']*6,label='MISCONFIGURATION_CONTROL'),
           dict(id='RE002',targets=[str(x) for x in range(9001,9007)],label='RECONNAISSANCE_PROBE')]
    protocol=dict(declared_utc=utc(),wrapper_sha256=sha(Path(__file__)),cases=cases,
        limits='Six unauthenticated REGISTER queries per case to unused lab IDs; one per second; no password guess or INVITE.',
        grouping='Same generator/session. Development gap test, not held-out fraud classification.',
        source='https://doi.org/10.1007/978-3-319-60774-0_9')
    manifest=BASE/'manifest.json'
    manifest.write_text(json.dumps(protocol,indent=2)+'\n')
    sender_code="""import socket,time,json,uuid,sys
targets=json.loads(sys.argv[1])
assert len(targets)==6 and set(targets)<=set(str(x) for x in range(9001,9007))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('172.16.200.68',5127));s.settimeout(2)
records=[]
for target in targets:
    cid='enum-'+uuid.uuid4().hex
    message='\\r\\n'.join([
      'REGISTER sip:172.16.200.81 SIP/2.0',
      'Via: SIP/2.0/UDP 172.16.200.68:5127;branch=z9hG4bK-'+cid,
      'Max-Forwards: 70',
      'From: <sip:'+target+'@172.16.200.81>;tag='+cid,
      'To: <sip:'+target+'@172.16.200.81>',
      'Call-ID: '+cid,'CSeq: 1 REGISTER',
      'Contact: <sip:'+target+'@172.16.200.68:5127>',
      'Expires: 0','Content-Length: 0','',''])
    started=time.time()
    s.sendto(message.encode(),('172.16.200.81',5060))
    reply,addr=s.recvfrom(4096)
    assert addr[0]=='172.16.200.81'
    records.append(dict(target=target,call_id=cid,response=reply.split(b'\\r\\n')[0].decode(),source_port=5127))
    time.sleep(max(0,started+1-time.time()))
s.close()
print(json.dumps(records))
"""
    (BASE/'generator_sender.py').write_text(sender_code)
    results=[]
    for row in cases:
        print('START',row['id'],flush=True)
        run=BASE/row['id'];run.mkdir(mode=0o700)
        (run/'cdr_before.csv').write_bytes(runner.CDR.read_bytes())
        offset=runner.FULL.stat().st_size
        cap=None
        error=None
        try:
            with (run/'tcpdump.log').open('x') as log:
                cap=subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0',
                    '-w',str(run/'traffic.pcap'),'udp and host 172.16.200.68 and port 5060'],
                    stdout=subprocess.DEVNULL,stderr=log)
                time.sleep(1)
                assert cap.poll() is None
                import shlex
                cmd='python3 - '+shlex.quote(json.dumps(row['targets']))
                remote=subprocess.run(runner.ssh(cmd),input=sender_code,capture_output=True,text=True,timeout=30)
                (run/'sender_stdout.json').write_text(remote.stdout)
                (run/'sender_stderr.txt').write_text(remote.stderr)
                assert remote.returncode==0
                assert len(json.loads(remote.stdout))==6
                time.sleep(2)
        except Exception as exc: error=repr(exc)
        finally:
            if cap is not None and cap.poll() is None:cap.send_signal(signal.SIGINT)
            if cap is not None:cap.wait(timeout=8)
            (run/'cdr_after.csv').write_bytes(runner.CDR.read_bytes())
            with runner.FULL.open(errors='replace') as f:
                f.seek(offset)
                (run/'asterisk_log_excerpt.txt').write_text(''.join(l for l in f if runner.GEN in l))
        assert error is None,error
        assert (run/'cdr_before.csv').read_bytes()==(run/'cdr_after.csv').read_bytes()
        packets=sip_packets(run/'traffic.pcap',run/'sip_packets.csv')
        requests=[p for p in packets if p['sip.Method']=='REGISTER' and p['ip.src']==runner.GEN]
        replies=[p for p in packets if p['sip.CSeq.method']=='REGISTER' and p['ip.src']==runner.PBX and p['sip.Status-Code']]
        assert len(requests)==len(replies)==6
        assert len({p['sip.Call-ID'] for p in requests})==6
        assert sorted(p['sip.to.user'] for p in requests)==sorted(row['targets'])
        end=utc()
        subprocess.run(['python3',str(ROOT/'scripts/candidate_v5_replay.py'),str(run/'traffic.pcap'),
            str(run/'v5_replay'),'--observation-end-utc',end],check=True,capture_output=True,text=True)
        v5=json.loads((run/'v5_replay/candidate_summary.json').read_text())
        from stream_progression_prototype import Progression
        # Existing event adapter emits REGISTER_SUCCESS/confirmed failure only, not REGISTER request diversity.
        with (run/'v5_replay/candidate_timeline.csv').open() as f:timeline=list(csv.DictReader(f))
        engine=Progression()
        alerts=[]
        for item in timeline:
            kind='AUTH_REJECTION' if item['event_type']=='CONFIRMED_REJECTION' else None
            if item['event_type']=='REGISTER_FINAL_RESPONSE' and item['status']=='200':kind='REGISTER_SUCCESS'
            if kind:
                alerts.extend(engine.accept(dict(event_id=item['event_number'],time_utc=item['time_utc'],
                    source_ip=item['entity'],account=item['target'],kind=kind,call_id=item['call_id'])))
        entry=dict(id=row['id'],label=row['label'],verified=True,unique_register_targets=len(set(row['targets'])),
            request_dialogs=6,response_codes=sorted(set(p['sip.Status-Code'] for p in replies)),
            pcap_sha256=sha(run/'traffic.pcap'),v5_counts=v5['counts'],
            current_progression_stages=[a['stage'] for a in alerts],cdr_delta=0,
            limitation='Unauthenticated unused-account probe; no confirmed guessing, compromise, DoS or demonstrated valid-ID discovery.')
        (run/'verification.json').write_text(json.dumps(entry,indent=2)+'\n')
        results.append(entry);print('DONE',json.dumps(entry),flush=True)
    postflight=runner.cmd(['asterisk','-rx','core show channels count']).strip()
    assert '0 active calls' in postflight
    (BASE/'summary.json').write_text(json.dumps(dict(status='complete',cases=results,postflight=postflight,
        manifest_sha256=sha(manifest),wrapper_sha256=sha(Path(__file__))),indent=2)+'\n')
if __name__=='__main__':main()

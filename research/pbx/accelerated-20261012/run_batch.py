#!/usr/bin/env python3
"""Capture, independently verify, then label-blind evaluate the frozen cases."""
import csv,fcntl,hashlib,json,statistics,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
from common_evaluator import predictions,load_v6,read_csv,confusion
ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
sys.path.insert(0,str(PROJECT/'scripts'))
import candidate_v5_replay as v5

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def command(args):
    r=subprocess.run(args,capture_output=True,text=True,timeout=25)
    if r.returncode:raise RuntimeError('Command failed: '+str(args[0]))
    return r.stdout
def idle():
    assert '0 active calls' in command(['asterisk','-rx','core show channels count'])
    for d in ['88001','88002']:
        assert 'no existence' in command(['asterisk','-rx','dialplan show '+d+'@internal'])
def check_freeze():
    freeze=json.loads((ROOT/'evaluation_freeze.json').read_text())
    assert all(sha(ROOT/name)==digest for name,digest in freeze['sha256'].items())
    assert sha(PROJECT/'scripts/progression_v6_development.py')==freeze['original_v6_sha256']
    assert sha(PROJECT/'scripts/candidate_v5_replay.py')==freeze['original_v5_sha256']

def verify(row,run):
    status=json.loads((run/'run_status.json').read_text())
    assert status['status']=='captured' and status['error'] is None and not status['cleanup_errors'],status
    assert sha(run/'traffic.pcap')==status['capture_sha256']
    assert '0 packets dropped by kernel' in (run/'tcpdump.log').read_text()
    packets=read_csv(run/'sip_packets.csv')
    before=list(csv.reader((run/'cdr_before.csv').open()))
    after=list(csv.reader((run/'cdr_after.csv').open()))
    assert after[:len(before)]==before,'CDR snapshot mismatch'
    delta=after[len(before):]
    assert len(delta)==row['call'],'CDR delta mismatch'
    for cdr in delta:
        assert cdr[1:3]==[row['account'],row['destination']]
        assert cdr[14]=='ANSWERED' and int(cdr[13])==6
    failed_lines=(run/'asterisk_failed_auth_evidence.txt').read_text().splitlines()
    assert len(failed_lines)==row['wrong'],('PBX auth count mismatch',len(failed_lines),row['wrong'])
    stop=status.get('capture_end_utc',status['end_utc'])
    v5.replay(run/'traffic.pcap',run/'v5',v5.epoch(stop),None)
    counts=json.loads((run/'v5/candidate_summary.json').read_text())['counts']
    assert counts.get('confirmed_rejected_digest_dialogs',0)==row['wrong'],counts
    assert counts.get('successful_register_200',0)==row['success'],counts
    assert counts.get('unresolved_at_observation_end',0)==0,counts
    calls={p['sip.Call-ID'] for p in packets if p['ip.src']=='172.16.200.68' and p['sip.Method']=='INVITE'}
    assert len(calls)==row['call'],('INVITE call count',calls)
    for cid in calls:
        leg=[p for p in packets if p['sip.Call-ID']==cid]
        assert any(p['ip.src']=='172.16.200.81' and p['sip.Status-Code']=='200' and p['sip.CSeq.method']=='INVITE' for p in leg)
        assert any(p['ip.src']=='172.16.200.68' and p['sip.Method']=='ACK' for p in leg)
        assert any(p['sip.Method']=='BYE' for p in leg)
        assert all((p['sip.r-uri.user'] or p['sip.to.user'])==row['destination']
                   for p in leg if p['ip.src']=='172.16.200.68' and p['sip.Method']=='INVITE')
    idle()
    return dict(case=row['id'],verified=True,pcap_sha256=sha(run/'traffic.pcap'),
                v5_timeline_sha256=sha(run/'v5/candidate_timeline.csv'),confirmed_rejections=row['wrong'],
                successful_register=row['success'],answered_cdr_delta=len(delta),call_ids=sorted(calls),
                capture_end_utc=stop,cleanup='idle and both temporary routes absent')

def aggregate(cases,invalid,manifest):
    metrics={}
    for method in manifest['methods']:
        rows=[dict(id=c['id'],truth=int(c['intent']=='SIMULATED_ABUSE'),**c['predictions'][method]) for c in cases]
        m=confusion(rows)
        m['false_alert_cases']=[r['id'] for r in rows if not r['truth'] and r['predicted']]
        m['missed_cases']=[r['id'] for r in rows if r['truth'] and not r['predicted']]
        attack_calls=[r for r in rows if r['truth'] and r['first_outbound_attempt_epoch'] is not None]
        early=[r['lead_time_seconds'] for r in attack_calls if r['alert_strictly_before_first_invite']]
        m['early_warning_attack_calls']=sum(r['alert_strictly_before_first_invite'] for r in attack_calls)
        m['attack_calls_denominator']=len(attack_calls)
        m['early_warning_fraction']=len(early)/len(attack_calls) if attack_calls else None
        m['positive_early_lead_median_seconds']=statistics.median(early) if early else None
        # Missed and at-attempt observations stay in the denominator and per-case table.
        metrics[method]=m
    return dict(finished_utc=datetime.now(timezone.utc).isoformat(),declared=len(manifest['scenarios']),
                verified=len(cases),incomplete=invalid,methods=metrics,cases=cases,
                answered_calls=sum(c['verification']['answered_cdr_delta'] for c in cases),
                endpoint=manifest['role_endpoint'],unit=manifest['evaluation_unit'],
                caveats=manifest['limits'],policy_scope='Independent fixed lab permission matrix, no generic compromise proof',
                native_comparison='Native observer left unloaded; this batch does not alter earlier native/external results',
                reproducibility='All original code, policy, runner, manifest and individual captures hashed; deterministic replay')

def main():
    lock=(ROOT/'batch.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    check_freeze();idle()
    assert not (ROOT/'final_results.json').exists()
    manifest=json.loads((ROOT/'prospective_manifest.json').read_text())
    policy=json.loads((ROOT/'policy.json').read_text())
    model=load_v6(ROOT/'frozen/progression_v6_development.py')
    results=[];invalid=[]
    for row in manifest['scenarios']:
        check_freeze();idle()
        run=ROOT/'runs/fresh'/row['id']
        if run.exists():raise RuntimeError('Case directory already exists; never overwrite evidence')
        print('START',row['id'],row['profile'],flush=True)
        with (ROOT/('runner_'+row['id']+'.log')).open('x') as log:
            try:
                result=subprocess.run([sys.executable,str(ROOT/'run_lab_case.py'),str(ROOT/'prospective_manifest.json'),row['id']],
                                      stdout=log,stderr=subprocess.STDOUT,timeout=180)
                assert result.returncode==0,'Runner failed; inspect its retained log'
                verification=verify(row,run)
                dump(run/'independent_verification.json',verification)
                # Detector APIs receive no row, label, expected count or CDR.
                predicted,decisions=predictions(read_csv(run/'v5/candidate_timeline.csv'),read_csv(run/'sip_packets.csv'),model,policy)
                # Descriptive parity check against the frozen original; never feeds predictions.
                offline,_=model.evaluate(run,run/'v5/candidate_timeline.csv',set(policy['lab_destinations']))
                online_expected=[a for a in offline if a['stage'] in {'RECONNAISSANCE','AUTHENTICATION_ATTACK','SUSPECTED_COMPROMISE','SUSPECTED_OUTBOUND_ATTEMPT'}]
                assert predicted['V6']['alerts']==online_expected,'Frozen replay parity mismatch'
                dump(run/'label_blind_predictions.json',dict(predictions=predicted,context_decisions=decisions))
                item=dict(id=row['id'],intent=row['intent'],profile=row['profile'],verification=verification,predictions=predicted)
                results.append(item)
                print('VERIFIED',row['id'],{k:v['predicted'] for k,v in predicted.items()},flush=True)
            except Exception as e:
                invalid.append(dict(id=row['id'],error=str(e)))
                print('INCOMPLETE',row['id'],str(e),flush=True)
                idle()  # Stop immediately if cleanup is unsafe.
        dump(ROOT/'interim_results.json',aggregate(results,invalid,manifest))
    check_freeze();idle()
    summary=aggregate(results,invalid,manifest)
    dump(ROOT/'final_results.json',summary)
    flat=[]
    for c in results:
        for method,p in c['predictions'].items():
            flat.append(dict(case=c['id'],truth=c['intent'],method=method,
                             **{k:v for k,v in p.items() if k!='alerts'}))
    with (ROOT/'per_case_metrics.csv').open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0]));w.writeheader();w.writerows(flat)
    dump(ROOT/'results_freeze.json',dict(frozen_utc=datetime.now(timezone.utc).isoformat(),
         hashes={name:sha(ROOT/name) for name in ['final_results.json','per_case_metrics.csv','evaluation_freeze.json','policy.json','prospective_manifest.json']},
         original_v6_unchanged=sha(PROJECT/'scripts/progression_v6_development.py')==sha(ROOT/'frozen/progression_v6_development.py')))
    print('FINAL',summary['verified'],'/',summary['declared'],'calls',summary['answered_calls'],flush=True)

if __name__=='__main__':main()

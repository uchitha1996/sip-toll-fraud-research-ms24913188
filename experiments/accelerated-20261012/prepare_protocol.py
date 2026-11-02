#!/usr/bin/env python3
"""Write independent account policy and fresh test protocol before any traffic."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write(name, value):
    with (ROOT/name).open('x') as f: json.dump(value,f,indent=2); f.write('\n')

def main():
    now=datetime.now(timezone.utc)
    policy=dict(version=1,created_utc=now.isoformat(),origin='Predeclared lab administrator account/destination permissions',
                lab_source_ip='172.16.200.68',lab_pbx_ip='172.16.200.81',lab_destinations=['88001','88002'],
                accounts={a:dict(sources=['172.16.200.68'],registration_allowed=True,allowed_destinations=[d])
                          for a,d in [('1001','88001'),('1002','88002')]},
                recovery_permissions=[dict(permission_reference='LAB-MAINT-20261012-A',source_ip='172.16.200.68',
                                           account='1001',valid_from_utc=now.isoformat(),
                                           valid_until_utc=(now+timedelta(hours=2)).isoformat(),max_confirmed_failures=8)],
                unknown_rule='Missing identity/source/recovery evidence remains unknown; it does not become benign',
                output_rule='Preserve every V6 stage; contextual review may reduce actionable alerts only for allowed recovery',
                boundary='Same-account attacker using allowed destination during maintenance remains indistinguishable; no proven fraud intent')
    write('policy.json',policy)
    # Fixed policy has no scenario IDs, intent labels or per-test permissions.
    settings=[
        ('C001','BENIGN','1001',0,1,1,'88001','normal_allowed_call'),
        ('C002','BENIGN','1002',0,1,1,'88002','second_account_allowed_call'),
        ('C003','BENIGN','1001',6,1,1,'88001','authorized_recovery_with_predeclared_permission'),
        ('C004','BENIGN','1002',6,1,1,'88002','legitimate_recovery_without_observed_maintenance_permission'),
        ('C005','BENIGN','1001',2,1,0,'88001','mistype_then_register_no_call'),
        ('C006','BENIGN','1002',2,0,0,'88002','two_wrong_dialogs_no_success'),
        ('C007','SIMULATED_ABUSE','1001',6,1,1,'88002','recovery_followed_by_forbidden_destination'),
        ('C008','SIMULATED_ABUSE','1002',6,1,1,'88001','recovery_without_permission_then_forbidden_destination'),
        ('C009','SIMULATED_ABUSE','1001',0,1,1,'88002','direct_forbidden_destination_without_auth_attack'),
        ('C010','SIMULATED_ABUSE','1002',10,0,0,'88002','ten_failed_auth_dialogs_no_call'),
        ('C011','SIMULATED_ABUSE','1001',6,1,1,'88001','matched_hidden_role_within_allowed_policy'),
        ('C012','SIMULATED_ABUSE','1002',6,1,1,'88002','matched_hidden_role_without_recovery_permission')]
    cases=[dict(id=sid,split='fresh',intent=intent,account=account,wrong=wrong,success=success,call=call,
                destination=destination,interval=1.8,post_register_pause=1.2 if call else 0,profile=profile)
           for sid,intent,account,wrong,success,call,destination,profile in settings]
    controls=[dict(id='P101',original_reference='P001',targets=['1001']*6),
              dict(id='P102',original_reference='P002',targets=['1001','1002']*3),
              dict(id='P103',original_reference='P003',targets=['9001']*6),
              dict(id='P104',original_reference='P004',targets=[str(x) for x in range(9001,9007)])]
    write('prospective_manifest.json',dict(created_utc=now.isoformat(),fixed_before_traffic=True,
        role_endpoint='Assigned BENIGN versus SIMULATED_ABUSE role; permission violation is separate observable evidence',
        evaluation_unit='One complete isolated case; failed/incomplete cases excluded with explicit accounting',
        methods=['baseline_10','baseline_5_sensitivity','V6','V6_context'],
        observation_boundary='All causal SIP events through capture end, zero future CDR inputs; early means strictly before first client INVITE',
        primary_baseline='10 confirmed failures in 60s per source/account',
        sensitivity='5 confirmed failures in 60s, predeclared to avoid favorable baseline selection',
        historical_data_use='Previously inspected archives are integrity checks and demonstrations only',
        label_blindness='Policy and predictions functions accept events only. Attach assigned roles after predicting',
        scope='Isolated two-Pi lab, no PSTN, one case at a time, native observer remains unloaded',
        max_answered_lab_calls=sum(x['call'] for x in cases),max_wrong_password_dialogs=sum(x['wrong'] for x in cases),
        registration_controls=controls,control_request_cap=24,p002_troubleshooting_seconds=120,
        control_boundary='Revised send-only generator; verify request and response transactions independently from PBX PCAP. Original P002 remains incomplete',
        scenarios=cases,matched_groups=[['C003','C011'],['C004','C012']],
        limits=['One source/PBX/day/two accounts','Two-account shared-source control is not five-account NAT validation',
                'Assigned intent cannot be inferred when policy-observable evidence is identical',
                'Replay event-clock lead time excludes online capture/delivery/processing latency']))
    names=['common_evaluator.py','run_lab_case.py','run_batch.py','run_registration_controls.py',
           'register_sender.py','prepare_protocol.py','test_common_evaluator.py','policy.json','prospective_manifest.json']
    hashes={name:sha(ROOT/name) for name in names}
    write('evaluation_freeze.json',dict(frozen_utc=datetime.now(timezone.utc).isoformat(),sha256=hashes,
                                      original_v6_sha256=sha(ROOT/'frozen/progression_v6_development.py'),
                                      original_v5_sha256=sha(ROOT/'frozen/candidate_v5_replay.py')))
    print(json.dumps({'frozen':True,'cases':len(cases),'registration_controls':4,'calls':sum(x['call'] for x in cases),'hashes':hashes}))

if __name__=='__main__':main()

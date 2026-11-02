#!/usr/bin/env python3
"""Serial lab runner and evidence gate. Stop on the first incomplete scenario."""
import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path('/home/astrix/sip-fraud-research')
BASE = ROOT / 'datasets/ml-lab-20260930'
MANIFEST = BASE / 'ml_protocol_manifest.json'
SCRIPTS = ROOT / 'scripts'
GEN, PBX = '172.16.200.68', '172.16.200.81'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def rows(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))

def cdr_rows(path):
    with path.open(newline='') as stream:
        return list(csv.reader(stream))

def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f'{args[1]} failed ({result.returncode}): {result.stdout[-400:]} {result.stderr[-400:]}')
    print(result.stdout.strip(), flush=True)

def inspect(row):
    run = BASE / row['split'] / row['id']
    plan = json.loads((run / 'predeclared_protocol.json').read_text())
    state = json.loads((run / 'run_status.json').read_text())
    assert plan['manifest_sha256'] == digest(MANIFEST) and all(plan[k] == v for k, v in row.items())
    assert state['status'] == 'captured' and state['error'] is None and not state['cleanup_errors']
    assert state['capture_sha256'] == digest(run / 'traffic.pcap')
    packets = rows(run / 'sip_packets.csv')
    assert len(packets) >= 2
    failures = (run / 'asterisk_failed_auth_evidence.txt').read_text().splitlines()
    assert len(failures) == row['wrong']
    before, after = cdr_rows(run / 'cdr_before.csv'), cdr_rows(run / 'cdr_after.csv')
    assert after[:len(before)] == before
    delta = after[len(before):]
    assert len(delta) == row['call']
    destination = plan['destination']
    if row['call']:
        assert delta[0][1:3] == [row['account'], destination]
        assert delta[0][14] == 'ANSWERED' and int(delta[0][13]) >= 5
    def match(p, src, dst, method='', code='', cseq=''):
        return (p['ip.src'] == src and p['ip.dst'] == dst
                and (not method or p['sip.Method'] == method)
                and (not code or p['sip.Status-Code'] == code)
                and (not cseq or p['sip.CSeq.method'] == cseq))
    assert sum(match(p, PBX, GEN, code='200', cseq='REGISTER') for p in packets) == row['success']
    client = {p['sip.Call-ID'] for p in packets if match(p, GEN, PBX, method='INVITE')
              and p['sip.r-uri.user'] == destination}
    outbound = {p['sip.Call-ID'] for p in packets if match(p, PBX, GEN, method='INVITE')
                and p['sip.r-uri.user'] == destination}
    assert len(client) == len(outbound) == row['call']
    if row['call']:
        assert client != outbound
        for cid, response_src, response_dst, ack_src, ack_dst in (
                (next(iter(client)), PBX, GEN, GEN, PBX),
                (next(iter(outbound)), GEN, PBX, PBX, GEN)):
            leg = [p for p in packets if p['sip.Call-ID'] == cid]
            assert any(match(p, response_src, response_dst, code='200', cseq='INVITE') for p in leg)
            assert any(match(p, ack_src, ack_dst, method='ACK') for p in leg)
            assert any(p['sip.Method'] == 'BYE' for p in leg)
    v5 = json.loads((run / 'v5_replay/candidate_summary.json').read_text())
    v6 = json.loads((run / 'v6_replay/progression_summary.json').read_text())
    assert v5['pcap_sha256'] == state['capture_sha256']
    assert v5['counts'].get('confirmed_rejected_digest_dialogs', 0) == row['wrong']
    assert v5['counts'].get('successful_register_200', 0) == row['success']
    assert v6['counts']['confirmed_rejections'] == row['wrong']
    assert v6['counts']['new_cdr_rows'] == row['call']
    route = subprocess.run(['asterisk', '-rx', f'dialplan show {destination}@internal'],
                           capture_output=True, text=True, timeout=15)
    assert 'no existence' in route.stdout
    result = {'scenario_id': row['id'], 'verified': True, 'packets': len(packets),
              'failed_auth_lines': len(failures), 'cdr_delta': len(delta),
              'cdr_billsec': int(delta[0][13]) if delta else 0,
              'v5_first_alert': v5['first_alert_stage'], 'v6_stages': v6['stages'],
              'pcap_sha256': state['capture_sha256']}
    (run / 'independent_verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)

def process(row, execute):
    run = BASE / row['split'] / row['id']
    if execute:
        assert not run.exists(), f'Existing run {run}; never overwrite evidence'
        command(['python3', str(SCRIPTS / 'lab_batch_runner.py'), str(MANIFEST), row['id']])
    assert (run / 'run_status.json').exists()
    if not (run / 'v5_replay/candidate_summary.json').exists():
        end = json.loads((run / 'run_status.json').read_text())['end_utc']
        command(['python3', str(SCRIPTS / 'candidate_v5_replay.py'), str(run / 'traffic.pcap'),
                 str(run / 'v5_replay'), '--observation-end-utc', end])
    if not (run / 'v6_replay/progression_summary.json').exists():
        command(['python3', str(SCRIPTS / 'progression_v6_development.py'), str(run),
                 '--v5-timeline', str(run / 'v5_replay/candidate_timeline.csv'),
                 '--lab-destination', json.loads((run / 'predeclared_protocol.json').read_text())['destination'],
                 '--output-dir', str(run / 'v6_replay')])
    inspect(row)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('split', choices=['development', 'heldout'])
    parser.add_argument('--start', type=int, default=1)
    parser.add_argument('--end', type=int, default=999)
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    for index, row in enumerate((r for r in manifest['scenarios'] if r['split'] == args.split), 1):
        if args.start <= index <= args.end:
            print(f'START {row["id"]} {row["split"]}', flush=True)
            process(row, execute=not (BASE / row['split'] / row['id']).exists())
            print(f'DONE {row["id"]}', flush=True)

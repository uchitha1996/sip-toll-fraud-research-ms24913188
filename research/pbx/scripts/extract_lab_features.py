#!/usr/bin/env python3
"""Export scenario features from verified SIP/CDR evidence, excluding rule outputs."""
import argparse
import csv
import hashlib
import json
from datetime import datetime
from pathlib import Path

BASE = Path('/home/astrix/sip-fraud-research/datasets/ml-lab-20260930')
GEN = '172.16.200.68'

def rows(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))

def when(iso):
    return datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()

def span(values):
    return max(values) - min(values) if len(values) > 1 else 0.0

def peak(values, window):
    values = sorted(values)
    return max((sum(t - window <= v <= t for v in values) for t in values), default=0)

def extract(row):
    root = BASE / row['split'] / row['id']
    status = json.loads((root / 'run_status.json').read_text())
    verification = json.loads((root / 'independent_verification.json').read_text())
    assert verification['verified'] and verification['pcap_sha256'] == status['capture_sha256']
    assert hashlib.sha256((root / 'traffic.pcap').read_bytes()).hexdigest() == status['capture_sha256']
    packets = rows(root / 'sip_packets.csv')
    timeline = rows(root / 'v5_replay/candidate_timeline.csv')
    req = [p for p in packets if p['ip.src'] == GEN and p['sip.Method']]
    req_times = [float(p['frame.time_epoch']) for p in req]
    reject = [when(e['time_utc']) for e in timeline if e['event_type'] == 'CONFIRMED_REJECTION']
    success = [when(e['time_utc']) for e in timeline if e['event_type'] == 'REGISTER_FINAL_RESPONSE'
               and e['status'] == '200']
    invites = [when(e['time_utc']) for e in timeline if e['event_type'] == 'REQUEST'
               and e['method'] == 'INVITE' and e['entity'] == GEN]
    with (root / 'cdr_before.csv').open(newline='') as handle:
        before = list(csv.reader(handle))
    with (root / 'cdr_after.csv').open(newline='') as handle:
        after = list(csv.reader(handle))
    assert after[:len(before)] == before
    delta = after[len(before):]
    billsec = sum(int(c[13]) for c in delta if c[14] == 'ANSWERED' and c[13].isdigit())
    profile = '|'.join(str(row[k]) for k in
                       ('account','wrong','interval','success','call','post_register_pause'))
    features = {
        'scenario_id': row['id'], 'split': row['split'], 'intent': row['intent'],
        'profile_group': profile, 'pcap_sha256': status['capture_sha256'],
        'confirmed_rejections': len(reject),
        'max_rejections_10s': peak(reject, 10.0),
        'rejection_span_s': round(span(reject), 4),
        'register_200': len(success),
        'client_invite_requests': len(invites),
        'client_options_requests': sum(p['sip.Method'] == 'OPTIONS' for p in req),
        'capture_request_span_s': round(span(req_times), 4),
        'rejection_to_success_s': round(min(success) - min(reject), 4) if reject and success else -1.0,
        'success_to_invite_s': round(min(invites) - min(success), 4) if success and invites else -1.0,
        'cdr_answered': sum(c[14] == 'ANSWERED' for c in delta),
        'cdr_billsec': billsec,
    }
    assert features['confirmed_rejections'] == row['wrong']
    assert features['register_200'] == row['success']
    assert features['cdr_answered'] == row['call']
    return features

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('split', choices=['development', 'heldout'])
    args = parser.parse_args()
    manifest = json.loads((BASE / 'ml_protocol_manifest.json').read_text())
    data = [extract(row) for row in manifest['scenarios'] if row['split'] == args.split]
    output = BASE / f'{args.split}_features.csv'
    with output.open('x', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(data[0]))
        writer.writeheader()
        writer.writerows(data)
    print(json.dumps({'split': args.split, 'rows': len(data), 'path': str(output),
                      'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}))

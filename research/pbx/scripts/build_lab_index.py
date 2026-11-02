#!/usr/bin/env python3
"""Make a compact, hash-linked inventory of all verified lab captures."""
import hashlib
import json
from pathlib import Path

BASE = Path('/home/astrix/sip-fraud-research/datasets/ml-lab-20260930')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    manifest = json.loads((BASE / 'ml_protocol_manifest.json').read_text())
    inventory = {}
    heldout = {}
    for row in manifest['scenarios']:
        root = BASE / row['split'] / row['id']
        verification = json.loads((root / 'independent_verification.json').read_text())
        state = json.loads((root / 'run_status.json').read_text())
        v5 = json.loads((root / 'v5_replay/candidate_summary.json').read_text())
        v6 = json.loads((root / 'v6_replay/progression_summary.json').read_text())
        assert verification['verified'] and state['status'] == 'captured'
        assert sha(root / 'traffic.pcap') == state['capture_sha256'] == verification['pcap_sha256']
        entry = {'split': row['split'], 'assigned_intent': row['intent'],
                 'run_dir': str(root), 'start_utc': state['start_utc'],
                 'end_utc': state['end_utc'], 'pcap_sha256': verification['pcap_sha256'],
                 'verification': verification, 'v5_first_alert': v5['first_alert_stage'],
                 'v6_stages': v6['stages'],
                 'v5_timeline_sha256': sha(root / 'v5_replay/candidate_timeline.csv'),
                 'v6_summary_sha256': sha(root / 'v6_replay/progression_summary.json')}
        inventory[row['id']] = entry
        if row['split'] == 'heldout':
            heldout[row['id']] = {'verification': verification,
                                  'v6': {'stages': v6['stages']}}
    assert len(inventory) == 34 and len(heldout) == 10
    for name, data in [('evidence_index.json', inventory),
                       ('heldout_stage_inventory.json', heldout)]:
        path = BASE / name
        path.write_text(json.dumps(data, indent=2) + '\n')
        print(name, len(data), sha(path))

if __name__ == '__main__':
    main()

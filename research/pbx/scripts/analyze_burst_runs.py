#!/usr/bin/env python3
"""Read-only postcapture replay of predeclared three-call lab bursts."""
import hashlib
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

from adapt_checkpoint_events import adapt, when
from stream_progression_prototype import Progression

ROOT = Path('/home/astrix/sip-fraud-research')
MANIFEST = ROOT / 'datasets/burst_development_manifest_20261001.json'
BASE = ROOT / 'datasets/burst-lab-20261001'
OUT = BASE / 'event_time_analysis'
SCRIPTS = ROOT / 'scripts'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    plan = json.loads(MANIFEST.read_text())
    assert len(plan['scenarios']) == 4
    for row in plan['scenarios']:
        run = BASE / row['split'] / row['id']
        verified = json.loads((run / 'independent_verification.json').read_text())
        assert verified['verified'] and verified['id'] == row['id']
        assert json.loads((run / 'predeclared_protocol.json').read_text())['manifest_sha256'] == sha(MANIFEST)
        v5 = run / 'v5_replay'
        assert not v5.exists()
        end = json.loads((run / 'run_status.json').read_text())['end_utc']
        subprocess.run(['python3', str(SCRIPTS / 'candidate_v5_replay.py'),
                        str(run / 'traffic.pcap'), str(v5),
                        '--observation-end-utc', end], check=True, capture_output=True, text=True)
    OUT.mkdir(mode=0o700, exist_ok=False)
    results = []
    for row in plan['scenarios']:
        run = BASE / row['split'] / row['id']
        start = time.perf_counter_ns()
        events = adapt(run)
        for event in events:
            if event['kind'] == 'OUTBOUND_INVITE':
                event['destination_group'] = row['destination_group']
                event['trunk'] = row['trunk']
        engine = Progression()
        for event in events:
            engine.accept(event)
        elapsed = time.perf_counter_ns() - start
        target = OUT / row['id']
        target.mkdir(mode=0o700)
        for filename, sequence in (('events.jsonl', events), ('alerts.jsonl', engine.outputs)):
            with (target / filename).open('x') as handle:
                for item in sequence:
                    handle.write(json.dumps(item, sort_keys=True) + '\n')
        invites = [e for e in events if e['kind'] == 'OUTBOUND_INVITE']
        burst = [a for a in engine.outputs if a['stage'] == 'CALL_BURST']
        assert len(invites) == 3 and len(burst) == 1
        assert burst[0]['event_id'] == invites[2]['event_id']
        result = {'id': row['id'], 'assigned_intent': row['intent'],
                  'account': row['account'], 'wrong': row['wrong'],
                  'event_count': len(events), 'stage_sequence': [a['stage'] for a in engine.outputs],
                  'burst_event_span_s': when(invites[2]['time_utc']) - when(invites[0]['time_utc']),
                  'burst_risk': burst[0]['risk'], 'analysis_ns': elapsed,
                  'pcap_sha256': sha(run / 'traffic.pcap'),
                  'events_sha256': sha(target / 'events.jsonl'),
                  'alerts_sha256': sha(target / 'alerts.jsonl'),
                  'cdr_count_independently_verified': 3,
                  'cdr_stage': 'omitted because SIP Call-ID cannot be uniquely linked to three same-account CDRs'}
        (target / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        results.append(result)
        print(json.dumps(result), flush=True)
    pairs = [('B001','B002'), ('B003','B004')]
    for left, right in pairs:
        a,b = [next(x for x in results if x['id'] == sid) for sid in (left,right)]
        assert a['stage_sequence'] == b['stage_sequence']
    summary = {'manifest_sha256': sha(MANIFEST), 'count': len(results),
               'verified_pairs_with_same_stages': pairs,
               'median_offline_analysis_ms': statistics.median(x['analysis_ns'] for x in results)/1e6,
               'results': results, 'warning': 'development cases, not live detection latency or fresh ML holdout'}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'summary_sha256': sha(OUT / 'summary.json'), 'count': len(results)}))

if __name__ == '__main__':
    main()

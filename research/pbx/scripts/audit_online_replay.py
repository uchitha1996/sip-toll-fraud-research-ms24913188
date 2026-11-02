#!/usr/bin/env python3
"""Read-only causal progression audit on archived 2026-09-30 lab runs."""
import hashlib
import inspect
import json
import os
import resource
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from adapt_checkpoint_events import adapt
from stream_progression_prototype import Progression

ROOT = Path('/home/astrix/sip-fraud-research/datasets/ml-lab-20260930')
OUT = Path('/home/astrix/sip-fraud-research/datasets/online-prototype-audit-20261001')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    active = subprocess.run(['asterisk', '-rx', 'core show channels count'],
                            capture_output=True, text=True, check=True).stdout
    assert '0 active calls' in active
    manifest_path = ROOT / 'ml_protocol_manifest.json'
    index_path = ROOT / 'evidence_index.json'
    manifest, index = json.loads(manifest_path.read_text()), json.loads(index_path.read_text())
    assert len(manifest['scenarios']) == len(index) == 34
    OUT.mkdir(mode=0o700, exist_ok=False)
    protocol = {'declared_utc': datetime.now(timezone.utc).isoformat(),
                'purpose': 'read-only event-time replay; not a live detector or new holdout',
                'manifest_sha256': sha(manifest_path), 'evidence_index_sha256': sha(index_path),
                'adapter_sha256': sha(Path(adapt.__code__.co_filename)),
                'engine_sha256': sha(Path(inspect.getfile(Progression))),
                'active_calls_before': active.strip()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n')
    results = []
    for row in manifest['scenarios']:
        sid = row['id']
        run = ROOT / row['split'] / sid
        assert sha(run / 'traffic.pcap') == index[sid]['pcap_sha256']
        target = OUT / row['split'] / sid
        target.mkdir(parents=True, mode=0o700, exist_ok=False)
        start = time.perf_counter_ns()
        events = adapt(run)
        engine = Progression()
        for event in events:
            engine.accept(event)
        elapsed_ns = time.perf_counter_ns() - start
        with (target / 'events.jsonl').open('x') as stream:
            for event in events:
                stream.write(json.dumps(event, sort_keys=True) + '\n')
        with (target / 'alerts.jsonl').open('x') as stream:
            for alert in engine.outputs:
                stream.write(json.dumps(alert, sort_keys=True) + '\n')
        observed = [alert['stage'] for alert in engine.outputs]
        reference = index[sid]['v6_stages']
        result = {'id': sid, 'split': row['split'], 'event_count': len(events),
                  'stages': observed, 'v6_stages': reference, 'stage_match': observed == reference,
                  'processing_ns': elapsed_ns, 'max_rss_kib_process': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  'pcap_sha256': index[sid]['pcap_sha256'],
                  'events_sha256': sha(target / 'events.jsonl'),
                  'alerts_sha256': sha(target / 'alerts.jsonl')}
        (target / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        results.append(result)
        print(json.dumps({'id': sid, 'stage_match': result['stage_match'],
                          'stages': observed, 'processing_ns': elapsed_ns}), flush=True)
    output = {'count': len(results), 'stage_matches': sum(x['stage_match'] for x in results),
              'note': 'Read-only development replay; model and V6 predictions are not features.',
              'results': results}
    (OUT / 'summary.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'output': str(OUT), 'count': len(results),
                      'stage_matches': output['stage_matches'],
                      'summary_sha256': sha(OUT / 'summary.json')}), flush=True)

if __name__ == '__main__':
    main()

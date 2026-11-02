#!/usr/bin/env python3
"""Measure a same-host external process over archived events, with no calls."""
import hashlib
import json
import os
import resource
import socket
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path('/home/astrix/sip-fraud-research')
ARCHIVE = ROOT / 'datasets/online-prototype-audit-20261001'
OUT = ROOT / 'datasets/external-service-replay-20261001'
SERVICE = ROOT / 'scripts/external_event_service.py'
PORT = 19056

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def percentile_ns(values, fraction):
    values = sorted(values)
    return values[min(len(values) - 1, int((len(values) - 1) * fraction))]

def main():
    os.umask(0o077)
    active = subprocess.run(['asterisk','-rx','core show channels count'],
                            check=True,capture_output=True,text=True).stdout
    assert '0 active calls' in active
    runs = json.loads((ARCHIVE/'summary.json').read_text())['results']
    assert len(runs) == 34
    OUT.mkdir(mode=0o700, exist_ok=False)
    protocol = {'archive_summary_sha256':sha(ARCHIVE/'summary.json'),
                'service_sha256':sha(SERVICE), 'source':'archived events, not live SIP',
                'bind':'127.0.0.1', 'port':PORT, 'active_calls_before':active.strip()}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    durations, process_times = [], []
    results = []
    with (OUT/'service.log').open('x') as log:
        child = subprocess.Popen(['python3','-u',str(SERVICE),'--port',str(PORT)],
                                 cwd=str(SERVICE.parent),stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(50):
                if child.poll() is not None:
                    raise RuntimeError('Service exited before ready')
                try:
                    with socket.create_connection(('127.0.0.1',PORT),timeout=.2):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Service did not bind in time')
            for row in runs:
                events_path = ARCHIVE/row['split']/row['id']/'events.jsonl'
                assert sha(events_path) == row['events_sha256']
                events = [json.loads(line) for line in events_path.read_text().splitlines()]
                observed = []
                with socket.create_connection(('127.0.0.1',PORT),timeout=5) as sock:
                    with sock.makefile('rb') as replies:
                        for event in events:
                            before = time.perf_counter_ns()
                            sock.sendall((json.dumps(event,sort_keys=True)+'\n').encode())
                            line = replies.readline()
                            after = time.perf_counter_ns()
                            if not line: raise RuntimeError('No service response')
                            response = json.loads(line)
                            if not response['ok']: raise ValueError(response['error'])
                            duration = after-before
                            processing = (response['decided_monotonic_ns']-
                                          response['received_monotonic_ns'])
                            assert 0 <= processing <= duration
                            durations.append(duration)
                            process_times.append(processing)
                            observed.extend(a['stage'] for a in response['alerts'])
                assert observed == row['stages']
                results.append({'id':row['id'],'split':row['split'],
                                'events':len(events),'stage_match':True})
        finally:
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill();child.wait(timeout=5)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    assert len(results)==34 and len(durations)==sum(r['events'] for r in results)
    summary = {'cases':len(results),'events':len(durations),
               'stage_matches':sum(r['stage_match'] for r in results),
               'median_loopback_roundtrip_ms':statistics.median(durations)/1e6,
               'p95_loopback_roundtrip_ms':percentile_ns(durations,.95)/1e6,
               'median_service_processing_ms':statistics.median(process_times)/1e6,
               'p95_service_processing_ms':percentile_ns(process_times,.95)/1e6,
               'service_child_cpu_s':usage.ru_utime+usage.ru_stime,
               'service_child_max_rss_kib':usage.ru_maxrss,
               'warning':'Archived local TCP replay excludes live capture and PBX call impact.',
               'results':results}
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='results'}))
    print('summary_sha256',sha(OUT/'summary.json'))

if __name__=='__main__':
    main()

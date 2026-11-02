#!/usr/bin/env python3
"""Read-only adapter from archived V5 timeline and SIP/CDR evidence to causal events."""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

GEN, PBX = '172.16.200.68', '172.16.200.81'

def rows(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))

def cdr_rows(path):
    with path.open(newline='') as stream:
        return list(csv.reader(stream))

def iso(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

def when(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

def adapt(root):
    candidates = [root / rel / 'candidate_timeline.csv' for rel in
                  ('v5_replay', 'v5_eval', 'v5_registered_replay')]
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        raise FileNotFoundError('V5 candidate timeline is missing')
    timeline = rows(path)
    packets = rows(root / 'sip_packets.csv')
    status = json.loads((root / 'run_status.json').read_text())
    assert status['status'] == 'captured'
    calls = {(p['ip.src'], p['sip.Call-ID']): p['sip.from.user']
             for p in packets if p['sip.Method'] == 'INVITE' and p['sip.from.user']}
    events = []
    invite_ids = set()
    for item in timeline:
        kind = None
        if item['event_type'] == 'CONFIRMED_REJECTION':
            kind = 'AUTH_REJECTION'
        elif item['event_type'] == 'REGISTER_FINAL_RESPONSE' and item['status'] == '200':
            kind = 'REGISTER_SUCCESS'
        elif item['event_type'] == 'REQUEST' and item['method'] == 'OPTIONS':
            kind = 'OPTIONS_REQUEST'
        elif (item['event_type'] == 'REQUEST' and item['method'] == 'INVITE'
              and item['entity'] == GEN and item['call_id'] not in invite_ids):
            kind = 'OUTBOUND_INVITE'
            invite_ids.add(item['call_id'])
        if kind is None:
            continue
        account = item['target'] if item['method'] == 'REGISTER' else calls.get((GEN, item['call_id']), '')
        event = {'event_id': 'v5:' + item['event_number'], 'time_utc': item['time_utc'],
                 'source_ip': item['entity'], 'account': account, 'kind': kind,
                 'call_id': item['call_id']}
        if kind == 'OPTIONS_REQUEST':
            event['target'] = item['target']
        if kind == 'OUTBOUND_INVITE':
            event['destination'] = item['target']
            assert account, 'INVITE account linkage missing'
        events.append(event)
    before, after = cdr_rows(root / 'cdr_before.csv'), cdr_rows(root / 'cdr_after.csv')
    assert after[:len(before)] == before
    delta = after[len(before):]
    for invite in (e for e in events if e['kind'] == 'OUTBOUND_INVITE'):
        cid, dst, account = invite['call_id'], invite['destination'], invite['account']
        leg = [p for p in packets if p['sip.Call-ID'] == cid]
        has_200 = any(p['ip.src'] == PBX and p['sip.Status-Code'] == '200'
                      and p['sip.CSeq.method'] == 'INVITE' for p in leg)
        has_ack = any(p['ip.src'] == GEN and p['sip.Method'] == 'ACK' for p in leg)
        byes = [p for p in leg if p['sip.Method'] == 'BYE']
        if has_200 and has_ack and byes:
            events.append({'event_id': 'sipbye:' + cid, 'time_utc': iso(max(float(p['frame.time_epoch']) for p in byes)),
                           'source_ip': GEN, 'account': account, 'kind': 'CALL_SIP_COMPLETED',
                           'call_id': cid})
            matches = [cdr for cdr in delta if len(cdr) >= 17 and cdr[1:3] == [account, dst]
                       and cdr[14] == 'ANSWERED' and cdr[13].isdigit()]
            if len(matches) == 1:
                # CDR availability is observed only by this run's final snapshot.
                events.append({'event_id': 'cdr:' + cid, 'time_utc': status['end_utc'],
                               'source_ip': GEN, 'account': account, 'kind': 'CDR_ANSWERED',
                               'call_id': cid, 'destination': dst, 'billsec': int(matches[0][13])})
    events.sort(key=lambda e: (when(e['time_utc']), e['event_id']))
    assert len({e['event_id'] for e in events}) == len(events)
    return events

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    with args.output.open('x') as target:
        for event in adapt(args.run_dir):
            target.write(json.dumps(event, sort_keys=True) + '\n')
    print(json.dumps({'run': str(args.run_dir), 'events': len(adapt(args.run_dir)),
                      'output': str(args.output)}))

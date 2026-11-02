#!/usr/bin/env python3
"""Development event-time SIP progression state machine; no call control."""
import argparse
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

KNOWN = {'OPTIONS_REQUEST', 'AUTH_REJECTION', 'REGISTER_SUCCESS',
         'OUTBOUND_INVITE', 'CALL_SIP_COMPLETED', 'CDR_ANSWERED'}

def epoch(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class Progression:
    def __init__(self, policy=None):
        self.policy = policy or {}
        self.last_time = float('-inf')
        self.ids = set()
        self.options = defaultdict(deque)
        self.failures = defaultdict(deque)
        self.auth_active = set()
        self.recon_active = set()
        self.suspected = {}
        self.calls = {}
        self.attempts = {}
        self.burst_calls = defaultdict(deque)
        self.burst_active = set()
        self.outputs = []

    @staticmethod
    def prune(queue, now, window):
        while queue and queue[0][0] < now - window:
            queue.popleft()

    def emit(self, event, stage, risk, evidence, reason, policy='UNKNOWN'):
        output = {'stage': stage, 'risk': risk, 'event_time_utc': event['time_utc'],
                  'source_ip': event['source_ip'], 'account': event.get('account', ''),
                  'destination': event.get('destination', ''),
                  'destination_group': event.get('destination_group', ''),
                  'trunk': event.get('trunk', ''),
                  'call_id': event.get('call_id', ''), 'event_id': event['event_id'],
                  'evidence_event_ids': evidence, 'policy': policy, 'reason': reason}
        self.outputs.append(output)
        return output

    def destination_policy(self, account, destination):
        allowed = self.policy.get(account)
        if allowed is None:
            return 'UNKNOWN'
        return 'ALLOWED' if destination in allowed else 'DISALLOWED'

    def accept(self, event):
        kind, ident = event['kind'], event['event_id']
        if kind not in KNOWN or not ident or not event['source_ip']:
            raise ValueError('Missing/unknown event kind, event ID or source IP')
        if ident in self.ids:
            return []
        now = epoch(event['time_utc'])
        if now < self.last_time:
            raise ValueError('Out-of-order event time')
        source, account = event['source_ip'], event.get('account', '')
        key = (source, account)
        if kind == 'OPTIONS_REQUEST' and not event.get('target'):
            raise ValueError('OPTIONS target required')
        if kind in {'AUTH_REJECTION', 'REGISTER_SUCCESS'} and not account:
            raise ValueError('Account required for REGISTER event')
        if kind in {'OUTBOUND_INVITE', 'CDR_ANSWERED'} and (
                not account or not event.get('call_id') or not event.get('destination')):
            raise ValueError('Account, Call-ID and destination required')
        if kind == 'CALL_SIP_COMPLETED' and (not account or not event.get('call_id')):
            raise ValueError('Account and Call-ID required')
        if kind == 'CDR_ANSWERED':
            call = self.calls.get((key, event['call_id']))
            if (not call or not call['sip_complete']
                    or call['destination'] != event['destination']):
                raise ValueError('CDR without linked completed SIP call')
        if kind == 'OUTBOUND_INVITE':
            previous = self.calls.get((key, event['call_id']))
            if previous and previous['destination'] != event['destination']:
                raise ValueError('Call-ID reused with different destination')
        self.last_time = now
        self.ids.add(ident)
        alerts = []
        if kind == 'OPTIONS_REQUEST':
            target = event.get('target', '')
            queue = self.options[source]
            queue.append((now, target, ident))
            self.prune(queue, now, 10)
            distinct = {item[1] for item in queue}
            if len(distinct) < 5:
                self.recon_active.discard(source)
            elif source not in self.recon_active:
                self.recon_active.add(source)
                alerts.append(self.emit(event, 'RECONNAISSANCE', 'REVIEW',
                                        [item[2] for item in queue],
                                        '5 distinct OPTIONS targets in 10 s'))
        elif kind == 'AUTH_REJECTION':
            queue = self.failures[key]
            queue.append((now, ident))
            self.prune(queue, now, 120)
            in_60 = [item for item in queue if item[0] >= now - 60]
            if len(in_60) < 10:
                self.auth_active.discard(key)
            elif key not in self.auth_active:
                self.auth_active.add(key)
                alerts.append(self.emit(event, 'AUTHENTICATION_ATTACK',
                                        'HIGH_SUSPICION', [item[1] for item in in_60],
                                        '10 confirmed digest rejections in 60 s'))
        elif kind == 'REGISTER_SUCCESS':
            queue = self.failures[key]
            self.prune(queue, now, 120)
            if len(queue) >= 5:
                failure_ids = tuple(item[1] for item in queue)
                prior = self.suspected.get(key)
                if not prior or prior[2] != failure_ids:
                    evidence = list(failure_ids) + [ident]
                    self.suspected[key] = (now, evidence, failure_ids)
                    alerts.append(self.emit(event, 'SUSPECTED_COMPROMISE', 'REVIEW',
                                            evidence, 'ambiguous_recovery'))
        elif kind == 'OUTBOUND_INVITE':
            cid, destination = event.get('call_id'), event.get('destination')
            fresh_call = (key, cid) not in self.calls
            if fresh_call:
                self.calls[key, cid] = {'time': now, 'destination': destination,
                                        'sip_complete': False}
            prior = self.suspected.get(key)
            if prior and prior[0] <= now <= prior[0] + 120 and (key, cid) not in self.attempts:
                policy = self.destination_policy(account, destination)
                risk = 'HIGH_SUSPICION' if policy == 'DISALLOWED' else 'REVIEW'
                evidence = prior[1] + [ident]
                self.attempts[key, cid] = {'time': now, 'destination': destination,
                                           'evidence': evidence, 'sip_complete': False,
                                           'answered': False, 'risk': risk, 'policy': policy}
                alerts.append(self.emit(event, 'SUSPECTED_OUTBOUND_ATTEMPT', risk,
                                        evidence, 'linked_invite_after_recovery', policy))
            # A group must come from a declared lab policy, not from the model's label.
            group = event.get('destination_group', '')
            if fresh_call and group:
                bucket = (account, event.get('trunk', ''), group)
                queue = self.burst_calls[bucket]
                queue.append((now, cid, ident,
                              self.destination_policy(account, destination)))
                self.prune(queue, now, 60)
                if len(queue) < 3:
                    self.burst_active.discard(bucket)
                elif bucket not in self.burst_active:
                    self.burst_active.add(bucket)
                    disallowed = any(item[3] == 'DISALLOWED' for item in queue)
                    policy = ('DISALLOWED' if disallowed else
                              'ALLOWED' if all(item[3] == 'ALLOWED' for item in queue)
                              else 'UNKNOWN')
                    alerts.append(self.emit(event, 'CALL_BURST',
                                            'HIGH_SUSPICION' if disallowed else 'REVIEW',
                                            [item[2] for item in queue],
                                            '3_distinct_calls_to_group_in_60_s',
                                            policy))
        elif kind == 'CALL_SIP_COMPLETED':
            cid = event.get('call_id')
            call = self.calls.get((key, cid))
            if not call or now < call['time']:
                raise ValueError('SIP completion without linked INVITE')
            call['sip_complete'] = True
            attempt = self.attempts.get((key, cid))
            if attempt and now >= attempt['time']:
                attempt['sip_complete'] = True
        elif kind == 'CDR_ANSWERED':
            cid, destination = event.get('call_id'), event.get('destination')
            attempt = self.attempts.get((key, cid))
            if (attempt and attempt['sip_complete'] and not attempt['answered']
                    and attempt['destination'] == destination and int(event.get('billsec', 0)) > 0):
                attempt['answered'] = True
                alerts.append(self.emit(event, 'ANSWERED_EMULATED_OUTBOUND',
                                        attempt['risk'], attempt['evidence'] + [ident],
                                        'SIP_completed_and_CDR_answered_retrospective',
                                        attempt['policy']))
        return alerts

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--policy', type=Path)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text()) if args.policy else {}
    engine = Progression(policy)
    with args.events.open() as source, args.output.open('x') as target:
        for line in source:
            if line.strip():
                for alert in engine.accept(json.loads(line)):
                    target.write(json.dumps(alert, sort_keys=True) + '\n')
    print(json.dumps({'events_sha256': sha(args.events), 'source_sha256': sha(Path(__file__)),
                      'alert_count': len(engine.outputs),
                      'stages': [a['stage'] for a in engine.outputs],
                      'output_sha256': sha(args.output)}))

if __name__ == '__main__':
    main()

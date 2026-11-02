#!/usr/bin/env python3
"""Causal, label-blind replay of frozen V6 and predeclared permission context."""
import argparse
import csv
import importlib.util
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

ONLINE = {'RECONNAISSANCE', 'AUTHENTICATION_ATTACK', 'SUSPECTED_COMPROMISE',
          'SUSPECTED_OUTBOUND_ATTEMPT'}

def epoch(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()

def read_csv(path):
    with Path(path).open(newline='') as f:
        return list(csv.DictReader(f))

def load_v6(path):
    spec = importlib.util.spec_from_file_location('frozen_v6', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def baseline(timeline, threshold):
    failures, emitted, alerts = defaultdict(deque), set(), []
    for row in timeline:
        if row['event_type'] != 'CONFIRMED_REJECTION':
            continue
        now = epoch(row['time_utc'])
        key = (row['entity'], row['target'])
        queue = failures[key]
        queue.append(now)
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= threshold and key not in emitted:
            emitted.add(key)
            alerts.append(dict(stage='FAILED_AUTH_THRESHOLD', time_utc=row['time_utc'],
                               source_ip=key[0], account=key[1], destination='',
                               call_id=row['call_id'], evidence=f'{threshold} confirmed failures / 60s'))
    return alerts

def frozen_online(timeline, packets, v6, lab_destinations):
    """Run unchanged V6 logic with only each causal prefix and zero CDR access.

    Prefix isolation also prevents a later INVITE identity from populating an
    earlier account mapping. Source and thresholds remain frozen. Hash metadata
    from the archived evaluator is ignored; the outer evidence manifest owns it.
    """
    original = v6.rows, v6.added_cdr, v6.sha
    seen, output = set(), []
    packet_prefix = []
    packet_index = 0
    ordered = sorted(packets, key=lambda p: float(p['frame.time_epoch']))
    try:
        for i, row in enumerate(timeline):
            now = epoch(row['time_utc'])
            while packet_index < len(ordered) and float(ordered[packet_index]['frame.time_epoch']) <= now + 0.000001:
                packet_prefix.append(ordered[packet_index])
                packet_index += 1
            v6.rows = lambda p: packet_prefix if Path(p).name == 'sip_packets.csv' else timeline[:i + 1]
            v6.added_cdr = lambda run: []
            v6.sha = lambda p: 'outer_manifest_records_actual_file_hash'
            stages, _ = v6.evaluate(Path('/causal-view'), Path('/causal-timeline'), set(lab_destinations))
            for stage in stages:
                if stage['stage'] not in ONLINE:
                    raise ValueError('Retrospective stage reached online adapter')
                key = tuple(stage[k] for k in ('stage', 'time_utc', 'source_ip', 'account', 'call_id'))
                if key not in seen:
                    seen.add(key)
                    output.append(dict(stage))
    finally:
        v6.rows, v6.added_cdr, v6.sha = original
    return sorted(output, key=lambda e: epoch(e['time_utc']))

def policy_outcome(policy, source, account, destination='', activity='REGISTER'):
    entry = policy['accounts'].get(account)
    if entry is None or source not in entry['sources']:
        return 'unknown'
    if activity == 'INVITE':
        return 'allowed' if destination in entry['allowed_destinations'] else 'violation'
    return 'allowed' if entry['registration_allowed'] else 'violation'

def recovery_authorized(policy, alert, timeline):
    now = epoch(alert['time_utc'])
    permits = policy['recovery_permissions']
    for permit in permits:
        if (alert['source_ip'], alert['account']) != (permit['source_ip'], permit['account']):
            continue
        if not epoch(permit['valid_from_utc']) <= now <= epoch(permit['valid_until_utc']):
            continue
        failures = sum(r['event_type'] == 'CONFIRMED_REJECTION'
                       and (r['entity'], r['target']) == (alert['source_ip'], alert['account'])
                       and now - 120 <= epoch(r['time_utc']) <= now for r in timeline)
        if failures <= permit['max_confirmed_failures']:
            return True
    return False

def context_layer(timeline, packets, stages, policy):
    """No scenario identifiers, outcomes, labels or CDR are accepted here."""
    decisions, actionable = [], []
    for alert in stages:
        activity = 'INVITE' if alert['destination'] else 'REGISTER'
        outcome = policy_outcome(policy, alert['source_ip'], alert['account'], alert['destination'], activity)
        recovery = recovery_authorized(policy, alert, timeline)
        allowed_recovery = alert['stage'] in {'SUSPECTED_COMPROMISE', 'SUSPECTED_OUTBOUND_ATTEMPT'} and outcome == 'allowed' and recovery
        decision = dict(alert, policy_outcome=outcome,
                        recovery_permission_observed=recovery,
                        disposition='authorized_recovery_review' if allowed_recovery else 'actionable_review')
        decisions.append(decision)
        if not allowed_recovery:
            actionable.append(decision)
    seen = set()
    for packet in sorted(packets, key=lambda p: float(p['frame.time_epoch'])):
        if packet['sip.Method'] != 'INVITE':
            continue
        source, account = packet['ip.src'], packet['sip.from.user']
        destination = packet['sip.r-uri.user'] or packet['sip.to.user']
        cid = packet['sip.Call-ID']
        if source != policy['lab_source_ip'] or (source, cid) in seen:
            continue
        seen.add((source, cid))
        outcome = policy_outcome(policy, source, account, destination, 'INVITE')
        if outcome == 'violation':
            stamp = datetime.fromtimestamp(float(packet['frame.time_epoch']),
                                          __import__('datetime').timezone.utc).isoformat().replace('+00:00', 'Z')
            alert = dict(stage='DESTINATION_POLICY_VIOLATION', time_utc=stamp,
                         source_ip=source, account=account, destination=destination,
                         call_id=cid, evidence='Observed INVITE outside independently frozen account allowlist',
                         policy_outcome=outcome, recovery_permission_observed=False,
                         disposition='actionable_review')
            actionable.append(alert)
            decisions.append(alert)
    return sorted(actionable, key=lambda a: epoch(a['time_utc'])), sorted(decisions, key=lambda a: epoch(a['time_utc']))

def predictions(timeline, packets, v6, policy):
    """One identical observation stream; labels are attached after this returns."""
    timeline = sorted(timeline, key=lambda r: epoch(r['time_utc']))
    stages = frozen_online(timeline, packets, v6, policy['lab_destinations'])
    contextual, decisions = context_layer(timeline, packets, stages, policy)
    methods = {'baseline_10': baseline(timeline, 10), 'baseline_5_sensitivity': baseline(timeline, 5),
               'V6': stages, 'V6_context': contextual}
    invites = [float(p['frame.time_epoch']) for p in packets
               if p['sip.Method'] == 'INVITE' and p['ip.src'] == policy['lab_source_ip']]
    first_invite = min(invites) if invites else None
    onset = min((epoch(r['time_utc']) for r in timeline if r['event_type'] == 'REQUEST'), default=None)
    result = {}
    for name, alerts in methods.items():
        first = epoch(alerts[0]['time_utc']) if alerts else None
        result[name] = dict(predicted=int(bool(alerts)), first_alert_utc=alerts[0]['time_utc'] if alerts else None,
                            first_stage=alerts[0]['stage'] if alerts else None,
                            ttd_seconds=round(first - onset, 6) if first is not None and onset is not None else None,
                            lead_time_seconds=round(first_invite - first, 6) if first_invite is not None and first is not None else None,
                            alert_strictly_before_first_invite=int(first < first_invite - 0.000001) if first is not None and first_invite is not None else 0,
                            first_outbound_attempt_epoch=first_invite, alerts=alerts)
    return result, decisions

def confusion(rows):
    tp = sum(r['truth'] == 1 and r['predicted'] == 1 for r in rows)
    fp = sum(r['truth'] == 0 and r['predicted'] == 1 for r in rows)
    tn = sum(r['truth'] == 0 and r['predicted'] == 0 for r in rows)
    fn = sum(r['truth'] == 1 and r['predicted'] == 0 for r in rows)
    ratio = lambda a, b: round(a / b, 6) if b else None
    recall, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    return dict(n=len(rows), tp=tp, fp=fp, tn=tn, fn=fn,
                precision=ratio(tp, tp + fp), recall=recall, specificity=specificity,
                fpr=ratio(fp, fp + tn), accuracy=ratio(tp + tn, len(rows)),
                f1=ratio(2 * tp, 2 * tp + fp + fn),
                balanced_accuracy=round((recall + specificity) / 2, 6) if recall is not None and specificity is not None else None)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    p.add_argument('policy', type=Path)
    p.add_argument('v6_source', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    data, context = predictions(read_csv(a.run / 'v5/candidate_timeline.csv'),
                                read_csv(a.run / 'sip_packets.csv'), load_v6(a.v6_source), json.loads(a.policy.read_text()))
    a.output.write_text(json.dumps({'predictions': data, 'context_decisions': context}, indent=2) + '\n')

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Independently verify an isolated three-call burst from SIP/CDR evidence."""
import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

GEN, PBX = '172.16.200.68', '172.16.200.81'

def table(path):
    with path.open(newline='') as handle:
        return list(csv.DictReader(handle))

def cdr(path):
    with path.open(newline='') as handle:
        return list(csv.reader(handle))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    run = args.run
    protocol = json.loads((run / 'predeclared_protocol.json').read_text())
    status = json.loads((run / 'run_status.json').read_text())
    account, dest = protocol['account'], protocol['destination']
    packets = table(run / 'sip_packets.csv')
    invites = {p['sip.Call-ID'] for p in packets
               if p['sip.Method'] == 'INVITE' and p['ip.src'] == GEN
               and p['sip.from.user'] == account and p['sip.r-uri.user'] == dest}
    complete = []
    for cid in sorted(invites):
        leg = [p for p in packets if p['sip.Call-ID'] == cid]
        if (any(p['ip.src'] == PBX and p['sip.Status-Code'] == '200'
                and p['sip.CSeq.method'] == 'INVITE' for p in leg)
                and any(p['ip.src'] == GEN and p['sip.Method'] == 'ACK' for p in leg)
                and any(p['sip.Method'] == 'BYE' for p in leg)):
            complete.append(cid)
    before, after = cdr(run / 'cdr_before.csv'), cdr(run / 'cdr_after.csv')
    prefix = after[:len(before)] == before
    delta = after[len(before):] if prefix else []
    answered = [r for r in delta if len(r) >= 17 and r[1:3] == [account, dest]
                and r[14] == 'ANSWERED' and r[13].isdigit() and int(r[13]) > 0]
    auth_lines = (run / 'asterisk_failed_auth_evidence.txt').read_text().splitlines()
    active = subprocess.run(['asterisk', '-rx', 'core show channels count'],
                            check=True, capture_output=True, text=True).stdout
    route = subprocess.run(['asterisk', '-rx', f'dialplan show {dest}@internal'],
                           capture_output=True, text=True).stdout
    checks = {
        'capture_hash': hashlib.sha256((run / 'traffic.pcap').read_bytes()).hexdigest()
                        == status['capture_sha256'],
        'captured_and_clean': status['status'] == 'captured' and not status['cleanup_errors'],
        'three_distinct_invites': len(invites) == 3,
        'three_sip_completed': len(complete) == 3,
        'cdr_prefix': prefix,
        'three_answered_cdr': len(answered) == 3,
        'expected_auth_log_count': len(auth_lines) == int(protocol['wrong']),
        'zero_active_calls': '0 active calls' in active,
        'route_removed': 'no existence' in route,
    }
    report = {'id': protocol['id'], 'checks': checks,
              'call_ids': sorted(invites), 'sip_completed_count': len(complete),
              'answered_cdr_count': len(answered),
              'billsec': [int(r[13]) for r in answered],
              'auth_log_count': len(auth_lines), 'verified': all(checks.values())}
    (run / 'independent_verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
    if not report['verified']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()

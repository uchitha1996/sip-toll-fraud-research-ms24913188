#!/usr/bin/env python3
"""Run one predeclared, isolated SIPp scenario; never route to a provider."""
import argparse
import csv
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from run_remote_sipp_challenges import ssh_sipp, sip_packets

ROOT = Path('/home/astrix/sip-fraud-research')
OUT = ROOT / 'datasets/ml-lab-20260930'
KEY = Path('/home/astrix/.ssh/sipp_lab_ed25519')
CDR = Path('/var/log/asterisk/cdr-csv/Master.csv')
FULL = Path('/var/log/asterisk/full')
GEN = '172.16.200.68'
PBX = '172.16.200.81'
REMOTE = '/home/sipp/sip-fraud-lab'
V5 = 'e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004'
V6 = 'c4b9231a89a815e93f1264119e229df1a563d574ba4b6a7e357d8125983eb2b4'
WRONG = {'1001': 'ee3fe537e7ae7f991e8fc78490c12781ba6d69a83e025f4afe41d8ba89905e4e',
         '1002': '610d5dce70125a4c3ed5b2acbe19bc17bd840ce2f0f204c1c872cf8889432de7'}
PREP = {'1001': 'd0779f3116b4a81ef96e992fe28cebe44ce899549cda4e9645700c7a06daa8d7',
        '1002': 'a02593b2f09b7ea657b178ea551b059f6c9381880f91b8e42d3b251dca98d28d'}

def utc():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def cmd(args, timeout=25):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args[0]} ({result.returncode})')
    return result.stdout

def ssh(command):
    return ['ssh', '-T', '-4', '-i', str(KEY), '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=6', f'sipp@{GEN}', command]

def run(row, manifest_hash):
    os.umask(0o077)
    sid, account = row['id'], row['account']
    assert sid.isalnum() and sid[0] in 'DH' and account in WRONG
    wrong, interval = int(row['wrong']), float(row['interval'])
    success, call = int(row['success']), int(row['call'])
    assert 0 <= wrong <= 10 and 0.8 <= interval <= 6 and success in (0, 1)
    assert call in (0, 1) and (not call or success)
    destination = {'1001': '88001', '1002': '88002'}[account]
    route = f'{destination}@internal'
    wrong_xml = 'failed_password_register.xml' if account == '1001' else 'failed_password_register_1002.xml'
    prep = ROOT / 'scripts' / ('prepare_valid_register.py' if account == '1001' else 'prepare_valid_register_1002.py')
    prep_out = ROOT / 'datasets/emulated-outbound-runs'
    reg = prep_out / f'.valid_register_{account}.xml'
    inv = prep_out / f'.valid_invite_{account}.xml'
    remote_reg, remote_inv = (f'{REMOTE}/{path.name}' for path in (reg, inv))
    assert sha(prep) == PREP[account]
    assert sha(ROOT / 'scripts/candidate_v5_replay.py') == V5
    assert sha(ROOT / 'scripts/progression_v6_development.py') == V6
    assert sha(Path('/home/astrix/sipp-lab') / wrong_xml) == WRONG[account]
    assert WRONG[account] in cmd(ssh(f'sha256sum {REMOTE}/{wrong_xml}'))
    assert PBX + '/24' in cmd(['ip', '-4', '-brief', 'address', 'show', 'wlan0'])
    assert GEN in cmd(ssh('ip -4 -brief address show wlan0'))
    assert '0 active calls' in cmd(['asterisk', '-rx', 'core show channels count'])
    if 'no existence' not in cmd(['asterisk', '-rx', f'dialplan show {route}']):
        raise RuntimeError('Temporary route present before run')
    run_dir = OUT / row['split'] / sid
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    protocol = dict(row, declared_utc=utc(), destination=destination,
                    manifest_sha256=manifest_hash, runner_sha256=sha(__file__),
                    prep_sha256=PREP[account], wrong_template_sha256=WRONG[account],
                    v5_sha256=V5, v6_sha256=V6,
                    invalid_if='Any missing or mismatched SIP, CDR, log, or cleanup evidence')
    (run_dir / 'predeclared_protocol.json').write_text(json.dumps(protocol, indent=2) + '\n')
    with (run_dir / 'scenario_ground_truth.csv').open('x', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['scenario_id', 'label', 'source_ip', 'pbx_ip', 'extension',
                         'destination', 'expected_wrong_password_dialogs',
                         'expected_register_success', 'expected_answered_call'])
        writer.writerow([sid, row['intent'], GEN, PBX, account, destination,
                         wrong, success, call])
    shutil.copyfile(CDR, run_dir / 'cdr_before.csv')
    log_offset = FULL.stat().st_size
    started = utc()
    capture = uas = None
    route_added = False
    error = None
    cleanup_errors = []
    wrong_starts = []
    try:
        if success:
            cmd(['python3', str(prep)])
            for source, target in ((reg, remote_reg), (inv, remote_inv)):
                cmd(['scp', '-p', '-4', '-i', str(KEY), '-o', 'BatchMode=yes',
                     '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                     str(source), f'sipp@{GEN}:{target}'], timeout=30)
            cmd(ssh(f'chmod 600 {remote_reg} {remote_inv}'))
        if call:
            route_added = True
            cmd(['asterisk', '-rx', f'dialplan add extension {destination},1,'
                 f'Dial(PJSIP/1002/sip:{destination}@{GEN}:5090,15,S(9)) into internal replace'])
            assert f'{GEN}:5090' in cmd(['asterisk', '-rx', f'dialplan show {route}'])
            sipp = f'{REMOTE}/runtime/usr/bin/sipp'
            lib = f'{REMOTE}/runtime/usr/lib/arm-linux-gnueabihf'
            uas_cmd = f'LD_LIBRARY_PATH={lib} {sipp} -sn uas -i {GEN} -p 5090 -t u1 -m 1 -nostdin -timeout 100s'
            with (run_dir / 'sipp_uas.log').open('x') as log:
                uas = subprocess.Popen(ssh(uas_cmd), stdout=log, stderr=subprocess.STDOUT)
            time.sleep(1.5)
            if uas.poll() is not None:
                raise RuntimeError('SIPp UAS exited early')
        with (run_dir / 'tcpdump.log').open('x') as caplog:
            capture = subprocess.Popen(['tcpdump', '-i', 'wlan0', '-n', '-U', '-s', '0',
                                        '-w', str(run_dir / 'traffic.pcap'),
                                        f'udp and host {GEN} and (port 5060 or port 5090)'],
                                       stdout=subprocess.DEVNULL, stderr=caplog)
        time.sleep(1)
        if capture.poll() is not None:
            raise RuntimeError('Capture exited early')
        first = time.monotonic()
        for index in range(wrong):
            time.sleep(max(0, first + interval * index - time.monotonic()))
            wrong_starts.append(utc())
            result = ssh_sipp(wrong_xml, 5114, int(account))
            (run_dir / f'sipp_wrong_{index + 1:02d}.log').write_text(result.stdout + '\nSTDERR:\n' + result.stderr)
            if result.returncode:
                raise RuntimeError(f'Wrong dialog {index + 1} exited {result.returncode}')
        if wrong:
            time.sleep(2.2)
        if success:
            valid = ssh_sipp(reg.name, 5115, int(account))
            (run_dir / 'sipp_register.log').write_text(valid.stdout + '\nSTDERR:\n' + valid.stderr)
            if valid.returncode:
                raise RuntimeError('Valid REGISTER failed')
        if call:
            time.sleep(float(row['post_register_pause']))
            invited = ssh_sipp(inv.name, 5116, int(destination))
            (run_dir / 'sipp_invite.log').write_text(invited.stdout + '\nSTDERR:\n' + invited.stderr)
            if invited.returncode or uas.wait(timeout=20):
                raise RuntimeError('Isolated call failed')
        time.sleep(2)
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    finally:
        if capture is not None:
            try:
                if capture.poll() is None:
                    capture.send_signal(signal.SIGINT)
                capture.wait(timeout=8)
            except Exception as exc:
                cleanup_errors.append(f'capture: {exc}')
        if uas is not None and uas.poll() is None:
            uas.terminate()
            try:
                uas.wait(timeout=8)
            except Exception as exc:
                cleanup_errors.append(f'uas: {exc}')
        try:
            shutil.copyfile(CDR, run_dir / 'cdr_after.csv')
            with FULL.open(errors='replace') as handle:
                handle.seek(log_offset)
                lines = [line for line in handle if 'Failed to authenticate' in line and GEN in line]
            (run_dir / 'asterisk_failed_auth_evidence.txt').write_text(''.join(lines))
            if (run_dir / 'traffic.pcap').is_file():
                sip_packets(run_dir / 'traffic.pcap', run_dir / 'sip_packets.csv')
        except Exception as exc:
            cleanup_errors.append(f'evidence: {exc}')
        if route_added:
            try:
                shown = cmd(['asterisk', '-rx', f'dialplan show {route}'])
                if f'{GEN}:5090' in shown:
                    removed = cmd(['asterisk', '-rx', f'dialplan remove extension {route}'])
                    if 'removed' not in removed:
                        cleanup_errors.append('Route removal not confirmed')
            except Exception as exc:
                cleanup_errors.append(f'route: {exc}')
        try:
            cmd(ssh(f'rm -f -- {remote_reg} {remote_inv}'))
        except Exception as exc:
            cleanup_errors.append(f'remote credentials: {exc}')
        for temporary in (reg, inv):
            temporary.unlink(missing_ok=True)
        if 'no existence' not in cmd(['asterisk', '-rx', f'dialplan show {route}']):
            cleanup_errors.append('Temporary route still present')
        status = {'case': sid, 'start_utc': started, 'end_utc': utc(),
                  'wrong_dialog_starts_utc': wrong_starts,
                  'capture_sha256': sha(run_dir / 'traffic.pcap') if (run_dir / 'traffic.pcap').is_file() else None,
                  'error': error, 'cleanup_errors': cleanup_errors,
                  'status': 'captured' if not error and not cleanup_errors else 'incomplete'}
        (run_dir / 'run_status.json').write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps({'run_dir': str(run_dir), 'status': status['status'], 'error': error,
                      'cleanup_errors': cleanup_errors}), flush=True)
    if error or cleanup_errors:
        raise SystemExit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('scenario_id')
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    matches = [row for row in manifest['scenarios'] if row['id'] == args.scenario_id]
    assert len(matches) == 1
    run(matches[0], sha(args.manifest))

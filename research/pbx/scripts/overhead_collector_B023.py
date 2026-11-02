#!/usr/bin/env python3
"""Restricted live SIP collector feeding the frozen-ML stage service."""
import csv
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/home/astrix/sip-fraud-research')
SERVICE = ROOT / 'scripts/external_event_service.py'
MODEL = ROOT / 'datasets/causal-review-ml-20261001/frozen_model.json'
OUT = ROOT / 'datasets/deployment-call-comparison-20261002/B023/live'
GEN, PBX = '172.16.200.68', '172.16.200.81'
FIELDS = ['frame.time_epoch','ip.src','ip.dst','sip.Method','sip.Status-Code',
          'sip.CSeq.method','sip.CSeq.seq','sip.Call-ID','sip.from.user',
          'sip.to.user','sip.r-uri.user']
PORT = 19058

def iso(epoch):
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    os.umask(0o077)
    assert '0 active calls' in subprocess.run(['asterisk','-rx','core show channels count'],
                                               check=True,capture_output=True,text=True).stdout
    OUT.mkdir(parents=True,mode=0o700,exist_ok=False)
    protocol = {'source':GEN,'pbx':PBX,'account':'1002','destination':'88002',
                'service_sha256':sha(SERVICE),'collector_sha256':sha(Path(__file__)),
                'model_scope':'No ML; shared auth-stage rule comparison',
                'scope':'live SIP fields from isolated generator, no CDR or call control',
                'rejection_grace_s':1.0,'max_duration_s':120,'idle_after_third_invite_s':10}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    results = {'AUTH_REJECTION':0,'REGISTER_SUCCESS':0,'OUTBOUND_INVITE':0,'OPTIONS_REQUEST':0}
    seen = set()
    pending = []
    packet_index = 0
    last_packet = time.monotonic()
    started = last_packet
    error = None
    tcp = decoder = service = None
    try:
        with (OUT/'service.log').open('x') as service_log, \
             (OUT/'capture_stderr.log').open('x') as capture_log, \
             (OUT/'decoder_stderr.log').open('x') as decoder_log, \
             (OUT/'events.jsonl').open('x') as event_log, \
             (OUT/'alerts.jsonl').open('x') as alert_log:
            service = subprocess.Popen(['python3','-u',str(SERVICE),'--port',str(PORT)],
                                       cwd=str(SERVICE.parent),stdout=service_log,stderr=subprocess.STDOUT)
            for _ in range(50):
                try:
                    connection = socket.create_connection(('127.0.0.1',PORT),timeout=.2)
                    break
                except OSError:
                    if service.poll() is not None: raise RuntimeError('Service exited')
                    time.sleep(.05)
            else: raise RuntimeError('Service not ready')
            connection.settimeout(5)
            reply = connection.makefile('rb')
            tcp = subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0','-w','-',
                                    f'udp and host {GEN} and port 5060'],
                                   stdout=subprocess.PIPE,stderr=capture_log)
            args = ['tshark','-l','-r','-','-Y','sip','-T','fields',
                    '-E','header=y','-E','separator=,','-E','quote=d']
            for field in FIELDS: args.extend(['-e',field])
            decoder = subprocess.Popen(args,stdin=tcp.stdout,stdout=subprocess.PIPE,
                                       stderr=decoder_log)
            tcp.stdout.close()
            pending_bytes = b''
            def emit(event, packet_epoch):
                event_log.write(json.dumps(event,sort_keys=True)+'\n');event_log.flush()
                sent = time.perf_counter_ns()
                connection.sendall((json.dumps(event,sort_keys=True)+'\n').encode())
                line = reply.readline()
                if not line: raise RuntimeError('External service closed')
                response = json.loads(line)
                if not response['ok']: raise ValueError(response['error'])
                decided = time.perf_counter_ns()
                results[event['kind']] += 1
                for alert in response['alerts']:
                    alert['collector_to_reply_ns'] = decided-sent
                    alert['service_processing_ns'] = (response['decided_monotonic_ns']-
                                                      response['received_monotonic_ns'])
                    alert['source_packet_epoch'] = packet_epoch
                    observed = datetime.now(timezone.utc)
                    alert['observed_decision_utc'] = observed.isoformat()
                    alert['source_to_decision_ms'] = (observed.timestamp()-float(packet_epoch))*1000
                    alert_log.write(json.dumps(alert,sort_keys=True)+'\n');alert_log.flush()
            def flush_due(now):
                nonlocal pending
                due, pending = [p for p in pending if p[0] <= now], [p for p in pending if p[0] > now]
                for _,event,stamp in due: emit(event,stamp)
            while time.monotonic()-started < 120:
                now = time.monotonic()
                flush_due(now)
                if (OUT/'STOP').exists(): break
                if decoder.poll() is not None and not pending_bytes:
                    raise RuntimeError('Decoder exited early')
                ready,_,_ = select.select([decoder.stdout],[],[],.2)
                if not ready: continue
                chunk = os.read(decoder.stdout.fileno(),65536)
                if not chunk: raise RuntimeError('Decoder pipe closed')
                pending_bytes += chunk
                while b'\n' in pending_bytes:
                    line,pending_bytes = pending_bytes.split(b'\n',1)
                    if not line.strip(): continue
                    values = next(csv.reader([line.decode(errors='replace')]))
                    if values == FIELDS: continue
                    if len(values) != len(FIELDS): raise ValueError('Incomplete SIP field row')
                    p = dict(zip(FIELDS,values));packet_index += 1
                    last_packet = time.monotonic()
                    stamp = p['frame.time_epoch']
                    source,method,code,cseq,cid = [p[x] for x in
                        ('ip.src','sip.Method','sip.Status-Code','sip.CSeq.seq','sip.Call-ID')]
                    event = None
                    if source == GEN and method == 'OPTIONS' and p['sip.r-uri.user']:
                        event = {'kind':'OPTIONS_REQUEST','source_ip':GEN,'account':'',
                                 'target':p['sip.r-uri.user'],'call_id':cid}
                    elif source == PBX and p['sip.CSeq.method']=='REGISTER' and code=='401' \
                            and cseq.isdigit() and int(cseq)>=2:
                        account = p['sip.to.user'] or p['sip.from.user']
                        if account == '1002':
                            event = {'kind':'AUTH_REJECTION','source_ip':GEN,'account':account,'call_id':cid}
                    elif source == PBX and p['sip.CSeq.method']=='REGISTER' and code=='200':
                        account = p['sip.to.user'] or p['sip.from.user']
                        if account == '1002':
                            event = {'kind':'REGISTER_SUCCESS','source_ip':GEN,'account':account,'call_id':cid}
                    elif False and source == GEN and method=='INVITE' and p['sip.from.user']=='1002' \
                            and p['sip.r-uri.user']=='88002':
                        event = {'kind':'OUTBOUND_INVITE','source_ip':GEN,'account':'1002',
                                 'call_id':cid,'destination':'88002','destination_group':'lab-uas',
                                 'trunk':'lab-trunk'}
                    if event is None: continue
                    key = ((event['kind'],cid) if event['kind']=='OUTBOUND_INVITE'
                           else (event['kind'],cid,cseq))
                    if key in seen: continue
                    seen.add(key)
                    event['event_id'] = 'live:'+str(packet_index)
                    event['time_utc'] = iso(stamp)
                    if event['kind']=='AUTH_REJECTION':
                        pending.append((time.monotonic()+1,event,stamp))
                    else:
                        flush_due(time.monotonic())
                        emit(event,stamp)
            flush_due(time.monotonic())
            reply.close();connection.close()
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)
    finally:
        for proc in (tcp,decoder,service):
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGINT if proc is tcp else signal.SIGTERM)
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=5)
    alerts=[json.loads(line) for line in (OUT/'alerts.jsonl').read_text().splitlines()] if (OUT/'alerts.jsonl').exists() else []
    status={'error':error,'counts':results,'alerts':[a['stage'] for a in alerts],
            'events_sha256':sha(OUT/'events.jsonl') if (OUT/'events.jsonl').exists() else None,
            'alerts_sha256':sha(OUT/'alerts.jsonl') if (OUT/'alerts.jsonl').exists() else None,
            'finished_utc':datetime.now(timezone.utc).isoformat()}
    (OUT/'status.json').write_text(json.dumps(status,indent=2)+'\n')
    print(json.dumps(status),flush=True)
    if error or results['AUTH_REJECTION']!=6 or results['REGISTER_SUCCESS']!=1 or results['OUTBOUND_INVITE']!=0 or status['alerts']!=['SUSPECTED_COMPROMISE']:
        raise SystemExit(1)

if __name__=='__main__':
    main()

#!/usr/bin/env python3
"""Restricted live five-stage + frozen ML service collector; no call control."""
import argparse,csv,hashlib,json,os,select,signal,socket,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
from packet_adapter import Adapter,FIELDS,GEN,PBX
R=Path('/home/astrix/sip-fraud-research');MODEL=R/'datasets/causal-review-ml-20261001/frozen_model.json'
SERVICE=R/'scripts/external_event_service_ml.py'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('out',type=Path);args=ap.parse_args();out=args.out
 os.umask(0o077);assert sha(MODEL)=='ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d'
 out.mkdir(parents=True,mode=0o700,exist_ok=False);adapter=Adapter();procs=[];counts={};error=None
 try:
  with (out/'service.log').open('x') as slog,(out/'capture.log').open('x') as clog,(out/'decoder.log').open('x') as dlog,(out/'events.jsonl').open('x') as elog,(out/'alerts.jsonl').open('x') as alog:
   service=subprocess.Popen(['python3','-u',str(SERVICE),'--port','19067','--ml-model',str(MODEL)],cwd=SERVICE.parent,stdout=slog,stderr=subprocess.STDOUT);procs.append(service)
   for _ in range(50):
    try:connection=socket.create_connection(('127.0.0.1',19067),timeout=.2);break
    except OSError:
     if service.poll() is not None:raise RuntimeError('Service exited')
     time.sleep(.05)
   else:raise RuntimeError('Service unavailable')
   connection.settimeout(5);reply=connection.makefile('rb')
   tcp=subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0','-w','-',f'udp and host {GEN} and port 5060'],stdout=subprocess.PIPE,stderr=clog);procs.append(tcp)
   cmd=['tshark','-l','-r','-','-Y','sip','-T','fields','-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence=f']
   for field in FIELDS:cmd.extend(['-e',field])
   decoder=subprocess.Popen(cmd,stdin=tcp.stdout,stdout=subprocess.PIPE,stderr=dlog);procs.append(decoder);tcp.stdout.close()
   def emit(events):
    for e in events:
     elog.write(json.dumps(e)+'\n');elog.flush();counts[e['kind']]=counts.get(e['kind'],0)+1
     connection.sendall((json.dumps(e)+'\n').encode());line=reply.readline()
     if not line:raise RuntimeError('No service reply')
     response=json.loads(line)
     if not response['ok']:raise ValueError(response['error'])
     wall=time.time();mono=time.perf_counter_ns()
     for a in response['alerts']:
      a.update(observed_epoch=wall,decision_epoch=wall+(response['decided_monotonic_ns']-mono)/1e9,
       decision_monotonic_ns=response['decided_monotonic_ns'],service_processing_ns=response['decided_monotonic_ns']-response['received_monotonic_ns'])
      alog.write(json.dumps(a)+'\n');alog.flush()
   started=time.monotonic();buffer=b''
   while time.monotonic()-started<180:
    emit(adapter.drain(time.monotonic()))
    if (out/'STOP').exists() and not adapter.queue:break
    if tcp.poll() is not None or decoder.poll() is not None:raise RuntimeError('Live capture exited')
    ready,_,_=select.select([decoder.stdout],[],[],.05)
    if not ready:continue
    block=os.read(decoder.stdout.fileno(),65536)
    if not block:raise RuntimeError('Decoder pipe closed')
    buffer+=block
    while b'\n' in buffer:
     line,buffer=buffer.split(b'\n',1)
     if not line.strip():continue
     values=next(csv.reader([line.decode()]));
     if values==FIELDS:continue
     if len(values)!=len(FIELDS):raise ValueError('Malformed SIP field row')
     emit(adapter.feed(dict(zip(FIELDS,values)),time.monotonic()))
   else:raise TimeoutError('Collector traffic limit')
   reply.close();connection.close()
 except Exception as exc:error=type(exc).__name__+': '+str(exc)
 finally:
  for proc in procs[1:]+procs[:1]:
   if proc.poll() is None:
    proc.send_signal(signal.SIGINT if proc.args[0]=='tcpdump' else signal.SIGTERM)
    try:proc.wait(timeout=5)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
  status={'error':error,'counts':counts,'model_sha256':sha(MODEL),'collector_sha256':sha(Path(__file__)),
   'adapter_sha256':sha(Path(__file__).with_name('packet_adapter.py')),'service_sha256':sha(SERVICE),'finished_utc':datetime.now(timezone.utc).isoformat()}
  (out/'status.json').write_text(json.dumps(status,indent=2)+'\n');print(json.dumps(status),flush=True)
 if error:raise SystemExit(1)
if __name__=='__main__':main()

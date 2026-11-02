#!/usr/bin/env python3
"""Predeclared, sequential, stop-on-failure isolated lab comparison."""
import argparse,hashlib,json,os,re,shutil,subprocess,threading,time
from pathlib import Path
from verify_full_case import verify
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;LOG=Path('/var/log/asterisk/full')
OUT=ROOT/'datasets/full-stage-deployment-comparison-20261002'
MODULE='res_sipfraud_full_lab.so';INSTALLED=Path('/usr/lib/asterisk/modules')/MODULE
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cli(s):return subprocess.run(['asterisk','-rx',s],capture_output=True,text=True,check=True).stdout
def idle():
 assert '0 active calls' in cli('core show channels count')
 for dest in ['88001','88002']:assert 'no existence' in cli('dialplan show '+dest+'@internal')
def preflight(plan):
 idle();assert '0 modules loaded' in cli('module show like sipfraud')
 for relative,expected in plan['sha256'].items():assert sha(ROOT/relative)==expected,relative
 assert sha(Path('/home/astrix/sipp-lab/options_scan.xml'))==plan['options_template_sha256']
 import sys
 sys.path.insert(0,str(ROOT/'scripts'))
 from lab_burst_runner import ssh
 remote=subprocess.run(ssh('sha256sum /home/sipp/sip-fraud-lab/options_scan.xml'),capture_output=True,text=True,check=True,timeout=20).stdout
 assert remote.split()[0]==plan['options_template_sha256']
 assert INSTALLED.exists(),'Installation required: sudo bash '+str(HERE/'install_full_module_checked.sh')
 assert sha(INSTALLED)==plan['module_sha256']
 assert not OUT.exists(),'Output exists; no automatic rerun or overwrite'
 for row in plan['scenarios']:assert not (ROOT/'datasets/burst-lab-20261001/development'/row['id']).exists()
def _sample(stop,out,offset):
 position=offset
 with (out/'resources.jsonl').open('x') as resources,(out/'native_log.jsonl').open('x') as native:
  while not stop.wait(.25):
   now=time.time();rows=[]
   for p in Path('/proc').glob('[0-9]*'):
    try:
     cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
     if Path(cmd.split()[0]).name not in ['asterisk','tcpdump','tshark'] and not any(s in cmd for s in ['full_external_collector.py','external_event_service_ml.py']):continue
     stat=(p/'stat').read_text().rsplit(')',1)[1].split()
     rows.append({'pid':int(p.name),'process':Path(cmd.split()[0]).name,'cpu_ticks':int(stat[11])+int(stat[12]),'rss_pages':int(stat[21])})
    except (OSError,ValueError,IndexError):pass
   resources.write(json.dumps({'epoch':now,'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),'page_bytes':os.sysconf('SC_PAGE_SIZE'),'processes':rows})+'\n');resources.flush()
   with LOG.open('rb') as log:
    assert log.seek(0,2)>=position,'Asterisk log rotated during case'
    log.seek(position);block=log.read();position=log.tell()
   for line in block.decode(errors='replace').splitlines():
    if 'SIPFRAUDFULL' in line:native.write(json.dumps({'observed_epoch':now,'line':line})+'\n');native.flush()
def sample(stop,out,offset):
 try:_sample(stop,out,offset)
 except Exception as exc:(out/'sampling_error.txt').write_text(type(exc).__name__+': '+str(exc))
def one(row,manifest):
 idle();out=OUT/row['id'];out.mkdir(mode=0o700)
 external=None;worker=None;stop=threading.Event();loaded=False;failure=None
 try:
  if row['mode']=='INTERNAL':
   cli('module load '+MODULE)
   loaded=MODULE in cli('module show like sipfraud');assert loaded,'Module did not load'
   status=cli('sipfraud full status');(out/'status_before.txt').write_text(status)
   for field in ['invalid=0','events=0','alerts=0','pending=0']:assert field in status,status
  elif row['mode']=='EXTERNAL':
   with (out/'collector.log').open('x') as log:external=subprocess.Popen(['python3','-u',str(HERE/'full_external_collector.py'),str(out/'external')],stdout=log,stderr=subprocess.STDOUT)
   ready=out/'external/capture.log'
   for _ in range(100):
    assert external.poll() is None,'External collector exited'
    if ready.exists() and 'listening on wlan0' in ready.read_text():break
    time.sleep(.1)
   else:raise RuntimeError('Capture not ready')
  worker=threading.Thread(target=sample,args=(stop,out,LOG.stat().st_size),daemon=True);worker.start()
  subprocess.run(['python3',str(HERE/'run_full_case.py'),str(manifest),row['id']],check=True,timeout=160)
  run=ROOT/'datasets/burst-lab-20261001/development'/row['id']
  subprocess.run(['python3',str(ROOT/'scripts/verify_burst_run.py'),str(run)],check=True,timeout=20)
  time.sleep(1.5)
  if external:
   (out/'external/STOP').touch();assert external.wait(timeout=15)==0
  if loaded:
   status=cli('sipfraud full status');(out/'status_after.txt').write_text(status)
   assert 'invalid=0' in status and 'pending=0' in status,status
 finally:
  stop.set()
  if worker:worker.join(timeout=5)
  if external and external.poll() is None:
   (out/'external/STOP').touch()
   try:external.wait(timeout=15)
   except subprocess.TimeoutExpired:external.terminate();external.wait(timeout=10)
  if loaded:cli('module unload '+MODULE)
  idle()
 assert not (out/'sampling_error.txt').exists(),'Sampling failed; case invalid'
 assert (out/'resources.jsonl').stat().st_size>0
 with (out/'alerts.jsonl').open('x') as alerts:
  if row['mode']=='EXTERNAL':alerts.write((out/'external/alerts.jsonl').read_text())
  else:
   for line in (out/'native_log.jsonl').read_text().splitlines():
    record=json.loads(line);s=record['line'];assert 'invalid=1' not in s,s
    match=re.search(r'decision_epoch=([0-9.]+).*alerts=(\[.*\])',s)
    if match:
     for alert in json.loads(match[2]):
      alert.update(decision_epoch=float(match[1]),observed_epoch=record['observed_epoch']);alerts.write(json.dumps(alert)+'\n')
 return verify(run,out,row)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');a=ap.parse_args();manifest=HERE/'comparison_manifest.json';plan=json.loads(manifest.read_text())
 preflight(plan)
 if not a.execute:print('Ready; read-only preflight passed. No traffic generated.');return
 os.umask(0o077);OUT.mkdir(mode=0o700);shutil.copyfile(manifest,OUT/'predeclared_manifest.json');reports=[]
 try:
  for row in plan['scenarios']:reports.append(one(row,manifest))
 except Exception as exc:
  (OUT/'STOPPED.json').write_text(json.dumps({'error':type(exc).__name__+': '+str(exc),'accepted':[r['id'] for r in reports]},indent=2)+'\n');raise
 finally:
  (OUT/'summary.json').write_text(json.dumps({'manifest_sha256':sha(manifest),'accepted':reports,'complete':len(reports)==len(plan['scenarios'])},indent=2)+'\n')
 print('All predeclared cases verified; observer unloaded and routes absent.')
if __name__=='__main__':main()

#!/usr/bin/env python3
"""New wrapper injects declared OPTIONS before existing isolated burst runner.
The original runner and verification gates remain unchanged.
"""
import argparse,json,sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time
R=Path('/home/astrix/sip-fraud-research');sys.path.insert(0,str(R/'scripts'))
import lab_burst_runner as runner
from run_remote_sipp_challenges import ssh_sipp
def main():
 ap=argparse.ArgumentParser();ap.add_argument('manifest',type=Path);ap.add_argument('id');a=ap.parse_args()
 plan=json.loads(a.manifest.read_text());row=next(r for r in plan['scenarios'] if r['id']==a.id)
 original=runner.ssh_sipp;injected=False;auth_base=None;auth_index=0
 def wrapped(xml,port,service,*args,**kw):
  nonlocal injected,auth_base,auth_index
  if not injected:
   injected=True;base=time.monotonic();rd=runner.OUT/row['split']/row['id']
   def option(i):
    time.sleep(max(0,base+i-time.monotonic()))
    target=1002+(i if row['options_distinct'] else 0)
    result=ssh_sipp('options_scan.xml',5140+i,target)
    (rd/f'sipp_options_{i+1:02d}.log').write_text(result.stdout+'\nSTDERR:\n'+result.stderr)
    if result.returncode:raise RuntimeError('OPTIONS stimulus failed')
   with ThreadPoolExecutor(max_workers=5) as pool:
    for future in [pool.submit(option,i) for i in range(5)]:future.result(timeout=25)
  if xml.startswith('failed_password_register'):
   if auth_base is None:auth_base=time.monotonic()
   time.sleep(max(0,auth_base+auth_index*float(row['interval'])-time.monotonic()));auth_index+=1
  return original(xml,port,service,*args,**kw)
 runner.ssh_sipp=wrapped
 runner.run(row,runner.sha(a.manifest))
if __name__=='__main__':main()

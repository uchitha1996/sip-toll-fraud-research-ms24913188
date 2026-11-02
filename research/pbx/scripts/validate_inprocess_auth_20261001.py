#!/usr/bin/env python3
"""Fresh restricted live in-process auth event validation; no calls/routes."""
import csv,hashlib,json,os,signal,subprocess,time
from pathlib import Path
from datetime import datetime,timezone
from lab_burst_runner import cmd,ssh,sha,PREP
from run_remote_sipp_challenges import ssh_sipp,sip_packets
R=Path('/home/astrix/sip-fraud-research')
O=R/'datasets/inprocess-auth-validation-20261001'
FULL=Path('/var/log/asterisk/full');CDR=Path('/var/log/asterisk/cdr-csv/Master.csv')
BIN=Path('/usr/lib/asterisk/modules/res_sipfraud_lab.so')
EXPECTED='02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26'
def cli(s):return cmd(['asterisk','-rx',s])
def utc():return datetime.now(timezone.utc).isoformat()
def main():
 os.umask(0o077);assert sha(BIN)==EXPECTED
 assert '0 active calls' in cli('core show channels count')
 assert '172.16.200.68' in cmd(ssh('ip -4 -brief address show wlan0'))
 O.mkdir(mode=0o700,exist_ok=False)
 plan={'declared_utc':utc(),'binary_sha256':EXPECTED,'source_sha256':sha(R/'inprocess-lab/res_sipfraud_lab.c'),
       'scope':'Registration-only lab validation; no calls, no routes, no latency comparison',
       'cases':[{'id':'A000','wrong':0,'success':1,'auth_alerts':0,'review_alerts':0},
                {'id':'A001','wrong':10,'success':0,'auth_alerts':1,'review_alerts':0},
                {'id':'A002','wrong':6,'success':1,'auth_alerts':0,'review_alerts':1}]}
 (O/'manifest.json').write_text(json.dumps(plan,indent=2)+'\n')
 print('DECLARED',sha(O/'manifest.json'),flush=True);reports=[]
 reg=R/'datasets/emulated-outbound-runs/.valid_register_1002.xml'
 inv=R/'datasets/emulated-outbound-runs/.valid_invite_1002.xml'
 remote='/home/sipp/sip-fraud-lab/.valid_register_1002.xml'
 assert not reg.exists() and not inv.exists()
 try:
  for row in plan['cases']:
   p=O/row['id'];p.mkdir();cli('module unload res_sipfraud_lab.so')
   cli('module load res_sipfraud_lab.so')
   before=cli('sipfraud lab status')
   assert 'account=1002 failures_window=0 auth_alerts=0 review_alerts=0' in before
   (p/'module_before.txt').write_text(before)
   cdr_before=CDR.read_bytes();(p/'cdr_before.csv').write_bytes(cdr_before)
   offset=FULL.stat().st_size;capture=None;error=None;codes=[]
   try:
    if row['success']:
     prep=R/'scripts/prepare_valid_register_1002.py';assert sha(prep)==PREP['1002']
     cmd(['python3',str(prep)])
     cmd(['scp','-p','-4','-i','/home/astrix/.ssh/sipp_lab_ed25519','-o','BatchMode=yes',
          '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',str(reg),'sipp@172.16.200.68:'+remote])
     cmd(ssh('chmod 600 '+remote))
    with (p/'tcpdump.log').open('x') as h:
     capture=subprocess.Popen(['tcpdump','-i','wlan0','-n','-U','-s','0','-w',str(p/'traffic.pcap'),
       'udp and host 172.16.200.68 and port 5060'],stdout=subprocess.DEVNULL,stderr=h)
    time.sleep(1);assert capture.poll() is None
    for i in range(row['wrong']):
     result=ssh_sipp('failed_password_register_1002.xml',5124,1002)
     codes.append(result.returncode);(p/f'wrong_{i+1:02d}.log').write_text(result.stdout+result.stderr)
     assert result.returncode==0;time.sleep(.8)
    if row['success']:
     time.sleep(2)
     result=ssh_sipp(reg.name,5125,1002);codes.append(result.returncode)
     (p/'register.log').write_text(result.stdout+result.stderr);assert result.returncode==0
    time.sleep(2)
   except Exception as exc:error=type(exc).__name__+': '+str(exc)
   finally:
    if capture and capture.poll() is None:capture.send_signal(signal.SIGINT);capture.wait(timeout=8)
    cmd(ssh('rm -f -- '+remote))
    reg.unlink(missing_ok=True);inv.unlink(missing_ok=True)
   after=cli('sipfraud lab status');(p/'module_after.txt').write_text(after)
   (p/'cdr_after.csv').write_bytes(CDR.read_bytes())
   with FULL.open(errors='replace') as h:h.seek(offset);lines=h.read().splitlines()
   fail=[x for x in lines if 'Failed to authenticate' in x and '172.16.200.68' in x]
   module=[x for x in lines if 'SIPFRAUDLAB' in x]
   (p/'failed_auth.log').write_text('\n'.join(fail)+'\n');(p/'module_events.log').write_text('\n'.join(module)+'\n')
   packets=sip_packets(p/'traffic.pcap',p/'sip_packets.csv')
   request=[x for x in packets if x['ip.src']=='172.16.200.68' and x['sip.Method']=='REGISTER']
   rejections=[x for x in packets if x['ip.src']=='172.16.200.81' and x['sip.Status-Code']=='401' and x['sip.CSeq.method']=='REGISTER']
   success={x['sip.Call-ID'] for x in packets if x['ip.src']=='172.16.200.81' and x['sip.Status-Code']=='200' and x['sip.CSeq.method']=='REGISTER'}
   expected=f"account=1002 failures_window={row['wrong']} auth_alerts={row['auth_alerts']} review_alerts={row['review_alerts']}"
   checks={'no_error':error is None,'register_request_count':len(request)==2*(row['wrong']+row['success']),
    'challenge_and_rejection_count':len(rejections)==2*row['wrong']+row['success'],
    'success_dialog_count':len(success)==row['success'],'failed_auth_log_count':len(fail)==row['wrong'],
    'inprocess_counters':expected in after,'no_new_cdr':CDR.read_bytes()==cdr_before,
    'no_invites':not any(x['sip.Method']=='INVITE' for x in packets),
    'zero_calls':'0 active calls' in cli('core show channels count'),
    'other_account_unaffected':'account=1001 failures_window=0 auth_alerts=0 review_alerts=0' in after}
   result={'id':row['id'],'checks':checks,'verified':all(checks.values()),'error':error,
           'module_events':module,'pcap_sha256':sha(p/'traffic.pcap'),'status':after,'sipp_exits':codes}
   (p/'verification.json').write_text(json.dumps(result,indent=2)+'\n');reports.append(result)
   print('CASE',json.dumps(result),flush=True)
   assert result['verified'],'Evidence validation failed; stopping batch'
  (O/'summary.json').write_text(json.dumps({'manifest_sha256':sha(O/'manifest.json'),'reports':reports,
       'all_verified':all(x['verified'] for x in reports),'limitation':'Auth-event subset only; log timestamps not used as detection latency.'},indent=2)+'\n')
 finally:
  cli('module unload res_sipfraud_lab.so')
  reg.unlink(missing_ok=True);inv.unlink(missing_ok=True)
 print('COMPLETE',sha(O/'summary.json'),flush=True)
if __name__=='__main__':main()


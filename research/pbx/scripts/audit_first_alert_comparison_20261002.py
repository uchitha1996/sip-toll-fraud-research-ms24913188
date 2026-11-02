#!/usr/bin/env python3
"""Read-only common-onset timing audit on the registered F-series evidence."""
import csv,json,hashlib
from pathlib import Path
from datetime import datetime
R=Path('/home/astrix/sip-fraud-research')
TABLE=R/'datasets/f-series-evaluation/20260930T094922Z/scenario_results.csv'
OUT=R/'datasets/first-alert-comparison-20261002'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def epoch(x):return datetime.fromisoformat(x.replace('Z','+00:00')).timestamp()
def readcsv(p):
 with p.open(newline='') as h:return list(csv.DictReader(h))
def main():
 OUT.mkdir(mode=0o700,exist_ok=False);results=[]
 for row in readcsv(TABLE):
  if row['case'] not in ['F05','F07','F08','F09','F10','F11','F12']:continue
  run=Path(row['run_dir']);assert sha(run/'traffic.pcap')==row['pcap_sha256']
  v3=readcsv(run/'replay_v3_timeline.csv')
  onset=min(float(x['request_epoch']) for x in v3)
  a3=next((x for x in v3 if x['predicted_stage']!='NORMAL'),None)
  s5=json.loads((run/'v5_eval/candidate_summary.json').read_text())
  assert abs(epoch(s5['first_request_utc'])-onset)<.001
  e6=readcsv(run/'v6_eval/progression_events.csv')
  times=[epoch(x['time_utc']) for x in e6]
  first6=min(times) if times else None
  first3=float(a3['decision_epoch']) if a3 else None
  first5=epoch(s5['first_alert_utc']) if s5['first_alert_utc'] else None
  suspected=next((epoch(x['time_utc']) for x in e6 if x['stage']=='SUSPECTED_COMPROMISE'),None)
  attempted=next((epoch(x['time_utc']) for x in e6 if x['stage']=='SUSPECTED_OUTBOUND_ATTEMPT'),None)
  result={'case':row['case'],'truth':row['truth'],'v3_first_stage':a3['predicted_stage'] if a3 else None,
          'v3_first_alert_s':first3-onset if first3 else None,'v5_first_stage':s5['first_alert_stage'],
          'v5_first_alert_s':first5-onset if first5 else None,'v6_first_stage':e6[0]['stage'] if e6 else None,
          'v6_first_alert_s':first6-onset if first6 else None,
          'v6_minus_v3_first_alert_s':first6-first3 if first6 and first3 else None,
          'review_before_first_linked_invite_s':attempted-suspected if attempted and suspected else None,
          'pcap_sha256':row['pcap_sha256']}
  results.append(result);print(json.dumps(result),flush=True)
 summary={'results':results,'source_table_sha256':sha(TABLE),
          'scope':'Seven inspected registered cases, common first-request onset; first-any-alert endpoints can name different stages and risks. Archived event-time comparison, not live computational latency or a new holdout.',
          'interpretation':'Earlier first alert is not always better: V3 counts normal challenges, while V5/V6 require confirmed rejections. Review before a linked INVITE does not prove unauthorized use and also occurs in benign recovery.',
          'h1_status':'Do not claim universally earlier detection; assess coverage and timing together.'}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print('COMPLETE',sha(OUT/'summary.json'),flush=True)
if __name__=='__main__':main()


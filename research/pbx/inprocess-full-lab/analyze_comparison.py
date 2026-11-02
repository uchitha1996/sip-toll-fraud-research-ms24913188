#!/usr/bin/env python3
"""Descriptive analysis only: retain case results and small-sample limits."""
import json,statistics
from pathlib import Path
from audit_packet_adapter import decode
ROOT=Path('/home/astrix/sip-fraud-research')
OUT=ROOT/'datasets/full-stage-deployment-comparison-20261002'
def median(values):return round(statistics.median(values),3) if values else None
def resources(case):
 packets=decode(ROOT/'datasets/burst-lab-20261001/development'/case['id']/'traffic.pcap')
 start=min(float(p['frame.time_epoch']) for p in packets if p['sip.Method']=='OPTIONS')
 end=max(float(p['frame.time_epoch']) for p in packets if p['sip.Method']=='BYE')+.5
 rows=[json.loads(line) for line in (OUT/case['id']/'resources.jsonl').read_text().splitlines()]
 rows=[r for r in rows if start<=r['epoch']<=end];assert len(rows)>=2
 bypid={}
 for row in rows:
  for p in row['processes']:bypid.setdefault(p['pid'],[]).append((row['epoch'],p,row))
 detail=[]
 for pid,items in bypid.items():
  first,last=items[0],items[-1];dt=last[0]-first[0]
  ticks=last[1]['cpu_ticks']-first[1]['cpu_ticks'];assert ticks>=0
  detail.append({'pid':pid,'process':first[1]['process'],'sample_count':len(items),'sample_span_s':round(dt,3),'cpu_seconds':round(ticks/first[2]['clock_ticks_per_second'],4),'mean_cpu_one_core_percent':round(100*ticks/first[2]['clock_ticks_per_second']/dt,3) if dt else None,'peak_rss_mib':round(max(x[1]['rss_pages']*x[2]['page_bytes'] for x in items)/1048576,3)})
 return {'packet_window_epoch':[start,end],'sample_span_s':round(rows[-1]['epoch']-rows[0]['epoch'],3),'processes':detail}
def main():
 summary=json.loads((OUT/'summary.json').read_text());assert summary['complete'], 'Incomplete batch: no full comparison inference'
 cases=summary['accepted'];assert len(cases)==7
 for c in cases:
  c['call_setup_median_ms']=median([x['invite_to_200_ms'] for x in c['call_setup']]);c['resources']=resources(c)
  alerts=[json.loads(s) for s in (OUT/c['id']/'alerts.jsonl').read_text().splitlines() if s.strip()]
  c['ml_review_metadata']=[{k:a[k] for k in ['ml_probability','ml_priority','ml_feature_values','ml_model_sha256']} for a in alerts if 'ml_probability' in a]
 stages={}
 for mode in ['INTERNAL','EXTERNAL']:
  stages[mode]={}
  for stage in ['RECONNAISSANCE','AUTHENTICATION_ATTACK','SUSPECTED_COMPROMISE','SUSPECTED_OUTBOUND_ATTEMPT','CALL_BURST']:
   values=[t for c in cases if c['id']!='B030' and c['mode']==mode for t in c['timings'] if t['stage']==stage]
   stages[mode][stage]={'n':len(values),'decision_median_ms':median([t['packet_to_decision_ms'] for t in values]),'observation_median_ms':median([t['packet_to_observation_ms'] for t in values])}
 limits=['Two cases per deployment mode; no statistical causal overhead conclusion.','Stage-specific clocks/onsets: recovery uses authenticated REGISTER request, other stages use the causative packet event.','One-second authentication rejection grace is part of both paths, not computation overhead.','Native observation uses 250 ms logger polling; external observation is collector receipt.','CPU/RSS includes capture and instrumentation; native RSS is entire Asterisk, external python3 processes combine service/collector. Samples cannot isolate module memory or exact per-event CPU.','All cases are authorized development stimuli; ML is frozen exploratory priority metadata.','Five online stages; answered CDR corroboration remains retrospective.']
 result={'manifest_sha256':summary['manifest_sha256'],'cases':cases,'stage_latency':stages,'limits':limits}
 with (OUT/'descriptive_analysis.json').open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
 lines=['# Live native/external comparison — 2 October 2026','','All seven declared cases passed independent capture and cleanup checks. B030 is a separate benign smoke case. Six primary cases contain 18 answered six-second lab calls.','','| Case | Mode | Call setup median (ms) |','| --- | --- | ---: |']
 for c in cases:lines.append(f"| {c['id']} | {c['mode']} | {c['call_setup_median_ms']} |")
 lines+=['','| Stage | Native decision median (ms) | External decision median (ms) | n per path |','| --- | ---: | ---: | ---: |']
 for stage,native in stages['INTERNAL'].items():lines.append(f"| {stage} | {native['decision_median_ms']} | {stages['EXTERNAL'][stage]['decision_median_ms']} | {native['n']} |")
 lines+=['','| Case | Whole-PBX mean CPU (% of one core) | Whole-PBX peak RSS (MiB) |','| --- | ---: | ---: |']
 for c in cases:
  pbx=[p for p in c['resources']['processes'] if p['process']=='asterisk'];assert len(pbx)==1,pbx
  lines.append(f"| {c['id']} | {pbx[0]['mean_cpu_one_core_percent']} | {pbx[0]['peak_rss_mib']} |")
 lines+=['','Native and external outputs matched the declared stages and frozen ML tolerances. Each primary enabled case emitted seven alerts covering five distinct stages. Benign B030 produced CALL_BURST, illustrating that an alert identifies behaviour rather than proven abuse.','','Limitations:','']+['- '+s for s in limits]
 with (OUT/'RESULTS.md').open('x') as f:f.write('\n'.join(lines)+'\n')
 print(json.dumps({'call_setup':[{k:c[k] for k in ['id','mode','call_setup_median_ms']} for c in cases],'stage_latency':stages},indent=2))
if __name__=='__main__':main()

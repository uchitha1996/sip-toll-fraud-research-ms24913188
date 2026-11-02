#!/usr/bin/env python3
import json
from pathlib import Path
from audit_native_core import check,sha,ROOT,HERE
paths=sorted((ROOT/'datasets/causal-ml-holdout-20261001').glob('B*/events.jsonl'))
assert len(paths)==10
rows=[]
for p in paths:
 events=[json.loads(s) for s in p.read_text().splitlines() if s.strip()]
 rows.append({'id':p.parent.name,'events':len(events),'alerts':check(events),'events_sha256':sha(p)})
summary={'scope':'C port regression on previously inspected frozen holdout, not new ML evaluation',
 'runs_matched':len(rows),'events':sum(x['events'] for x in rows),'alerts':sum(x['alerts'] for x in rows),'rows':rows,
 'source_sha256':{p.name:sha(p) for p in HERE.glob('*') if p.suffix in ['.c','.h','.py','.so']}}
out=ROOT/'datasets/full-stage-port-audit-20261002/holdout_port_verification.json'
with out.open('x') as h:h.write(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k not in ['rows','source_sha256']}))

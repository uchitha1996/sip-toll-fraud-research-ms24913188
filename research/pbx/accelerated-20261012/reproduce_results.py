#!/usr/bin/env python3
"""Portable read-only replication. No network, PBX access, credentials or calls."""
import hashlib,json
from pathlib import Path
from common_evaluator import predictions,load_v6,read_csv,confusion
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    protocol=json.loads((ROOT/'evaluation_freeze.json').read_text())
    assert all(sha(ROOT/name)==value for name,value in protocol['sha256'].items())
    finalfreeze=json.loads((ROOT/'results_freeze.json').read_text())
    assert all(sha(ROOT/name)==value for name,value in finalfreeze['hashes'].items())
    saved=json.loads((ROOT/'final_results.json').read_text())
    policy=json.loads((ROOT/'policy.json').read_text())
    v6=load_v6(ROOT/'frozen/progression_v6_development.py')
    rows={m:[] for m in saved['methods']}
    for case in saved['cases']:
        run=ROOT/'runs/fresh'/case['id']
        assert sha(run/'traffic.pcap')==case['verification']['pcap_sha256']
        assert sha(run/'v5/candidate_timeline.csv')==case['verification']['v5_timeline_sha256']
        computed,_=predictions(read_csv(run/'v5/candidate_timeline.csv'),read_csv(run/'sip_packets.csv'),v6,policy)
        assert computed==case['predictions'],case['id']
        for method,p in computed.items():
            rows[method].append(dict(truth=int(case['intent']=='SIMULATED_ABUSE'),predicted=p['predicted']))
    for method,data in rows.items():
        metrics=confusion(data)
        assert all(saved['methods'][method][key]==value for key,value in metrics.items()),method
    print(json.dumps(dict(reproduced_cases=len(saved['cases']),pcap_hashes_matched=len(saved['cases']),
                         prediction_and_confusion_equality=True,network_access=False,
                         methods={m:confusion(rows[m]) for m in rows}),indent=2))
if __name__=='__main__':main()

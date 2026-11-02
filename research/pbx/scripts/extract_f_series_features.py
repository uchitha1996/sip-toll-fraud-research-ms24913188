#!/usr/bin/env python3
"""Create a leakage-conscious scenario feature table for F01-F12.

Features use SIP/CDR/V5 protocol evidence only. V3/V6 predictions are excluded.
The 12-row table is for feature/schema inspection, not final ML training.
"""
import csv
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from aggregate_f_series import CASES, DATA, REAL

def rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))

def cdr_rows(path):
    with path.open(newline="") as f:
        return list(csv.reader(f))

def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

def max_count(times, window):
    q, best = deque(), 0
    for t in sorted(times):
        q.append(t)
        while q and q[0] < t - window:
            q.popleft()
        best = max(best, len(q))
    return best

def span(times):
    return 0.0 if len(times) < 2 else max(times) - min(times)

def main():
    outdir = DATA / "f-series-evaluation" / "feature-schema"
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = []
    for case, (rel, truth, expected) in CASES.items():
        run = DATA / rel
        packets = rows(run / "sip_packets.csv")
        req = [r for r in packets if r["sip.Method"]]
        req_times = [float(r["frame.time_epoch"]) for r in req]
        options = [r for r in req if r["sip.Method"] == "OPTIONS"]
        registers = [r for r in req if r["sip.Method"] == "REGISTER"]
        invites = [r for r in req if r["sip.Method"] == "INVITE"]
        v5p = run / ("v5_registered_replay/candidate_timeline.csv" if case in REAL
                     else "v5_eval/candidate_timeline.csv")
        v5 = rows(v5p)
        rejected = [ts(r["time_utc"]) for r in v5 if r["event_type"] == "CONFIRMED_REJECTION"]
        reg200 = [ts(r["time_utc"]) for r in v5 if r["event_type"] == "REGISTER_FINAL_RESPONSE"
                  and r["status"] == "200"]
        v5_invites = [ts(r["time_utc"]) for r in v5 if r["event_type"] == "REQUEST"
                      and r["method"] == "INVITE"]
        before, after = cdr_rows(run / "cdr_before.csv"), cdr_rows(run / "cdr_after.csv")
        assert after[:len(before)] == before
        delta = after[len(before):]
        answered = [r for r in delta if len(r) >= 17 and r[14] == "ANSWERED"]
        bill = [int(r[13]) for r in answered if r[13].isdigit()]
        first_success = min(reg200) if reg200 else None
        first_invite = min(v5_invites) if v5_invites else None
        first_rej = min(rejected) if rejected else None
        feat = {
            "case": case, "truth": truth, "expected_stage": expected,
            "capture_duration_s": round(span(req_times), 6),
            "request_count": len(req),
            "max_requests_10s": max_count(req_times, 10),
            "max_requests_60s": max_count(req_times, 60),
            "options_requests": len(options),
            "unique_options_targets": len({r["sip.r-uri.user"] for r in options if r["sip.r-uri.user"]}),
            "register_requests": len(registers),
            "invite_requests": len(invites),
            "unique_invite_targets": len({r["sip.r-uri.user"] for r in invites if r["sip.r-uri.user"]}),
            "confirmed_rejections": len(rejected),
            "max_rejections_10s": max_count(rejected, 10),
            "max_rejections_60s": max_count(rejected, 60),
            "rejection_span_s": round(span(rejected), 6),
            "register_200": len(reg200),
            "failure_then_success": int(bool(rejected and reg200 and first_rej < max(reg200))),
            "seconds_first_rejection_to_success": (
                round(first_success - first_rej, 6) if first_rej is not None and first_success is not None else ""
            ),
            "success_then_invite": int(first_success is not None and first_invite is not None
                                       and first_success <= first_invite),
            "seconds_success_to_invite": (
                round(first_invite - first_success, 6) if first_success is not None
                and first_invite is not None and first_invite >= first_success else ""
            ),
            "cdr_new_rows": len(delta),
            "cdr_answered": len(answered),
            "cdr_unique_destinations": len({r[2] for r in delta if len(r) >= 3 and r[2]}),
            "cdr_total_billsec": sum(bill),
            "cdr_mean_billsec": round(sum(bill) / len(bill), 3) if bill else 0.0,
        }
        result.append(feat)
    fields = list(result[0])
    with (outdir / "f_series_features.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(result)
    schema = {
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rows": len(result),
        "purpose": "Feature/schema development only; do not fit final ML on only these 12 rows.",
        "excluded_as_features": ["V3 prediction", "V5 predicted_stage/risk_score", "V6 prediction"],
        "safe_protocol_features": [
            "transaction-confirmed rejection counts",
            "successful REGISTER count",
            "OPTIONS/INVITE counts and target diversity",
            "timing/window counts",
            "CDR delta, answered count and billsec"
        ],
        "next": "Generate a larger development set, freeze preprocessing/model, then collect a fresh held-out set."
    }
    (outdir / "feature_schema.json").write_text(json.dumps(schema, indent=2) + "\n")
    for r in result:
        print(r["case"], r["truth"], "rej", r["confirmed_rejections"],
              "span", r["rejection_span_s"], "opt_targets", r["unique_options_targets"],
              "reg200", r["register_200"], "cdr_ans", r["cdr_answered"],
              "fail_success", r["failure_then_success"])

if __name__ == "__main__":
    main()

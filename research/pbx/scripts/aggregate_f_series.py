#!/usr/bin/env python3
"""Aggregate the registered F01-F12 scenario evaluation.

This is scenario-level evaluation of fixed lab captures. It does not turn the
small F-series into a population accuracy estimate or an ML training set.
"""
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/astrix/sip-fraud-research")
DATA = ROOT / "datasets"
CASES = {
    "F01": ("normal-call-runs/20260930T044410Z-f01-real-phone", "BENIGN", "NONE"),
    "F02": ("normal-call-runs/20260930T051058Z-f02-real-phone", "BENIGN", "NONE"),
    "F03": ("sipp-remote-runs/20260929T055638Z-f03-options-monitor-1002", "BENIGN", "NONE"),
    "F04": ("emulated-outbound-runs/20260929T061243Z-f04-account1002-88002", "BENIGN", "NONE"),
    "F05": ("emulated-outbound-runs/20260929T061334Z-f05-account1002-88002", "BENIGN", "NONE"),
    "F06": ("normal-call-runs/20260930T050420Z-f06-real-phone", "BENIGN", "NONE"),
    "F07": ("sipp-remote-runs/20260929T055952Z-f07-options-targets-1002-1006", "ATTACK", "RECONNAISSANCE"),
    "F08": ("sipp-remote-runs/20260929T100512Z-f08-options-targets-1001-1006", "ATTACK", "RECONNAISSANCE"),
    "F09": ("sipp-remote-runs/20260929T060228Z-f09-auth-only-1002", "ATTACK", "AUTHENTICATION_ATTACK"),
    "F10": ("sipp-remote-runs/20260929T100727Z-f10-slow-auth-only-1001", "ATTACK", "AUTHENTICATION_ATTACK"),
    "F11": ("emulated-outbound-runs/20260929T061506Z-f11-account1002-88002", "ATTACK", "ANSWERED_EMULATED_OUTBOUND"),
    "F12": ("emulated-outbound-runs/20260929T100901Z-f12-account1001-88001-slow", "ATTACK", "ANSWERED_EMULATED_OUTBOUND"),
}
REAL = {"F01", "F02", "F06"}


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_num(value):
    return "" if value is None else value


def metrics(rows, key):
    tp = sum(r["truth"] == "ATTACK" and r[key] for r in rows)
    fp = sum(r["truth"] == "BENIGN" and r[key] for r in rows)
    tn = sum(r["truth"] == "BENIGN" and not r[key] for r in rows)
    fn = sum(r["truth"] == "ATTACK" and not r[key] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(rows)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr, "accuracy": accuracy}


def main():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = DATA / "f-series-evaluation" / stamp
    out.mkdir(parents=True, mode=0o700)
    rows = []
    for case, (rel, truth, expected) in CASES.items():
        run = DATA / rel
        proto = load(run / "predeclared_protocol.json")
        v3 = load(run / "replay_v3_summary.json")
        if case in REAL:
            v5p = run / "v5_registered_replay/candidate_summary.json"
            v6p = run / "v6_registered_replay/progression_summary.json"
        else:
            v5p = run / "v5_eval/candidate_summary.json"
            v6p = run / "v6_eval/progression_summary.json"
        v5, v6 = load(v5p), load(v6p)
        stages = v6.get("stages", [])
        row = {
            "case": case, "label": proto["label"], "truth": truth,
            "expected_stage": expected, "run_dir": str(run),
            "pcap_sha256": digest(run / "traffic.pcap"),
            "v3_alert": bool(v3.get("first_alert_stage")),
            "v3_stage": v3.get("first_alert_stage") or "",
            "v3_ttd_s": safe_num(v3.get("time_to_first_alert_seconds")),
            "v5_alert": bool(v5.get("first_alert_stage")),
            "v5_stage": v5.get("first_alert_stage") or "",
            "v5_ttd_s": safe_num(v5.get("time_to_first_alert_seconds")),
            "v6_alert": bool(stages), "v6_stages": "|".join(stages),
            "v6_stage_pass": (not stages if expected == "NONE" else expected in stages),
            "v6_new_cdr_rows": v6.get("counts", {}).get("new_cdr_rows", ""),
        }
        rows.append(row)
    fields = list(rows[0])
    with (out / "scenario_results.csv").open("x", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scenario_count": len(rows),
        "truth_counts": {
            "BENIGN": sum(r["truth"] == "BENIGN" for r in rows),
            "ATTACK": sum(r["truth"] == "ATTACK" for r in rows),
        },
        "binary_metrics": {
            "V3": metrics(rows, "v3_alert"),
            "V5": metrics(rows, "v5_alert"),
            "V6": metrics(rows, "v6_alert"),
        },
        "v6_stage_pass_count": sum(r["v6_stage_pass"] for r in rows),
        "v6_stage_pass_rate": sum(r["v6_stage_pass"] for r in rows) / len(rows),
        "source_hashes": {
            "aggregator": digest(Path(__file__)),
            "v3": digest(DATA / "runs/20260923T094044Z/stage_detector_v3.py"),
            "v5": digest(ROOT / "scripts/candidate_v5_replay.py"),
            "v6": digest(ROOT / "scripts/progression_v6_development.py"),
        },
        "interpretation_limit": (
            "Registered small lab scenario set; V6 is a development/refinement detector. "
            "Do not present these 12 scenarios as production or population accuracy."
        ),
    }
    (out / "metrics.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = [
        "# F01-F12 scenario-level evaluation",
        "",
        f"Created UTC: {summary['created_utc']}",
        "",
        "This table consolidates the registered F-series captures without changing any source evidence.",
        "It is a small controlled lab set (6 benign, 6 attack), not a production accuracy estimate.",
        "",
        "| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in summary["binary_metrics"].items():
        lines.append(
            f"| {name} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
            f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
            f"{m['fpr']:.3f} | {m['accuracy']:.3f} |"
        )
    lines += [
        "",
        f"V6 expected-stage pass: {summary['v6_stage_pass_count']}/{len(rows)} "
        f"({summary['v6_stage_pass_rate']:.3f}).",
        "",
        "Important failure cases: F03 tests benign repeated OPTIONS to one target; "
        "F05 tests benign credential recovery followed by an authorized call. "
        "These are especially useful when designing the next refinement/ML features.",
        "",
        "Use scenario_results.csv for the exact case-by-case evidence.",
    ]
    (out / "README.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"output": str(out), **summary["binary_metrics"],
                      "v6_stage_pass": summary["v6_stage_pass_count"]}, indent=2))


if __name__ == "__main__":
    main()

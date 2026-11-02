#!/usr/bin/env python3
"""Replay frozen V3 rules on one saved SIP capture without changing the baseline."""

import argparse
import csv
import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def csv_rows(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_detector(path):
    spec = importlib.util.spec_from_file_location("frozen_stage_detector_v3", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load detector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--detector", type=Path, required=True,
                        help="Archived frozen V3 source file")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    detector_path = args.detector.resolve()
    capture = run_dir / "traffic.pcap"
    packet_csv = run_dir / "sip_packets.csv"
    truth_csv = run_dir / "scenario_ground_truth.csv"
    for required in (capture, packet_csv, truth_csv, detector_path):
        if not required.is_file():
            parser.error(f"Missing evidence file: {required}")

    v3 = load_detector(detector_path)
    packets = csv_rows(packet_csv)
    truth = csv_rows(truth_csv)
    if not packets or not truth:
        parser.error("Capture and scenario ground truth must contain data rows")

    responses = v3.index_responses(packets)
    states = defaultdict(v3.new_state)
    timeline = []
    for row in packets:
        method = v3.clean(row.get("sip.Method")).upper()
        if method not in {"OPTIONS", "REGISTER", "INVITE"}:
            continue
        request_time = v3.packet_epoch(row)
        entity = v3.request_entity(row)
        target = v3.request_target(row, method)
        response_time, status = v3.correlated_response(row, responses)
        decision_time = (
            response_time if method == "REGISTER" and status else request_time
        )
        state = states[entity]
        v3.prune(state, decision_time)
        state[method].append(request_time)
        state["TARGETS"].append((request_time, target))
        if method == "REGISTER" and status in v3.FAILURE_CODES:
            state["FAILED_REGISTER"].append(response_time)
        if method == "INVITE" and v3.is_outside_target(target):
            state["OUTSIDE_INVITE"].append(request_time)
        v3.prune(state, decision_time)
        predicted, score, reason = v3.classify(state)
        timeline.append({
            "event_number": len(timeline) + 1,
            "request_epoch": request_time,
            "decision_epoch": decision_time,
            "entity": entity,
            "method": method,
            "target": target,
            "response_status": status,
            "options_count": len(state["OPTIONS"]),
            "failed_register_count": len(state["FAILED_REGISTER"]),
            "invite_count": len(state["INVITE"]),
            "outside_invite_count": len(state["OUTSIDE_INVITE"]),
            "predicted_stage": predicted,
            "risk_score": score,
            "reason": reason,
        })
    if not timeline:
        parser.error("No OPTIONS, REGISTER, or INVITE requests were captured")

    alerts = [event for event in timeline if event["predicted_stage"] != "NORMAL"]
    cdr_before = run_dir / "cdr_before.csv"
    cdr_after = run_dir / "cdr_after.csv"
    new_cdr = None
    if cdr_before.is_file() and cdr_after.is_file():
        with cdr_before.open(newline="") as handle:
            before_count = sum(1 for _ in csv.reader(handle))
        with cdr_after.open(newline="") as handle:
            after_count = sum(1 for _ in csv.reader(handle))
        new_cdr = after_count - before_count
        if new_cdr < 0:
            raise RuntimeError("CDR shrank during capture")

    summary = {
        "replayed_utc": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir),
        "scenario_ground_truth": truth,
        "packet_rows": len(packets),
        "request_events": len(timeline),
        "predicted_stages": dict(Counter(
            event["predicted_stage"] for event in timeline
        )),
        "first_alert_stage": alerts[0]["predicted_stage"] if alerts else None,
        "first_alert_event": alerts[0]["event_number"] if alerts else None,
        "time_to_first_alert_seconds": (
            round(alerts[0]["decision_epoch"] - timeline[0]["request_epoch"], 6)
            if alerts else None
        ),
        "new_cdr_rows": new_cdr,
        "pcap_sha256": sha256(capture),
        "packet_csv_sha256": sha256(packet_csv),
        "detector_sha256": sha256(detector_path),
        "note": "Scenario labels are independent of detector output. "
                "Event-level precision/recall is not calculated from these "
                "scenario-level ground-truth labels.",
    }
    timeline_path = run_dir / "replay_v3_timeline.csv"
    summary_path = run_dir / "replay_v3_summary.json"
    if timeline_path.exists() or summary_path.exists():
        parser.error("Replay output already exists; original results were preserved")
    with timeline_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(timeline[0]))
        writer.writeheader()
        writer.writerows(timeline)
    with summary_path.open("x", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")
    print(json.dumps({
        "run_dir": str(run_dir),
        "requests": len(timeline),
        "first_alert_stage": summary["first_alert_stage"],
        "first_alert_event": summary["first_alert_event"],
        "time_to_first_alert_seconds": summary["time_to_first_alert_seconds"],
        "new_cdr_rows": new_cdr,
    }))


if __name__ == "__main__":
    main()

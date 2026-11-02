#!/usr/bin/env python3
"""Windowed SIP attack-stage detector and evaluator for the research dataset."""

import csv
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "datasets"
PACKET_FILE = DATA_DIR / "sip_packets_v2.csv"
TRUTH_FILE = DATA_DIR / "ground_truth_events.csv"
TIMELINE_FILE = DATA_DIR / "stage_detection_timeline_v3.csv"
SUMMARY_FILE = DATA_DIR / "stage_detection_summary_v3.csv"
METRICS_FILE = DATA_DIR / "stage_detection_metrics_v3.csv"

WINDOW_SECONDS = 10.0
MATCH_TOLERANCE_SECONDS = 1.0
FAILURE_CODES = {"401", "403", "404"}
ATTACK_STAGES = {
    "RECONNAISSANCE",
    "AUTHENTICATION_ATTACK",
    "FRAUD_BURST",
}
TRUTH_MAP = {
    "normal_register": "NORMAL",
    "reconnaissance": "RECONNAISSANCE",
    "auth_attack": "AUTHENTICATION_ATTACK",
    "fraud_burst": "FRAUD_BURST",
}
STAGE_ORDER = [
    "NORMAL",
    "RECONNAISSANCE",
    "AUTHENTICATION_ATTACK",
    "FRAUD_BURST",
]


def clean(value):
    return (value or "").strip()


def packet_epoch(row):
    return float(clean(row.get("frame.time_epoch")))


def truth_epoch(value):
    parsed = datetime.fromisoformat(clean(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def utc_text(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def request_target(row, method):
    if method == "REGISTER":
        return clean(row.get("sip.to.user")) or clean(row.get("sip.r-uri.user"))
    return clean(row.get("sip.r-uri.user")) or clean(row.get("sip.to.user"))


def request_entity(row):
    source_ip = clean(row.get("ip.src"))
    from_user = clean(row.get("sip.from.user"))
    # The original synthetic capture places every packet on loopback, so use the
    # SIP identity there. For real captures, source IP is the safer entity key.
    if source_ip in {"", "127.0.0.1", "::1"}:
        return from_user or source_ip or "unknown"
    return source_ip


def is_outside_target(target):
    return target.startswith("00") or target.startswith("+")


def load_rows(path):
    with path.open(newline="", errors="ignore") as handle:
        return list(csv.DictReader(handle))


def match_truth_to_requests(truth_rows, request_rows):
    matched = []
    request_index = 0

    for truth in truth_rows:
        truth_method = clean(truth.get("method")).upper()
        truth_user = clean(truth.get("user"))
        truth_target = clean(truth.get("target"))
        truth_time = truth_epoch(truth.get("timestamp"))
        found = None

        while request_index < len(request_rows):
            request = request_rows[request_index]
            request_index += 1
            method = clean(request.get("sip.Method")).upper()
            user = clean(request.get("sip.from.user"))
            target = request_target(request, method)
            delta = abs(packet_epoch(request) - truth_time)

            if (
                method == truth_method
                and user == truth_user
                and target == truth_target
                and delta <= MATCH_TOLERANCE_SECONDS
            ):
                found = request
                break

        if found is None:
            raise RuntimeError(
                "Could not match ground truth event: "
                f"{truth.get('timestamp')} {truth_method} {truth_user} {truth_target}"
            )

        matched.append((truth, found))

    return matched


def index_responses(packet_rows):
    responses = defaultdict(list)
    for row in packet_rows:
        status = clean(row.get("sip.Status-Code"))
        cseq_method = clean(row.get("sip.CSeq.method")).upper()
        call_id = clean(row.get("sip.Call-ID"))
        if status and cseq_method and call_id:
            responses[(call_id, cseq_method)].append((packet_epoch(row), status))
    for values in responses.values():
        values.sort()
    return responses


def correlated_response(request, responses):
    method = clean(request.get("sip.Method")).upper()
    call_id = clean(request.get("sip.Call-ID"))
    request_time = packet_epoch(request)
    candidates = responses.get((call_id, method), [])
    for response_time, status in candidates:
        if request_time <= response_time <= request_time + 5.0:
            return response_time, status
    return request_time, ""


def new_state():
    return {
        "OPTIONS": deque(),
        "REGISTER": deque(),
        "INVITE": deque(),
        "FAILED_REGISTER": deque(),
        "OUTSIDE_INVITE": deque(),
        "TARGETS": deque(),
    }


def prune(state, now):
    cutoff = now - WINDOW_SECONDS
    for key in ("OPTIONS", "REGISTER", "INVITE", "FAILED_REGISTER", "OUTSIDE_INVITE"):
        while state[key] and state[key][0] < cutoff:
            state[key].popleft()
    while state["TARGETS"] and state["TARGETS"][0][0] < cutoff:
        state["TARGETS"].popleft()


def classify(state):
    options_count = len(state["OPTIONS"])
    failed_register_count = len(state["FAILED_REGISTER"])
    invite_count = len(state["INVITE"])
    outside_invite_count = len(state["OUTSIDE_INVITE"])
    unique_targets = len({target for _, target in state["TARGETS"] if target})

    if outside_invite_count >= 5 or invite_count >= 10:
        return "FRAUD_BURST", 100, "Rapid external INVITE activity"
    if failed_register_count >= 10:
        return "AUTHENTICATION_ATTACK", 70, "Repeated failed REGISTER transactions"
    if options_count >= 5 or (options_count >= 3 and unique_targets >= 5):
        return "RECONNAISSANCE", 30, "Rapid OPTIONS scan across SIP targets"
    return "NORMAL", 0, "Thresholds not reached"


def calculate_class_metrics(confusion, label, total):
    tp = confusion[label][label]
    fp = sum(confusion[actual][label] for actual in STAGE_ORDER if actual != label)
    fn = sum(confusion[label][predicted] for predicted in STAGE_ORDER if predicted != label)
    tn = total - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return tp, fp, fn, tn, precision, recall, f1, false_positive_rate


def main():
    packet_rows = load_rows(PACKET_FILE)
    truth_rows = load_rows(TRUTH_FILE)
    request_rows = [
        row
        for row in packet_rows
        if clean(row.get("sip.Method")).upper() in {"REGISTER", "OPTIONS", "INVITE"}
    ]

    matched = match_truth_to_requests(truth_rows, request_rows)
    responses = index_responses(packet_rows)
    states = defaultdict(new_state)
    events = []

    for event_number, (truth, request) in enumerate(matched, start=1):
        method = clean(request.get("sip.Method")).upper()
        source_ip = clean(request.get("ip.src"))
        entity = request_entity(request)
        target = request_target(request, method)
        request_time = packet_epoch(request)
        response_time, response_status = correlated_response(request, responses)
        decision_time = response_time if method == "REGISTER" and response_status else request_time

        state = states[entity]
        prune(state, decision_time)
        state[method].append(request_time)
        state["TARGETS"].append((request_time, target))

        if method == "REGISTER" and response_status in FAILURE_CODES:
            state["FAILED_REGISTER"].append(response_time)
        if method == "INVITE" and is_outside_target(target):
            state["OUTSIDE_INVITE"].append(request_time)

        prune(state, decision_time)
        predicted, risk_score, reason = classify(state)
        actual = TRUTH_MAP.get(clean(truth.get("label")), "UNKNOWN")
        unique_targets = len({value for _, value in state["TARGETS"] if value})

        events.append(
            {
                "event_number": event_number,
                "request_time_epoch": request_time,
                "request_time_utc": utc_text(request_time),
                "decision_time_epoch": decision_time,
                "decision_time_utc": utc_text(decision_time),
                "entity": entity,
                "source_ip": source_ip,
                "method": method,
                "target": target,
                "response_status": response_status,
                "ground_truth": actual,
                "predicted_stage": predicted,
                "correct": int(actual == predicted),
                "options_count": len(state["OPTIONS"]),
                "failed_register_count": len(state["FAILED_REGISTER"]),
                "invite_count": len(state["INVITE"]),
                "outside_invite_count": len(state["OUTSIDE_INVITE"]),
                "unique_targets": unique_targets,
                "risk_score": risk_score,
                "reason": reason,
            }
        )

    timeline_headers = [key for key in events[0] if not key.endswith("_epoch")]
    with TIMELINE_FILE.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=timeline_headers)
        writer.writeheader()
        for event in events:
            writer.writerow({key: event[key] for key in timeline_headers})

    confusion = {actual: Counter() for actual in STAGE_ORDER}
    for event in events:
        confusion[event["ground_truth"]][event["predicted_stage"]] += 1

    metric_rows = []
    for label in STAGE_ORDER:
        values = calculate_class_metrics(confusion, label, len(events))
        metric_rows.append(
            {
                "scope": "stage",
                "class": label,
                "tp": values[0],
                "fp": values[1],
                "fn": values[2],
                "tn": values[3],
                "precision": f"{values[4]:.4f}",
                "recall": f"{values[5]:.4f}",
                "f1": f"{values[6]:.4f}",
                "false_positive_rate": f"{values[7]:.4f}",
                "support": sum(confusion[label].values()),
            }
        )

    binary_tp = binary_fp = binary_fn = binary_tn = 0
    for event in events:
        actual_attack = event["ground_truth"] in ATTACK_STAGES
        predicted_attack = event["predicted_stage"] in ATTACK_STAGES
        if actual_attack and predicted_attack:
            binary_tp += 1
        elif not actual_attack and predicted_attack:
            binary_fp += 1
        elif actual_attack and not predicted_attack:
            binary_fn += 1
        else:
            binary_tn += 1

    binary_precision = binary_tp / (binary_tp + binary_fp) if binary_tp + binary_fp else 0.0
    binary_recall = binary_tp / (binary_tp + binary_fn) if binary_tp + binary_fn else 0.0
    binary_f1 = (
        2 * binary_precision * binary_recall / (binary_precision + binary_recall)
        if binary_precision + binary_recall
        else 0.0
    )
    binary_fpr = binary_fp / (binary_fp + binary_tn) if binary_fp + binary_tn else 0.0
    metric_rows.append(
        {
            "scope": "binary",
            "class": "ATTACK",
            "tp": binary_tp,
            "fp": binary_fp,
            "fn": binary_fn,
            "tn": binary_tn,
            "precision": f"{binary_precision:.4f}",
            "recall": f"{binary_recall:.4f}",
            "f1": f"{binary_f1:.4f}",
            "false_positive_rate": f"{binary_fpr:.4f}",
            "support": binary_tp + binary_fn,
        }
    )

    with METRICS_FILE.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metric_rows[0]))
        writer.writeheader()
        writer.writerows(metric_rows)

    scenarios = []
    scenario_start = 0
    scenario_number = 0
    while scenario_start < len(events):
        scenario_number += 1
        actual = events[scenario_start]["ground_truth"]
        scenario_end = scenario_start
        while scenario_end + 1 < len(events) and events[scenario_end + 1]["ground_truth"] == actual:
            scenario_end += 1
        group = events[scenario_start : scenario_end + 1]
        matching_alert = next((event for event in group if event["predicted_stage"] == actual), None)
        detected = actual == "NORMAL" or matching_alert is not None
        ttd = ""
        detection_time = ""
        if actual in ATTACK_STAGES and matching_alert:
            ttd = f"{matching_alert['decision_time_epoch'] - group[0]['request_time_epoch']:.6f}"
            detection_time = matching_alert["decision_time_utc"]

        scenarios.append(
            {
                "scenario_number": scenario_number,
                "ground_truth_stage": actual,
                "entity": group[0]["entity"],
                "event_count": len(group),
                "start_time_utc": group[0]["request_time_utc"],
                "end_time_utc": group[-1]["request_time_utc"],
                "detected": int(detected),
                "detection_time_utc": detection_time,
                "time_to_detect_seconds": ttd,
            }
        )
        scenario_start = scenario_end + 1

    with SUMMARY_FILE.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scenarios[0]))
        writer.writeheader()
        writer.writerows(scenarios)

    print("V3 windowed stage detection completed")
    print(f"Window: {WINDOW_SECONDS:.1f} seconds")
    print(f"Matched events: {len(events)} of {len(truth_rows)}")
    print()
    print("Confusion matrix (rows=actual, columns=predicted)")
    print("ACTUAL\\PRED".ljust(26), *(label[:10].rjust(11) for label in STAGE_ORDER))
    for actual in STAGE_ORDER:
        print(actual.ljust(26), *(str(confusion[actual][label]).rjust(11) for label in STAGE_ORDER))
    print()
    print(
        "Binary attack metrics: "
        f"precision={binary_precision:.4f}, recall={binary_recall:.4f}, "
        f"F1={binary_f1:.4f}, false-positive-rate={binary_fpr:.4f}"
    )
    print()
    print("Scenario detection")
    for scenario in scenarios:
        raw_ttd = scenario["time_to_detect_seconds"]
        ttd_text = f"{raw_ttd}s" if raw_ttd else "N/A"
        print(
            f"{scenario['ground_truth_stage']:<24} "
            f"detected={scenario['detected']} TTD={ttd_text}"
        )
    print()
    print("Timeline:", TIMELINE_FILE)
    print("Scenario summary:", SUMMARY_FILE)
    print("Metrics:", METRICS_FILE)


if __name__ == "__main__":
    main()

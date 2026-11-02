#!/usr/bin/env python3
"""Read-only, protocol-aware SIP candidate replay on one archived packet capture.

Development rule: match final responses by Call-ID, CSeq, method, and reversed
addresses; count a rejected digest REGISTER after a 1 s retry grace period;
ignore stale challenges and successful retries. Alert at 10 confirmed rejections
from one source within 60 s. Other stage thresholds match frozen V3.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


SHORT_SECONDS = 10.0
LONG_SECONDS = 60.0
RETRY_GRACE_SECONDS = 1.0
FIELDS = (
    "frame.time_epoch", "ip.src", "ip.dst", "sip.Method", "sip.Status-Code",
    "sip.CSeq.method", "sip.CSeq.seq", "sip.Call-ID", "sip.from.user",
    "sip.to.user", "sip.r-uri.user", "sip.auth.username", "sip.auth.stale",
)


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def epoch(iso):
    return datetime.fromisoformat(iso.strip().replace("Z", "+00:00")).timestamp()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean(value):
    return (value or "").strip()


def extract(pcap):
    command = ["tshark", "-r", str(pcap), "-Y", "sip", "-T", "fields",
               "-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
    for field in FIELDS:
        command.extend(("-e", field))
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=45)
    packets = list(csv.DictReader(io.StringIO(result.stdout)))
    if not packets:
        raise RuntimeError("No SIP packets decoded from capture")
    for packet in packets:
        packet["time"] = float(packet["frame.time_epoch"])
        packet["digest_present"] = bool(clean(packet["sip.auth.username"]))
        packet["stale"] = clean(packet["sip.auth.stale"]).lower() == "true"
    return sorted(packets, key=lambda p: p["time"])


def entity(packet):
    ip = clean(packet["ip.src"])
    if ip in ("", "127.0.0.1", "::1"):
        return clean(packet["sip.from.user"]) or ip or "unknown"
    return ip


def target(packet, method):
    if method == "REGISTER":
        return clean(packet["sip.to.user"]) or clean(packet["sip.r-uri.user"])
    return clean(packet["sip.r-uri.user"]) or clean(packet["sip.to.user"])


def fresh_state():
    return {field: deque() for field in (
        "options", "targets", "invites", "outside", "failures_10s", "failures_60s")}


def prune(state, now):
    for field, seconds in (("options", SHORT_SECONDS), ("targets", SHORT_SECONDS),
                           ("invites", SHORT_SECONDS), ("outside", SHORT_SECONDS),
                           ("failures_10s", SHORT_SECONDS), ("failures_60s", LONG_SECONDS)):
        queue = state[field]
        while queue and queue[0][0] < now - seconds:
            queue.popleft()


def classify(state):
    options = len(state["options"])
    unique_targets = len({value for _, value in state["targets"] if value})
    if len(state["outside"]) >= 5 or len(state["invites"]) >= 10:
        return "FRAUD_BURST", 100, "Rapid external INVITE requests"
    if len(state["failures_60s"]) >= 10:
        return "AUTHENTICATION_ATTACK", 70, "10 rejected digest dialogs in 60 s"
    if options >= 5 or (options >= 3 and unique_targets >= 5):
        return "RECONNAISSANCE", 30, "Rapid OPTIONS requests"
    return "NORMAL", 0, "Thresholds not reached"


def read_truth(pcap):
    path = pcap.parent / "scenario_ground_truth.csv"
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def replay(pcap, output, observation_end, baseline):
    packets = extract(pcap)
    if observation_end < packets[-1]["time"]:
        raise RuntimeError("Observation end precedes the last captured SIP packet")
    states = defaultdict(fresh_state)
    requests = {}
    pending = {}
    timeline = []
    stats = defaultdict(int)
    first_request = None

    def add_event(now, kind, request, status="", digest=False, stale=False):
        key = request["entity"]
        state = states[key]
        prune(state, now)
        predicted, score, reason = classify(state)
        event = {
            "event_number": len(timeline) + 1, "time_utc": utc(now),
            "epoch": now, "event_type": kind, "entity": key,
            "method": request["method"], "target": request["target"],
            "call_id": request["call_id"], "cseq": request["cseq"],
            "status": status, "digest_present": int(digest),
            "stale_challenge": int(stale),
            "failed_digest_10s": len(state["failures_10s"]),
            "failed_digest_60s": len(state["failures_60s"]),
            "options_10s": len(state["options"]),
            "predicted_stage": predicted, "risk_score": score, "reason": reason,
        }
        timeline.append(event)

    def flush_failures(now, include_boundary=False):
        due = sorted((value["due"], key) for key, value in pending.items()
                     if value["due"] < now or include_boundary and value["due"] <= now)
        for due_time, key in due:
            item = pending.pop(key, None)
            if item is None:
                continue
            req = item["request"]
            state = states[req["entity"]]
            state["failures_10s"].append((due_time, req["call_id"]))
            state["failures_60s"].append((due_time, req["call_id"]))
            stats["confirmed_rejected_digest_dialogs"] += 1
            add_event(due_time, "CONFIRMED_REJECTION", req, status=item["status"],
                      digest=True)

    for packet in packets:
        now = packet["time"]
        flush_failures(now)
        method = clean(packet["sip.Method"]).upper()
        if method in ("REGISTER", "OPTIONS", "INVITE"):
            call_id, cseq = clean(packet["sip.Call-ID"]), clean(packet["sip.CSeq.seq"])
            request_key = (call_id, cseq, method, clean(packet["ip.src"]),
                           clean(packet["ip.dst"]))
            if request_key in requests and now - requests[request_key]["epoch"] < 5:
                stats["retransmitted_requests_skipped"] += 1
                continue
            req = {"entity": entity(packet), "method": method,
                   "target": target(packet, method), "call_id": call_id,
                   "cseq": cseq, "epoch": now,
                   "digest": packet["digest_present"],
                   "from_user": clean(packet["sip.from.user"])}
            requests[request_key] = req
            stats["request_events"] += 1
            if first_request is None:
                first_request = now
            state = states[req["entity"]]
            prune(state, now)
            state["targets"].append((now, req["target"]))
            if method == "OPTIONS":
                state["options"].append((now, req["target"]))
            if method == "INVITE":
                state["invites"].append((now, req["target"]))
                if req["target"].startswith(("00", "+")):
                    state["outside"].append((now, req["target"]))
            add_event(now, "REQUEST", req, digest=req["digest"])
            continue

        status = clean(packet["sip.Status-Code"])
        response_method = clean(packet["sip.CSeq.method"]).upper()
        if not status.isdigit() or int(status) < 200 or response_method != "REGISTER":
            continue
        request_key = (clean(packet["sip.Call-ID"]), clean(packet["sip.CSeq.seq"]),
                       response_method, clean(packet["ip.dst"]), clean(packet["ip.src"]))
        req = requests.get(request_key)
        if req is None or now - req["epoch"] > 5 or req.get("final_seen"):
            stats["unmatched_or_repeated_register_responses"] += 1
            continue
        req["final_seen"] = True
        dialog = (req["entity"], req["from_user"], req["call_id"])
        if status == "200":
            stats["successful_register_200"] += 1
            if dialog in pending:
                pending.pop(dialog)
                stats["rejection_cancelled_by_success"] += 1
        elif status in ("401", "403"):
            if packet["stale"]:
                stats["stale_digest_challenges_ignored"] += 1
            elif not req["digest"]:
                stats["initial_unauthenticated_challenges_ignored"] += 1
            else:
                pending[dialog] = {"request": req,
                                   "due": now + RETRY_GRACE_SECONDS,
                                   "status": status}
                stats["authenticated_rejections_pending"] += 1
        add_event(now, "REGISTER_FINAL_RESPONSE", req, status=status,
                  digest=req["digest"], stale=packet["stale"])

    flush_failures(observation_end, include_boundary=True)
    stats["unresolved_at_observation_end"] = len(pending)
    alerts = [row for row in timeline if row["predicted_stage"] != "NORMAL"]
    first = alerts[0] if alerts else None
    output.mkdir(mode=0o700, parents=True)
    timeline_path = output / "candidate_timeline.csv"
    summary_path = output / "candidate_summary.json"
    if timeline_path.exists() or summary_path.exists():
        raise RuntimeError("Candidate output exists; use a new directory")
    with timeline_path.open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[key for key in timeline[0] if key != "epoch"])
        writer.writeheader()
        writer.writerows({key: value for key, value in row.items() if key != "epoch"}
                         for row in timeline)
    summary = {
        "candidate_rule": "V5 development: exact CSeq, digest+terminal rejection, 1 s grace, 10 in 60 s",
        "capture": str(pcap), "source_sha256": sha(Path(__file__)),
        "frozen_v3_sha256": sha(baseline) if baseline else None,
        "pcap_sha256": sha(pcap), "observation_end_utc": utc(observation_end),
        "first_request_utc": utc(first_request),
        "first_alert_stage": first["predicted_stage"] if first else None,
        "first_alert_event_type": first["event_type"] if first else None,
        "first_alert_utc": first["time_utc"] if first else None,
        "time_to_first_alert_seconds": round(first["epoch"] - first_request, 6) if first else None,
        "scenario_ground_truth": read_truth(pcap),
        "counts": dict(stats),
        "note": "Selected scenario labels are not independent event-level accuracy metrics. "
                "A pending rejection counts only after an observed one-second retry grace.",
    }
    with summary_path.open("x") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"capture": str(pcap), "alert": summary["first_alert_stage"],
                      "ttd_s": summary["time_to_first_alert_seconds"],
                      "counts": dict(stats)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--observation-end-utc")
    args = parser.parse_args()
    os.umask(0o077)
    pcap = args.capture.resolve()
    if not pcap.is_file():
        parser.error(f"Missing capture: {pcap}")
    truth = read_truth(pcap)
    end = args.observation_end_utc or (truth[0].get("end_utc") if len(truth) == 1 else None)
    observation_end = epoch(end) if end else pcap.stat().st_mtime
    replay(pcap, args.output_dir.resolve(), observation_end, args.baseline)


if __name__ == "__main__":
    main()

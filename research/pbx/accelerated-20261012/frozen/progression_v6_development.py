#!/usr/bin/env python3
"""Offline development replay: link confirmed SIP auth failures to a later call.

V5 supplies transaction-matched confirmed rejections and successful REGISTER
responses. V6 links events by (source IP, account), then checks an outbound
INVITE and independent SIP/CDR evidence. No rule here proves credential theft.
"""
import argparse
import csv
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

MIN_REJECTIONS = 5
AUTH_WINDOW_S = 120
CALL_WINDOW_S = 120
RECON_TARGETS = 5
RECON_WINDOW_S = 10
AUTH_ALERT_REJECTIONS = 10
AUTH_ALERT_WINDOW_S = 60


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def cdr_rows(path):
    with path.open(newline="") as stream:
        return list(csv.reader(stream))


def epoch(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def utc(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def cdr_utc(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def added_cdr(run):
    before, after = cdr_rows(run / "cdr_before.csv"), cdr_rows(run / "cdr_after.csv")
    if after[:len(before)] != before:
        raise ValueError("CDR after snapshot does not preserve before snapshot")
    return after[len(before):]


def call_index(packets):
    accounts = {}
    for row in packets:
        if row["sip.Method"] == "INVITE" and row["sip.from.user"]:
            accounts[(row["ip.src"], row["sip.Call-ID"])] = row["sip.from.user"]
    return accounts


def completed_sip_call(packets, invite):
    source, call_id = invite["source_ip"], invite["call_id"]
    peer = invite["pbx_ip"]
    leg = [row for row in packets if row["sip.Call-ID"] == call_id]
    return (any(row["ip.src"] == peer and row["ip.dst"] == source
                and row["sip.Status-Code"] == "200"
                and row["sip.CSeq.method"] == "INVITE" for row in leg)
            and any(row["ip.src"] == source and row["ip.dst"] == peer
                    and row["sip.Method"] == "ACK" for row in leg)
            and any(row["sip.Method"] == "BYE" for row in leg))


def evaluate(run, v5_path, lab_destinations):
    timeline = rows(v5_path)
    packets = rows(run / "sip_packets.csv")
    accounts = call_index(packets)
    failures = defaultdict(deque)
    recent_auth = defaultdict(deque)
    recent_options = defaultdict(deque)
    recon_emitted, auth_emitted = set(), set()
    suspected = {}
    seen_calls = set()
    events = []
    attempts = []
    for row in timeline:
        now = epoch(row["time_utc"])
        source = row["entity"]
        account = row["target"] if row["method"] == "REGISTER" else ""
        key = (source, account)
        if row["event_type"] == "REQUEST" and row["method"] == "OPTIONS":
            recent = recent_options[source]
            recent.append((now, row["target"]))
            while recent and recent[0][0] < now - RECON_WINDOW_S:
                recent.popleft()
            distinct = {target for _, target in recent if target}
            if len(distinct) >= RECON_TARGETS and source not in recon_emitted:
                recon_emitted.add(source)
                events.append({"stage": "RECONNAISSANCE", "time_utc": utc(now),
                               "source_ip": source, "account": "", "destination": "",
                               "call_id": row["call_id"],
                               "evidence": f"{len(distinct)} distinct OPTIONS targets in 10 s"})
            continue
        if row["event_type"] == "CONFIRMED_REJECTION" and account:
            failures[key].append(now)
            recent = recent_auth[key]
            recent.append(now)
            while recent and recent[0] < now - AUTH_ALERT_WINDOW_S:
                recent.popleft()
            if len(recent) >= AUTH_ALERT_REJECTIONS and key not in auth_emitted:
                auth_emitted.add(key)
                events.append({"stage": "AUTHENTICATION_ATTACK", "time_utc": utc(now),
                               "source_ip": source, "account": account,
                               "destination": "", "call_id": row["call_id"],
                               "evidence": "10 confirmed authenticated rejections in 60 s"})
            continue
        if (row["event_type"] == "REGISTER_FINAL_RESPONSE"
                and row["status"] == "200" and account):
            recent = failures[key]
            while recent and recent[0] < now - AUTH_WINDOW_S:
                recent.popleft()
            if len(recent) >= MIN_REJECTIONS:
                suspected[key] = {"time": now, "first_failure": recent[0],
                                  "rejections": len(recent)}
                events.append({"stage": "SUSPECTED_COMPROMISE", "time_utc": utc(now),
                               "source_ip": source, "account": account,
                               "destination": "", "call_id": "",
                               "evidence": f"{len(recent)} confirmed rejections then REGISTER 200"})
            continue
        if row["event_type"] != "REQUEST" or row["method"] != "INVITE":
            continue
        cid, dst = row["call_id"], row["target"]
        account = accounts.get((source, cid), "")
        key = (source, account)
        prior = suspected.get(key)
        outbound = dst.startswith(("00", "+")) or dst in lab_destinations
        if not prior or not outbound or not (prior["time"] <= now <= prior["time"] + CALL_WINDOW_S):
            continue
        if (source, cid) in seen_calls:
            continue
        seen_calls.add((source, cid))
        attempt = {"time": now, "source_ip": source, "pbx_ip": "172.16.200.81",
                   "account": account, "destination": dst, "call_id": cid,
                   "first_failure": prior["first_failure"]}
        attempts.append(attempt)
        events.append({"stage": "SUSPECTED_OUTBOUND_ATTEMPT", "time_utc": utc(now),
                       "source_ip": source, "account": account, "destination": dst,
                       "call_id": cid, "evidence": "linked INVITE after suspicious REGISTER"})
    new_cdr = added_cdr(run)
    answered = 0
    for attempt in attempts:
        if not completed_sip_call(packets, attempt):
            continue
        matches = [cdr for cdr in new_cdr if len(cdr) >= 17
                   and cdr[1:3] == [attempt["account"], attempt["destination"]]
                   and cdr[14] == "ANSWERED" and cdr[13].isdigit()
                   and int(cdr[13]) > 0 and cdr[9] and cdr[11]
                   and -2 <= cdr_utc(cdr[9]) - attempt["time"] <= 5]
        if len(matches) != 1:
            continue
        cdr = matches[0]
        answered += 1
        events.append({"stage": "ANSWERED_EMULATED_OUTBOUND" if
                       attempt["destination"] in lab_destinations else "ANSWERED_OUTBOUND",
                       "time_utc": utc(cdr_utc(cdr[11])),
                       "source_ip": attempt["source_ip"], "account": attempt["account"],
                       "destination": attempt["destination"], "call_id": attempt["call_id"],
                       "evidence": f"SIP 200/ACK/BYE and CDR ANSWERED, billsec={cdr[13]}"})
    return events, {"confirmed_rejections": sum(row["event_type"] == "CONFIRMED_REJECTION"
                    for row in timeline), "register_200": sum(row["event_type"] ==
                    "REGISTER_FINAL_RESPONSE" and row["status"] == "200" for row in timeline),
                    "new_cdr_rows": len(new_cdr), "linked_outbound_attempts": len(attempts),
                    "answered_linked_calls": answered, "v5_timeline_sha256": sha(v5_path),
                    "pcap_sha256": sha(run / "traffic.pcap")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--v5-timeline", type=Path)
    parser.add_argument("--lab-destination", action="append", default=[])
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    v5 = args.v5_timeline or run / "candidate_v5/candidate_timeline.csv"
    if not v5.is_file():
        v5 = run / "v5_replay/candidate_timeline.csv"
    events, counts = evaluate(run, v5, set(args.lab_destination))
    output = (args.output_dir or run / "v6_development_v3").resolve()
    output.mkdir(mode=0o700)
    with (output / "progression_events.csv").open("x", newline="") as stream:
        fields = ["stage", "time_utc", "source_ip", "account", "destination", "call_id", "evidence"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(events)
    summary = {"method": "V6 development; same source IP and account",
               "source_sha256": sha(Path(__file__)),
               "rule": f"{RECON_TARGETS} distinct OPTIONS targets/{RECON_WINDOW_S}s; "
                       f"{AUTH_ALERT_REJECTIONS} confirmed rejections/{AUTH_ALERT_WINDOW_S}s; "
                       f">={MIN_REJECTIONS} rejections/{AUTH_WINDOW_S}s + REGISTER 200, "
                       f"outbound INVITE/{CALL_WINDOW_S}s, independent SIP/CDR confirmation",
               "case": run.name, "lab_destinations": args.lab_destination,
               "counts": counts, "stages": [event["stage"] for event in events],
               "first_suspected_utc": next((e["time_utc"] for e in events if
                    e["stage"] == "SUSPECTED_COMPROMISE"), None),
               "first_attempt_utc": next((e["time_utc"] for e in events if
                    e["stage"] == "SUSPECTED_OUTBOUND_ATTEMPT"), None),
               "note": "Development cases are previously inspected. Suspected does not prove theft; "
                       "CDR stage is retrospective and its write latency was not measured. "
                       "Asterisk CDR wall times are interpreted as UTC for this lab, checked "
                       "against capture timestamps. Isolated runs prevent concurrent CDR ambiguity."}
    (output / "progression_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"case": run.name, "stages": summary["stages"], "counts": counts}))


if __name__ == "__main__":
    main()

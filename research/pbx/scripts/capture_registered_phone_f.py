#!/usr/bin/env python3
"""Capture one registered real-phone F scenario on the Asterisk PBX Pi.

Run one case at a time, after both phones register. The operator places and
answers the prescribed internal calls while tcpdump records. This runner
captures evidence and independent call checks; detector replay follows later.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from run_remote_sipp_challenges import sip_packets


ROOT = Path("/home/astrix/sip-fraud-research")
DATA = ROOT / "datasets/normal-call-runs"
CDR = Path("/var/log/asterisk/cdr-csv/Master.csv")
FULL = Path("/var/log/asterisk/full")
PBX = "172.16.200.81"
SIPP = "172.16.200.68"
DETECTORS = {
    "v3": (ROOT / "datasets/runs/20260923T094044Z/stage_detector_v3.py",
           "579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a"),
    "v5": (ROOT / "scripts/candidate_v5_replay.py",
           "e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004"),
    "v6": (ROOT / "scripts/progression_v6_development.py",
           "c4b9231a89a815e93f1264119e229df1a563d574ba4b6a7e357d8125983eb2b4"),
}
CASES = {
    "F01": {"duration_s": 300, "caller": "1001", "callee": "1002", "min_calls": 2,
            "instructions": "At least two separate answered 1001 to 1002 calls, each hung up"},
    "F02": {"duration_s": 300, "caller": "1002", "callee": "1001", "min_calls": 2,
            "instructions": "At least two separate answered 1002 to 1001 calls, each hung up"},
    "F06": {"duration_s": 180, "caller": "either", "callee": "other", "min_calls": 5,
            "instructions": "Five separate answered calls between 1001 and 1002, first INVITE through final BYE within 120 seconds"},
}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"Command failed ({args[0]}): {result.stderr[-160:]}")
    return result.stdout


def preflight():
    for path, expected in DETECTORS.values():
        if sha(path) != expected:
            raise RuntimeError(f"Frozen detector hash mismatch: {path.name}")
    if "172.16.200.81/24" not in command("ip", "-4", "-brief", "address", "show", "wlan0"):
        raise RuntimeError("PBX wlan0 address changed")
    contacts = command("asterisk", "-rx", "pjsip show contacts")
    found = {extension: re.search(rf"\b{extension}/sip:{extension}@([^\s;]+)", contacts)
             for extension in ("1001", "1002")}
    if not all(found.values()):
        raise RuntimeError("Both phone contacts must be present: " + contacts)
    if "0 active calls" not in command("asterisk", "-rx", "core show channels count"):
        raise RuntimeError("Existing Asterisk call is active")
    dialplan = command("asterisk", "-rx", "dialplan show internal")
    if "'1001'" not in dialplan or "'1002'" not in dialplan or "'8800" in dialplan:
        raise RuntimeError("Unexpected internal dialplan")
    return {key: match.group(1) for key, match in found.items()}


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.reader(stream))


def packet_time(row):
    return float(row["frame.time_epoch"])


def verify(run, case, settings):
    packets = list(csv.DictReader((run / "sip_packets.csv").open(newline="")))
    before, after = rows(run / "cdr_before.csv"), rows(run / "cdr_after.csv")
    if after[:len(before)] != before:
        raise ValueError("CDR before snapshot is not a prefix of after snapshot")
    new = after[len(before):]
    answered = [row for row in new if len(row) >= 17 and row[14] == "ANSWERED"
                and row[13].isdigit() and int(row[13]) > 0
                and (row[1], row[2]) in {("1001", "1002"), ("1002", "1001")}
                and (settings["caller"] == "either" or
                     (row[1], row[2]) == (settings["caller"], settings["callee"]))]
    clients = {}
    for row in packets:
        if (row["sip.Method"] == "INVITE" and row["ip.dst"] == PBX
                and row["ip.src"] not in {PBX, SIPP}
                and (row["sip.from.user"], row["sip.r-uri.user"]) in
                {("1001", "1002"), ("1002", "1001")}
                and (settings["caller"] == "either" or
                     (row["sip.from.user"], row["sip.r-uri.user"]) ==
                     (settings["caller"], settings["callee"]))):
            clients.setdefault(row["sip.Call-ID"], row)
    completed = []
    for callid, invite in clients.items():
        leg = [row for row in packets if row["sip.Call-ID"] == callid]
        source = invite["ip.src"]
        checks = (
            any(row["ip.src"] == PBX and row["ip.dst"] == source
                and row["sip.Status-Code"] == "200" and row["sip.CSeq.method"] == "INVITE"
                for row in leg),
            any(row["ip.src"] == source and row["ip.dst"] == PBX
                and row["sip.Method"] == "ACK" for row in leg),
            any(row["sip.Method"] == "BYE" for row in leg),
        )
        if all(checks):
            completed.append({"call_id": callid, "src": invite["sip.from.user"],
                              "dst": invite["sip.r-uri.user"], "invite_epoch": packet_time(invite),
                              "last_bye_epoch": max(packet_time(row) for row in leg
                                                    if row["sip.Method"] == "BYE")})
    if len(completed) < settings["min_calls"] or len(answered) < settings["min_calls"]:
        raise ValueError("Fewer than required completed SIP calls or positive-billsec ANSWERED CDRs")
    if case == "F06":
        ordered = sorted(completed, key=lambda item: item["invite_epoch"])
        if not any(ordered[i+4]["last_bye_epoch"] - ordered[i]["invite_epoch"] <= 120
                   for i in range(len(ordered) - 4)):
            raise ValueError("Five completed calls did not fit in the declared 120-second burst")
    if "0 packets dropped by kernel" not in (run / "tcpdump.log").read_text():
        raise ValueError("Capture drop count nonzero or unavailable")
    if any(row["ip.src"] == SIPP or row["ip.dst"] == SIPP for row in packets):
        raise ValueError("SIPp generator traffic appeared in phone capture")
    result = {"valid": True, "case": case, "answered_cdr_count": len(answered),
              "answered_cdrs": [{"src": row[1], "dst": row[2], "billsec": int(row[13])}
                                 for row in answered], "complete_client_calls": completed,
              "new_cdr_rows": len(new), "decoded_sip_packets": len(packets)}
    (run / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    with (run / "scenario_ground_truth.csv").open("x", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("scenario_id", "label", "answered_cdr_count", "complete_client_calls",
                         "evaluation_unit", "source"))
        writer.writerow((case, "BENIGN_REAL_PHONE", len(answered), len(completed),
                         "one_full_session", "real_softphones"))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=CASES)
    args = parser.parse_args()
    os.umask(0o077)
    settings = CASES[args.case]
    contacts = preflight()
    run = DATA / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
                  f"-{args.case.lower()}-real-phone")
    run.mkdir(parents=True, mode=0o700)
    plan = {"case": args.case, "label": "BENIGN_REAL_PHONE", "registered_role": "one fresh negative scenario",
            "declared_utc": utc(), "runner_sha256": sha(Path(__file__)),
            "detector_sha256": {name: expected for name, (_, expected) in DETECTORS.items()},
            "generator": "two live real softphones; client software binary hash unavailable",
            "phone_contact_hosts": contacts, "pbx": PBX,
            "duration_s": settings["duration_s"], "planned_call_schedule": settings["instructions"],
            "source_account": settings["caller"], "destination": settings["callee"],
            "capture_filter": f"udp and port 5060 and not host {SIPP}",
            "invalid_if": "Registration absent, insufficient complete answered calls, wrong direction/timing, CDR/SIP mismatch, capture loss or unexpected source"}
    (run / "predeclared_protocol.json").write_text(json.dumps(plan, indent=2) + "\n")
    (run / "cdr_before.csv").write_bytes(CDR.read_bytes())
    log_start = FULL.stat().st_size
    cap = None
    errors = []
    started = utc()
    try:
        with (run / "tcpdump.log").open("x") as log:
            cap = subprocess.Popen(["tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0",
                                    "-w", str(run / "traffic.pcap"),
                                    f"udp and port 5060 and not host {SIPP}"],
                                   stdout=subprocess.DEVNULL, stderr=log)
            time.sleep(1)
            if cap.poll() is not None:
                raise RuntimeError("tcpdump exited before calls")
            print(json.dumps({"capture_started": True, "case": args.case, "run_dir": str(run),
                              "started_utc": started, "duration_s": settings["duration_s"],
                              "instructions": settings["instructions"]}), flush=True)
            time.sleep(settings["duration_s"])
    except Exception as exc:
        errors.append(f"capture: {type(exc).__name__}: {exc}")
    finally:
        if cap is not None:
            try:
                if cap.poll() is None:
                    cap.send_signal(signal.SIGINT)
                cap.wait(timeout=8)
            except Exception as exc:
                errors.append(f"capture cleanup: {exc}")
        (run / "cdr_after.csv").write_bytes(CDR.read_bytes())
        with FULL.open(errors="replace") as stream:
            stream.seek(log_start)
            (run / "asterisk_log_during_capture.txt").write_text(stream.read())
    ended = utc()
    result = None
    if (run / "traffic.pcap").is_file():
        try:
            sip_packets(run / "traffic.pcap", run / "sip_packets.csv")
            result = verify(run, args.case, settings)
        except Exception as exc:
            errors.append(f"verification: {type(exc).__name__}: {exc}")
    else:
        errors.append("No PCAP")
    status = {"run_dir": str(run), "case": args.case, "start_utc": started, "end_utc": ended,
              "pcap_sha256": sha(run / "traffic.pcap") if (run / "traffic.pcap").is_file() else None,
              "verified": result, "errors": errors}
    (run / "capture_status.json").write_text(json.dumps(status, indent=2) + "\n")
    print(json.dumps(status), flush=True)
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

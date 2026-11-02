#!/usr/bin/env python3
"""Capture fresh real-phone normal SIP calls on the PBX Pi for five minutes."""
import csv
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from run_remote_sipp_challenges import sip_packets

ROOT = Path("/home/astrix/sip-fraud-research/datasets/normal-call-runs")
CDR = Path("/var/log/asterisk/cdr-csv/Master.csv")
SECONDS = 300


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = ROOT / f"{stamp}-n1-real-phone"
    run.mkdir(mode=0o700)
    protocol = {"scenario_id": "N1-real-phone", "label": "NORMAL_ANSWERED_INTERNAL_CALLS",
                "declared_utc": utc(), "duration_s": SECONDS,
                "expected": "1001 to 1002 and 1002 to 1001, each answered and hung up",
                "capture_filter": "udp and port 5060 and not host 172.16.200.68",
                "invalid_if": "Fewer than two independently matched answered calls, missing SIP or CDR, or capture loss",
                "evaluation_role": "development normal control, not final unseen holdout"}
    (run / "predeclared_protocol.json").write_text(json.dumps(protocol, indent=2) + "\n")
    shutil.copyfile(CDR, run / "cdr_before.csv")
    capture = None
    error = None
    started = utc()
    try:
        with (run / "tcpdump.log").open("x") as log:
            capture = subprocess.Popen(["tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0",
                                        "-w", str(run / "traffic.pcap"),
                                        "udp and port 5060 and not host 172.16.200.68"],
                                       stdout=subprocess.DEVNULL, stderr=log)
            time.sleep(1)
            if capture.poll() is not None:
                raise RuntimeError("Capture exited before calls")
            print(json.dumps({"capture_started": True, "run_dir": str(run),
                              "start_utc": started, "duration_s": SECONDS}), flush=True)
            time.sleep(SECONDS)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if capture is not None:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            capture.wait(timeout=8)
        shutil.copyfile(CDR, run / "cdr_after.csv")
    ended = utc()
    packets = sip_packets(run / "traffic.pcap", run / "sip_packets.csv")
    with (run / "cdr_before.csv").open(newline="") as stream:
        before = list(csv.reader(stream))
    with (run / "cdr_after.csv").open(newline="") as stream:
        after = list(csv.reader(stream))
    if after[:len(before)] != before:
        error = error or "CDR snapshot prefix mismatch"
    new = after[len(before):]
    relevant = [r for r in new if len(r) >= 15 and (r[1], r[2]) in
                {("1001", "1002"), ("1002", "1001")}]
    status = {"run_dir": str(run), "start_utc": started, "end_utc": ended,
              "decoded_sip_packets": len(packets), "new_cdr_rows": len(new),
              "relevant_cdrs": [{"src": r[1], "dst": r[2], "billsec": r[13],
                                 "disposition": r[14]} for r in relevant],
              "pcap_sha256": sha(run / "traffic.pcap"),
              "tcpdump_tail": (run / "tcpdump.log").read_text()[-240:],
              "error": error}
    (run / "capture_status.json").write_text(json.dumps(status, indent=2) + "\n")
    print(json.dumps(status), flush=True)
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

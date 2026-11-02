#!/usr/bin/env python3
"""Capture a scripted benign-intent OPTIONS burst to one known lab extension."""
import csv
import hashlib
import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from run_remote_sipp_challenges import ssh_sipp, sip_packets

ROOT = Path("/home/astrix/sip-fraud-research")
DATA = ROOT / "datasets/sipp-remote-runs"
CDR = Path("/var/log/asterisk/cdr-csv/Master.csv")
FULL = Path("/var/log/asterisk/full")
KEY = Path("/home/astrix/.ssh/sipp_lab_ed25519")
GEN = "sipp@172.16.200.68"
REMOTE_XML = "/home/sipp/sip-fraud-lab/.benign_options_1001.xml"
EXPECTED_V3 = "579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a"
EXPECTED_V5 = "e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004"


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ssh(command):
    return ["ssh", "-T", "-4", "-i", str(KEY), "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", GEN, command]


def require(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args[0]} ({result.returncode})")
    return result


def main():
    os.umask(0o077)
    assert sha(ROOT / "datasets/runs/20260923T094044Z/stage_detector_v3.py") == EXPECTED_V3
    assert sha(ROOT / "scripts/candidate_v5_replay.py") == EXPECTED_V5
    assert "172.16.200.81/24" in require(["ip", "-4", "-brief", "address", "show", "wlan0"]).stdout
    assert "172.16.200.68" in require(ssh("ip -4 -brief address show wlan0")).stdout
    run = DATA / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-b1-options-keepalive")
    run.mkdir(mode=0o700)
    protocol = {"case": "B1", "declared_utc": utc(), "role": "development benign-burst stress",
                "label": "SCRIPTED_BENIGN_OPTIONS_HEALTH_CHECK",
                "stimulus": "Eight OPTIONS to the same known lab target 1001, monitor identity, no authentication/call",
                "expected_requests": 8, "expected_401": 8, "expected_failed_auth": 0,
                "expected_register_200": 0, "expected_invites": 0, "expected_cdr_delta": 0,
                "invalid_if": "Counts, source, target, PCAP, logs or CDR mismatch"}
    (run / "predeclared_protocol.json").write_text(json.dumps(protocol, indent=2) + "\n")
    with (run / "scenario_ground_truth.csv").open("x", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("scenario_id", "label", "method", "attempts", "unique_targets",
                         "start_utc", "end_utc", "source_ip", "pbx_ip"))
        writer.writerow(("B1", protocol["label"], "OPTIONS", 8, 1, "", "",
                         "172.16.200.68", "172.16.200.81"))
    xml = (Path("/home/astrix/sipp-lab/options_scan.xml").read_text()
           .replace('name="OPTIONS scan"', 'name="OPTIONS health check"')
           .replace("scanner", "monitor"))
    local_xml = run / "benign_options_1001.xml"
    local_xml.write_text(xml)
    (run / "cdr_before.csv").write_bytes(CDR.read_bytes())
    offset = FULL.stat().st_size
    cap = None
    error, cleanup_errors = None, []
    start = utc()
    try:
        require(["scp", "-4", "-i", str(KEY), "-o", "BatchMode=yes", "-o",
                 "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                 str(local_xml), f"{GEN}:{REMOTE_XML}"])
        with (run / "tcpdump.log").open("x") as log:
            cap = subprocess.Popen(["tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0",
                                    "-w", str(run / "traffic.pcap"),
                                    "udp and host 172.16.200.68 and port 5060"],
                                   stdout=subprocess.DEVNULL, stderr=log)
            time.sleep(1)
            if cap.poll() is not None:
                raise RuntimeError("Capture exited before traffic")
            result = ssh_sipp(".benign_options_1001.xml", 5122, 1001, count=8, rate=8)
            (run / "sipp.log").write_text(result.stdout + "\nSTDERR:\n" + result.stderr)
            if result.returncode:
                raise RuntimeError(f"SIPp exited {result.returncode}")
            time.sleep(1)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if cap is not None:
            try:
                if cap.poll() is None:
                    cap.send_signal(signal.SIGINT)
                cap.wait(timeout=8)
            except Exception as exc:
                cleanup_errors.append(f"capture: {exc}")
        try:
            require(ssh(f"rm -f -- {REMOTE_XML}"))
        except Exception as exc:
            cleanup_errors.append(f"remote XML: {exc}")
        (run / "cdr_after.csv").write_bytes(CDR.read_bytes())
        with FULL.open(errors="replace") as stream:
            stream.seek(offset)
            failures = [line for line in stream if "Failed to authenticate" in line
                        and "172.16.200.68" in line]
        (run / "asterisk_failed_auth_evidence.txt").write_text("".join(failures))
    end = utc()
    if (run / "traffic.pcap").is_file():
        packets = sip_packets(run / "traffic.pcap", run / "sip_packets.csv")
        options = [p for p in packets if p["sip.Method"] == "OPTIONS" and
                   p["ip.src"] == "172.16.200.68" and p["sip.r-uri.user"] == "1001"]
        replies = [p for p in packets if p["sip.Status-Code"] == "401" and
                   p["ip.src"] == "172.16.200.81"]
        if (len(options), len(replies), len(failures)) != (8, 8, 0) or (
            run / "cdr_before.csv").read_bytes() != (run / "cdr_after.csv").read_bytes():
            error = error or "Independent count or CDR verification failed"
    else:
        options, replies = [], []
        error = error or "No PCAP"
    truth = run / "scenario_ground_truth.csv"
    text = truth.read_text().replace(",,,172.16.200.68,", f",{start},{end},172.16.200.68,")
    truth.write_text(text)
    status = {"run_dir": str(run), "start_utc": start, "end_utc": end,
              "requests": len(options), "replies_401": len(replies),
              "failed_auth_logs": len(failures), "pcap_sha256": sha(run / "traffic.pcap"),
              "error": error, "cleanup_errors": cleanup_errors}
    (run / "run_status.json").write_text(json.dumps(status, indent=2) + "\n")
    print(json.dumps(status), flush=True)
    if error or cleanup_errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Capture four labelled SIPp scenarios from the separate LAN generator."""

import argparse
import csv
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


PBX_IP = "172.16.200.81"
GENERATOR_IP = "172.16.200.68"
KEY = Path("/home/astrix/.ssh/sipp_lab_ed25519")
PBX_ROOT = Path("/home/astrix/sip-fraud-research")
REMOTE_ROOT = "/home/sipp/sip-fraud-lab"
REMOTE_SIPP = REMOTE_ROOT + "/runtime/usr/bin/sipp"
REMOTE_LIB = REMOTE_ROOT + "/runtime/usr/lib/arm-linux-gnueabihf"
CDR = Path("/var/log/asterisk/cdr-csv/Master.csv")
FULL_LOG = Path("/var/log/asterisk/full")
DETECTOR = PBX_ROOT / "datasets/runs/20260923T094044Z/stage_detector_v3.py"
REPLAY = PBX_ROOT / "scripts/replay_v3_capture.py"
FIELDS = (
    "frame.time_epoch", "ip.src", "ip.dst", "sip.Method", "sip.Status-Code",
    "sip.CSeq.method", "sip.Call-ID", "sip.from.user", "sip.to.user",
    "sip.r-uri.user",
)
CASES = (
    ("options-4", "RECONNAISSANCE", "OPTIONS", 4, 4, 5111),
    ("options-5", "RECONNAISSANCE", "OPTIONS", 5, 5, 5112),
    ("auth-10-fast", "AUTHENTICATION_ATTACK", "REGISTER", 10, 1, 5113),
    ("auth-10-slow", "AUTHENTICATION_ATTACK", "REGISTER", 10, 1, 5114),
)


def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ssh_sipp(xml, port, service, count=1, rate=1):
    args = [
        REMOTE_SIPP, f"{PBX_IP}:5060", "-sf", f"{REMOTE_ROOT}/{xml}",
        "-i", GENERATOR_IP, "-p", str(port), "-t", "u1", "-s", str(service),
        "-m", str(count), "-r", str(rate), "-l", "1", "-nostdin", "-timeout", "15s",
    ]
    remote_command = f"LD_LIBRARY_PATH={shlex.quote(REMOTE_LIB)} " + shlex.join(args)
    ssh = [
        "ssh", "-T", "-4", "-i", str(KEY), "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=6", f"sipp@{GENERATOR_IP}", remote_command,
    ]
    return subprocess.run(ssh, capture_output=True, text=True, timeout=38)


def sip_packets(capture, output):
    command = [
        "tshark", "-r", str(capture), "-Y", "sip", "-T", "fields",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
    ]
    for field in FIELDS:
        command.extend(("-e", field))
    with output.open("x") as handle:
        subprocess.run(command, stdout=handle, check=True, timeout=25)
    with output.open(newline="") as handle:
        return list(csv.DictReader(handle))


def run_case(root, case):
    name, label, method, attempts, targets, port = case
    run_dir = root / name
    run_dir.mkdir(mode=0o700)
    xml_name = "options_scan.xml" if method == "OPTIONS" else "failed_password_register.xml"
    xml_source = Path("/home/astrix/sipp-lab") / xml_name
    xml_copy = run_dir / xml_name
    xml_copy.write_bytes(xml_source.read_bytes())
    (run_dir / "cdr_before.csv").write_bytes(CDR.read_bytes())
    log_offset = FULL_LOG.stat().st_size
    start = utc()
    capture = run_dir / "traffic.pcap"
    results = []
    with (run_dir / "tcpdump.log").open("x") as capture_log:
        packet_capture = subprocess.Popen([
            "tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0", "-w",
            str(capture), f"udp and host {GENERATOR_IP} and port 5060",
        ], stdout=subprocess.DEVNULL, stderr=capture_log)
        try:
            time.sleep(1)
            if packet_capture.poll() is not None:
                raise RuntimeError("tcpdump exited before the scenario")
            if name == "auth-10-fast":
                jobs = [(1001, 10, 3)]
            elif method == "OPTIONS":
                jobs = [(9101 + i, 1, 1) for i in range(attempts)]
            else:
                jobs = [(1001, 1, 1) for _ in range(attempts)]
            for index, (service, count, rate) in enumerate(jobs, 1):
                result = ssh_sipp(xml_name, port, service, count, rate)
                (run_dir / f"sipp_{index:02d}.txt").write_text(
                    result.stdout + "\nSTDERR:\n" + result.stderr,
                    encoding="utf-8",
                )
                results.append(result.returncode)
                if result.returncode:
                    raise RuntimeError(f"SIPp dialog {index} exited {result.returncode}")
                if name == "auth-10-slow" and index < attempts:
                    time.sleep(3)
        finally:
            time.sleep(1)
            if packet_capture.poll() is None:
                packet_capture.send_signal(signal.SIGINT)
            packet_capture.wait(timeout=8)
    end = utc()
    (run_dir / "cdr_after.csv").write_bytes(CDR.read_bytes())
    (run_dir / "sipp_exits.json").write_text(json.dumps(results) + "\n")
    with (run_dir / "scenario_ground_truth.csv").open("x", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("scenario_id", "label", "method", "attempts", "unique_targets",
                         "start_utc", "end_utc", "source_ip", "pbx_ip"))
        writer.writerow((name, label, method, attempts, targets, start, end,
                         GENERATOR_IP, PBX_IP))
    with FULL_LOG.open(errors="replace") as handle:
        handle.seek(log_offset)
        new_logs = handle.read()
    failed_lines = [line for line in new_logs.splitlines()
                    if "Failed to authenticate" in line and GENERATOR_IP in line]
    (run_dir / "asterisk_failed_auth_evidence.txt").write_text(
        "\n".join(failed_lines) + ("\n" if failed_lines else ""))
    rows = sip_packets(capture, run_dir / "sip_packets.csv")
    requests = [r for r in rows if r["sip.Method"] == method
                and r["ip.src"] == GENERATOR_IP and r["ip.dst"] == PBX_IP]
    replies = [r for r in rows if r["sip.Status-Code"] == "401"
               and r["ip.src"] == PBX_IP and r["ip.dst"] == GENERATOR_IP]
    expected_requests = attempts * (2 if method == "REGISTER" else 1)
    verification = {
        "case": name, "source_ip": GENERATOR_IP, "pbx_ip": PBX_IP,
        "expected_requests": expected_requests, "captured_requests": len(requests),
        "captured_401_replies": len(replies), "failed_auth_log_entries": len(failed_lines),
        "sipp_exit_codes": results, "xml_sha256": digest(xml_copy),
        "pcap_sha256": digest(capture),
    }
    verified = len(requests) == expected_requests and len(replies) == expected_requests
    verified &= len(results) == len(jobs) and all(code == 0 for code in results)
    if method == "REGISTER":
        verified &= len(failed_lines) == attempts
    verification["valid_capture"] = bool(verified)
    (run_dir / "capture_verification.json").write_text(
        json.dumps(verification, indent=2) + "\n")
    if not verified:
        raise RuntimeError(f"Evidence counts did not match in {run_dir}: {verification}")
    replay = subprocess.run(
        ["python3", str(REPLAY), str(run_dir), "--detector", str(DETECTOR)],
        check=True, capture_output=True, text=True, timeout=30)
    print(replay.stdout.strip(), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_root", type=Path, help="Existing session directory")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.run_root.resolve()
    if not root.is_dir() or not KEY.is_file() or not DETECTOR.is_file():
        parser.error("Missing run directory, SSH key, or frozen detector")
    for case in CASES:
        run_case(root, case)


if __name__ == "__main__":
    main()

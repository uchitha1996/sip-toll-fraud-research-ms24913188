#!/usr/bin/env python3
"""Measure three offline replay stages on fixed F08/F10/F12 Pi captures.

V3 consumes previously extracted SIP CSV; V5 reads PCAP through tshark; V6
consumes V5's timeline. These are distinct pipeline costs, not live PBX load.
"""
import csv
import hashlib
import json
import os
import resource
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/astrix/sip-fraud-research")
DATA = ROOT / "datasets"
V3 = DATA / "runs/20260923T094044Z/stage_detector_v3.py"
V3_REPLAY = ROOT / "scripts/replay_v3_capture.py"
V5 = ROOT / "scripts/candidate_v5_replay.py"
V6 = ROOT / "scripts/progression_v6_development.py"
HASHES = {
    V3: "579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a",
    V5: "e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004",
    V6: "c4b9231a89a815e93f1264119e229df1a563d574ba4b6a7e357d8125983eb2b4",
}
CASES = {
    "F08": (DATA / "sipp-remote-runs/20260929T100512Z-f08-options-targets-1001-1006",
            "3f7fe5026e4d4decc25f8e31f231f5b47aa2f0c5ce4b048e16b724b0732f4d31",
            "RECONNAISSANCE", "RECONNAISSANCE", ["RECONNAISSANCE"]),
    "F10": (DATA / "sipp-remote-runs/20260929T100727Z-f10-slow-auth-only-1001",
            "67f614b547553523f61922ac69348625d9ce24b5bd9d48734d3726f6c67e2059",
            None, "AUTHENTICATION_ATTACK", ["AUTHENTICATION_ATTACK"]),
    "F12": (DATA / "emulated-outbound-runs/20260929T100901Z-f12-account1001-88001-slow",
            "99cfec70185fd02633c5b3b9f5f7f56fe1b8c6864eaeaba42e564730f6691d84",
            None, "AUTHENTICATION_ATTACK", ["AUTHENTICATION_ATTACK",
            "SUSPECTED_COMPROMISE", "SUSPECTED_OUTBOUND_ATTEMPT",
            "ANSWERED_EMULATED_OUTBOUND"]),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timed(command, log_path):
    begin = time.monotonic_ns()
    with log_path.open("x") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        _, status, usage = os.wait4(proc.pid, 0)
        code = os.waitstatus_to_exitcode(status)
        proc.returncode = code
    return {"wall_s": round((time.monotonic_ns() - begin) / 1e9, 6),
            "user_cpu_s": round(usage.ru_utime, 6),
            "system_cpu_s": round(usage.ru_stime, 6),
            "max_rss_kib": usage.ru_maxrss, "exit_code": code}


def check_outcome(v3_dir, v5_dir, v6_dir, expected):
    v3 = json.loads((v3_dir / "replay_v3_summary.json").read_text())
    v5 = json.loads((v5_dir / "candidate_summary.json").read_text())
    v6 = json.loads((v6_dir / "progression_summary.json").read_text())
    observed = [v3["first_alert_stage"], v5["first_alert_stage"], v6["stages"]]
    if observed != list(expected):
        raise RuntimeError(f"Detector outcome changed: {observed} != {expected}")
    return observed


def main():
    os.umask(0o077)
    for source, expected in HASHES.items():
        if sha(source) != expected:
            raise RuntimeError(f"Frozen hash mismatch: {source}")
    for case, (source, expected, *_rest) in CASES.items():
        if sha(source / "traffic.pcap") != expected:
            raise RuntimeError(f"PCAP hash mismatch: {case}")
    active = subprocess.run(["asterisk", "-rx", "core show channels count"],
                            capture_output=True, text=True, check=True).stdout
    if "0 active calls" not in active:
        raise RuntimeError("PBX has active calls; postpone offline resource replay")
    out = DATA / "performance-runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-f08-f10-f12")
    out.mkdir(parents=True, mode=0o700)
    protocol = {"declared_utc": utc(), "kind": "offline replay resource measurement",
                "script_sha256": sha(Path(__file__)),
                "source_hashes": {str(p): h for p, h in HASHES.items()},
                "pcap_hashes": {case: values[1] for case, values in CASES.items()},
                "repetitions_per_case": 3, "unit": "one complete scenario per replay",
                "incomparability": "V3 reads pre-extracted SIP CSV; V5 includes tshark extraction; V6 is incremental after V5. No live PBX or alert-delivery measurement.",
                "load_before": Path("/proc/loadavg").read_text().strip(),
                "mem_available_kib_before": next(line.strip() for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")),
                "active_calls_before": active.strip()}
    (out / "predeclared_protocol.json").write_text(json.dumps(protocol, indent=2) + "\n")
    rows = []
    try:
        for case, (source, _digest, expected_v3, expected_v5, expected_v6) in CASES.items():
            for repetition in range(1, 4):
                rep = out / case / f"rep_{repetition:02d}"
                v3_dir, v5_dir, v6_dir = rep / "v3_input", rep / "v5", rep / "v6"
                v3_dir.mkdir(parents=True, mode=0o700)
                for name in ("traffic.pcap", "sip_packets.csv", "scenario_ground_truth.csv",
                             "cdr_before.csv", "cdr_after.csv"):
                    shutil.copy2(source / name, v3_dir / name)
                commands = {
                    "V3": ["python3", str(V3_REPLAY), "--detector", str(V3), str(v3_dir)],
                    "V5": ["python3", str(V5), "--baseline", str(V3),
                           "--observation-end-utc", json.loads((source / "run_status.json").read_text())["end_utc"],
                           str(source / "traffic.pcap"), str(v5_dir)],
                }
                for detector in (("V3", "V5") if repetition % 2 else ("V5", "V3")):
                    result = timed(commands[detector], rep / f"{detector.lower()}.log")
                    rows.append({"case": case, "repetition": repetition, "detector": detector, **result})
                    if result["exit_code"]:
                        raise RuntimeError(f"{case} rep {repetition} {detector} failed")
                v6_cmd = ["python3", str(V6), "--v5-timeline", str(v5_dir / "candidate_timeline.csv"),
                          "--output-dir", str(v6_dir)]
                if case == "F12":
                    v6_cmd.extend(["--lab-destination", "88001"])
                v6_cmd.append(str(source))
                result = timed(v6_cmd, rep / "v6.log")
                rows.append({"case": case, "repetition": repetition, "detector": "V6_incremental", **result})
                if result["exit_code"]:
                    raise RuntimeError(f"{case} rep {repetition} V6 failed")
                check_outcome(v3_dir, v5_dir, v6_dir,
                              (expected_v3, expected_v5, expected_v6))
        status = "completed"
    except Exception as exc:
        status = f"incomplete: {type(exc).__name__}: {exc}"
    with (out / "measurements.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case", "repetition", "detector", "wall_s",
                                                   "user_cpu_s", "system_cpu_s", "max_rss_kib", "exit_code"])
        writer.writeheader()
        writer.writerows(rows)
    summary = {"status": status, "measurement_count": len(rows),
               "load_after": Path("/proc/loadavg").read_text().strip(),
               "run_dir": str(out), "measurement_csv_sha256": sha(out / "measurements.csv")}
    (out / "run_status.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    if status != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

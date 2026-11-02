#!/usr/bin/env python3
"""Run a scripted benign mistyped-password recovery and isolated answered call."""
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

from run_remote_sipp_challenges import ssh_sipp, sip_packets

ROOT = Path("/home/astrix/sip-fraud-research")
RUNS = ROOT / "datasets/emulated-outbound-runs"
KEY = Path("/home/astrix/.ssh/sipp_lab_ed25519")
CDR = Path("/var/log/asterisk/cdr-csv/Master.csv")
FULL = Path("/var/log/asterisk/full")
V3 = ROOT / "datasets/runs/20260923T094044Z/stage_detector_v3.py"
V5 = ROOT / "scripts/candidate_v5_replay.py"
PREP = ROOT / "scripts/prepare_valid_register.py"
PBX_REG = RUNS / ".valid_register_1001.xml"
PBX_INV = RUNS / ".valid_invite_1001.xml"
GEN_ROOT = "/home/sipp/sip-fraud-lab"
GEN_IP = "172.16.200.68"
GEN_USER = f"sipp@{GEN_IP}"
REMOTE_REG = f"{GEN_ROOT}/.valid_register_1001.xml"
REMOTE_INV = f"{GEN_ROOT}/.valid_invite_1001.xml"
ROUTE = "88001@internal"
EXPECTED_V3 = "579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a"
EXPECTED_V5 = "e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004"


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def require(args, timeout=20):
    result = command(args, timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}")
    return result


def ssh(remote_command):
    return ["ssh", "-T", "-4", "-i", str(KEY), "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=6", GEN_USER, remote_command]


def main():
    os.umask(0o077)
    assert sha(V3) == EXPECTED_V3 and sha(V5) == EXPECTED_V5
    assert sha(Path("/home/astrix/sipp-lab/failed_password_register.xml")) == (
        "ee3fe537e7ae7f991e8fc78490c12781ba6d69a83e025f4afe41d8ba89905e4e")
    assert "172.16.200.81/24" in require(["ip", "-4", "-brief", "address", "show", "wlan0"]).stdout
    assert "172.16.200.68" in require(ssh("ip -4 -brief address show wlan0")).stdout
    existing = command(["asterisk", "-rx", f"dialplan show {ROUTE}"])
    if "no existence" not in existing.stdout:
        raise RuntimeError("Synthetic route already exists; inspect it first")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = RUNS / f"{stamp}-n3-four-mistypes-then-call"
    run.mkdir(mode=0o700)
    (run / "predeclared_protocol.json").write_text(json.dumps({
        "case": "N3", "declared_utc": utc(), "role": "development boundary control",
        "label": "SCRIPTED_BENIGN_RECOVERY_WITH_CALL",
        "stimulus": "4 wrong digest REGISTER dialogs, then valid REGISTER and one answered isolated call",
        "expected_failed_auth_logs": 4, "expected_register_200": 1,
        "expected_answered_cdr": 1, "expected_v6_suspected": False,
        "invalid_if": "Missing or mismatched PCAP, failed-auth logs, SIP leg, CDR, or cleanup",
    }, indent=2) + "\n")
    with (run / "scenario_ground_truth.csv").open("x", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(("scenario_id", "label", "source_ip", "pbx_ip", "extension",
                         "destination", "expected_wrong_password_dialogs",
                         "expected_register_success", "expected_answered_call"))
        writer.writerow(("N3-four-mistypes-then-call", "SCRIPTED_BENIGN_RECOVERY_WITH_CALL",
                         GEN_IP, "172.16.200.81", "1001", "88001", 4, 1, 1))
    shutil.copyfile(CDR, run / "cdr_before.csv")
    log_offset = FULL.stat().st_size
    started = utc()
    route_added = False
    capture = None
    uas = None
    error = None
    cleanup_errors = []
    wrong_starts = []
    try:
        require(["python3", str(PREP)])
        for source, destination in ((PBX_REG, REMOTE_REG), (PBX_INV, REMOTE_INV)):
            require(["scp", "-p", "-4", "-i", str(KEY), "-o", "BatchMode=yes",
                     "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                     str(source), f"{GEN_USER}:{destination}"], timeout=30)
        require(ssh(f"chmod 600 {REMOTE_REG} {REMOTE_INV}"))
        route_added = True
        require(["asterisk", "-rx", "dialplan add extension 88001,1,"
                         "Dial(PJSIP/1002/sip:88001@172.16.200.68:5090,15,S(9)) "
                         "into internal replace"])
        shown = require(["asterisk", "-rx", f"dialplan show {ROUTE}"]).stdout
        if "172.16.200.68:5090" not in shown:
            raise RuntimeError("Synthetic route target did not match the SIPp Pi")
        lib = f"{GEN_ROOT}/runtime/usr/lib/arm-linux-gnueabihf"
        sipp = f"{GEN_ROOT}/runtime/usr/bin/sipp"
        uas_cmd = (f"LD_LIBRARY_PATH={lib} {sipp} -sn uas -i {GEN_IP} -p 5090 "
                   "-t u1 -m 1 -nostdin -timeout 70s")
        with (run / "sipp_uas.log").open("x") as log:
            uas = subprocess.Popen(ssh(uas_cmd), stdout=log, stderr=subprocess.STDOUT)
            time.sleep(1.5)
            if uas.poll() is not None:
                raise RuntimeError("SIPp UAS exited before traffic")
            with (run / "tcpdump.log").open("x") as caplog:
                capture = subprocess.Popen([
                    "tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0", "-w",
                    str(run / "traffic.pcap"), "udp and host 172.16.200.68 and "
                    "(port 5060 or port 5090)"], stdout=subprocess.DEVNULL,
                    stderr=caplog)
                time.sleep(1)
                if capture.poll() is not None:
                    raise RuntimeError("Packet capture exited before traffic")
                first = time.monotonic()
                for index in range(4):
                    time.sleep(max(0, first + 3.0 * index - time.monotonic()))
                    wrong_starts.append(utc())
                    result = ssh_sipp("failed_password_register.xml", 5114, 1001)
                    (run / f"sipp_wrong_{index+1:02d}.log").write_text(
                        result.stdout + "\nSTDERR:\n" + result.stderr)
                    if result.returncode:
                        raise RuntimeError(f"Wrong-password dialog {index+1} failed")
                time.sleep(2.2)
                valid = ssh_sipp(".valid_register_1001.xml", 5115, 1001)
                (run / "sipp_register.log").write_text(
                    valid.stdout + "\nSTDERR:\n" + valid.stderr)
                if valid.returncode:
                    raise RuntimeError("Valid registration SIPp dialog failed")
                invited = ssh_sipp(".valid_invite_1001.xml", 5116, 88001)
                (run / "sipp_invite.log").write_text(
                    invited.stdout + "\nSTDERR:\n" + invited.stderr)
                if invited.returncode:
                    raise RuntimeError("Authenticated call SIPp dialog failed")
                if uas.wait(timeout=15):
                    raise RuntimeError("SIPp UAS did not finish successfully")
                time.sleep(2)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if capture is not None:
            try:
                if capture.poll() is None:
                    capture.send_signal(signal.SIGINT)
                capture.wait(timeout=8)
            except Exception as exc:
                cleanup_errors.append(f"capture: {exc}")
        if uas is not None and uas.poll() is None:
            uas.terminate()
            try:
                uas.wait(timeout=8)
            except Exception as exc:
                cleanup_errors.append(f"uas: {exc}")
        try:
            shutil.copyfile(CDR, run / "cdr_after.csv")
            with FULL.open(errors="replace") as handle:
                handle.seek(log_offset)
                lines = [line for line in handle if "Failed to authenticate" in line
                         and GEN_IP in line]
            (run / "asterisk_failed_auth_evidence.txt").write_text("".join(lines))
            if (run / "traffic.pcap").is_file():
                sip_packets(run / "traffic.pcap", run / "sip_packets.csv")
        except Exception as exc:
            cleanup_errors.append(f"evidence: {exc}")
        if route_added:
            try:
                shown = command(["asterisk", "-rx", f"dialplan show {ROUTE}"])
                if "172.16.200.68:5090" in shown.stdout:
                    removed = command(["asterisk", "-rx", f"dialplan remove extension {ROUTE}"])
                    if "removed" not in removed.stdout:
                        cleanup_errors.append("synthetic route removal not confirmed")
            except Exception as exc:
                cleanup_errors.append(f"route cleanup: {exc}")
        try:
            remote_clean = command(ssh(f"rm -f -- {REMOTE_REG} {REMOTE_INV}"))
            if remote_clean.returncode:
                cleanup_errors.append("generator temporary credential removal failed")
        except Exception as exc:
            cleanup_errors.append(f"generator credential cleanup: {exc}")
        for temporary in (PBX_REG, PBX_INV):
            try:
                temporary.unlink(missing_ok=True)
            except Exception as exc:
                cleanup_errors.append(f"PBX credential cleanup: {exc}")
        ended = utc()
        (run / "run_status.json").write_text(json.dumps({
            "case": "N3", "start_utc": started, "end_utc": ended,
            "wrong_dialog_starts_utc": wrong_starts,
            "capture_sha256": sha(run / "traffic.pcap") if (run / "traffic.pcap").is_file() else None,
            "error": error, "cleanup_errors": cleanup_errors,
            "status": "captured" if not error and not cleanup_errors else "incomplete",
        }, indent=2) + "\n")
    print(json.dumps({"run_dir": str(run), "error": error,
                      "cleanup_errors": cleanup_errors, "wrong_dialogs": len(wrong_starts)}), flush=True)
    if error or cleanup_errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

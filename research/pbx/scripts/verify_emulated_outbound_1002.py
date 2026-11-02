#!/usr/bin/env python3
"""Check independent SIP/CDR and planned auth counts for account-1002 F calls."""
import csv
import json
import sys
from pathlib import Path

PBX, GEN = "172.16.200.81", "172.16.200.68"

def main(root):
    plan = json.loads((root / "predeclared_protocol.json").read_text())
    status = json.loads((root / "run_status.json").read_text())
    assert plan["case"] in {"F04", "F05", "F11"}
    assert status["status"] == "captured" and status["error"] is None
    assert status["cleanup_errors"] == []
    with (root / "sip_packets.csv").open(newline="") as stream:
        packets = list(csv.DictReader(stream))
    with (root / "cdr_before.csv").open(newline="") as stream:
        before = list(csv.reader(stream))
    with (root / "cdr_after.csv").open(newline="") as stream:
        after = list(csv.reader(stream))
    assert after[:len(before)] == before and len(after) - len(before) == 1
    cdr = after[-1]
    assert cdr[1:3] == ["1002", "88002"]
    assert cdr[14] == "ANSWERED" and int(cdr[13]) >= 5
    failures = (root / "asterisk_failed_auth_evidence.txt").read_text().splitlines()
    assert len(failures) == plan["expected_wrong_password_dialogs"]

    def match(row, src, dst, method="", status="", cseq=""):
        return (row["ip.src"] == src and row["ip.dst"] == dst
                and (not method or row["sip.Method"] == method)
                and (not status or row["sip.Status-Code"] == status)
                and (not cseq or row["sip.CSeq.method"] == cseq))

    outbound = {row["sip.Call-ID"] for row in packets
                if match(row, PBX, GEN, method="INVITE")
                and row["sip.r-uri.user"] == "88002"}
    client = {row["sip.Call-ID"] for row in packets
              if match(row, GEN, PBX, method="INVITE")
              and row["sip.r-uri.user"] == "88002"}
    assert len(outbound) == len(client) == 1 and outbound != client
    for cid, response_src, response_dst, ack_src, ack_dst in (
            (next(iter(outbound)), GEN, PBX, PBX, GEN),
            (next(iter(client)), PBX, GEN, GEN, PBX)):
        leg = [row for row in packets if row["sip.Call-ID"] == cid]
        assert any(match(row, response_src, response_dst, status="200", cseq="INVITE")
                   for row in leg)
        assert any(match(row, ack_src, ack_dst, method="ACK") for row in leg)
        assert any(row["sip.Method"] == "BYE" for row in leg)
    assert sum(match(row, PBX, GEN, status="200", cseq="REGISTER")
               for row in packets) == 1
    print(json.dumps({"case": plan["case"], "packets": len(packets),
                      "failed_auth_lines": len(failures), "cdr_delta": 1,
                      "answered_billsec": cdr[13], "client_legs": len(client),
                      "outbound_legs": len(outbound)}))

if __name__ == "__main__":
    main(Path(sys.argv[1]))

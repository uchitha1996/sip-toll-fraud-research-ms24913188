#!/usr/bin/env python3
"""Verify the two fresh answered internal calls independently of the detectors."""
import csv
import hashlib
import json
import sys
from pathlib import Path

PBX = "172.16.200.81"
DIRECTIONS = (("1001", "1002"), ("1002", "1001"))


def csv_rows(path):
    with path.open(newline="") as stream:
        return list(csv.reader(stream))


def packet_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def sip_complete(packets, call_id, source):
    leg = [row for row in packets if row["sip.Call-ID"] == call_id]
    return (any(row["ip.src"] == PBX and row["ip.dst"] == source
                and row["sip.Status-Code"] == "200"
                and row["sip.CSeq.method"] == "INVITE" for row in leg)
            and any(row["ip.src"] == source and row["ip.dst"] == PBX
                    and row["sip.Method"] == "ACK" for row in leg)
            and any(row["sip.Method"] == "BYE" for row in leg))


def main(run):
    packets = packet_rows(run / "sip_packets.csv")
    before, after = csv_rows(run / "cdr_before.csv"), csv_rows(run / "cdr_after.csv")
    if after[:len(before)] != before:
        raise ValueError("CDR before snapshot is not a prefix of after snapshot")
    new = after[len(before):]
    verified = []
    for caller, destination in DIRECTIONS:
        answered = [row for row in new if len(row) >= 17 and row[1:3] ==
                    [caller, destination] and row[14] == "ANSWERED"
                    and row[13].isdigit() and int(row[13]) > 0]
        clients = [row for row in packets if row["sip.Method"] == "INVITE"
                   and row["ip.dst"] == PBX and row["ip.src"] != PBX
                   and row["sip.from.user"] == caller
                   and row["sip.r-uri.user"] == destination]
        complete = [(row["sip.Call-ID"], row["ip.src"]) for row in clients
                    if sip_complete(packets, row["sip.Call-ID"], row["ip.src"])]
        unique = list(dict.fromkeys(complete))
        if not answered or not unique:
            raise ValueError(f"Missing matched answered CDR or complete client SIP call: {caller}->{destination}")
        verified.append({"caller": caller, "destination": destination,
                         "answered_cdr_count": len(answered),
                         "billsec": [int(row[13]) for row in answered],
                         "complete_client_call_ids": [cid for cid, _ in unique]})
    pcap = run / "traffic.pcap"
    log = (run / "tcpdump.log").read_text()
    if "0 packets dropped by kernel" not in log:
        raise ValueError("Capture drop count is not zero")
    with (run / "scenario_ground_truth.csv").open("x", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("scenario_id", "label", "caller", "destination", "answered_cdr_count",
                         "client_call_count", "source", "role"))
        for item in verified:
            writer.writerow(("N1", "NORMAL_ANSWERED_INTERNAL_CALL", item["caller"],
                             item["destination"], item["answered_cdr_count"],
                             len(item["complete_client_call_ids"]), "real_softphone",
                             "development_control"))
    result = {"valid": True, "verified": verified, "new_cdr_rows": len(new),
              "decoded_sip_packets": len(packets),
              "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
              "note": "One capture contains three answered calls in two directions; SIP packets are not independent scenarios."}
    (run / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main(Path(sys.argv[1]))

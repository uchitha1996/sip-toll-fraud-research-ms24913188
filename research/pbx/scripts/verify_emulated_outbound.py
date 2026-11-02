#!/usr/bin/env python3
"""Independent signalling/CDR checks for selected emulated outbound cases."""
import csv
import sys
from pathlib import Path

PBX, GEN = "172.16.200.81", "172.16.200.68"
for name in sys.argv[1:]:
    root = Path(name)
    with (root / "sip_packets.csv").open(newline="") as handle:
        packets = list(csv.DictReader(handle))
    with (root / "cdr_before.csv").open(newline="") as handle:
        before = list(csv.reader(handle))
    with (root / "cdr_after.csv").open(newline="") as handle:
        after = list(csv.reader(handle))
    assert after[:len(before)] == before and len(after) - len(before) == 1
    cdr = after[-1]
    assert cdr[1:3] == ["1001", "88001"]
    assert cdr[14] == "ANSWERED" and int(cdr[13]) >= 5
    def match(row, src, dst, method="", status="", cseq=""):
        return (row["ip.src"] == src and row["ip.dst"] == dst
                and (not method or row["sip.Method"] == method)
                and (not status or row["sip.Status-Code"] == status)
                and (not cseq or row["sip.CSeq.method"] == cseq))
    outbound = {row["sip.Call-ID"] for row in packets
                if match(row, PBX, GEN, method="INVITE")
                and row["sip.r-uri.user"] == "88001"}
    client = {row["sip.Call-ID"] for row in packets
              if match(row, GEN, PBX, method="INVITE")
              and row["sip.r-uri.user"] == "88001"}

    assert len(outbound) == len(client) == 1 and outbound != client
    for cid in outbound:
        rows = [row for row in packets if row["sip.Call-ID"] == cid]
        assert any(match(row, GEN, PBX, status="200", cseq="INVITE") for row in rows)
        assert any(match(row, PBX, GEN, method="ACK") for row in rows)
        assert any(row["sip.Method"] == "BYE" for row in rows)
    for cid in client:
        rows = [row for row in packets if row["sip.Call-ID"] == cid]
        assert any(match(row, PBX, GEN, status="200", cseq="INVITE") for row in rows)
        assert any(match(row, GEN, PBX, method="ACK") for row in rows)
        assert any(row["sip.Method"] == "BYE" for row in rows)
    assert any(match(row, PBX, GEN, status="200", cseq="REGISTER")
               for row in packets)
    failures = root / "asterisk_failed_auth_evidence.txt"
    fail_count = len(failures.read_text().splitlines()) if failures.exists() else 0
    print(f"{root.name}: packets={len(packets)} cdr_delta=1 "
          f"answered_billsec={cdr[13]} client_legs={len(client)} "
          f"outbound_legs={len(outbound)} failed_auth_lines={fail_count}")

#!/usr/bin/env python3
import csv
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / "datasets" / "ground_truth_events.csv"
PBX_IP = "127.0.0.1"
PBX_PORT = 5060
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = 5090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LOCAL_IP, LOCAL_PORT))
sock.settimeout(0.15)

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")

def send(method, user, target, label, cseq):
    callid = f"{uuid.uuid4()}@{LOCAL_IP}"
    branch = "z9hG4bK-" + uuid.uuid4().hex[:12]
    tag = uuid.uuid4().hex[:10]
    uri = f"sip:{target}@{PBX_IP}"
    headers = [
        f"{method} {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {LOCAL_IP}:{LOCAL_PORT};branch={branch};rport",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{PBX_IP}>;tag={tag}",
        f"To: <sip:{target}@{PBX_IP}>",
        f"Call-ID: {callid}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:{user}@{LOCAL_IP}:{LOCAL_PORT}>",
        "User-Agent: SIP-Fraud-Research-Generator",
    ]
    if method == "REGISTER":
        headers.append("Expires: 60")
    headers.append("Content-Length: 0")
    message = "\r\n".join(headers) + "\r\n\r\n"

    ts = utc_now()
    sock.sendto(message.encode(), (PBX_IP, PBX_PORT))
    try:
        sock.recvfrom(8192)
    except socket.timeout:
        pass
    return [ts, method, user, target, label]
events = []
cseq = 1

def scenario(method, user, targets, label, delay):
    global cseq
    for target in targets:
        row = send(method, user, target, label, cseq)
        events.append(row)
        print(f"Sent {method} user={user} target={target} label={label}")
        cseq += 1
        time.sleep(delay)

# Same V3 baseline shape used on Azure: 5 + 10 + 15 + 20 = 50 events.
scenario("REGISTER", "1001", ["1001"] * 5, "normal_register", 0.90)
scenario("OPTIONS", "scanner", [str(9100+i) for i in range(10)], "reconnaissance", 0.40)
scenario("REGISTER", "1002", ["1002"] * 15, "auth_attack", 0.25)
outside = ["0044123456789","0012025550172","00971501234567","0094771234567"]
scenario("INVITE", "1002", [outside[i % len(outside)] for i in range(20)], "fraud_burst", 0.18)

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","method","user","target","label"])
    w.writerows(events)

print("SIP traffic generation completed.")
print("Ground truth:", OUT)

#!/usr/bin/env python3
import csv, socket, time, uuid
from datetime import datetime, timezone
from pathlib import Path

BASE=Path(__file__).resolve().parent.parent
OUT=BASE/"datasets"/"ground_truth_events_v4.csv"
PBX_IP="127.0.0.1"; PBX_PORT=5060
LOCAL_IP="127.0.0.1"; LOCAL_PORT=5091
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((LOCAL_IP,LOCAL_PORT)); sock.settimeout(0.10)
events=[]; cseq=1

def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")

def send(scenario,method,user,target,label):
    global cseq
    callid=f"{uuid.uuid4()}@{LOCAL_IP}"; tag=uuid.uuid4().hex[:10]
    branch="z9hG4bK-"+uuid.uuid4().hex[:12]
    uri=f"sip:{target}@{PBX_IP}"
    h=[f"{method} {uri} SIP/2.0",
       f"Via: SIP/2.0/UDP {LOCAL_IP}:{LOCAL_PORT};branch={branch};rport",
       "Max-Forwards: 70",f"From: <sip:{user}@{PBX_IP}>;tag={tag}",
       f"To: <sip:{target}@{PBX_IP}>",f"Call-ID: {callid}",
       f"CSeq: {cseq} {method}",f"Contact: <sip:{user}@{LOCAL_IP}:{LOCAL_PORT}>",
       "User-Agent: SIP-Fraud-Research-V4"]
    if method=="REGISTER": h.append("Expires: 60")
    h.append("Content-Length: 0")
    ts=now(); sock.sendto(("\r\n".join(h)+"\r\n\r\n").encode(),(PBX_IP,PBX_PORT))
    try: sock.recvfrom(8192)
    except socket.timeout: pass
    events.append([scenario,ts,method,user,target,label])
    print(f"S{scenario:02d}: {method} user={user} target={target} label={label}")
    cseq+=1

def run(scenario,method,user,targets,label,delay):
    for target in targets:
        send(scenario,method,user,target,label); time.sleep(delay)

# V4 robustness scenarios reconstructed from the Azure baseline definitions.
run(1,"REGISTER","2001",["2001"]*5,"normal_register",0.70)
run(2,"OPTIONS","scanner02",[str(9100+i) for i in range(4)],"reconnaissance",0.30)
run(3,"OPTIONS","monitor03",[str(9200+i) for i in range(4)],"benign_options",0.80)
run(4,"OPTIONS","scanner04",[str(9300+i) for i in range(5)],"reconnaissance",0.40)
run(5,"OPTIONS","scanner05",[str(9400+i) for i in range(5)],"reconnaissance",3.20)
run(6,"REGISTER","2006",["2006"]*9,"auth_attack",0.25)
run(7,"REGISTER","2007",["2007"]*3,"normal_register",0.80)
run(8,"REGISTER","2008",["2008"]*10,"auth_attack",0.25)
run(9,"REGISTER","2009",["2009"]*10,"auth_attack",1.30)
outside=["0044123456789","0012025550172","00971501234567","0094771234567"]
run(10,"INVITE","2010",[outside[i%4] for i in range(4)],"fraud_burst",0.20)
run(11,"INVITE","2011",[outside[i%4] for i in range(4)],"benign_invite",0.50)
run(12,"INVITE","2012",[outside[(i+2)%4] for i in range(5)],"fraud_burst",0.20)

OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open("w",newline="") as f:
    w=csv.writer(f); w.writerow(["scenario_number","timestamp","method","user","target","label"]); w.writerows(events)
print("\nV4 robustness traffic generation completed")
print("Ground truth:",OUT)

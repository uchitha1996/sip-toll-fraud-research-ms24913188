#!/usr/bin/env python3
"""Bounded six REGISTER requests per case, outbound-only observations."""
import json,socket,sys,time,uuid
targets=json.loads(sys.argv[1])
allowed={"1001","1002","9001","9002","9003","9004","9005","9006"}
assert len(targets)==6 and all(t in allowed for t in targets)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("172.16.200.68",5140))
sent=[]
for target in targets:
    cid="pp2b-"+uuid.uuid4().hex
    lines=[
      "REGISTER sip:172.16.200.81 SIP/2.0",
      "Via: SIP/2.0/UDP 172.16.200.68:5140;branch=z9hG4bK"+cid,
      "Max-Forwards: 70",
      "From: <sip:"+target+"@172.16.200.81>;tag="+cid,
      "To: <sip:"+target+"@172.16.200.81>",
      "Call-ID: "+cid,
      "CSeq: 1 REGISTER",
      "Contact: <sip:"+target+"@172.16.200.68:5140>",
      "Expires: 0",
      "Content-Length: 0",
      "",""]
    n=s.sendto("\r\n".join(lines).encode(),("172.16.200.81",5060))
    assert n>150
    sent.append({"target":target,"call_id":cid,"sender_bytes":n})
    time.sleep(0.8)
s.close()
print(json.dumps(sent))

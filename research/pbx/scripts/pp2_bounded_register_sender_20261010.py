#!/usr/bin/env python3
"""Twenty-four-at-most bounded unauthenticated lab REGISTER requests, no INVITE."""
import json,socket,sys,time,uuid
targets=json.loads(sys.argv[1])
allowed={str(x) for x in (1001,1002,9001,9002,9003,9004,9005,9006)}
assert len(targets)==6 and all(t in allowed for t in targets)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("172.16.200.68",5139))
s.settimeout(4)
result=[]
for target in targets:
    cid="pp2-"+uuid.uuid4().hex
    lines=[
      "REGISTER sip:172.16.200.81 SIP/2.0",
      "Via: SIP/2.0/UDP 172.16.200.68:5139;branch=z9hG4bK"+cid,
      "Max-Forwards: 70",
      "From: <sip:"+target+"@172.16.200.81>;tag="+cid,
      "To: <sip:"+target+"@172.16.200.81>",
      "Call-ID: "+cid,
      "CSeq: 1 REGISTER",
      "Contact: <sip:"+target+"@172.16.200.68:5139>",
      "Expires: 0",
      "Content-Length: 0",
      "",""]
    s.sendto("\r\n".join(lines).encode(),("172.16.200.81",5060))
    payload,addr=s.recvfrom(4096)
    assert addr[0]=="172.16.200.81"
    response=payload.split(b"\r\n",1)[0].decode(errors="replace")
    assert response.startswith("SIP/2.0 ") and not response.startswith("SIP/2.0 2"),response
    result.append({"target":target,"call_id":cid,"response":response})
    time.sleep(0.8)
s.close()
print(json.dumps(result))

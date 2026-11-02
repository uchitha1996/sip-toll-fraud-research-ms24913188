#!/usr/bin/env python3
import socket, re, hashlib, uuid

HOST="127.0.0.1"; PORT=5060; LPORT=5094
USER="1001"; WRONG="WrongLabPassword"

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def build(cseq, callid, branch, tag, auth=None):
    uri=f"sip:{HOST}:{PORT}"
    lines=[
        f"REGISTER {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {HOST}:{LPORT};branch={branch};rport",
        f"From: <sip:{USER}@{HOST}>;tag={tag}",
        f"To: <sip:{USER}@{HOST}>",
        f"Call-ID: {callid}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{USER}@{HOST}:{LPORT}>",
        "Max-Forwards: 70",
        "Expires: 60",
    ]
    if auth:
        lines.append("Authorization: "+auth)
    lines.append("Content-Length: 0")
    return "\r\n".join(lines)+"\r\n\r\n"

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((HOST,LPORT)); s.settimeout(2)
callid=f"{uuid.uuid4()}@{HOST}"; tag=uuid.uuid4().hex[:8]
s.sendto(build(1,callid,"z9hG4bK-"+uuid.uuid4().hex[:10],tag).encode(),(HOST,PORT))
resp=s.recvfrom(8192)[0].decode(errors="ignore")
challenge=next(x for x in resp.split("\r\n") if x.lower().startswith("www-authenticate:"))
params=dict(re.findall(r'(\w+)="?([^",]+)"?',challenge.split(":",1)[1]))
realm=params["realm"]; nonce=params["nonce"]; opaque=params.get("opaque","")
qop="auth"; nc="00000001"; cnonce=uuid.uuid4().hex
uri=f"sip:{HOST}:{PORT}"
ha1=md5(f"{USER}:{realm}:{WRONG}"); ha2=md5(f"REGISTER:{uri}")
digest=md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
auth=(f'Digest username="{USER}",realm="{realm}",nonce="{nonce}",uri="{uri}",'
      f'response="{digest}",algorithm=MD5,cnonce="{cnonce}",nc={nc},qop={qop}')
if opaque:
    auth += f',opaque="{opaque}"'
s.sendto(build(2,callid,"z9hG4bK-"+uuid.uuid4().hex[:10],tag,auth).encode(),(HOST,PORT))
print(s.recvfrom(8192)[0].decode(errors="ignore").splitlines()[0])

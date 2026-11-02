#!/usr/bin/env python3
import socket, re, hashlib, uuid, time

PBX=("127.0.0.1",5060)

def md5(s): return hashlib.md5(s.encode()).hexdigest()

def failed_auth_once(src_ip, src_port, user="1001"):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind((src_ip,src_port)); s.settimeout(1)
    callid=f"{uuid.uuid4()}@{src_ip}"; tag=uuid.uuid4().hex[:8]
    uri="sip:127.0.0.1:5060"
    def msg(cseq,branch,auth=None):
        h=[f"REGISTER {uri} SIP/2.0",
           f"Via: SIP/2.0/UDP {src_ip}:{src_port};branch={branch};rport",
           f"From: <sip:{user}@127.0.0.1>;tag={tag}",
           f"To: <sip:{user}@127.0.0.1>",f"Call-ID: {callid}",
           f"CSeq: {cseq} REGISTER",f"Contact: <sip:{user}@{src_ip}:{src_port}>",
           "Max-Forwards: 70","Expires: 60"]
        if auth: h.append("Authorization: "+auth)
        h.append("Content-Length: 0")
        return "\r\n".join(h)+"\r\n\r\n"
    s.sendto(msg(1,"z9hG4bK-"+uuid.uuid4().hex[:10]).encode(),PBX)
    resp=s.recvfrom(8192)[0].decode(errors="ignore")
    chal=next(x for x in resp.split("\r\n") if x.lower().startswith("www-authenticate:"))
    p=dict(re.findall(r'(\w+)="?([^",]+)"?',chal.split(":",1)[1]))
    realm,nonce=p["realm"],p["nonce"]; opaque=p.get("opaque","")
    nc="00000001"; qop="auth"; cnonce=uuid.uuid4().hex
    wrong="WrongLabPassword"
    ha1=md5(f"{user}:{realm}:{wrong}"); ha2=md5(f"REGISTER:{uri}")
    digest=md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    auth=(f'Digest username="{user}",realm="{realm}",nonce="{nonce}",uri="{uri}",'
          f'response="{digest}",algorithm=MD5,cnonce="{cnonce}",nc={nc},qop={qop}')
    if opaque: auth+=f',opaque="{opaque}"'
    s.sendto(msg(2,"z9hG4bK-"+uuid.uuid4().hex[:10],auth).encode(),PBX)
    try: s.recvfrom(8192)
    except socket.timeout: pass
    s.close()

def options_once(src_ip,src_port,target):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.bind((src_ip,src_port)); s.settimeout(.5)
    callid=f"{uuid.uuid4()}@{src_ip}"
    m=(f"OPTIONS sip:{target}@127.0.0.1 SIP/2.0\r\n"
       f"Via: SIP/2.0/UDP {src_ip}:{src_port};branch=z9hG4bK-{uuid.uuid4().hex[:10]};rport\r\n"
       f"From: <sip:scanner@127.0.0.1>;tag={uuid.uuid4().hex[:8]}\r\n"
       f"To: <sip:{target}@127.0.0.1>\r\nCall-ID: {callid}\r\n"
       f"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
    s.sendto(m.encode(),PBX)
    try: s.recvfrom(8192)
    except socket.timeout: pass
    s.close()

print("Running controlled loopback research traffic only")
for i in range(10):
    failed_auth_once("127.0.0.2",5200+i)
    time.sleep(.08)
for i in range(5):
    options_once("127.0.0.3",5300+i,9100+i)
    time.sleep(.08)
print("Controlled attack traffic complete")

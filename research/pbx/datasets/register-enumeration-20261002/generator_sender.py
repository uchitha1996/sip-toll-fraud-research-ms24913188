import socket,time,json,uuid,sys
targets=json.loads(sys.argv[1])
assert len(targets)==6 and set(targets)<=set(str(x) for x in range(9001,9007))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('172.16.200.68',5127));s.settimeout(2)
records=[]
for target in targets:
    cid='enum-'+uuid.uuid4().hex
    message='\r\n'.join([
      'REGISTER sip:172.16.200.81 SIP/2.0',
      'Via: SIP/2.0/UDP 172.16.200.68:5127;branch=z9hG4bK-'+cid,
      'Max-Forwards: 70',
      'From: <sip:'+target+'@172.16.200.81>;tag='+cid,
      'To: <sip:'+target+'@172.16.200.81>',
      'Call-ID: '+cid,'CSeq: 1 REGISTER',
      'Contact: <sip:'+target+'@172.16.200.68:5127>',
      'Expires: 0','Content-Length: 0','',''])
    started=time.time()
    s.sendto(message.encode(),('172.16.200.81',5060))
    reply,addr=s.recvfrom(4096)
    assert addr[0]=='172.16.200.81'
    records.append(dict(target=target,call_id=cid,response=reply.split(b'\r\n')[0].decode(),source_port=5127))
    time.sleep(max(0,started+1-time.time()))
s.close()
print(json.dumps(records))

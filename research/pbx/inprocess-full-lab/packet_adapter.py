"""Bounded transaction matching and retry grace shared by live/offline audit.
Packet matching is independent of detector predictions and assigned intent.
"""
from datetime import datetime,timezone
GEN,PBX='172.16.200.68','172.16.200.81'
FIELDS=['frame.time_epoch','ip.src','ip.dst','sip.Method','sip.Status-Code','sip.CSeq.method',
 'sip.CSeq.seq','sip.Call-ID','sip.from.user','sip.to.user','sip.r-uri.user','sip.auth.username','sip.auth.stale']
def iso(t):return datetime.fromtimestamp(float(t),timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
class Adapter:
 def __init__(self):self.transactions={};self.queue=[];self.seen=set();self.count=0
 def feed(self,p,clock):
  stamp=float(p['frame.time_epoch']);src=p['ip.src'];dst=p['ip.dst'];cid=p['sip.Call-ID'];seq=p['sip.CSeq.seq']
  method=p['sip.Method'];code=p['sip.Status-Code'];event=None;grace=False
  if src==GEN and dst==PBX and method=='REGISTER':
   account=p['sip.from.user']
   if account in ['1001','1002']:
    key=(cid,seq)
    if key not in self.transactions:
     self.transactions={k:v for k,v in self.transactions.items() if v['stamp']>=stamp-120}
     if len(self.transactions)>=512:raise ValueError('Transaction capacity')
     self.transactions[key]={'account':account,'auth':bool(p['sip.auth.username']),'stamp':stamp,'responded':False}
  elif src==PBX and dst==GEN and p['sip.CSeq.method']=='REGISTER' and code in ['200','401','403']:
   tx=self.transactions.get((cid,seq))
   if tx and tx['auth'] and not tx['responded']:
    tx['responded']=True
    if code=='200':
     for queued in self.queue:
      if queued['event']['kind']=='AUTH_REJECTION' and queued['event']['call_id']==cid:queued['cancel']=True
     event={'kind':'REGISTER_SUCCESS','account':tx['account']}
    elif p['sip.auth.stale'].strip().lower()!='true':event={'kind':'AUTH_REJECTION','account':tx['account']};grace=True
  elif src==GEN and dst==PBX and method=='OPTIONS' and p['sip.r-uri.user']:
   event={'kind':'OPTIONS_REQUEST','account':'','target':p['sip.r-uri.user']}
  elif src==GEN and dst==PBX and method=='INVITE':
   account=p['sip.from.user'];destination=p['sip.r-uri.user']
   if (account,destination) in [('1001','88001'),('1002','88002')]:
    event={'kind':'OUTBOUND_INVITE','account':account,'destination':destination,'destination_group':'lab-uas','trunk':'lab-trunk'}
  if event:
   key=(event['kind'],cid) if event['kind']=='OUTBOUND_INVITE' else (event['kind'],cid,seq)
   if key not in self.seen:
    if len(self.seen)>=2048 or len(self.queue)>=512:raise ValueError('Adapter capacity')
    self.seen.add(key);self.count+=1
    event.update(source_ip=GEN,call_id=cid,event_id='packet:'+str(self.count),time_utc=iso(stamp))
    self.queue.append({'event':event,'due':clock+(1 if grace else 0),'cancel':False})
  return self.drain(clock)
 def drain(self,clock):
  events=[]
  while self.queue and (self.queue[0]['cancel'] or self.queue[0]['due']<=clock):
   queued=self.queue.pop(0)
   if not queued['cancel']:events.append(queued['event'])
  return events

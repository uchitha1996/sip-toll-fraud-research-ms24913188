"""ctypes bridge used only for offline independent port verification."""
import ctypes,json
from datetime import datetime
from pathlib import Path
KINDS=['OPTIONS_REQUEST','AUTH_REJECTION','REGISTER_SUCCESS','OUTBOUND_INVITE','CALL_SIP_COMPLETED','CDR_ANSWERED']
class NativeCore:
 def __init__(self,library):
  self.lib=ctypes.CDLL(str(library));self.lib.sf_create.restype=ctypes.c_void_p
  self.lib.sf_destroy.argtypes=[ctypes.c_void_p]
  self.lib.sf_feed.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_double]+[ctypes.c_char_p]*7+[ctypes.c_int]
  self.lib.sf_feed.restype=ctypes.c_char_p;self.ptr=self.lib.sf_create()
  if not self.ptr:raise MemoryError('Native engine allocation')
 def accept(self,e):
  if e['source_ip']!='172.16.200.68':raise ValueError('Restricted lab generator only')
  stamp=datetime.fromisoformat(e['time_utc'].replace('Z','+00:00')).timestamp()
  keys=['event_id','account','target','call_id','destination','destination_group','trunk']
  r=self.lib.sf_feed(self.ptr,KINDS.index(e['kind']),stamp,*[str(e.get(k,'')).encode() for k in keys],int(e.get('billsec',0)))
  if r is None:raise ValueError('Native invalid event/order/capacity')
  return json.loads(r)
 def close(self):
  if self.ptr:self.lib.sf_destroy(self.ptr);self.ptr=None

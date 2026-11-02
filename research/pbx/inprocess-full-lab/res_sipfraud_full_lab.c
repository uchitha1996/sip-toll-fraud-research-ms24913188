/* GPL-2.0. Passive PJSIP observer, restricted to the isolated SIPp laboratory.
 * Never consumes a message or controls calls. Frozen ML is priority metadata.
 */
#include "asterisk.h"
#include <time.h>
#include <pthread.h>
#include <math.h>
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"
#include "asterisk/res_pjsip.h"
#include "progression_core.h"
#include "progression_core.c"
#define TX_CAP 512
#define EV_CAP 512
struct transaction {char cid[SF_TEXT],account[16];long cseq;int authenticated,responded;double stamp;};
struct queued {struct sf_event event;double due;int canceled;};
static struct transaction tx[TX_CAP];static unsigned ntx;
static struct queued queue[EV_CAP];static unsigned nq;
static struct sf_core *engine;
static unsigned long event_serial,event_count,alert_count;
static pthread_t worker;static int running,invalid;
AST_MUTEX_DEFINE_STATIC(state_lock);
static double epoch_now(void){struct timespec t;clock_gettime(CLOCK_REALTIME,&t);return t.tv_sec+t.tv_nsec/1e9;}
static double mono_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void fail_case(const char *reason)
{if(!invalid){invalid=1;ast_log(LOG_ERROR,"SIPFRAUDFULL invalid=1 reason=%s\n",reason);}}
static int pj_copy(char *out,size_t size,const pj_str_t *in)
{if(in->slen<0 || (size_t)in->slen>=size)return -1;memcpy(out,in->ptr,in->slen);out[in->slen]=0;return 0;}
static int uri_user(char *out,size_t size,pjsip_uri *uri)
{
 pjsip_uri *raw=pjsip_uri_get_uri(uri);pjsip_sip_uri *sip;
 if(!PJSIP_URI_SCHEME_IS_SIP(raw) && !PJSIP_URI_SCHEME_IS_SIPS(raw))return -1;
 sip=(pjsip_sip_uri *)raw;return pj_copy(out,size,&sip->user);
}
static int allowed_account(const char *s){return !strcmp(s,"1001") || !strcmp(s,"1002");}
static void publish(const struct sf_event *e)
{
 const char *s;unsigned long long ns;struct timespec mt;double decided;
 if(sf_accept(engine,e)){fail_case("core_event_order_or_capacity");return;}
 event_count++;s=sf_result(engine);if(!strcmp(s,"[]"))return;
 clock_gettime(CLOCK_MONOTONIC,&mt);ns=(unsigned long long)mt.tv_sec*1000000000ULL+mt.tv_nsec;decided=epoch_now();
 ast_log(LOG_NOTICE,"SIPFRAUDFULL decision_epoch=%.9f decision_monotonic_ns=%llu alerts=%s\n",decided,ns,s);
 while((s=strstr(s,"\"stage\""))){alert_count++;s++;}
}
static void flush(double now)
{
 unsigned done=0,i;while(done<nq && (queue[done].canceled || queue[done].due<=now)){
  if(!queue[done].canceled && !invalid)publish(&queue[done].event);
  done++;
 }
 if(done){for(i=done;i<nq;i++)queue[i-done]=queue[i];nq-=done;}
}
static void enqueue(struct sf_event *e,int grace)
{
 if(invalid)return;
 if(nq==EV_CAP){fail_case("pending_queue_capacity");return;}
 snprintf(e->id,sizeof(e->id),"native:%lu",++event_serial);
 queue[nq].event=*e;queue[nq].due=mono_now()+(grace?1.0:0.0);queue[nq].canceled=0;nq++;
 flush(mono_now());
}
static void *tick(void *unused)
{
 struct timespec delay={0,20000000};(void)unused;
 for(;;){ast_mutex_lock(&state_lock);if(!running){ast_mutex_unlock(&state_lock);break;}flush(mono_now());ast_mutex_unlock(&state_lock);nanosleep(&delay,NULL);}
 return NULL;
}
static pj_bool_t observe_request(pjsip_rx_data *rdata)
{
 pjsip_msg *m=rdata->msg_info.msg;pjsip_cid_hdr *cid;pjsip_from_hdr *from;pjsip_cseq_hdr *cseq;
 struct sf_event e;unsigned i,k;int auth;
 if(!m || strcmp(rdata->pkt_info.src_name,"172.16.200.68"))return PJ_FALSE;
 memset(&e,0,sizeof(e));
 cid=pjsip_msg_find_hdr(m,PJSIP_H_CALL_ID,NULL);from=pjsip_msg_find_hdr(m,PJSIP_H_FROM,NULL);cseq=pjsip_msg_find_hdr(m,PJSIP_H_CSEQ,NULL);
 if(!cid || !from || !cseq || pj_copy(e.cid,sizeof(e.cid),&cid->id) || uri_user(e.account,sizeof(e.account),from->uri))return PJ_FALSE;
 ast_mutex_lock(&state_lock);
 e.stamp=epoch_now();
 if(m->line.req.method.id==PJSIP_OPTIONS_METHOD){
  if(!uri_user(e.target,sizeof(e.target),m->line.req.uri)){e.account[0]=0;e.kind=SF_OPTIONS;enqueue(&e,0);}
 }else if(m->line.req.method.id==PJSIP_REGISTER_METHOD && allowed_account(e.account)){
  for(i=0;i<ntx;i++)if(tx[i].cseq==cseq->cseq && !strcmp(tx[i].cid,e.cid))break;
  if(i==ntx){
   k=0;for(i=0;i<ntx;i++)if(tx[i].stamp>=e.stamp-120)tx[k++]=tx[i];ntx=k;
   if(ntx==TX_CAP){fail_case("transaction_capacity");}else{
    struct transaction *t=&tx[ntx++];memset(t,0,sizeof(*t));strcpy(t->cid,e.cid);strcpy(t->account,e.account);
    auth=pjsip_msg_find_hdr(m,PJSIP_H_AUTHORIZATION,NULL)!=NULL;t->authenticated=auth;t->cseq=cseq->cseq;t->stamp=e.stamp;
   }
  }
 }else if(m->line.req.method.id==PJSIP_INVITE_METHOD && allowed_account(e.account)){
  if(!uri_user(e.destination,sizeof(e.destination),m->line.req.uri) &&
     ((!strcmp(e.account,"1001") && !strcmp(e.destination,"88001")) || (!strcmp(e.account,"1002") && !strcmp(e.destination,"88002")))){
   e.kind=SF_INVITE;strcpy(e.group,"lab-uas");strcpy(e.trunk,"lab-trunk");enqueue(&e,0);
  }
 }
 ast_mutex_unlock(&state_lock);return PJ_FALSE;
}
static pj_status_t observe_response(pjsip_tx_data *data)
{
 pjsip_msg *m=data->msg;pjsip_cid_hdr *cid;pjsip_cseq_hdr *cseq;pjsip_www_authenticate_hdr *challenge;
 struct sf_event e;unsigned i;int code;
 if(!m || m->type!=PJSIP_RESPONSE_MSG || strcmp(data->tp_info.dst_name,"172.16.200.68"))return PJ_SUCCESS;
 cseq=pjsip_msg_find_hdr(m,PJSIP_H_CSEQ,NULL);cid=pjsip_msg_find_hdr(m,PJSIP_H_CALL_ID,NULL);
 if(!cid || !cseq || cseq->method.id!=PJSIP_REGISTER_METHOD)return PJ_SUCCESS;
 code=m->line.status.code;if(code!=200 && code!=401 && code!=403)return PJ_SUCCESS;
 memset(&e,0,sizeof(e));if(pj_copy(e.cid,sizeof(e.cid),&cid->id))return PJ_SUCCESS;
 ast_mutex_lock(&state_lock);flush(mono_now());
 e.stamp=epoch_now();
 for(i=0;i<ntx;i++)if(tx[i].cseq==cseq->cseq && !strcmp(tx[i].cid,e.cid))break;
 if(i<ntx && tx[i].authenticated && !tx[i].responded){
  tx[i].responded=1;strcpy(e.account,tx[i].account);
  if(code==200){
   for(i=0;i<nq;i++)if(queue[i].event.kind==SF_REJECT && !strcmp(queue[i].event.cid,e.cid))queue[i].canceled=1;
   e.kind=SF_REGISTER;enqueue(&e,0);
  }else{
   challenge=pjsip_msg_find_hdr(m,PJSIP_H_WWW_AUTHENTICATE,NULL);
   if(!challenge || !challenge->challenge.digest.stale){e.kind=SF_REJECT;enqueue(&e,1);}
  }
 }
 ast_mutex_unlock(&state_lock);return PJ_SUCCESS;
}
static pjsip_module observer={.name={"SIP Fraud Full Lab",18},.id=-1,.priority=0,.on_rx_request=observe_request,.on_tx_response=observe_response};
static char *status(struct ast_cli_entry *entry,int command,struct ast_cli_args *args)
{
 if(command==CLI_INIT){entry->command="sipfraud full status";entry->usage="Usage: sipfraud full status\nPassive five-stage lab observer and frozen causal ML.\n";return NULL;}
 if(command==CLI_GENERATE)return NULL;
 if(args->argc!=3)return CLI_SHOWUSAGE;
 ast_mutex_lock(&state_lock);ast_cli(args->fd,"invalid=%d events=%lu alerts=%lu pending=%u transactions=%u model=" MODEL_HASH "\n",invalid,event_count,alert_count,nq,ntx);ast_mutex_unlock(&state_lock);return CLI_SUCCESS;
}
static struct ast_cli_entry commands[]={AST_CLI_DEFINE(status,"Show bounded full SIP fraud lab observer")};
static int load_module(void)
{
 engine=ast_calloc(1,sizeof(*engine));if(!engine)return AST_MODULE_LOAD_DECLINE;sf_init(engine);
 memset(tx,0,sizeof(tx));ntx=nq=0;invalid=0;event_serial=event_count=alert_count=0;running=1;
 if(ast_sip_register_service(&observer)){ast_free(engine);engine=NULL;running=0;return AST_MODULE_LOAD_DECLINE;}
 if(ast_pthread_create_background(&worker,NULL,tick,NULL)){
  running=0;ast_sip_unregister_service(&observer);ast_free(engine);engine=NULL;return AST_MODULE_LOAD_DECLINE;
 }
 ast_cli_register_multiple(commands,ARRAY_LEN(commands));return AST_MODULE_LOAD_SUCCESS;
}
static int unload_module(void)
{
 ast_cli_unregister_multiple(commands,ARRAY_LEN(commands));ast_sip_unregister_service(&observer);
 ast_mutex_lock(&state_lock);running=0;ast_mutex_unlock(&state_lock);pthread_join(worker,NULL);
 ast_free(engine);engine=NULL;return 0;
}
AST_MODULE_INFO(ASTERISK_GPL_KEY,AST_MODFLAG_LOAD_ORDER,"Passive full SIP fraud laboratory progression",
 .support_level=AST_MODULE_SUPPORT_EXTENDED,.load=load_module,.unload=unload_module,
 .load_pri=AST_MODPRI_APP_DEPEND,.requires="res_pjsip");

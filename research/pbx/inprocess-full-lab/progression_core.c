/* GPL-2.0. Bounded laboratory port of the frozen progression and causal score.
 * No call control. Capacity exhaustion invalidates the case; no silent eviction.
 * One declared generator, accounts 1001/1002, UNKNOWN destination policy.
 */
#include "progression_core.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#define MODEL_HASH "ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d"
static const double mean[4]={6.5,4.7,12.960280000000001,16.051260000000003};
static const double scale[4]={1.5652475842498528,.9,5.638711408078977,5.650308574263888};
static const double coef[4]={.17775209390599728,.12366751093399207,.1278862628493443,.15568323695962824};
static int append(struct sf_core *c,const char *fmt,...)
{
    va_list ap; int n; va_start(ap,fmt);
    n=vsnprintf(c->result+c->used,SF_RESULT-c->used,fmt,ap); va_end(ap);
    if(n<0 || (unsigned)n>=SF_RESULT-c->used){c->failed=1;return -1;}
    c->used+=(unsigned)n;return 0;
}
void sf_init(struct sf_core *c){memset(c,0,sizeof(*c));c->last_time=-INFINITY;}
const char *sf_result(struct sf_core *c){return c->result;}
static int safe(const char *s,size_t cap)
{
    size_t i;for(i=0;i<cap;i++){
        unsigned char v=(unsigned char)s[i];if(!v)return 1;
        if(v<32 || v>126 || v=='"' || v=='\\')return 0;
    }return 0;
}
static int emit(struct sf_core *c,const struct sf_event *e,const char *stage,const char *risk,const double *features)
{
    if(c->used>1 && append(c,",")<0)return -1;
    if(append(c,"{\"stage\":\"%s\",\"risk\":\"%s\",\"source_ip\":\"172.16.200.68\",\"account\":\"%s\",\"call_id\":\"%s\",\"event_id\":\"%s\",\"event_epoch\":%.9f,\"destination\":\"%s\",\"policy\":\"UNKNOWN\"",stage,risk,e->account,e->cid,e->id,e->stamp,e->destination)<0)return -1;
    if(features){
        int i;double z=.0038816133580195427,p;
        for(i=0;i<4;i++)z+=coef[i]*(features[i]-mean[i])/scale[i];
        p=1/(1+exp(-z));
        if(append(c,",\"ml_probability\":%.15g,\"ml_priority\":\"%s\",\"ml_model_sha256\":\"%s\",\"ml_feature_values\":[%.9g,%.9g,%.9g,%.9g]",p,p<.4?"LOWER":p>=.6?"HIGHER":"REVIEW",MODEL_HASH,features[0],features[1],features[2],features[3])<0)return -1;
    }
    return append(c,"}");
}
static unsigned prune_fail(struct sf_account *a,double stamp)
{
    unsigned i,k=0;for(i=0;i<a->nfail;i++)if(a->failures[i]>=stamp-120)a->failures[k++]=a->failures[i];
    a->nfail=k;return k;
}
int sf_accept(struct sf_core *c,const struct sf_event *e)
{
    unsigned i,j,k;int ai=-1;struct sf_account *a=NULL;struct sf_call *call=NULL;
    c->used=0;c->result[0]=0;
    if(c->failed || !isfinite(e->stamp) || e->kind<0 || e->kind>SF_CDR || !e->id[0] ||
       !safe(e->id,sizeof(e->id)) || !safe(e->cid,sizeof(e->cid)) || !safe(e->target,sizeof(e->target)) ||
       !safe(e->account,sizeof(e->account)) || !safe(e->destination,sizeof(e->destination)) ||
       !safe(e->group,sizeof(e->group)) || !safe(e->trunk,sizeof(e->trunk)))return -1;
    for(i=0;i<c->nids;i++)if(!strcmp(c->ids[i],e->id)){strcpy(c->result,"[]");return 0;}
    if(e->stamp<c->last_time || c->nids==SF_IDS){c->failed=1;return -1;}
    if(!strcmp(e->account,"1001"))ai=0;else if(!strcmp(e->account,"1002"))ai=1;
    if(e->kind!=SF_OPTIONS && ai<0)return -1;
    if(e->kind==SF_OPTIONS && !e->target[0])return -1;
    if(e->kind>=SF_INVITE && (!e->cid[0] || ((e->kind==SF_INVITE || e->kind==SF_CDR) && !e->destination[0])))return -1;
    if(ai>=0)a=&c->accounts[ai];
    if(e->kind>=SF_INVITE){
        for(i=0;i<a->ncalls;i++)if(!strcmp(a->calls[i].cid,e->cid)){call=&a->calls[i];break;}
        if(e->kind==SF_INVITE && call && strcmp(call->destination,e->destination))return -1;
        if(e->kind==SF_COMPLETE && (!call || e->stamp<call->stamp))return -1;
        if(e->kind==SF_CDR && (!call || !call->complete || strcmp(call->destination,e->destination)))return -1;
    }
    strcpy(c->ids[c->nids++],e->id);c->last_time=e->stamp;append(c,"[");
    if(e->kind==SF_OPTIONS){
        k=0;for(i=0;i<c->noptions;i++)if(c->options[i].stamp>=e->stamp-10)c->options[k++]=c->options[i];
        c->noptions=k;if(k==SF_CAP){c->failed=1;return -1;}
        c->options[k].stamp=e->stamp;strcpy(c->options[k].target,e->target);c->noptions++;
        k=0;for(i=0;i<c->noptions;i++){
            for(j=0;j<i;j++)if(!strcmp(c->options[i].target,c->options[j].target))break;
            if(j==i)k++;
        }
        if(k<5)c->recon_active=0;
        else if(!c->recon_active){c->recon_active=1;emit(c,e,"RECONNAISSANCE","REVIEW",NULL);}
    }else if(e->kind==SF_REJECT){
        prune_fail(a,e->stamp);if(a->nfail==SF_CAP){c->failed=1;return -1;}
        a->failures[a->nfail++]=e->stamp;a->failure_serial++;
        k=0;for(i=0;i<a->nfail;i++)if(a->failures[i]>=e->stamp-60)k++;
        if(k<10)a->auth_active=0;
        else if(!a->auth_active){a->auth_active=1;emit(c,e,"AUTHENTICATION_ATTACK","HIGH_SUSPICION",NULL);}
    }else if(e->kind==SF_REGISTER){
        prune_fail(a,e->stamp);
        /* A changed surviving failure set is a new eligible recovery episode. */
        if(a->nfail>=5 && (!a->has_recovery || a->review_serial!=a->failure_serial || a->review_nfail!=a->nfail)){
            double f[4],lo=a->failures[0],hi=a->failures[a->nfail-1];unsigned peak=0;
            for(i=0;i<a->nfail;i++){k=0;for(j=0;j<a->nfail;j++)if(a->failures[j]>=a->failures[i]-10 && a->failures[j]<=a->failures[i])k++;if(k>peak)peak=k;}
            f[0]=a->nfail;f[1]=peak;f[2]=round((hi-lo)*10000)/10000;f[3]=round((e->stamp-lo)*10000)/10000;
            a->has_recovery=1;a->recovery=e->stamp;a->review_serial=a->failure_serial;a->review_nfail=a->nfail;
            emit(c,e,"SUSPECTED_COMPROMISE","REVIEW",f);
        }
    }else if(e->kind==SF_INVITE){
        int fresh=!call;
        if(fresh){
            if(a->ncalls==SF_CAP){c->failed=1;return -1;}
            call=&a->calls[a->ncalls++];memset(call,0,sizeof(*call));call->stamp=e->stamp;
            strcpy(call->cid,e->cid);strcpy(call->destination,e->destination);strcpy(call->group,e->group);strcpy(call->trunk,e->trunk);
        }
        if(a->has_recovery && e->stamp>=a->recovery && e->stamp<=a->recovery+120 && !call->attempt){
            call->attempt=1;emit(c,e,"SUSPECTED_OUTBOUND_ATTEMPT","REVIEW",NULL);
        }
        if(fresh && e->group[0]){
            k=0;for(i=0;i<a->ncalls;i++)if(a->calls[i].stamp>=e->stamp-60 && !strcmp(a->calls[i].group,e->group) && !strcmp(a->calls[i].trunk,e->trunk))k++;
            if(k<3)a->burst_active=0;
            else if(!a->burst_active){a->burst_active=1;emit(c,e,"CALL_BURST","REVIEW",NULL);}
        }
    }else if(e->kind==SF_COMPLETE){call->complete=1;
    }else if(e->kind==SF_CDR && call->attempt && !call->answered && e->billsec>0){
        call->answered=1;emit(c,e,"ANSWERED_EMULATED_OUTBOUND","REVIEW",NULL);
    }
    append(c,"]");return c->failed?-1:0;
}

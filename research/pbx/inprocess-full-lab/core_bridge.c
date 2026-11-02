#include "progression_core.h"
#include <stdlib.h>
#include <string.h>
void *sf_create(void){struct sf_core *c=malloc(sizeof(*c));if(c)sf_init(c);return c;}
void sf_destroy(void *p){free(p);}
const char *sf_feed(void *p,int kind,double stamp,const char *id,const char *account,
 const char *target,const char *cid,const char *destination,const char *group,const char *trunk,int billsec)
{
 struct sf_event e;memset(&e,0,sizeof(e));e.kind=kind;e.stamp=stamp;e.billsec=billsec;
#define COPY(field,value) do{if(strlen(value)>=sizeof(e.field))return NULL;strcpy(e.field,value);}while(0)
 COPY(id,id);COPY(account,account);COPY(target,target);COPY(cid,cid);
 COPY(destination,destination);COPY(group,group);COPY(trunk,trunk);
#undef COPY
 if(sf_accept(p,&e))return NULL;
 return sf_result(p);
}

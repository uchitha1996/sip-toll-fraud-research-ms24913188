#ifndef SIPFRAUD_PROGRESSION_CORE_H
#define SIPFRAUD_PROGRESSION_CORE_H
#define SF_CAP 256
#define SF_IDS 2048
#define SF_TEXT 256
#define SF_RESULT 8192
enum sf_kind { SF_OPTIONS, SF_REJECT, SF_REGISTER, SF_INVITE, SF_COMPLETE, SF_CDR };
struct sf_event { int kind, billsec; double stamp; char id[SF_TEXT], account[16], target[SF_TEXT], cid[SF_TEXT], destination[16], group[32], trunk[32]; };
struct sf_call { double stamp; char cid[SF_TEXT],destination[16],group[32],trunk[32]; int complete,attempt,answered; };
struct sf_account { double failures[SF_CAP]; unsigned nfail; unsigned failure_serial,review_serial,review_nfail; double recovery; int has_recovery,auth_active,burst_active; struct sf_call calls[SF_CAP]; unsigned ncalls; };
struct sf_option { double stamp; char target[SF_TEXT]; };
struct sf_core { struct sf_account accounts[2]; struct sf_option options[SF_CAP]; unsigned noptions; int recon_active; double last_time; char ids[SF_IDS][SF_TEXT]; unsigned nids; char result[SF_RESULT]; unsigned used; int failed; };
void sf_init(struct sf_core *c);
int sf_accept(struct sf_core *c, const struct sf_event *e);
const char *sf_result(struct sf_core *c);
#endif

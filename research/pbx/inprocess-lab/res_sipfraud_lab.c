/* Development-only Asterisk 20 module: restricted in-process auth stage.
 * GPL-2.0, matching the Asterisk module interface. No call control.
 */
#include "asterisk.h"
#include <time.h>
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/cli.h"
#include "asterisk/lock.h"
#include "asterisk/security_events.h"
#include "asterisk/stasis.h"
#include "asterisk/json.h"

struct auth_state {
    const char *account;
    double failures[128];
    unsigned int count;
    unsigned int auth_alerts;
    unsigned int review_alerts;
    int auth_active;
    int review_active;
};
static struct auth_state accounts[] = {{.account = "1001"}, {.account = "1002"}};
static struct stasis_subscription *subscription;
AST_MUTEX_DEFINE_STATIC(state_lock);

static double seconds_now(void)
{
    struct timespec stamp;
    clock_gettime(CLOCK_MONOTONIC, &stamp);
    return stamp.tv_sec + stamp.tv_nsec / 1000000000.0;
}

static struct auth_state *find_account(const char *account)
{
    unsigned int i;
    if (!account) return NULL;
    for (i = 0; i < ARRAY_LEN(accounts); ++i)
        if (!strcmp(accounts[i].account, account)) return &accounts[i];
    return NULL;
}

static void expire(struct auth_state *s, double now)
{
    unsigned int i, kept = 0;
    for (i = 0; i < s->count; ++i)
        if (s->failures[i] >= now - 120.0) s->failures[kept++] = s->failures[i];
    s->count = kept;
    if (kept < 5) s->review_active = 0;
    if (kept < 10) s->auth_active = 0;
}

static void security_event(void *data, struct stasis_subscription *sub,
                           struct stasis_message *message)
{
    struct ast_json_payload *payload;
    struct ast_json *json;
    struct auth_state *s;
    const char *account, *remote;
    enum ast_security_event_type event_type;
    double now;
    unsigned int i, recent = 0;
    if (stasis_message_type(message) != ast_security_event_type()) return;
    payload = stasis_message_data(message);
    if (!payload || !payload->json) return;
    json = payload->json;
    account = ast_json_object_string_get(json, "AccountID");
    remote = ast_json_object_string_get(json, "RemoteAddress");
    /* Restrict this experiment to the declared SIPp generator. */
    if (!remote || !strstr(remote, "/172.16.200.68/")) return;
    s = find_account(account);
    if (!s) return;
    event_type = ast_json_integer_get(ast_json_object_get(json, "SecurityEvent"));
    if (event_type != AST_SECURITY_EVENT_CHAL_RESP_FAILED &&
        event_type != AST_SECURITY_EVENT_INVAL_PASSWORD &&
        event_type != AST_SECURITY_EVENT_SUCCESSFUL_AUTH) return;
    now = seconds_now();
    ast_mutex_lock(&state_lock);
    expire(s, now);
    if (event_type == AST_SECURITY_EVENT_SUCCESSFUL_AUTH) {
        if (s->count >= 5 && !s->review_active) {
            s->review_active = 1;
            ++s->review_alerts;
            ast_log(LOG_NOTICE, "SIPFRAUDLAB stage=SUSPECTED_COMPROMISE risk=REVIEW account=%s failures=%u source=172.16.200.68\n",
                    s->account, s->count);
        }
    } else {
        if (s->count == ARRAY_LEN(s->failures)) {
            for (i = 1; i < s->count; ++i) s->failures[i - 1] = s->failures[i];
            --s->count;
        }
        s->failures[s->count++] = now;
        for (i = 0; i < s->count; ++i)
            if (s->failures[i] >= now - 60.0) ++recent;
        if (recent >= 10 && !s->auth_active) {
            s->auth_active = 1;
            ++s->auth_alerts;
            ast_log(LOG_NOTICE, "SIPFRAUDLAB stage=AUTHENTICATION_ATTACK risk=HIGH_SUSPICION account=%s failures_60s=%u source=172.16.200.68\n",
                    s->account, recent);
        }
    }
    ast_mutex_unlock(&state_lock);
}

static char *show_status(struct ast_cli_entry *entry, int command,
                         struct ast_cli_args *args)
{
    unsigned int i;
    switch (command) {
    case CLI_INIT:
        entry->command = "sipfraud lab status";
        entry->usage = "Usage: sipfraud lab status\nShows restricted in-process auth counters.\n";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }
    if (args->argc != 3) return CLI_SHOWUSAGE;
    ast_mutex_lock(&state_lock);
    for (i = 0; i < ARRAY_LEN(accounts); ++i)
        ast_cli(args->fd, "account=%s failures_window=%u auth_alerts=%u review_alerts=%u\n",
                accounts[i].account, accounts[i].count,
                accounts[i].auth_alerts, accounts[i].review_alerts);
    ast_mutex_unlock(&state_lock);
    return CLI_SUCCESS;
}

static struct ast_cli_entry commands[] = {
    AST_CLI_DEFINE(show_status, "Show SIP fraud lab in-process auth state")
};

static int load_module(void)
{
    subscription = stasis_subscribe(ast_security_topic(), security_event, NULL);
    if (!subscription) return AST_MODULE_LOAD_DECLINE;
    stasis_subscription_accept_message_type(subscription, ast_security_event_type());
    stasis_subscription_set_filter(subscription, STASIS_SUBSCRIPTION_FILTER_SELECTIVE);
    ast_cli_register_multiple(commands, ARRAY_LEN(commands));
    return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
    ast_cli_unregister_multiple(commands, ARRAY_LEN(commands));
    if (subscription) subscription = stasis_unsubscribe_and_join(subscription);
    return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Restricted SIP fraud lab auth progression");

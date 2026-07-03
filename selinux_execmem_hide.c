// SPDX-License-Identifier: GPL-3.0-only
// KPM: selinux-execmem-hide
// Oculta regla execmem dirty en verificaciones de selinux
// para bypasear detectores de entorno rooteado

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/gfp.h>

// --- API KPM (sin hook.h) ---
#define KPM_NAME(n)       static const char kpm_name[] = n
#define KPM_VERSION(v)    static const char kpm_version[] = v
#define KPM_LICENSE(l)    MODULE_LICENSE(l)
#define KPM_AUTHOR(a)     MODULE_AUTHOR(a)
#define KPM_DESCRIPTION(d) MODULE_DESCRIPTION(d)

#define KPM_INIT(f)       static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)       static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

typedef enum {
    HOOK_NO_ERR = 0,
} hook_err_t;

typedef struct {
    unsigned long arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs4_t;

extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);
// -------------------------

#define log_i(fmt, ...) printk(KERN_INFO "[execmem-hide] " fmt, ##__VA_ARGS__)
#define log_e(fmt, ...) printk(KERN_ERR "[execmem-hide][E] " fmt, ##__VA_ARGS__)

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static int (*fn_security_context_to_sid)(const char *sctx, u32 sctx_len,
                                          u32 *sid, int gfp);
static u32 system_server_sid;

static uid_t get_current_uid(void)
{
    return current_uid().val;
}

static void after_security_compute_av(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    u32 ssid = (u32)args->arg0;
    u32 tsid = (u32)args->arg1;
    struct av_decision *avd;
    uid_t uid;

    if (!system_server_sid)
        return;

    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    uid = get_current_uid();
    if (uid < 10000)
        return;

    avd = (struct av_decision *)(unsigned long)args->arg3;
    if (avd) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static void *find_sym(const char *name)
{
    return (void *)kallsyms_lookup_name(name);
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    void *sym;
    int ret;
    (void)args; (void)event; (void)reserved;

    fn_security_context_to_sid = find_sym("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        log_e("security_context_to_sid not found\n");
        return -1;
    }

    {
        const char *ctx = "u:r:system_server:s0";
        ret = fn_security_context_to_sid(ctx, sizeof("u:r:system_server:s0") - 1,
                                          &system_server_sid, GFP_KERNEL);
        if (ret || !system_server_sid) {
            log_e("SID resolution failed: %d\n", ret);
            return -1;
        }
    }

    log_i("system_server SID = %u\n", system_server_sid);

    sym = find_sym("security_compute_av");
    if (!sym) {
        log_e("security_compute_av not found\n");
        return -1;
    }

    ret = hook_wrap(sym, 4,
                    NULL, (void *)after_security_compute_av, NULL);
    if (ret) {
        log_e("hook_wrap failed: %d\n", ret);
        return -1;
    }

    log_i("loaded\n");
    return 0;
}

static long kpm_exit(void *reserved)
{
    void *sym;
    (void)reserved;

    sym = find_sym("security_compute_av");
    if (sym) unhook_func(sym);
    log_i("unloaded\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

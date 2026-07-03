// SPDX-License-Identifier: GPL-3.0-only
// KPM: selinux-execmem-hide
// Hooks security_compute_av and clears execmem permissions for app processes
// to hide dirty SELinux execmem rules from root detection.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/gfp.h>

// --- KPM API (without SDK headers, matches framework_spoof.c) ---
#define KPM_NAME(name)          static const char kpm_name[] = name
#define KPM_VERSION(ver)        static const char kpm_version[] = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)             static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

typedef enum {
    HOOK_NO_ERR = 0,
} hook_err_t;

typedef struct {
    unsigned long arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs4_t;

extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);
// --------------------------------------------------------------

// --- KPatch-Next module info ---
struct kpm_info {
    const char *name;
    const char *version;
    const char *author;
    const char *description;
};

static struct kpm_info kpm_info = {
    .name = "selinux_execmem_hide",
    .version = "1.0.0",
    .author = "SrMatdroid",
    .description = "Hides dirty execmem SELinux rules from app detection",
};
EXPORT_SYMBOL(kpm_info);
// -------------------------------

#define log_i(fmt, ...) printk(KERN_INFO "[execmem-hide] " fmt, ##__VA_ARGS__)
#define log_e(fmt, ...) printk(KERN_ERR  "[execmem-hide][E] " fmt, ##__VA_ARGS__)

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static int (*fn_sec_ctx_to_sid)(const char *, u32, u32 *, int);
static u32 system_server_sid;

static void after_security_compute_av(hook_fargs4_t *args, void *udata)
{
    u32 ssid;
    u32 tsid;
    struct av_decision *avd;
    uid_t uid;

    (void)udata;

    if (!system_server_sid)
        return;

    ssid = (u32)args->arg0;
    tsid = (u32)args->arg1;

    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    uid = current_uid().val;
    if (uid < 10000)
        return;

    avd = (struct av_decision *)(unsigned long)args->arg3;
    if (avd) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    void *sym;
    int ret;
    (void)args; (void)event; (void)reserved;

    fn_sec_ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_sec_ctx_to_sid) {
        log_e("security_context_to_sid not found\n");
        return -1;
    }

    ret = fn_sec_ctx_to_sid("u:r:system_server:s0", 22,
                            &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        log_e("SID resolution failed: %d\n", ret);
        return -1;
    }

    log_i("system_server SID = %u\n", system_server_sid);

    sym = (void *)kallsyms_lookup_name("security_compute_av");
    if (!sym) {
        log_e("security_compute_av not found\n");
        return -1;
    }

    ret = (int)hook_wrap(sym, 4, NULL, (void *)after_security_compute_av, NULL);
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
    sym = (void *)kallsyms_lookup_name("security_compute_av");
    if (sym) unhook_func(sym);
    log_i("unloaded\n");
    return 0;
}

KPM_NAME("selinux_execmem_hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules from app detection");
KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

MODULE_INFO(kpm_module, "1");

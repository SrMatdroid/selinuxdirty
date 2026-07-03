// selinux-execmem-hide.kpm
// Hooks security_compute_av and clears execmem permissions for app processes
// to hide dirty SELinux execmem rules from root detection.

#include "kpmodule.h"
#include "hook.h"
#include "kputils.h"
#include "log.h"
#include <linux/kallsyms.h>
#include <linux/gfp.h>
#include <linux/string.h>

KPM_NAME("selinux_execmem_hide");
KPM_VERSION("1.0.0");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules from app detection");

// GFP_KERNEL value for kernel 5.10
// (__GFP_RECLAIM | __GFP_IO | __GFP_FS) = (0xC00 | 0x40 | 0x80) = 0xCC0
#ifndef GFP_KERNEL
#define GFP_KERNEL ((gfp_t)0xCC0)
#endif

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static u32 system_server_sid;

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

    uid = current_uid();
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
    unsigned long sym;
    int ret;
    (void)args; (void)event; (void)reserved;

    // Resolve security_context_to_sid
    unsigned long (*sec_ctx_to_sid)(const char *, u32, u32 *, gfp_t);
    sec_ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!sec_ctx_to_sid) {
        logke("security_context_to_sid not found\n");
        return -1;
    }

    {
        const char *ctx = "u:r:system_server:s0";
        ret = (int)sec_ctx_to_sid(ctx, 22, &system_server_sid, GFP_KERNEL);
        if (ret || !system_server_sid) {
            logke("SID resolution failed: %d\n", ret);
            return -1;
        }
    }

    logki("system_server SID = %u\n", system_server_sid);

    // Resolve security_compute_av
    sym = kallsyms_lookup_name("security_compute_av");
    if (!sym) {
        logke("security_compute_av not found\n");
        return -1;
    }

    ret = (int)hook_wrap((void *)sym, 4, NULL, (void *)after_security_compute_av, NULL);
    if (ret) {
        logke("hook_wrap failed: %d\n", ret);
        return -1;
    }

    logki("loaded\n");
    return 0;
}

static long kpm_exit(void *reserved)
{
    unsigned long sym;
    (void)reserved;

    sym = kallsyms_lookup_name("security_compute_av");
    if (sym)
        hook_unwrap((void *)sym, NULL, (void *)after_security_compute_av);

    logki("unloaded\n");
    return 0;
}

// Control channel stub -- allows kpatch ctl to call without error
static long kpm_ctl(const char *ctl_args, char *__user out_msg, int outlen)
{
    (void)ctl_args; (void)out_msg; (void)outlen;
    return 0;
}

KPM_INIT(kpm_init);
KPM_CTL0(kpm_ctl);
KPM_EXIT(kpm_exit);

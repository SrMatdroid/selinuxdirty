// SPDX-License-Identifier: GPL-3.0-only
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/printk.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_DESCRIPTION("Hide execmem sepolicy from detectors");
KPM_AUTHOR("SrMatdroid");

typedef unsigned int gfp_t;
#define GFP_KERNEL ((gfp_t)0xcc0)

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static int (*fn_security_context_to_sid)(const char *scontext, u32 scontext_len,
                                          u32 *out_sid, gfp_t gfp) = NULL;

static void *g_security_compute_av_addr = NULL;
static u32 system_server_sid = 0;

static int my_strlen(const char *s)
{
    int n = 0;
    while (*s++) n++;
    return n;
}

static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    (void)udata;
    if (!system_server_sid) return;

    uid_t uid = (uid_t)current_uid();
    if (uid < 10000) return;

    u32 ssid = (u32)args->arg0;
    u32 tsid = (u32)args->arg1;
    struct av_decision *avd = (struct av_decision *)args->arg3;

    if (!avd) return;

    if (ssid == system_server_sid && tsid == system_server_sid) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long execmem_hide_init(const char *args, const char *event, void *reserved)
{
    (void)args; (void)event; (void)reserved;
    int ret = 0;

    fn_security_context_to_sid =
        (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        pr_err("[execmem-hide] security_context_to_sid not found\n");
        return -2;
    }

    const char *sys_ctx = "u:r:system_server:s0";
    ret = fn_security_context_to_sid(sys_ctx, my_strlen(sys_ctx),
                                      &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        pr_err("[execmem-hide] failed to resolve SID: %d\n", ret);
        return -22;
    }

    pr_info("[execmem-hide] system_server SID = %u\n", system_server_sid);

    g_security_compute_av_addr = (void *)kallsyms_lookup_name("security_compute_av");
    if (!g_security_compute_av_addr) {
        pr_err("[execmem-hide] security_compute_av not found\n");
        return -2;
    }

    hook_err_t err = hook_wrap5(g_security_compute_av_addr,
                                 NULL, after_security_compute_av, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[execmem-hide] hook_wrap5 failed: %d\n", err);
        return -22;
    }

    pr_info("[execmem-hide] loaded\n");
    return 0;
}

static long execmem_hide_exit(void *reserved)
{
    (void)reserved;
    if (g_security_compute_av_addr)
        hook_unwrap(g_security_compute_av_addr, NULL, after_security_compute_av);
    pr_info("[execmem-hide] unloaded\n");
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

// selinux_execmem_hide.c
// KPM: Oculta dirty sepolicy rules (system_server execmem) a apps detectoras

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide dirty execmem sepolicy rule from untrusted app detectors");
KPM_AUTHOR("SrMatdroid");

// SELinux AVC structures
struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

// Global variables
static void *g_security_compute_av_addr = NULL;
static u32 system_server_sid = 0;

// After hook callback
static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    u32 ssid;
    u32 tsid;
    struct av_decision *avd;
    uid_t uid;

    if (!system_server_sid || !args)
        return;

    uid = current_uid();
    if (uid < 10000)
        return;

    ssid = (u32)args->arg0;
    tsid = (u32)args->arg1;

    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    avd = (struct av_decision *)args->arg3;
    if (avd) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long execmem_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    const char *sys_ctx = "u:r:system_server:s0";
    hook_err_t err;
    int (*fn_sec_ctx_to_sid)(const char *scontext, u32 scontext_len,
                              u32 *out_sid, gfp_t gfp);
    int ret;

    fn_sec_ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_sec_ctx_to_sid) {
        pr_err("[execmem-hide] security_context_to_sid not found\n");
        return -2;
    }

    ret = fn_sec_ctx_to_sid(sys_ctx, strlen(sys_ctx),
                             &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        pr_err("[execmem-hide] Failed to resolve system_server SID: %d\n", ret);
        return -22;
    }

    pr_info("[execmem-hide] system_server SID = %u\n", system_server_sid);

    g_security_compute_av_addr = (void *)kallsyms_lookup_name("security_compute_av");
    if (!g_security_compute_av_addr) {
        pr_err("[execmem-hide] security_compute_av not found\n");
        return -2;
    }

    err = hook_wrap5(g_security_compute_av_addr,
                      NULL, after_security_compute_av, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[execmem-hide] hook_wrap5 failed: %d\n", err);
        return -22;
    }

    pr_info("[execmem-hide] Hook installed successfully\n");
    return 0;
}

static long execmem_hide_exit(void *__user reserved)
{
    if (g_security_compute_av_addr) {
        hook_unwrap(g_security_compute_av_addr, NULL, after_security_compute_av);
        pr_info("[execmem-hide] Hook removed\n");
    }
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

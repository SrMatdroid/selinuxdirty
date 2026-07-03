// SPDX-License-Identifier: GPL-3.0-only
#include <kpmodule.h>
#include <hook.h>
#include <kpm_compat.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL-3.0");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules");

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static u32 system_server_sid = 0;

static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    u32 ssid, tsid;
    struct av_decision *avd;
    unsigned int uid;

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

static long execmem_hide_init(const char *args, const char *event, void *reserved)
{
    int (*ctx_to_sid)(const char *ctx, u32 len, u32 *sid, u32 gfp);
    void *target;
    hook_err_t err;
    unsigned long addr;

    // Get security_context_to_sid
    addr = kallsyms_lookup_name("security_context_to_sid");
    if (!addr) {
        pr_err("execmem-hide: security_context_to_sid not found\n");
        return -2;
    }
    ctx_to_sid = (int (*)(const char *, u32, u32 *, u32))addr;

    // Resolve system_server SID
    if (ctx_to_sid("u:r:system_server:s0", 22, &system_server_sid, 0xcc0)) {
        pr_err("execmem-hide: Failed to resolve system_server SID\n");
        return -22;
    }

    pr_info("execmem-hide: system_server SID = %u\n", system_server_sid);

    // Get security_compute_av
    addr = kallsyms_lookup_name("security_compute_av");
    if (!addr) {
        pr_err("execmem-hide: security_compute_av not found\n");
        return -2;
    }
    target = (void *)addr;

    // Install hook (5 arguments for newer kernels)
    err = hook_wrap5(target, NULL, after_security_compute_av, NULL);
    if (err) {
        pr_err("execmem-hide: hook_wrap5 failed\n");
        return -22;
    }

    pr_info("execmem-hide: Loaded successfully\n");
    return 0;
}

static long execmem_hide_exit(void *reserved)
{
    unsigned long addr = kallsyms_lookup_name("security_compute_av");
    if (addr) {
        hook_unwrap((void *)addr, NULL, after_security_compute_av);
        pr_info("execmem-hide: Unloaded\n");
    }
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

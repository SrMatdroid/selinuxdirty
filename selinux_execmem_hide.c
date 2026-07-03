// SPDX-License-Identifier: GPL-3.0-only
#include <kpmodule.h>
#include <hook.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL-3.0");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules");

// SELinux AVC decision structure
struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static u32 system_server_sid = 0;

// After hook: modify SELinux decision
static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    u32 ssid, tsid;
    struct av_decision *avd;

    if (!system_server_sid || !args)
        return;

    // current_uid() from kputils.h
    if (current_uid() < 10000)
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
    // Function pointer for security_context_to_sid
    int (*ctx_to_sid)(const char *ctx, u32 len, u32 *sid, u32 gfp);
    void *target;
    hook_err_t err;

    // Resolve security_context_to_sid
    ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!ctx_to_sid) {
        pr_err("execmem-hide: security_context_to_sid not found\n");
        return -2;
    }

    // Get system_server SID
    if (ctx_to_sid("u:r:system_server:s0", 22, &system_server_sid, 0xcc0)) {
        pr_err("execmem-hide: Failed to resolve system_server SID\n");
        return -22;
    }

    pr_info("execmem-hide: system_server SID = %u\n", system_server_sid);

    // Find security_compute_av
    target = (void *)kallsyms_lookup_name("security_compute_av");
    if (!target) {
        pr_err("execmem-hide: security_compute_av not found\n");
        return -2;
    }

    // Hook with 5 arguments (newer kernels)
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
    void *target = (void *)kallsyms_lookup_name("security_compute_av");
    if (target)
        hook_unwrap(target, NULL, after_security_compute_av);
    
    pr_info("execmem-hide: Unloaded\n");
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

// SPDX-License-Identifier: GPL-3.0-only
// KPM: selinux-execmem-hide
// Hooks security_compute_av to hide dirty execmem SELinux rules

#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL-3.0");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules from root detection");

// SELinux AVC decision structure
struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

// Global state
static u32 system_server_sid = 0;

// After-hook: modify SELinux decision for app processes
static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    u32 ssid, tsid;
    struct av_decision *avd;
    uid_t uid;

    if (!system_server_sid || !args)
        return;

    // Only affect app processes (UID >= 10000)
    uid = current_uid();
    if (uid < 10000)
        return;

    ssid = (u32)args->arg0;
    tsid = (u32)args->arg1;

    // Only intercept system_server accessing itself
    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    // Clear all allowed permissions (hides execmem)
    avd = (struct av_decision *)args->arg3;
    if (avd) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

// Module initialization
static long execmem_hide_init(const char *args, const char *event, void *reserved)
{
    int (*ctx_to_sid)(const char *ctx, u32 len, u32 *sid, u32 gfp);
    void *target;
    hook_err_t err;

    // Resolve system_server SID
    ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!ctx_to_sid) {
        pr_err("execmem-hide: security_context_to_sid not found\n");
        return -2;
    }

    if (ctx_to_sid("u:r:system_server:s0", 22, &system_server_sid, 0xcc0)) {
        pr_err("execmem-hide: failed to resolve system_server SID\n");
        return -22;
    }

    pr_info("execmem-hide: system_server SID = %u\n", system_server_sid);

    // Hook security_compute_av (5 args in newer kernels)
    target = (void *)kallsyms_lookup_name("security_compute_av");
    if (!target) {
        pr_err("execmem-hide: security_compute_av not found\n");
        return -2;
    }

    err = hook_wrap5(target, NULL, after_security_compute_av, NULL);
    if (err) {
        pr_err("execmem-hide: hook_wrap5 failed: %d\n", err);
        return -22;
    }

    pr_info("execmem-hide: loaded successfully\n");
    return 0;
}

// Module cleanup
static long execmem_hide_exit(void *reserved)
{
    void *target = (void *)kallsyms_lookup_name("security_compute_av");
    if (target)
        hook_unwrap(target, NULL, after_security_compute_av);
    
    pr_info("execmem-hide: unloaded\n");
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

// SPDX-License-Identifier: GPL-3.0-only
// KPM: selinux-execmem-hide v1.0.0
// Oculta la regla "system_server execmem" de detecciones

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/gfp.h>
#include "hook.h"

#define KPM_NAME(name)          static const char kpm_name[] = name
#define KPM_VERSION(ver)        static const char kpm_version[] = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)             static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

#define mem_info(fmt, ...) printk(KERN_INFO "[execmem-hide] " fmt, ##__VA_ARGS__)
#define mem_err(fmt, ...)  printk(KERN_ERR  "[execmem-hide][E] " fmt, ##__VA_ARGS__)

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

static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    if (!system_server_sid)
        return;

    u32 ssid = (u32)args->arg0;
    u32 tsid = (u32)args->arg1;
    struct av_decision *avd = (struct av_decision *)args->arg3;

    if (!avd)
        return;

    if (ssid == system_server_sid && tsid == system_server_sid) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
    (void)udata;
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    int ret = 0;
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    fn_security_context_to_sid =
        (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        mem_err("security_context_to_sid not found\n");
        return -1;
    }

    const char *sys_ctx = "u:r:system_server:s0";
    ret = fn_security_context_to_sid(sys_ctx, strlen(sys_ctx),
                                      &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        mem_err("failed to resolve SID: %d\n", ret);
        return -1;
    }

    mem_info("system_server SID = %u\n", system_server_sid);

    g_security_compute_av_addr = (void *)kallsyms_lookup_name("security_compute_av");
    if (!g_security_compute_av_addr) {
        mem_err("security_compute_av not found\n");
        return -1;
    }

    err = hook_wrap(g_security_compute_av_addr, 5,
                    NULL, (void *)after_security_compute_av, NULL);
    if (err != HOOK_NO_ERR) {
        mem_err("hook_wrap failed: %d\n", err);
        return -1;
    }

    mem_info("cargado\n");
    return 0;
}

static long kpm_exit(void *reserved)
{
    (void)reserved;
    if (g_security_compute_av_addr) unhook_func(g_security_compute_av_addr);
    mem_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

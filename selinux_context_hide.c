// SPDX-License-Identifier: GPL-3.0-only
// KPM: selinux-context-hide v1.0.0
// Oculta context strings de KernelSU/Magisk al sondear /proc/self/attr/current

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include "hook.h"

#define KPM_NAME(name)          static const char kpm_name[] = name
#define KPM_VERSION(ver)        static const char kpm_version[] = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)             static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

#define ctx_info(fmt, ...) printk(KERN_INFO "[ctx-hide] " fmt, ##__VA_ARGS__)
#define ctx_err(fmt, ...)  printk(KERN_ERR  "[ctx-hide][E] " fmt, ##__VA_ARGS__)

static void *g_setprocattr_addr = NULL;

static int contains_suspect(const char *buf)
{
    if (strstr(buf, "magisk")) return 1;
    if (strstr(buf, "kernelsu")) return 1;
    if (strstr(buf, "u:r:su:s0")) return 1;
    if (strstr(buf, "u:r:ksu:s0")) return 1;
    return 0;
}

static void before_setprocattr(hook_fargs4_t *args, void *udata)
{
    const char *name = (const char *)args->arg1;
    if (!name || strcmp(name, "current") != 0)
        return;

    const char *value = (const char *)args->arg2;
    size_t size = (size_t)args->arg3;
    if (!value || size == 0 || size >= 128)
        return;

    char local[128];
    memcpy(local, value, size);
    local[size] = '\0';

    if (contains_suspect(local)) {
        args->ret = -22;
        args->skip_origin = 1;
    }
    (void)udata;
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    g_setprocattr_addr = (void *)kallsyms_lookup_name("security_setprocattr");
    if (!g_setprocattr_addr) {
        ctx_err("security_setprocattr not found\n");
        return -1;
    }

    err = hook_wrap(g_setprocattr_addr, 4,
                    (void *)before_setprocattr, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        ctx_err("hook_wrap failed: %d\n", err);
        return -1;
    }

    ctx_info("cargado\n");
    return 0;
}

static long kpm_exit(void *reserved)
{
    (void)reserved;
    if (g_setprocattr_addr) unhook_func(g_setprocattr_addr);
    ctx_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

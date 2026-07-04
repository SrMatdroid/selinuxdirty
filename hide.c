// SPDX-License-Identifier: GPL-2.0-only
// KPM: hide v1.0.0
// Oculta reglas execmem SELinux de detecciones

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include "hook.h"

#define KPM_NAME(name)          static const char kpm_name[] = name
#define KPM_VERSION(ver)        static const char kpm_version[] = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)             static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

#define hide_info(fmt, ...) printk(KERN_INFO "[hide] " fmt, ##__VA_ARGS__)

#define SECCLASS_PROCESS  2
#define PROCESS__EXECMEM  0x00000002

static void *g_avc_denied = NULL;
static void *g_avc_has_perm = NULL;
static void *g_security_getprocattr = NULL;

static void before_avc_denied(hook_fargs5_t *args, void *udata)
{
    u16 tclass = (u16)args->arg2;
    u32 requested = (u32)args->arg3;
    (void)udata;
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM))
        args->skip_origin = 1;
}

static void before_avc_has_perm(hook_fargs5_t *args, void *udata)
{
    u16 tclass = (u16)args->arg2;
    u32 requested = (u32)args->arg3;
    (void)udata;
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM)) {
        args->skip_origin = 1;
        args->ret = -13;
    }
}

static int kstrcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

static void before_getprocattr(hook_fargs3_t *args, void *udata)
{
    const char *name = (const char *)(unsigned long)args->arg1;
    (void)udata;
    if (name && kstrcmp(name, "current") == 0) {
        char **value_ptr = (char **)(unsigned long)args->arg2;
        *value_ptr = "u:r:untrusted_app:s0:c512,c768";
        args->skip_origin = 1;
        args->ret = 32;
    }
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    g_avc_denied = (void *)kallsyms_lookup_name("avc_denied");
    if (g_avc_denied) {
        err = hook_wrap(g_avc_denied, 5, (void *)before_avc_denied, NULL, NULL);
        hide_info("avc_denied hook: %d\n", err);
    } else {
        hide_info("avc_denied not found\n");
    }

    g_avc_has_perm = (void *)kallsyms_lookup_name("avc_has_perm");
    if (g_avc_has_perm) {
        err = hook_wrap(g_avc_has_perm, 5, (void *)before_avc_has_perm, NULL, NULL);
        hide_info("avc_has_perm hook: %d\n", err);
    } else {
        hide_info("avc_has_perm not found\n");
    }

    g_security_getprocattr = (void *)kallsyms_lookup_name("security_getprocattr");
    if (g_security_getprocattr) {
        err = hook_wrap(g_security_getprocattr, 3, (void *)before_getprocattr, NULL, NULL);
        hide_info("security_getprocattr hook: %d\n", err);
    } else {
        hide_info("security_getprocattr not found\n");
    }

    hide_info("cargado\n");
    return 0;
}

static long kpm_exit(void *reserved)
{
    (void)reserved;
    if (g_avc_denied) unhook_func(g_avc_denied);
    if (g_avc_has_perm) unhook_func(g_avc_has_perm);
    if (g_security_getprocattr) unhook_func(g_security_getprocattr);
    hide_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

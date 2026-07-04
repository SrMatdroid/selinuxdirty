// SPDX-License-Identifier: GPL-2.0-only
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/printk.h>

#define EACCES 13

static int kstrcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

#define SECCLASS_PROCESS  2
#define PROCESS__EXECMEM  0x00000002

KPM_NAME("hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hide execmem SELinux rules from detection");

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
        args->ret = -EACCES;
    }
}

static void before_getprocattr(hook_fargs3_t *args, void *udata)
{
    const char *name = (const char *)(unsigned long)args->arg1;
    (void)udata;
    if (name && kstrcmp(name, "current") == 0) {
        if (current_uid() == 0) {
            char **value_ptr = (char **)(unsigned long)args->arg2;
            *value_ptr = "u:r:untrusted_app:s0:c512,c768";
            args->skip_origin = 1;
            args->ret = 32;
        }
    }
}

static long hide_init(const char *args, const char *event, void *reserved)
{
    void *sym;
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    pr_info("hide: init, event: %s, args: %s\n", event, args);

    sym = (void *)kallsyms_lookup_name("avc_denied");
    if (sym) {
        err = hook_wrap(sym, 5, (void *)before_avc_denied, NULL, NULL);
        pr_info("hide: avc_denied hook: %d\n", err);
    } else {
        pr_info("hide: avc_denied not found\n");
    }

    sym = (void *)kallsyms_lookup_name("avc_has_perm");
    if (sym) {
        err = hook_wrap(sym, 5, (void *)before_avc_has_perm, NULL, NULL);
        pr_info("hide: avc_has_perm hook: %d\n", err);
    } else {
        pr_info("hide: avc_has_perm not found\n");
    }

    sym = (void *)kallsyms_lookup_name("security_getprocattr");
    if (sym) {
        err = hook_wrap(sym, 3, (void *)before_getprocattr, NULL, NULL);
        pr_info("hide: security_getprocattr hook: %d\n", err);
    } else {
        pr_info("hide: security_getprocattr not found\n");
    }

    return 0;
}

static long hide_exit(void *reserved)
{
    void *sym;
    (void)reserved;

    sym = (void *)kallsyms_lookup_name("avc_denied");
    if (sym)
        hook_unwrap(sym, (void *)before_avc_denied, NULL);

    sym = (void *)kallsyms_lookup_name("avc_has_perm");
    if (sym)
        hook_unwrap(sym, (void *)before_avc_has_perm, NULL);

    sym = (void *)kallsyms_lookup_name("security_getprocattr");
    if (sym)
        hook_unwrap(sym, (void *)before_getprocattr, NULL);

    pr_info("hide: exit\n");
    return 0;
}

KPM_INIT(hide_init);
KPM_EXIT(hide_exit);

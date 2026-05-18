// selinux_context_hide.c
// KPM: intercept SELinux context validation for root-related types
// License: GPL-3.0

#include <kpmodule.h>
#include <hook.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

/* kallsyms_lookup_name declarado manualmente */
extern unsigned long kallsyms_lookup_name(const char *name);

KPM_NAME("selinux-context-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide KSU/Magisk SELinux contexts from untrusted apps");
KPM_AUTHOR("SrMatdroid");

static const char *hidden_types[] = {
    "u:r:ksu:s0",
    "u:r:ksu_file:s0",
    "u:r:magisk:s0",
    "u:r:magisk_file:s0",
    "u:r:magisk_daemon:s0",
    NULL
};

static int (*orig_security_setprocattr)(const char *lsm, const char *name,
                                        void *value, size_t size) = NULL;

static int hook_security_setprocattr(const char *lsm, const char *name,
                                     void *value, size_t size)
{
    if (!name || strcmp(name, "current") != 0)
        goto original;

    if (!value || size == 0)
        goto original;

    uid_t uid = current_uid().val;
    if (uid < 10000)
        goto original;

    const char *ctx = (const char *)value;

    for (int i = 0; hidden_types[i] != NULL; i++) {
        const char *type = hidden_types[i];
        size_t type_len = strlen(type);
        if (size >= type_len && strncmp(ctx, type, type_len) == 0) {
            return -EINVAL;
        }
    }

original:
    return orig_security_setprocattr(lsm, name, value, size);
}

static long selinux_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    void *sym = (void *)kallsyms_lookup_name("security_setprocattr");
    if (!sym) {
        pr_err("[selinux-hide] No se encontró security_setprocattr\n");
        return -ENOENT;
    }

    int ret = hook_func(sym, (void *)hook_security_setprocattr,
                        (void **)&orig_security_setprocattr);
    if (ret) {
        pr_err("[selinux-hide] hook_func falló: %d\n", ret);
        return ret;
    }

    pr_info("[selinux-hide] Hook instalado @ %px\n", sym);
    return 0;
}

static long selinux_hide_exit(void *__user reserved)
{
    if (orig_security_setprocattr) {
        unhook_func((void *)hook_security_setprocattr);
        pr_info("[selinux-hide] Hook eliminado\n");
    }
    return 0;
}

KPM_INIT(selinux_hide_init);
KPM_EXIT(selinux_hide_exit);

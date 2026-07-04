// SPDX-License-Identifier: GPL-3.0-only
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/printk.h>

KPM_NAME("selinux-context-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_DESCRIPTION("Hide KSU/Magisk SELinux context probing");
KPM_AUTHOR("SrMatdroid");

#define KPM_EINVAL 22

static void *g_setprocattr_addr = NULL;

static int my_strlen(const char *s)
{
    int n = 0;
    while (*s++) n++;
    return n;
}

static int my_memcmp(const void *a, const void *b, unsigned long n)
{
    const unsigned char *p = a, *q = b;
    while (n--) {
        if (*p != *q) return *p - *q;
        p++; q++;
    }
    return 0;
}

static int my_strstr(const char *haystack, const char *needle)
{
    if (!needle[0]) return 1;
    for (int i = 0; haystack[i]; i++) {
        int j;
        for (j = 0; needle[j] && haystack[i + j] == needle[j]; j++);
        if (!needle[j]) return 1;
    }
    return 0;
}

static int contains_suspect(const char *buf, int len)
{
    if (my_strstr(buf, "magisk")) return 1;
    if (my_strstr(buf, "kernelsu")) return 1;
    if (my_strstr(buf, "u:r:su:s0")) return 1;
    if (my_strstr(buf, "u:r:ksu:s0")) return 1;
    (void)len;
    return 0;
}

static void before_setprocattr(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    const char *name = (const char *)args->arg2;
    if (!name) return;
    if (my_memcmp(name, "current", 8) != 0) return;

    uid_t uid = (uid_t)current_uid();
    if (uid < 10000) return;

    const char *value = (const char *)args->arg3;
    if (!value) return;

    char local[128];
    int i;
    for (i = 0; i < 127 && value[i]; i++)
        local[i] = value[i];
    local[i] = '\0';

    if (contains_suspect(local, i)) {
        args->ret = -KPM_EINVAL;
        args->skip_origin = 1;
    }
}

static long context_hide_init(const char *args, const char *event, void *reserved)
{
    (void)args; (void)event; (void)reserved;

    g_setprocattr_addr = (void *)kallsyms_lookup_name("security_setprocattr");
    if (!g_setprocattr_addr) {
        pr_err("[context-hide] symbol not found\n");
        return -KPM_EINVAL;
    }

    hook_err_t err = hook_wrap4(g_setprocattr_addr,
                                 before_setprocattr, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[context-hide] hook_wrap4 failed: %d\n", err);
        return -KPM_EINVAL;
    }

    pr_info("[context-hide] loaded\n");
    return 0;
}

static long context_hide_exit(void *reserved)
{
    (void)reserved;
    if (g_setprocattr_addr)
        hook_unwrap(g_setprocattr_addr, before_setprocattr, NULL);
    pr_info("[context-hide] unloaded\n");
    return 0;
}

KPM_INIT(context_hide_init);
KPM_EXIT(context_hide_exit);

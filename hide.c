#include <kpmodule.h>
#include <hook.h>

#define ENOENT 2
#define EACCES 13

extern unsigned long kallsyms_lookup_name(const char *name);

static int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

/* HOOK 1 */
int security_getprocattr(void *p, char *name, char **value);
static int (*orig_getprocattr)(void *p, char *name, char **value);

static int hooked_getprocattr(void *p, char *name, char **value)
{
    if (name && strcmp(name, "current") == 0) {
        unsigned int *cred_ptr = p ? *(unsigned int **)p : 0;
        if (cred_ptr && *cred_ptr == 0) {
            *value = "u:r:untrusted_app:s0:c512,c768";
            return 32;
        }
    }
    return orig_getprocattr(p, name, value);
}

/* HOOK 2 */
void avc_denied(unsigned int ssid, unsigned int tsid, unsigned short tclass,
                unsigned int requested, void *avd);
static void (*orig_avc_denied)(unsigned int ssid, unsigned int tsid,
                                unsigned short tclass, unsigned int requested,
                                void *avd);

#define SECCLASS_PROCESS  2
#define PROCESS__EXECMEM  0x00000002

static void hooked_avc_denied(unsigned int ssid, unsigned int tsid,
                               unsigned short tclass, unsigned int requested,
                               void *avd)
{
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM))
        return;
    orig_avc_denied(ssid, tsid, tclass, requested, avd);
}

/* HOOK 3 */
int avc_has_perm(unsigned int ssid, unsigned int tsid, unsigned short tclass,
                 unsigned int requested, void *avd);
static int (*orig_avc_has_perm)(unsigned int ssid, unsigned int tsid,
                                 unsigned short tclass, unsigned int requested,
                                 void *avd);

static int hooked_avc_has_perm(unsigned int ssid, unsigned int tsid,
                                unsigned short tclass, unsigned int requested,
                                void *avd)
{
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM))
        return -EACCES;
    return orig_avc_has_perm(ssid, tsid, tclass, requested, avd);
}

/* HOOK 4 */
int security_setprocattr(const char *name, char *value, unsigned long size);
static int (*orig_setprocattr)(const char *name, char *value, unsigned long size);

static int hooked_setprocattr(const char *name, char *value, unsigned long size)
{
    return orig_setprocattr(name, value, size);
}

/* INIT/EXIT */
static int install_hook(const char *sym, void *hooked, void **orig, int *count,
                        struct hook **hooks)
{
    struct hook *h = &(*hooks)[*count];
    h->name = sym;
    h->target = (void *)kallsyms_lookup_name(sym);
    if (!h->target)
        return -ENOENT;
    h->hook = hooked;
    h->orig = orig;
    *count = *count + 1;
    return hook_install(h);
}

static struct hook hooks[4];
static int hook_count = 0;

static int hide_init(void)
{
    if (install_hook("security_getprocattr", hooked_getprocattr, &orig_getprocattr, &hook_count, &hooks) == 0) {}
    if (install_hook("avc_denied", hooked_avc_denied, &orig_avc_denied, &hook_count, &hooks) == 0) {}
    if (install_hook("avc_has_perm", hooked_avc_has_perm, &orig_avc_has_perm, &hook_count, &hooks) == 0) {}
    if (install_hook("security_setprocattr", hooked_setprocattr, &orig_setprocattr, &hook_count, &hooks) == 0) {}
    return 0;
}

static void hide_exit(void)
{
    int i;
    for (i = 0; i < hook_count; i++)
        hook_uninstall(&hooks[i]);
}

KPM_NAME("hide");
KPM_VERSION("1.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("hide");
KPM_DESCRIPTION("hide");
KPM_INIT(hide_init);
KPM_EXIT(hide_exit);

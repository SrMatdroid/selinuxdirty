#include <kpmodule.h>
#include <hook.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

#define NULL ((void*)0)

extern unsigned long kallsyms_lookup_name(const char *name);

/* strcmp manual */
static int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

/* ============================================================
 * HOOK 1: security_getprocattr - oculta contextos KSU/Magisk
 * ============================================================ */
struct task_struct;
int security_getprocattr(struct task_struct *p, char *name, char **value);
static int (*orig_getprocattr)(struct task_struct *p, char *name, char **value);

static int hooked_getprocattr(struct task_struct *p, char *name, char **value)
{
    if (name && strcmp(name, "current") == 0) {
        if (p && p->cred && p->cred->uid.val == 0) {
            *value = "u:r:untrusted_app:s0:c512,c768";
            return 32;
        }
    }
    return orig_getprocattr(p, name, value);
}

/* ============================================================
 * HOOK 2: avc_denied - silencia denegaciones execmem
 * ============================================================ */
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

/* ============================================================
 * HOOK 3: avc_has_perm - fuerza denegación execmem
 * ============================================================ */
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
        return -13;
    return orig_avc_has_perm(ssid, tsid, tclass, requested, avd);
}

/* ============================================================
 * HOOK 4: security_setprocattr - oculta escrituras anómalas
 * ============================================================ */
int security_setprocattr(const char *name, char *value, unsigned long size);
static int (*orig_setprocattr)(const char *name, char *value, unsigned long size);

static int hooked_setprocattr(const char *name, char *value, unsigned long size)
{
    return orig_setprocattr(name, value, size);
}

/* ============================================================
 * Estructuras e init/exit
 * ============================================================ */
static struct hook hooks[4];
static int hook_count = 0;

static int install_hook(const char *sym, void *hooked, void **orig, int idx)
{
    hooks[idx].target = (void *)kallsyms_lookup_name(sym);
    if (!hooks[idx].target)
        return -13;
    hooks[idx].hook = hooked;
    hooks[idx].orig = orig;
    return hook_install(&hooks[idx]);
}

static int __init hide_init(void)
{
    if (install_hook("security_getprocattr", hooked_getprocattr, &orig_getprocattr, 0) == 0)
        hook_count++;
    if (install_hook("avc_denied", hooked_avc_denied, &orig_avc_denied, 1) == 0)
        hook_count++;
    if (install_hook("avc_has_perm", hooked_avc_has_perm, &orig_avc_has_perm, 2) == 0)
        hook_count++;
    if (install_hook("security_setprocattr", hooked_setprocattr, &orig_setprocattr, 3) == 0)
        hook_count++;
    return 0;
}

static void __exit hide_exit(void)
{
    int i;
    for (i = 0; i < hook_count; i++)
        hook_uninstall(&hooks[i]);
}

static struct kpmodule hide_module = {
    .name = "hide",
    .version = "1.0",
    .init = hide_init,
    .exit = hide_exit,
};

KPM_MODULE(hide_module);

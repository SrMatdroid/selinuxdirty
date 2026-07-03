#include <kpmodule.h>
#include <hook.h>

#define EACCES 13

extern unsigned long kallsyms_lookup_name(const char *name);

static int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

/* ============================================================
 * HOOK 1: security_getprocattr
 * ============================================================ */
static int (*orig_getprocattr)(void *p, char *name, char **value);

static int hooked_getprocattr(void *p, char *name, char **value)
{
    if (name && strcmp(name, "current") == 0) {
        /* p apunta a task_struct; cred está en el offset 0x0 (primer campo) */
        unsigned int *cred = *(unsigned int **)p;
        if (cred && *cred == 0) { /* uid 0 */
            *value = "u:r:untrusted_app:s0:c512,c768";
            return 32;
        }
    }
    return orig_getprocattr(p, name, value);
}

/* ============================================================
 * HOOK 2: avc_denied
 * ============================================================ */
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
 * HOOK 3: avc_has_perm
 * ============================================================ */
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

/* ============================================================
 * HOOK 4: security_setprocattr
 * ============================================================ */
static int (*orig_setprocattr)(const char *name, char *value, unsigned long size);

static int hooked_setprocattr(const char *name, char *value, unsigned long size)
{
    return orig_setprocattr(name, value, size);
}

/* ============================================================
 * Gestión de hooks
 * ============================================================ */
static hook_t hooks[4];
static int hook_count = 0;

static int hide_init(void)
{
    /* security_getprocattr */
    hooks[0].name = "security_getprocattr";
    hooks[0].target = (void *)kallsyms_lookup_name("security_getprocattr");
    hooks[0].hook = hooked_getprocattr;
    hooks[0].orig = &orig_getprocattr;
    if (hooks[0].target) {
        hook_install(&hooks[0]);
        hook_count++;
    }

    /* avc_denied */
    hooks[1].name = "avc_denied";
    hooks[1].target = (void *)kallsyms_lookup_name("avc_denied");
    hooks[1].hook = hooked_avc_denied;
    hooks[1].orig = &orig_avc_denied;
    if (hooks[1].target) {
        hook_install(&hooks[1]);
        hook_count++;
    }

    /* avc_has_perm */
    hooks[2].name = "avc_has_perm";
    hooks[2].target = (void *)kallsyms_lookup_name("avc_has_perm");
    hooks[2].hook = hooked_avc_has_perm;
    hooks[2].orig = &orig_avc_has_perm;
    if (hooks[2].target) {
        hook_install(&hooks[2]);
        hook_count++;
    }

    /* security_setprocattr */
    hooks[3].name = "security_setprocattr";
    hooks[3].target = (void *)kallsyms_lookup_name("security_setprocattr");
    hooks[3].hook = hooked_setprocattr;
    hooks[3].orig = &orig_setprocattr;
    if (hooks[3].target) {
        hook_install(&hooks[3]);
        hook_count++;
    }

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

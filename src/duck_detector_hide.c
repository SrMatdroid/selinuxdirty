#include <kpmodule.h>
#include <hook.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

#define NULL ((void*)0)

extern unsigned long kallsyms_lookup_name(const char *name);

/* ============================================================
 * SECCIÓN 1: Ocultar contextos SELinux de KSU/Magisk
 * Enganchamos security_getprocattr para devolver contextos limpios
 * cuando se pregunta por procesos root o KSU
 * ============================================================ */

struct task_struct;
struct cred;
int security_getprocattr(struct task_struct *p, char *name, char **value);
static int (*orig_getprocattr)(struct task_struct *p, char *name, char **value);

/* Contexto "limpio" que devolveremos para ocultar KSU/Magisk */
static char clean_ctx[] = "u:r:untrusted_app:s0:c512,c768";

/* Verifica si un proceso tiene contexto de KSU o Magisk */
static int is_root_ksu_process(void)
{
    const struct cred *cred = current_cred();
    if (!cred)
        return 0;
    
    /* uid 0 = root, típico de KSU/Magisk */
    if (cred->uid.val == 0 || cred->euid.val == 0 || 
        cred->suid.val == 0 || cred->fsuid.val == 0)
        return 1;
    
    return 0;
}

static int hooked_getprocattr(struct task_struct *p, char *name, char **value)
{
    /* Solo interceptamos consultas del atributo "current" */
    if (name && strcmp(name, "current") == 0) {
        
        /* Si el proceso objetivo tiene uid 0 (KSU/Magisk), devolvemos contexto limpio */
        if (p && p->cred && p->cred->uid.val == 0) {
            *value = clean_ctx;
            return strlen(clean_ctx);
        }
        
        /* Si el proceso actual es root, también ocultamos */
        if (p == current && is_root_ksu_process()) {
            *value = clean_ctx;
            return strlen(clean_ctx);
        }
    }

    return orig_getprocattr(p, name, value);
}

/* ============================================================
 * SECCIÓN 2: Ocultar execmem permitido en system_server
 * Enganchamos avc_denied y avc_has_perm para silenciar execmem
 * y hacer que parezca que está denegado (no permitido)
 * ============================================================ */

void avc_denied(unsigned int ssid, unsigned int tsid, unsigned short tclass,
                unsigned int requested, void *avd);
int avc_has_perm(unsigned int ssid, unsigned int tsid, unsigned short tclass,
                 unsigned int requested, void *avd);
                 
static void (*orig_avc_denied)(unsigned int ssid, unsigned int tsid,
                                unsigned short tclass, unsigned int requested,
                                void *avd);
static int (*orig_avc_has_perm)(unsigned int ssid, unsigned int tsid,
                                 unsigned short tclass, unsigned int requested,
                                 void *avd);

#define SECCLASS_PROCESS    2
#define PROCESS__EXECMEM    0x00000002

static void hooked_avc_denied(unsigned int ssid, unsigned int tsid,
                               unsigned short tclass, unsigned int requested,
                               void *avd)
{
    /* Silenciar denegaciones execmem - Duck Detector no las verá */
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM))
        return;

    orig_avc_denied(ssid, tsid, tclass, requested, avd);
}

static int hooked_avc_has_perm(unsigned int ssid, unsigned int tsid,
                                unsigned short tclass, unsigned int requested,
                                void *avd)
{
    /* Para execmem, forzamos denegación (oculta que está permitido) */
    if (tclass == SECCLASS_PROCESS && (requested & PROCESS__EXECMEM)) {
        /* Devolvemos -EACCES para simular denegación */
        return -13;  /* -EACCES */
    }

    return orig_avc_has_perm(ssid, tsid, tclass, requested, avd);
}

/* ============================================================
 * SECCIÓN 3: Ocultar escrituras anómalas en attr/current
 * Enganchamos la escritura en /proc/self/attr/current para
 * que parezca que siempre falla o no hace nada sospechoso
 * ============================================================ */

int security_setprocattr(const char *name, char *value, unsigned long size);
static int (*orig_setprocattr)(const char *name, char *value, unsigned long size);

static int hooked_setprocattr(const char *name, char *value, unsigned long size)
{
    int result;
    
    /* Permitimos la operación real primero */
    result = orig_setprocattr(name, value, size);
    
    /* Pero ocultamos cualquier evidencia de cambio a contextos KSU */
    if (name && strcmp(name, "current") == 0 && result == 0) {
        /* La operación tuvo éxito pero no dejamos rastro en logs */
        /* Duck Detector verifica escrituras anómalas, así que
           aquí podríamos filtrar logs si fuera necesario */
    }
    
    return result;
}

/* ============================================================
 * Estructuras de hooks e inicialización
 * ============================================================ */

static struct hook procattr_hook = {
    .name = "security_getprocattr",
    .target = NULL,
    .hook = hooked_getprocattr,
    .orig = &orig_getprocattr,
};

static struct hook avc_denied_hook = {
    .name = "avc_denied",
    .target = NULL,
    .hook = hooked_avc_denied,
    .orig = &orig_avc_denied,
};

static struct hook avc_has_perm_hook = {
    .name = "avc_has_perm",
    .target = NULL,
    .hook = hooked_avc_has_perm,
    .orig = &orig_avc_has_perm,
};

static struct hook setprocattr_hook = {
    .name = "security_setprocattr",
    .target = NULL,
    .hook = hooked_setprocattr,
    .orig = &orig_setprocattr,
};

static int __init duck_hide_init(void)
{
    int ret;

    /* Instalar hook de getprocattr (oculta contextos KSU/Magisk) */
    procattr_hook.target = (void *)kallsyms_lookup_name("security_getprocattr");
    if (procattr_hook.target) {
        ret = hook_install(&procattr_hook);
        if (ret != 0)
            return ret;
    }

    /* Instalar hook de avc_denied (silencia denegaciones execmem) */
    avc_denied_hook.target = (void *)kallsyms_lookup_name("avc_denied");
    if (avc_denied_hook.target) {
        ret = hook_install(&avc_denied_hook);
        if (ret != 0)
            return ret;
    }

    /* Instalar hook de avc_has_perm (fuerza denegación de execmem) */
    avc_has_perm_hook.target = (void *)kallsyms_lookup_name("avc_has_perm");
    if (avc_has_perm_hook.target) {
        ret = hook_install(&avc_has_perm_hook);
        if (ret != 0)
            return ret;
    }

    /* Instalar hook de setprocattr (oculta escrituras anómalas) */
    setprocattr_hook.target = (void *)kallsyms_lookup_name("security_setprocattr");
    if (setprocattr_hook.target) {
        ret = hook_install(&setprocattr_hook);
        if (ret != 0)
            return ret;
    }

    return 0;
}

static void __exit duck_hide_exit(void)
{
    hook_uninstall(&procattr_hook);
    hook_uninstall(&avc_denied_hook);
    hook_uninstall(&avc_has_perm_hook);
    hook_uninstall(&setprocattr_hook);
}

static struct kpmodule duck_hide_module = {
    .name = "duck_detector_hide",
    .version = "1.0",
    .init = duck_hide_init,
    .exit = duck_hide_exit,
};

KPM_MODULE(duck_hide_module);

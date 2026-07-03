// SPDX-License-Identifier: GPL-3.0-only
/*
 * KPM: selinux-execmem-hide
 * Hooks security_compute_av and clears execmem permissions for app processes
 * to hide dirty SELinux execmem rules from root detection.
 * 
 * Compatible with: APatch / KernelSU / Magisk with KPM support
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/printk.h>

// ============================================================
// KPM API Definitions
// ============================================================
#define KPM_NAME(name)          static const char __kpm_name[] __used = name
#define KPM_VERSION(ver)        static const char __kpm_version[] __used = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             module_init(f)
#define KPM_EXIT(f)             module_exit(f)

typedef enum {
    HOOK_NO_ERR = 0,
} hook_err_t;

typedef struct {
    unsigned long arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs4_t;

// Funciones proporcionadas por el framework KPM
extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);
// ============================================================

#define LOG_TAG "[execmem-hide] "
#define log_i(fmt, ...) pr_info(LOG_TAG fmt, ##__VA_ARGS__)
#define log_e(fmt, ...) pr_err(LOG_TAG "[E] " fmt, ##__VA_ARGS__)

// Estructura de decisión AVC de SELinux
struct av_decision {
    u32 allowed;      // Permisos permitidos
    u32 auditallow;   // Permisos a auditar (allow)
    u32 auditdeny;    // Permisos a auditar (deny)
    u32 seqno;        // Número de secuencia
    u32 flags;        // Flags de decisión
};

// Variables globales
static int (*fn_sec_ctx_to_sid)(const char *ctx, u32 ctxlen, u32 *sid, gfp_t gfp);
static void *target_fn = NULL;  // security_compute_av
static u32 system_server_sid = 0;

/**
 * after_security_compute_av - Hook que se ejecuta después de security_compute_av
 * 
 * Esta función intercepta las decisiones de SELinux y oculta los permisos
 * execmem para aplicaciones de usuario cuando system_server está involucrado.
 */
static void after_security_compute_av(hook_fargs4_t *args, void *udata)
{
    u32 ssid, tsid;
    struct av_decision *avd;
    uid_t uid;
    
    // Validaciones básicas
    if (!args || !udata)
        return;
    
    if (!system_server_sid)
        return;

    // Extraer SIDs de los argumentos
    ssid = (u32)args->arg0;  // Source SID
    tsid = (u32)args->arg1;  // Target SID

    // Solo nos interesa cuando system_server está involucrado
    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    // Solo para apps de usuario (UID >= 10000)
    uid = __kuid_val(current_uid());
    if (uid < 10000)
        return;

    // Modificar la decisión de SELinux
    avd = (struct av_decision *)(unsigned long)args->arg3;
    if (avd) {
        // Ocultar todos los permisos permitidos
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

/**
 * kpm_init - Punto de entrada del KPM
 */
static int __init kpm_init(void)
{
    int ret;

    log_i("Initializing KPM: SELinux execmem hide\n");

    // 1. Buscar función security_context_to_sid en el kernel
    fn_sec_ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_sec_ctx_to_sid) {
        log_e("Cannot find security_context_to_sid in kernel symbols\n");
        return -ENOENT;
    }
    log_i("Found security_context_to_sid at %px\n", fn_sec_ctx_to_sid);

    // 2. Buscar función security_compute_av en el kernel
    target_fn = (void *)kallsyms_lookup_name("security_compute_av");
    if (!target_fn) {
        log_e("Cannot find security_compute_av in kernel symbols\n");
        return -ENOENT;
    }
    log_i("Found security_compute_av at %px\n", target_fn);

    // 3. Resolver el SID de system_server
    ret = fn_sec_ctx_to_sid("u:r:system_server:s0", 22,
                            &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        log_e("Failed to resolve system_server SID (ret=%d)\n", ret);
        return -EINVAL;
    }
    log_i("system_server SID = %u\n", system_server_sid);

    // 4. Instalar el hook
    ret = (int)hook_wrap(target_fn, 4, NULL,  // before = NULL
                         (void *)after_security_compute_av,  // after hook
                         NULL);  // udata
    if (ret) {
        log_e("Failed to install hook (ret=%d)\n", ret);
        system_server_sid = 0;
        return -EINVAL;
    }

    log_i("KPM loaded successfully!\n");
    log_i("  - Target: security_compute_av\n");
    log_i("  - system_server SID: %u\n", system_server_sid);
    log_i("  - Effect: Hides execmem rules from apps\n");
    
    return 0;
}

/**
 * kpm_exit - Punto de salida del KPM
 */
static void __exit kpm_exit(void)
{
    if (target_fn) {
        unhook_func(target_fn);
        log_i("Hook removed from security_compute_av\n");
    }
    
    system_server_sid = 0;
    log_i("KPM unloaded\n");
}

// Registro del módulo
module_init(kpm_init);
module_exit(kpm_exit);

// Metadata del KPM
KPM_NAME("selinux_execmem_hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules from app detection by hooking security_compute_av");

MODULE_INFO(kpm_module, "1");
MODULE_INFO(compatibility, "apatch-kernel-5.10+");

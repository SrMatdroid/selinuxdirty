// SPDX-License-Identifier: GPL-3.0-only
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/version.h>

// --- KPM API definitions ---
// Estas son definiciones mínimas para compilación
typedef enum {
    HOOK_NO_ERR = 0,
} hook_err_t;

typedef struct {
    unsigned long arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs4_t;

// Estas funciones deben ser proporcionadas por el kernel con soporte KPM
extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);

#define KPM_NAME(name)          static const char __modname[] __used = name
#define KPM_VERSION(ver)        static const char __modver[] __used = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

// --------------------------------------------------------------

#define log_i(fmt, ...) printk(KERN_INFO "[execmem-hide] " fmt, ##__VA_ARGS__)
#define log_e(fmt, ...) printk(KERN_ERR  "[execmem-hide][E] " fmt, ##__VA_ARGS__)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
// Estructura moderna de av_decision
struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};
#else
// Estructura legacy
struct av_decision {
    u32 allowed;
    u32 decided;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};
#endif

// Forward declarations
static int (*fn_sec_ctx_to_sid)(const char *ctx, u32 ctxlen, u32 *sid, gfp_t gfp);
static void *security_compute_av_ptr = NULL;
static u32 system_server_sid = 0;

static void after_security_compute_av(hook_fargs4_t *args, void *udata)
{
    u32 ssid, tsid;
    struct av_decision *avd;
    uid_t uid;
    
    if (!args || !udata)
        return;
    
    if (!system_server_sid)
        return;

    ssid = (u32)args->arg0;
    tsid = (u32)args->arg1;
    
    if (ssid != system_server_sid || tsid != system_server_sid)
        return;

    uid = current_uid().val;
    if (uid < 10000)
        return;

    avd = (struct av_decision *)(unsigned long)args->arg3;
    if (avd) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static int __init kpm_init(void)
{
    int ret;
    
    log_i("Initializing execmem hide module\n");
    
    // Buscar símbolos del kernel
    fn_sec_ctx_to_sid = (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_sec_ctx_to_sid) {
        log_e("security_context_to_sid not found\n");
        return -ENOENT;
    }

    security_compute_av_ptr = (void *)kallsyms_lookup_name("security_compute_av");
    if (!security_compute_av_ptr) {
        log_e("security_compute_av not found\n");
        return -ENOENT;
    }

    // Resolver SID de system_server
    ret = fn_sec_ctx_to_sid("u:r:system_server:s0", 22, 
                            &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        log_e("SID resolution failed: %d\n", ret);
        return -EINVAL;
    }

    log_i("system_server SID = %u\n", system_server_sid);

    // Instalar hook
    ret = (int)hook_wrap(security_compute_av_ptr, 4, NULL, 
                         (void *)after_security_compute_av, NULL);
    if (ret) {
        log_e("hook_wrap failed: %d\n", ret);
        return -EINVAL;
    }

    log_i("Module loaded successfully\n");
    return 0;
}

static void __exit kpm_exit(void)
{
    if (security_compute_av_ptr) {
        unhook_func(security_compute_av_ptr);
    }
    log_i("Module unloaded\n");
}

module_init(kpm_init);
module_exit(kpm_exit);

KPM_NAME("selinux_execmem_hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Hides dirty execmem SELinux rules from app detection");

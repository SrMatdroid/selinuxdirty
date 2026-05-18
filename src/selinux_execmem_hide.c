#include <kpmodule.h>
#include <hook.h>
#include "compat.h"

#define EINVAL  22
#define ENOENT  2
#define GFP_KERNEL 0xCC0UL // Bandera genérica si tu compat.h no la hereda

// KernelPatch maneja u32/u16 mediante sus tipos base embebidos, o usando los del propio compilador
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned int gfp_t;

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

static void (*orig_security_compute_av)(u32 ssid, u32 tsid, u16 tclass,
                                        struct av_decision *avd) = NULL;

static int (*fn_security_context_to_sid)(const char *scontext, u32 scontext_len,
                                         u32 *out_sid, gfp_t gfp) = NULL;

static u32 system_server_sid = 0;
size_t strlen(const char *s);

static void hook_security_compute_av(u32 ssid, u32 tsid, u16 tclass,
                                     struct av_decision *avd)
{
    orig_security_compute_av(ssid, tsid, tclass, avd);

    if (!system_server_sid)
        return;

    if (ssid == system_server_sid && tsid == system_server_sid) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long execmem_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    unsigned long addr_context = kallsyms_lookup_name("security_context_to_sid");
    fn_security_context_to_sid = (void *)addr_context;
    
    if (!fn_security_context_to_sid) {
        pr_err("[execmem-hide] No se encontró security_context_to_sid\n");
        return -ENOENT;
    }

    const char *sys_ctx = "u:r:system_server:s0";
    int ret = fn_security_context_to_sid(sys_ctx, strlen(sys_ctx),
                                         &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        pr_err("[execmem-hide] Fallo al resolver SID: %d\n", ret);
        return -EINVAL;
    }

    unsigned long addr_compute = kallsyms_lookup_name("security_compute_av");
    void *sym = (void *)addr_compute;
    
    if (!sym) {
        pr_err("[execmem-hide] No se encontró security_compute_av\n");
        return -ENOENT;
    }

    ret = hook_func(sym, (void *)hook_security_compute_av,
                    (void **)&orig_security_compute_av);
    if (ret) {
        pr_err("[execmem-hide] hook_func falló: %d\n", ret);
        return ret;
    }

    pr_info("[execmem-hide] Hook instalado, SID=%u\n", system_server_sid);
    return 0;
}

static long execmem_hide_exit(void *__user reserved)
{
    if (orig_security_compute_av) {
        unhook_func((void *)hook_security_compute_av);
        pr_info("[execmem-hide] Hook eliminado\n");
    }
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

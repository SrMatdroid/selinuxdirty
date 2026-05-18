// selinux_execmem_hide.c
// KPM: Oculta dirty sepolicy rules (system_server execmem) a apps detectoras
// License: GPL-3.0
// Author: SrMatdroid

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide dirty execmem sepolicy rule from untrusted app detectors");
KPM_AUTHOR("SrMatdroid");

// Definir av_decision manualmente - struct interno del kernel
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

static void hook_security_compute_av(u32 ssid, u32 tsid, u16 tclass,
                                      struct av_decision *avd)
{
    orig_security_compute_av(ssid, tsid, tclass, avd);

    // SID no resuelto en init, no hacer nada
    if (!system_server_sid)
        return;

    // Solo apps no privilegiadas (uid >= 10000)
    uid_t uid = current_uid().val;
    if (uid < 10000)
        return;

    // Si una app untrusted consulta AV para system_server -> system_server
    // ocultar todos los permisos (incluido execmem)
    if (ssid == system_server_sid && tsid == system_server_sid) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long execmem_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    int ret = 0;

    fn_security_context_to_sid =
        (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        pr_err("[execmem-hide] No se encontró security_context_to_sid\n");
        return -ENOENT;
    }

    const char *sys_ctx = "u:r:system_server:s0";
    ret = fn_security_context_to_sid(sys_ctx, strlen(sys_ctx),
                                      &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        pr_err("[execmem-hide] Fallo al resolver SID system_server: %d\n", ret);
        return -EINVAL;
    }

    pr_info("[execmem-hide] system_server SID resuelto = %u\n", system_server_sid);

    void *sym = (void *)kallsyms_lookup_name("security_compute_av");
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

    pr_info("[execmem-hide] Hook instalado @ %px\n", sym);
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

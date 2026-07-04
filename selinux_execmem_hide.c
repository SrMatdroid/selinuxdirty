// selinux_execmem_hide.c
// KPM: Oculta dirty sepolicy rules (system_server execmem) a apps detectoras
// License: GPL-3.0
// Author: SrMatdroid
//
// Target: KernelPatch / KPatch-Next, GKI 5.10, ARM64
//
// IMPORTANTE (leer antes de tocar la lógica):
// - security_compute_av() en el kernel real tiene 5 argumentos, NO 4.
//   La firma es: void security_compute_av(u32 ssid, u32 tsid, u16 tclass,
//                                          struct av_decision *avd,
//                                          struct extended_perms *xperms);
//   Si hookeas con 4 args te falta el registro de xperms y arriesgas panic
//   cuando el kernel intente usar ese puntero. Por eso aquí se usa hook_wrap5.
// - No se llama manualmente a la función original: hook_wrap ya la ejecuta
//   automáticamente entre el callback "before" y el "after". Solo usamos
//   "after" porque necesitamos leer avd DESPUÉS de que el kernel lo rellene.
// - current_uid() aquí se asume que devuelve un entero plano (uid_t), no
//   kuid_t. Verifícalo contra tu copia de kputils.h; si devuelve kuid_t,
//   cambia la línea correspondiente para usar .val.

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/printk.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide dirty execmem sepolicy rule from untrusted app detectors");
KPM_AUTHOR("SrMatdroid");

// gfp_t/GFP_KERNEL definidos localmente para no depender de <linux/gfp.h>,
// que no está garantizado en el set de headers stub de KPM.
// GFP_KERNEL = __GFP_RECLAIM (0xc00) | __GFP_IO (0x40) | __GFP_FS (0x80) = 0xcc0
// Este layout de bits es estable desde kernel 4.13+, válido para GKI 5.10.
typedef unsigned int gfp_t;
#define GFP_KERNEL ((gfp_t)0xcc0)

// Códigos de error como literales para no depender de <uapi/asm-generic/errno.h>
#define KPM_ENOENT 2
#define KPM_EINVAL 22

// av_decision - struct interna del kernel, layout estable (services.c / avc_ss.h)
struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

// extended_perms - solo necesitamos el tipo para el puntero, no tocamos su contenido
struct extended_perms;

static int (*fn_security_context_to_sid)(const char *scontext, u32 scontext_len,
                                          u32 *out_sid, gfp_t gfp) = NULL;

static void *g_security_compute_av_addr = NULL;
static u32 system_server_sid = 0;

// Callback "after": se ejecuta cuando security_compute_av YA rellenó avd.
// argno = 5 -> hook_fargs5_t, arg0..arg4 mapean 1:1 con los parámetros reales.
static void after_security_compute_av(hook_fargs5_t *args, void *udata)
{
    if (!system_server_sid)
        return;

    // Solo apps no privilegiadas (uid >= 10000). Ajusta si tu caso de uso
    // necesita filtrar también uids de sistema.
    uid_t uid = (uid_t)current_uid();
    if (uid < 10000)
        return;

    u32 ssid = (u32)args->arg0;
    u32 tsid = (u32)args->arg1;
    struct av_decision *avd = (struct av_decision *)args->arg3;

    if (!avd)
        return;

    // Si una app untrusted consulta AV para system_server -> system_server,
    // ocultar todos los permisos (incluido execmem).
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
        pr_err("[execmem-hide] No se encontro security_context_to_sid\n");
        return -KPM_ENOENT;
    }

    const char *sys_ctx = "u:r:system_server:s0";
    ret = fn_security_context_to_sid(sys_ctx, strlen(sys_ctx),
                                      &system_server_sid, GFP_KERNEL);
    if (ret || !system_server_sid) {
        pr_err("[execmem-hide] Fallo al resolver SID system_server: %d\n", ret);
        return -KPM_EINVAL;
    }

    pr_info("[execmem-hide] system_server SID resuelto = %u\n", system_server_sid);

    g_security_compute_av_addr = (void *)kallsyms_lookup_name("security_compute_av");
    if (!g_security_compute_av_addr) {
        pr_err("[execmem-hide] No se encontro security_compute_av\n");
        return -KPM_ENOENT;
    }

    // 5 argumentos reales: ssid, tsid, tclass, avd, xperms.
    hook_err_t err = hook_wrap5(g_security_compute_av_addr,
                                 NULL, after_security_compute_av, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[execmem-hide] hook_wrap5 fallo: %d\n", err);
        return -KPM_EINVAL;
    }

    pr_info("[execmem-hide] Hook instalado @ %px\n", g_security_compute_av_addr);
    return 0;
}

static long execmem_hide_exit(void *__user reserved)
{
    if (g_security_compute_av_addr) {
        hook_unwrap(g_security_compute_av_addr, NULL, after_security_compute_av);
        pr_info("[execmem-hide] Hook eliminado\n");
    }
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

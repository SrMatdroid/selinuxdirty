// selinux_context_hide.c
// KPM: Oculta context strings de KernelSU/Magisk al sondear /proc/self/attr/current
// License: GPL-3.0
// Author: SrMatdroid
//
// Target: KernelPatch / KPatch-Next, GKI 5.10, ARM64
//
// QUÉ TAPA ESTO Y QUÉ NO:
// - Tapa: apps untrusted escribiendo strings de contexto ("u:r:magisk:s0",
//   "u:r:su:s0", variantes con "kernelsu", etc.) a /proc/self/attr/current
//   y usando el errno de vuelta (EINVAL vs EACCES/EPERM) como oráculo para
//   saber si esos dominios existen en la política.
// - NO tapa: lecturas directas de /sys/fs/selinux/policy que parsean el
//   avtab binario buscando la regla "system_server execmem". Eso es otro
//   vector y no lo toca este hook (ver nota en el chat).
//
// FIRMA REAL (GKI 5.10, ANTES del refactor lsmid de kernel 6.5+):
//   int security_setprocattr(const char *lsm, const char *name,
//                             void *value, size_t size);
// 4 argumentos -> hook_wrap4.

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/printk.h>

KPM_NAME("selinux-context-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide KSU/Magisk SELinux context probing on /proc/self/attr/current");
KPM_AUTHOR("SrMatdroid");

#define KPM_EINVAL 22

// Tamaño máximo razonable para un context string SELinux. Si el probe manda
// algo más largo, no es un context string real, lo dejamos pasar tal cual.
#define MAX_CTX_LEN 128

static void *g_setprocattr_addr = NULL;

// Palabras clave que delatan un probe de detección. Ajusta esta lista si
// tu build de KPatch-Next/KernelSU-Next usa un nombre de dominio distinto
// a los genéricos "su"/"magisk"/"kernelsu".
static const char *suspect_keywords[] = {
    "magisk",
    "kernelsu",
    "ksu",
    "u:r:su:s0",
};
#define N_KEYWORDS (sizeof(suspect_keywords) / sizeof(suspect_keywords[0]))

static int contains_suspect_keyword(const char *buf)
{
    for (size_t i = 0; i < N_KEYWORDS; i++) {
        if (strstr(buf, suspect_keywords[i]))
            return 1;
    }
    return 0;
}

// Callback "before": decidimos ANTES de que corra la función real si
// queremos bloquear el intento devolviendo -EINVAL directamente.
static void before_security_setprocattr(hook_fargs4_t *args, void *udata)
{
    // arg1 = name ("current", "prev", "exec", etc.)
    const char *name = (const char *)args->arg1;
    if (!name || strcmp(name, "current") != 0)
        return;

    // Solo apps no privilegiadas.
    uid_t uid = (uid_t)current_uid();
    if (uid < 10000)
        return;

    const char *value = (const char *)args->arg2;
    size_t size = (size_t)args->arg3;
    if (!value || size == 0 || size >= MAX_CTX_LEN)
        return;

    // Copiamos a buffer local con null-terminator seguro. El buffer que
    // llega aquí ya fue copiado desde userspace por proc_pid_attr_write
    // antes de llamar a security_setprocattr, así que es memoria de
    // kernel accesible directamente (no hace falta copy_from_user aquí).
    char local[MAX_CTX_LEN];
    memcpy(local, value, size);
    local[size] = '\0';

    if (contains_suspect_keyword(local)) {
        args->ret = -KPM_EINVAL;
        args->skip_origin = 1;
    }
}

static long context_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    g_setprocattr_addr = (void *)kallsyms_lookup_name("security_setprocattr");
    if (!g_setprocattr_addr) {
        pr_err("[context-hide] No se encontro security_setprocattr\n");
        return -KPM_EINVAL;
    }

    hook_err_t err = hook_wrap4(g_setprocattr_addr,
                                 before_security_setprocattr, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("[context-hide] hook_wrap4 fallo: %d\n", err);
        return -KPM_EINVAL;
    }

    pr_info("[context-hide] Hook instalado @ %px\n", g_setprocattr_addr);
    return 0;
}

static long context_hide_exit(void *__user reserved)
{
    if (g_setprocattr_addr) {
        hook_unwrap(g_setprocattr_addr, before_security_setprocattr, NULL);
        pr_info("[context-hide] Hook eliminado\n");
    }
    return 0;
}

KPM_INIT(context_hide_init);
KPM_EXIT(context_hide_exit);

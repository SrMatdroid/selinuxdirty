#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>

KPM_NAME("selinux-execmem-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide dirty execmem sepolicy rule from untrusted app detectors");
KPM_AUTHOR("SrMatdroid");

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
    unsigned int uid;

    orig_security_compute_av(ssid, tsid, tclass, avd);

    if (!system_server_sid)
        return;

    uid = current_uid().val;
    if (uid < 10000)
        return;

    if (ssid == system_server_sid && tsid == system_server_sid) {
        avd->allowed = 0;
        avd->auditallow = 0;
    }
}

static long execmem_hide_init(const char *args, const char *event,
                                void *__user reserved)
{
    int ret;
    void *sym;

    fn_security_context_to_sid =
        (void *)kallsyms_lookup_name("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        pr_err("[execmem-hide] security_context_to_sid not found\n");
        return -ENOENT;
    }

    {
        const char *sys_ctx = "u:r:system_server:s0";
        ret = fn_security_context_to_sid(sys_ctx, strlen(sys_ctx),
                                          &system_server_sid, GFP_KERNEL);
        if (ret || !system_server_sid) {
            pr_err("[execmem-hide] SID resolution failed: %d\n", ret);
            return -EINVAL;
        }
    }

    pr_info("[execmem-hide] system_server SID = %u\n", system_server_sid);

    sym = (void *)kallsyms_lookup_name("security_compute_av");
    if (!sym) {
        pr_err("[execmem-hide] security_compute_av not found\n");
        return -ENOENT;
    }

    ret = hook(sym, (void *)hook_security_compute_av,
               (void **)&orig_security_compute_av);
    if (ret) {
        pr_err("[execmem-hide] hook failed: %d\n", ret);
        return ret;
    }

    pr_info("[execmem-hide] Hook installed\n");
    return 0;
}

static long execmem_hide_exit(void *__user reserved)
{
    if (orig_security_compute_av) {
        unhook((void *)hook_security_compute_av);
        pr_info("[execmem-hide] Hook removed\n");
    }
    return 0;
}

KPM_INIT(execmem_hide_init);
KPM_EXIT(execmem_hide_exit);

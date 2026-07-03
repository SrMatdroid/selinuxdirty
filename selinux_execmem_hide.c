#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/errno.h>

#define __GFP_DIRECT_RECLAIM 0x400u
#define __GFP_KSWAPD_RECLAIM 0x800u
#define __GFP_IO 0x40u
#define __GFP_FS 0x80u
#define __GFP_RECLAIM ((gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))
#define GFP_KERNEL ((gfp_t)(__GFP_RECLAIM | __GFP_IO | __GFP_FS))

typedef u32 uid_t;

struct task_struct_offset {
    int16_t pid_offset;
    int16_t tgid_offset;
    int16_t thread_pid_offset;
    int16_t ptracer_cred_offset;
    int16_t real_cred_offset;
    int16_t cred_offset;
    int16_t comm_offset;
    int16_t fs_offset;
    int16_t files_offset;
    int16_t loginuid_offset;
    int16_t sessionid_offset;
    int16_t seccomp_offset;
    int16_t security_offset;
    int16_t stack_offset;
    int16_t tasks_offset;
    int16_t mm_offset;
    int16_t active_mm_offset;
};

extern struct task_struct_offset task_struct_offset;

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

struct find_sym_data {
    const char *name;
    void *addr;
};

static int sym_name_cmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int find_sym_cb(void *data, const char *name, void *mod, unsigned long addr)
{
    struct find_sym_data *d = data;
    if (!sym_name_cmp(name, d->name)) {
        d->addr = (void *)addr;
        return 1;
    }
    return 0;
}

static void *find_sym(const char *name)
{
    unsigned long addr;

    addr = kallsyms_lookup_name(name);
    if (addr)
        return (void *)addr;

    if (kallsyms_on_each_symbol) {
        struct find_sym_data data = { .name = name, .addr = NULL };
        kallsyms_on_each_symbol(find_sym_cb, &data);
        return data.addr;
    }

    return NULL;
}

static void (*orig_security_compute_av)(u32 ssid, u32 tsid, u16 tclass,
                                         struct av_decision *avd) = NULL;

static int (*fn_security_context_to_sid)(const char *scontext, u32 scontext_len,
                                          u32 *out_sid, gfp_t gfp) = NULL;

static u32 system_server_sid = 0;

static uid_t get_current_uid(void)
{
    void *task;
    void *cred;

    __asm__ volatile("mrs %0, sp_el0" : "=r" (task));
    cred = *(void **)((char *)task + task_struct_offset.cred_offset);
    return *(uid_t *)((char *)cred + cred_offset.uid_offset);
}

static void hook_security_compute_av(u32 ssid, u32 tsid, u16 tclass,
                                       struct av_decision *avd)
{
    uid_t uid;

    orig_security_compute_av(ssid, tsid, tclass, avd);

    if (!system_server_sid)
        return;

    uid = get_current_uid();
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

    fn_security_context_to_sid = (void *)find_sym("security_context_to_sid");
    if (!fn_security_context_to_sid) {
        pr_err("[execmem-hide] security_context_to_sid not found\n");
        return -ENOENT;
    }

    {
        const char *sys_ctx = "u:r:system_server:s0";
        ret = fn_security_context_to_sid(sys_ctx, sizeof("u:r:system_server:s0") - 1,
                                          &system_server_sid, GFP_KERNEL);
        if (ret || !system_server_sid) {
            pr_err("[execmem-hide] SID resolution failed: %d\n", ret);
            return -EINVAL;
        }
    }

    pr_info("[execmem-hide] system_server SID = %u\n", system_server_sid);

    sym = find_sym("security_compute_av");
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

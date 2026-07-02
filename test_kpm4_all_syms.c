#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/errno.h>

KPM_NAME("test4-allsyms");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Test all 6 symbols - immediate return 0");
KPM_AUTHOR("test");

/* Force reference to all 6 symbols */
struct task_struct_offset;
extern struct task_struct_offset task_struct_offset;
extern struct cred_offset cred_offset;

static void *dummy_sym(void)
{
    (void)task_struct_offset.cred_offset;
    (void)cred_offset.uid_offset;
    (void)kallsyms_lookup_name;
    (void)printk;
    (void)hook;
    (void)unhook;
    return 0;
}

static long test_init(const char *args, const char *event, void *__user reserved)
{
    (void)dummy_sym();
    return 0;
}

static long test_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(test_init);
KPM_EXIT(test_exit);

#include <kpmodule.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <linux/errno.h>

KPM_NAME("test3-kallsyms");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Test kallsyms_lookup_name export");
KPM_AUTHOR("test");

static long test_init(const char *args, const char *event, void *__user reserved)
{
    unsigned long addr = kallsyms_lookup_name("printk");
    if (!addr)
        return -ENOENT;
    return 0;
}

static long test_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(test_init);
KPM_EXIT(test_exit);

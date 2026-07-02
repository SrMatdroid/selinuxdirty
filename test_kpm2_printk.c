#include <kpmodule.h>
#include <ktypes.h>
#include <linux/printk.h>
#include <linux/errno.h>

KPM_NAME("test2-printk");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Test printk export only");
KPM_AUTHOR("test");

static long test_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("test2-printk loaded\n");
    return 0;
}

static long test_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(test_init);
KPM_EXIT(test_exit);

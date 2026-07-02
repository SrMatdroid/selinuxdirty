#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <linux/cred.h>
#include <linux/errno.h>

KPM_NAME("test5-taskcred");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Test task_struct_offset + cred_offset exports");
KPM_AUTHOR("test");

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

static long test_init(const char *args, const char *event, void *__user reserved)
{
    uid_t uid;
    void *task;
    void *cred;

    __asm__ volatile("mrs %0, sp_el0" : "=r" (task));
    cred = *(void **)((char *)task + task_struct_offset.cred_offset);
    uid = *(uid_t *)((char *)cred + cred_offset.uid_offset);
    (void)uid;
    return 0;
}

static long test_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(test_init);
KPM_EXIT(test_exit);

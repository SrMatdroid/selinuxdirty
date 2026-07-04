// hook.h - KPatch hook API declarations for kernel modules
// Memory layout must match KPatch's internal structures exactly.

#ifndef _KPM_HOOK_H
#define _KPM_HOOK_H

#include <linux/types.h>

typedef enum {
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
    HOOK_BAD_RELO = 4092,
    HOOK_TRANSIT_NO_MEM = 4091,
    HOOK_CHAIN_FULL = 4090,
} hook_err_t;

// Memory layout MUST match KPatch's hook_fargs0_t:
//   void *chain;       offset 0
//   int skip_origin;   offset 8
//   [local 64 bytes];  offset 16
//   uint64_t ret;      offset 80
//   uint64_t args[N];  offset 88+

typedef struct {
    void *chain;
    int skip_origin;
    unsigned char local[64];
    uint64_t ret;
    uint64_t arg0, arg1, arg2, arg3;
} hook_fargs4_t;

typedef struct {
    void *chain;
    int skip_origin;
    unsigned char local[64];
    uint64_t ret;
    uint64_t arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7;
} hook_fargs8_t;

typedef hook_fargs4_t hook_fargs3_t;
typedef hook_fargs8_t hook_fargs5_t;

extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);

#endif

#pragma once

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  size_t;
typedef unsigned int   gfp_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define ENOENT      2
#define EINVAL      22
#define EPERM       1
#define GFP_KERNEL  0x400000u

#define KERN_ERR   "\0013"
#define KERN_INFO  "\0016"

extern int    strcmp(const char *cs, const char *ct);
extern int    strncmp(const char *cs, const char *ct, size_t count);
extern size_t strlen(const char *s);
extern int    printk(const char *fmt, ...);
extern unsigned long kallsyms_lookup_name(const char *name);

#define pr_info(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)  printk(KERN_ERR  fmt, ##__VA_ARGS__)
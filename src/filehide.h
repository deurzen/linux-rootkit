#ifndef _GROUP7_FILEHIDE_H
#define _GROUP7_FILEHIDE_H

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>


struct g7_linux_dirent {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    char           d_name[];
};

long g7_getdents(unsigned int, struct linux_dirent __user *, unsigned int);
long g7_getdents64(unsigned int, struct linux_dirent64 __user *, unsigned int);

void hide_files(void);
void unhide_files(void);

#endif//_GROUP7_FILEHIDE_H

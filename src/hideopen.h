#ifndef _GROUP7_HIDEOPEN_H
#define _GROUP7_HIDEOPEN_H

#include <linux/types.h>

typedef struct fd_list *fd_list_t_ptr;
typedef struct fd_list {
    int fd;
    fd_list_t_ptr prev;
    fd_list_t_ptr next;
} fd_list_t;

extern fd_list_t hidden_fds;

void clear_hidden_fds(void);
bool list_contains_fd(fd_list_t_ptr, int);
fd_list_t_ptr find_fd_in_list(fd_list_t_ptr, int);
fd_list_t_ptr add_fd_to_list(fd_list_t_ptr, int);
fd_list_t_ptr remove_fd_from_list(fd_list_t_ptr list, int fd);

#endif//_GROUP7_HIDEOPEN_H
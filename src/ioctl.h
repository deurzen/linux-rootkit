#ifndef _GROUP7_IOCTL_H
#define _GROUP7_IOCTL_H

#include <linux/ioctl.h>

#define G7_MAGIC_NUMBER '@'
#define G7_DEVICE "g7rkp"

#define G7_PING _IOWR(G7_MAGIC_NUMBER, 0x0, char *)

#define G7_FILEHIDE _IOR(G7_MAGIC_NUMBER, 0x1, char *)

typedef struct {
    const char *name;
    int (*handler)(unsigned long);
} channel_t;

void report_channels(void);
channel_t detect_channel(unsigned int);

// handlers
int handle_ping(unsigned long);
int handle_filehide(unsigned long);


#endif//_GROUP7_IOCTL_H

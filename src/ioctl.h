#ifndef _GROUP7_IOCTL_H
#define _GROUP7_IOCTL_H

#include <linux/ioctl.h>

#define G7_MAGIC_NUMBER '@'
#define G7_DEVICE "g7rkp"

#define G7_PING _IOWR(G7_MAGIC_NUMBER, 0x0, char *)


void handle_ping(unsigned long);


#endif//_GROUP7_IOCTL_H

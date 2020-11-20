#ifndef _GROUP7_CHARDEV_H
#define _GROUP7_CHARDEV_H

#include <linux/ioctl.h>

#define G7_MAGIC_NUMBER '@'
#define G7_DEVICE "G7RKP"

#define G7_PING  _IOWR(G7_MAGIC_NUMBER, 0x0, char *)

#define G7_WRITE _IOW(G7_MAGIC_NUMBER, 0x1, char *)
#define G7_READ  _IOW(G7_MAGIC_NUMBER, 0x2, char *)


void handle_ping(unsigned long);


#endif//_GROUP7_CHARDEV_H

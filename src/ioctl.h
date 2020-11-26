#ifndef _GROUP7_IOCTL_H
#define _GROUP7_IOCTL_H

#define G7_MAGIC_NUMBER '@'
#define G7_DEVICE "g7rkp"

#define G7_PING _IOWR(G7_MAGIC_NUMBER, 0x0, char *)
#define G7_FILEHIDE _IOR(G7_MAGIC_NUMBER, 0x1, char *)

#endif//_GROUP7_IOCTL_H

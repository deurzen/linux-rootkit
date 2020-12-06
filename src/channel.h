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
int handle_modhide(unsigned long);
int handle_filehide(unsigned long);
int handle_openhide(unsigned long);
int handle_pidhide(unsigned long);
int handle_backdoor(unsigned long);
int handle_togglebd(unsigned long);

#endif//_GROUP7_CHANNEL_H

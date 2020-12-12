#ifndef _GROUP7_INPUTLOG_H
#define _GROUP7_INPUTLOG_H

void send_udp(pid_t pid, struct file *, char *, int);
void log_input(const char *, const char *);
void unlog_input(void);

#endif//_GROUP7_INPUTLOG_H

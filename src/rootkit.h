#ifndef _GROUP7_ROOTKIT_H
#define _GROUP7_ROOTKIT_H

#include "hook.h"

typedef struct {
    sc_hook_t hooks[16];
    bool hiding_files;
} rootkit_t;

#endif//_GROUP7_ROOTKIT_H

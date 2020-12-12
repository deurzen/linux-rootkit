#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <net/sock.h>

#include "common.h"
#include "inputlog.h"

struct socket *sock;

void
log_input(const char *ip, const char *port)
{
    size_t i;
    u8 ip_quad[4];
    unsigned long ip_ul;
    unsigned long port_ul;

    int size;
    struct sockaddr_in addr;
    struct msghdr msg;
    struct kvec iov;

    if (sock)
        return;

    if (sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock))
        return;

    { // parse ip address and port from passed in strings
        kstrtoul(port, 10, &port_ul);
        in4_pton(ip, -1, ip_quad, -1, NULL);

        ip_ul = 0;
        for (i = 0; i < 4; ++i)
            ip_ul += (ip_quad[i] & 0xFF) << (8 * i);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip_ul);
    addr.sin_port = htons(port_ul);

    if (kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        sock_release(sock);
        sock = NULL;
        return;
    }

    char *buf = "test";
    iov.iov_base = buf;
    iov.iov_len = strlen(buf);

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);

    size = kernel_sendmsg(sock, &msg, &iov, 1, strlen(buf));
    if (size > 0)
	DEBUG_INFO("sent %d bytes\n", size);
}

void
unlog_input(void)
{
    if (!sock)
        return;

    sock_release(sock);
    sock = NULL;
}

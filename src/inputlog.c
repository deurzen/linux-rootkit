#include <linux/kernel.h>
#include <linux/inet.h>

#include "common.h"
#include "inputlog.h"

struct socket sock;

void
log_input(const char *ip, const char *port)
{
    size_t i;
    u8 ip_quad[4];
    unsigned long ip_ul;
    unsigned long port_ul;

    kstrtoul(port, 10, &port_ul);
    in4_pton(ip, -1, ip_quad, -1, NULL);

    ip_ul = 0;
    for (i = 0; i < 4; ++i)
        ip_ul += (ip_quad[i] & 0xFF) << (8 * i);

    DEBUG_INFO("ip_s = %s, port_s = %s, ip: %lu, port: %lu\n", ip, port, ip_ul, port_ul);
}

void
unlog_input(void)
{

}

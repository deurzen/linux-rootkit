#ifndef _GROUP7_COMMON_H
#define _GROUP7_COMMON_H

#ifdef DEBUG
#define DEBUG_INFO(...) do{ pr_info(__VA_ARGS__); } while(0)
#define DEBUG_NOTICE(...) do{ pr_notice(__VA_ARGS__); } while(0)
#else
#define DEBUG_INFO(...) do{} while (0)
#define DEBUG_NOTICE(...) do{} while (0)
#endif

typedef enum {
    v4,
    v6
} ip_version;

typedef u8 ip_t[16];

#endif//_GROUP7_COMMON_H

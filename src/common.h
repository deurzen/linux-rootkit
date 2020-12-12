#ifndef _GROUP7_COMMON_H
#define _GROUP7_COMMON_H

#ifdef DEBUG
#define DEBUG_INFO(...) do{ pr_info(__VA_ARGS__); } while(0)
#define DEBUG_NOTICE(...) do{ pr_notice(__VA_ARGS__); } while(0)
#else
#define DEBUG_INFO(...) do{} while (0)
#define DEBUG_NOTICE(...) do{} while (0)
#endif

#endif//_GROUP7_COMMON_H

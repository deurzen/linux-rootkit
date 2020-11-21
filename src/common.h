#ifndef _GROUP7_COMMON_H
#define _GROUP7_COMMON_H

#ifdef DEBUG
#define DEBUG_INFO(...) do{ pr_info(__VA_ARGS__); } while(false)
#define DEBUG_NOTICE(...) do{ pr_notice(__VA_ARGS__); } while(false)
#else
#define DEBUG_INFO(...) do{} while (false)
#define DEBUG_NOTICE(...) do{} while (false)
#endif

#endif//_GROUP7_COMMON_H

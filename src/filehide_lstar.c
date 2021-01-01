#include <linux/kernel.h>

#include "filehide_lstar.h"
#include "common.h"

static unsigned long read_lstar(void);

void
test_lstar(void)
{
    unsigned long lstar = read_lstar();

    DEBUG_INFO("LSTAR is %0lx\n", lstar);
}

static unsigned long 
read_lstar(void)
{
    unsigned int low, high;

    __asm__ volatile (
                    "movl $0xc0000082, %%ecx\n\t" //https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/msr-index.h#L15
                    "rdmsr\n\t"
                    "mov %%eax, %[low]\n\t"
                    "mov %%edx, %[high]"
                    : [low] "=r" (low), [high] "=r" (high) 
                    :
                    : "ecx", "eax", "edx"
                );

    //Get two 32bit values into a 64bit variable
    unsigned long ret = high;
    ret <<= 32;
    ret |= low;

    return ret;
}
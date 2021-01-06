#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>

#include "filehide_lstar.h"
#include "common.h"

#define SEARCHLEN  4096

//This signature entails the register clearing and setup before the call (opcode e8); what follows is the offset for do_syscall64.
//Should definitely be unique enough for the limited amount of bytes we search as even 
//$ hexdump -C vmlinux | grep -A 2 "31 ff 48 89 c7" only results in two matches for the whole kernel image
static char sig[20] = {0x45, 0x31, 0xe4, 0x45, 0x31, 0xed, 0x45, 0x31, 0xf6, 0x45, 0x31, 0xff, 0x48, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0xe8, 0x00};

static unsigned long read_msr(unsigned int);
static char *find_do_syscall64(char *lstar_addr);

void g7_syscall_64(unsigned long, struct pt_regs *);
void (*do_syscall64)(unsigned long, struct pt_regs *);

void
test_lstar(void)
{   
    char *lstar_addr = (char *)read_msr(MSR_LSTAR);
    
    char *syscall64_base = find_do_syscall64(lstar_addr);
}


static char *
find_do_syscall64(char *lstar_addr)
{
    //parse asm and find sig
    return NULL;
}

void
g7_syscall_64(unsigned long nr, struct pt_regs *regs)
{
    do_syscall64(nr, regs);
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

// static void
// write_msr(unsigned int low, unsigned int high, unsigned int msr)
// {
//     __asm__ volatile (
//                     "movl $0xc0000082, %%ecx\n\t"
//                     "mov %[low], %%eax\n\t"
//                     "mov %[high], %%edx\n\t"
//                     "wrmsr"
//                     :
//                     : [low] "r" (low), [high] "r" (high)
//                     : "ecx", "eax", "edx"
//     );
// }
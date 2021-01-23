import os
import re
import subprocess
from elftools.elf import elffile

v_off_g = 0
file_g = None

class RkLoadSymbols(gdb.Command):
    """Determine the KASLR-Offset and map the symbols."""

    v_off = 0
    symbol = "native_safe_halt"

    def __init__(self):
        super(RkLoadSymbols, self).__init__("rk-load-symbols", gdb.COMMAND_USER, gdb.COMMAND_DATA)


    def invoke(self, arg, from_tty):
        if not arg:
            print("Please provide an argument")
            return None

        self.get_v_off(arg)
        self.load_sym(arg)

    def load_sym(self, arg):
        v_off = hex(self.v_off)

        print(f"attempting to load symbols from \"{arg}\" with offset {v_off}")
        try:
            gdb.execute(f"add-symbol-file {arg} -o {self.v_off}")
        except:
            print("error loading symbol file, does it exist?")
            return None

    def get_v_off(self, arg):
        global file_g
        global v_off_g

        sym_addr = get_symbol_address(arg, self.symbol)

        if sym_addr is None:
            return None

        file_g = arg

        #minimal assumption: user is at login prompt
        try:
            real = gdb.execute("where", to_string=True).split(" ")[2]
        except:
            print("error executing where, is the VM running?")
            return None

        real_addr = int(real, 16)
        self.v_off = ((real_addr - sym_addr) & (~0xf))
        v_off_g = self.v_off

RkLoadSymbols()




class RkKaslrOffset(gdb.Command):
    """Output the calculated physical and virtual KASLR offset."""

    symbol = "native_safe_halt"
    obj_addr = None

    def __init__(self):
        super(RkKaslrOffset, self).__init__("rk-kaslr-offset", gdb.COMMAND_USER, gdb.COMMAND_DATA)

    # assuming rk-load-symbols has already been run
    def invoke(self, arg, from_tty):
        global file_g

        if file_g is None:
            print("no object file has been read in to calculate offsets, please run `rk-load-symbols` first")
            return None

        self.obj_addr = get_symbol_address(file_g, self.symbol)
        obj_addr = hex(self.obj_addr)

        print(f"address for symbol `{self.symbol}` inside object file \"{file_g}\" is {obj_addr}")

        print(f"looking up addresses for symbol `{self.symbol}`")

        v_addr = self.get_v_addr()

        if v_addr is None:
            print(f"could not retrieve virtual address address for symbol `{self.symbol}`")
            return None

        p_addr = self.get_p_addr(v_addr)

        if p_addr is None:
            print(f"could not retrieve physical address address for symbol `{self.symbol}`")
            return None

        print(f"found virtual address {v_addr} with associated physical address {p_addr}")

        v_addr = v_addr.strip()
        p_addr = p_addr.strip()

        v_bytes = gdb.execute(f"x/8xb {v_addr}", to_string=True).split()[-7:]
        p_bytes = gdb.execute(f"monitor xp/8xb {p_addr}", to_string=True).split()[-7:]

        print(f"8 bytes of memory read starting from virtual address {v_addr}: {v_bytes}")
        print(f"8 bytes of memory read starting from physical address {p_addr}: {p_bytes}")

        print(f"bytes read are {'equal' if v_bytes == p_bytes else 'different'}")

        print()

        print(f"calculating offsets relating to object file address {obj_addr}")

        v_off = self.get_off(v_addr)
        p_off = self.get_off(p_addr)

        print(f"virtual KASLR offset: {v_off}")
        print(f"physical KASLR offset: {p_off}")


    def get_v_addr(self):
        try:
            return gdb.execute(f"p {self.symbol}", to_string=True).split(" ")[-2]
        except:
            print("error executing `where`, is the VM running?")
            return None


    def get_p_addr(self, v_addr):
        try:
            return gdb.execute(f"monitor gva2gpa {v_addr}", to_string=True).split(" ")[-1]
        except:
            print("error interacting with monitor, is the VM running?")
            return None


    def get_off(self, addr):
        global file_g

        if self.obj_addr is None:
            return None

        real_addr = int(addr, 16)

        return hex((real_addr - self.obj_addr) & (~0xf))


RkKaslrOffset()




class RKSyscallCheck(gdb.Command):
  """Check the integrity of the syscall table. Run rk-load-symbols first."""

  symbol = "sys_call_table"
  sys_call_table = 0

  def __init__(self):
    super(RKSyscallCheck, self).__init__("rk-syscall-check", gdb.COMMAND_USER, gdb.COMMAND_DATA)


  def invoke(self, arg, from_tty):
    global v_off_g
    global file_g

    if v_off_g == 0:
      print("KASLR offset is 0 - run `rk-load-symbols` first")
      print("if KASLR is enabled, just run `add-symbol-file <file>`")
      return None

    print("this might take a while")
    print("exits silently when no tampering has been detected")

    self.load_syscall_table()
    self.check_syscall_table()

  def load_syscall_table(self):
    global file_g

    ret = get_symbol_address(file_g, self.symbol)
    if ret is None:
      return None

    self.sys_call_table = ret + v_off_g

  def check_syscall_table(self):
    global syscalls

    for i, l in enumerate(syscalls):
      if l == "sys_ni_syscall":
        continue

      cur = gdb.execute(f"x *({self.sys_call_table} + ({i} * 8))", to_string = True)
      addr = re.search(r"(0x\w+)", cur)

      if addr is None:
        print("error parsing gdb x output")
        continue

      addr = int(addr.group(1), 16)

      self.check_integrity(l, addr)

  def check_integrity(self, symbol, addr):
    global file_g
    global v_off_g

    should = get_symbol_address(file_g, symbol)

    if should is None:
      return None

    should += v_off_g

    if should != addr:
      print(f"syscall table compromised for {symbol}!")
      print(f"expected: {hex(should)}, table points to: {hex(addr)}")



RKSyscallCheck()




# return address of symbol from file through nm
def get_symbol_address(file, symbol):
    stream = os.popen(f"nm {file} | grep -w \"\\b{symbol}\\b$\" | awk \'{{print $1}}\'")
    sym = stream.read()
    stream.close()

    # symbol address _before_ randomization
    try:
        sym_addr = int(sym, 16)
        return sym_addr
    except:
        print(f"error retrieving address from '{file}', did you specify a file?")
        return None


syscalls = [
    '__x64_sys_read',
    '__x64_sys_write',
    '__x64_sys_open',
    '__x64_sys_close',
    '__x64_sys_newstat',
    '__x64_sys_newfstat',
    '__x64_sys_newlstat',
    '__x64_sys_poll',
    '__x64_sys_lseek',
    '__x64_sys_mmap',
    '__x64_sys_mprotect',
    '__x64_sys_munmap',
    '__x64_sys_brk',
    '__x64_sys_rt_sigaction',
    '__x64_sys_rt_sigprocmask',
    '__x64_sys_rt_sigreturn',
    '__x64_sys_ioctl',
    '__x64_sys_pread64',
    '__x64_sys_pwrite64',
    '__x64_sys_readv',
    '__x64_sys_writev',
    '__x64_sys_access',
    '__x64_sys_pipe',
    '__x64_sys_select',
    '__x64_sys_sched_yield',
    '__x64_sys_mremap',
    '__x64_sys_msync',
    '__x64_sys_mincore',
    '__x64_sys_madvise',
    '__x64_sys_shmget',
    '__x64_sys_shmat',
    '__x64_sys_shmctl',
    '__x64_sys_dup',
    '__x64_sys_dup2',
    '__x64_sys_pause',
    '__x64_sys_nanosleep',
    '__x64_sys_getitimer',
    '__x64_sys_alarm',
    '__x64_sys_setitimer',
    '__x64_sys_getpid',
    '__x64_sys_sendfile64',
    '__x64_sys_socket',
    '__x64_sys_connect',
    '__x64_sys_accept',
    '__x64_sys_sendto',
    '__x64_sys_recvfrom',
    '__x64_sys_sendmsg',
    '__x64_sys_recvmsg',
    '__x64_sys_shutdown',
    '__x64_sys_bind',
    '__x64_sys_listen',
    '__x64_sys_getsockname',
    '__x64_sys_getpeername',
    '__x64_sys_socketpair',
    '__x64_sys_setsockopt',
    '__x64_sys_getsockopt',
    '__x64_sys_clone',
    '__x64_sys_fork',
    '__x64_sys_vfork',
    '__x64_sys_execve',
    '__x64_sys_exit',
    '__x64_sys_wait4',
    '__x64_sys_kill',
    '__x64_sys_newuname',
    '__x64_sys_semget',
    '__x64_sys_semop',
    '__x64_sys_semctl',
    '__x64_sys_shmdt',
    '__x64_sys_msgget',
    '__x64_sys_msgsnd',
    '__x64_sys_msgrcv',
    '__x64_sys_msgctl',
    '__x64_sys_fcntl',
    '__x64_sys_flock',
    '__x64_sys_fsync',
    '__x64_sys_fdatasync',
    '__x64_sys_truncate',
    '__x64_sys_ftruncate',
    '__x64_sys_getdents',
    '__x64_sys_getcwd',
    '__x64_sys_chdir',
    '__x64_sys_fchdir',
    '__x64_sys_rename',
    '__x64_sys_mkdir',
    '__x64_sys_rmdir',
    '__x64_sys_creat',
    '__x64_sys_link',
    '__x64_sys_unlink',
    '__x64_sys_symlink',
    '__x64_sys_readlink',
    '__x64_sys_chmod',
    '__x64_sys_fchmod',
    '__x64_sys_chown',
    '__x64_sys_fchown',
    '__x64_sys_lchown',
    '__x64_sys_umask',
    '__x64_sys_gettimeofday',
    '__x64_sys_getrlimit',
    '__x64_sys_getrusage',
    '__x64_sys_sysinfo',
    '__x64_sys_times',
    '__x64_sys_ptrace',
    '__x64_sys_getuid',
    '__x64_sys_syslog',
    '__x64_sys_getgid',
    '__x64_sys_setuid',
    '__x64_sys_setgid',
    '__x64_sys_geteuid',
    '__x64_sys_getegid',
    '__x64_sys_setpgid',
    '__x64_sys_getppid',
    '__x64_sys_getpgrp',
    '__x64_sys_setsid',
    '__x64_sys_setreuid',
    '__x64_sys_setregid',
    '__x64_sys_getgroups',
    '__x64_sys_setgroups',
    '__x64_sys_setresuid',
    '__x64_sys_getresuid',
    '__x64_sys_setresgid',
    '__x64_sys_getresgid',
    '__x64_sys_getpgid',
    '__x64_sys_setfsuid',
    '__x64_sys_setfsgid',
    '__x64_sys_getsid',
    '__x64_sys_capget',
    '__x64_sys_capset',
    '__x64_sys_rt_sigpending',
    '__x64_sys_rt_sigtimedwait',
    '__x64_sys_rt_sigqueueinfo',
    '__x64_sys_rt_sigsuspend',
    '__x64_sys_sigaltstack',
    '__x64_sys_utime',
    '__x64_sys_mknod',
    'sys_ni_syscall',
    '__x64_sys_personality',
    '__x64_sys_ustat',
    '__x64_sys_statfs',
    '__x64_sys_fstatfs',
    '__x64_sys_sysfs',
    '__x64_sys_getpriority',
    '__x64_sys_setpriority',
    '__x64_sys_sched_setparam',
    '__x64_sys_sched_getparam',
    '__x64_sys_sched_setscheduler',
    '__x64_sys_sched_getscheduler',
    '__x64_sys_sched_get_priority_max',
    '__x64_sys_sched_get_priority_min',
    '__x64_sys_sched_rr_get_interval',
    '__x64_sys_mlock',
    '__x64_sys_munlock',
    '__x64_sys_mlockall',
    '__x64_sys_munlockall',
    '__x64_sys_vhangup',
    '__x64_sys_modify_ldt',
    '__x64_sys_pivot_root',
    '__x64_sys_sysctl',
    '__x64_sys_prctl',
    '__x64_sys_arch_prctl',
    '__x64_sys_adjtimex',
    '__x64_sys_setrlimit',
    '__x64_sys_chroot',
    '__x64_sys_sync',
    '__x64_sys_acct',
    '__x64_sys_settimeofday',
    '__x64_sys_mount',
    '__x64_sys_umount',
    '__x64_sys_swapon',
    '__x64_sys_swapoff',
    '__x64_sys_reboot',
    '__x64_sys_sethostname',
    '__x64_sys_setdomainname',
    '__x64_sys_iopl',
    '__x64_sys_ioperm',
    'sys_ni_syscall',
    '__x64_sys_init_module',
    '__x64_sys_delete_module',
    'sys_ni_syscall',
    'sys_ni_syscall',
    '__x64_sys_quotactl',
    'sys_ni_syscall',
    'sys_ni_syscall',
    'sys_ni_syscall',
    'sys_ni_syscall',
    'sys_ni_syscall',
    'sys_ni_syscall',
    '__x64_sys_gettid',
    '__x64_sys_readahead',
    '__x64_sys_setxattr',
    '__x64_sys_lsetxattr',
    '__x64_sys_fsetxattr',
    '__x64_sys_getxattr',
    '__x64_sys_lgetxattr',
    '__x64_sys_fgetxattr',
    '__x64_sys_listxattr',
    '__x64_sys_llistxattr',
    '__x64_sys_flistxattr',
    '__x64_sys_removexattr',
    '__x64_sys_lremovexattr',
    '__x64_sys_fremovexattr',
    '__x64_sys_tkill',
    '__x64_sys_time',
    '__x64_sys_futex',
    '__x64_sys_sched_setaffinity',
    '__x64_sys_sched_getaffinity',
    'sys_ni_syscall',
    '__x64_sys_io_setup',
    '__x64_sys_io_destroy',
    '__x64_sys_io_getevents',
    '__x64_sys_io_submit',
    '__x64_sys_io_cancel',
    'sys_ni_syscall',
    '__x64_sys_lookup_dcookie',
    '__x64_sys_epoll_create',
    'sys_ni_syscall',
    'sys_ni_syscall',
    '__x64_sys_remap_file_pages',
    '__x64_sys_getdents64',
    '__x64_sys_set_tid_address',
    '__x64_sys_restart_syscall',
    '__x64_sys_semtimedop',
    '__x64_sys_fadvise64',
    '__x64_sys_timer_create',
    '__x64_sys_timer_settime',
    '__x64_sys_timer_gettime',
    '__x64_sys_timer_getoverrun',
    '__x64_sys_timer_delete',
    '__x64_sys_clock_settime',
    '__x64_sys_clock_gettime',
    '__x64_sys_clock_getres',
    '__x64_sys_clock_nanosleep',
    '__x64_sys_exit_group',
    '__x64_sys_epoll_wait',
    '__x64_sys_epoll_ctl',
    '__x64_sys_tgkill',
    '__x64_sys_utimes',
    'sys_ni_syscall',
    '__x64_sys_mbind',
    '__x64_sys_set_mempolicy',
    '__x64_sys_get_mempolicy',
    '__x64_sys_mq_open',
    '__x64_sys_mq_unlink',
    '__x64_sys_mq_timedsend',
    '__x64_sys_mq_timedreceive',
    '__x64_sys_mq_notify',
    '__x64_sys_mq_getsetattr',
    '__x64_sys_kexec_load',
    '__x64_sys_waitid',
    '__x64_sys_add_key',
    '__x64_sys_request_key',
    '__x64_sys_keyctl',
    '__x64_sys_ioprio_set',
    '__x64_sys_ioprio_get',
    '__x64_sys_inotify_init',
    '__x64_sys_inotify_add_watch',
    '__x64_sys_inotify_rm_watch',
    '__x64_sys_migrate_pages',
    '__x64_sys_openat',
    '__x64_sys_mkdirat',
    '__x64_sys_mknodat',
    '__x64_sys_fchownat',
    '__x64_sys_futimesat',
    '__x64_sys_newfstatat',
    '__x64_sys_unlinkat',
    '__x64_sys_renameat',
    '__x64_sys_linkat',
    '__x64_sys_symlinkat',
    '__x64_sys_readlinkat',
    '__x64_sys_fchmodat',
    '__x64_sys_faccessat',
    '__x64_sys_pselect6',
    '__x64_sys_ppoll',
    '__x64_sys_unshare',
    '__x64_sys_set_robust_list',
    '__x64_sys_get_robust_list',
    '__x64_sys_splice',
    '__x64_sys_tee',
    '__x64_sys_sync_file_range',
    '__x64_sys_vmsplice',
    '__x64_sys_move_pages',
    '__x64_sys_utimensat',
    '__x64_sys_epoll_pwait',
    '__x64_sys_signalfd',
    '__x64_sys_timerfd_create',
    '__x64_sys_eventfd',
    '__x64_sys_fallocate',
    '__x64_sys_timerfd_settime',
    '__x64_sys_timerfd_gettime',
    '__x64_sys_accept4',
    '__x64_sys_signalfd4',
    '__x64_sys_eventfd2',
    '__x64_sys_epoll_create1',
    '__x64_sys_dup3',
    '__x64_sys_pipe2',
    '__x64_sys_inotify_init1',
    '__x64_sys_preadv',
    '__x64_sys_pwritev',
    '__x64_sys_rt_tgsigqueueinfo',
    '__x64_sys_perf_event_open',
    '__x64_sys_recvmmsg',
    '__x64_sys_fanotify_init',
    '__x64_sys_fanotify_mark',
    '__x64_sys_prlimit64',
    '__x64_sys_name_to_handle_at',
    '__x64_sys_open_by_handle_at',
    '__x64_sys_clock_adjtime',
    '__x64_sys_syncfs',
    '__x64_sys_sendmmsg',
    '__x64_sys_setns',
    '__x64_sys_getcpu',
    '__x64_sys_process_vm_readv',
    '__x64_sys_process_vm_writev',
    '__x64_sys_kcmp',
    '__x64_sys_finit_module',
    '__x64_sys_sched_setattr',
    '__x64_sys_sched_getattr',
    '__x64_sys_renameat2',
    '__x64_sys_seccomp',
    '__x64_sys_getrandom',
    '__x64_sys_memfd_create',
    '__x64_sys_kexec_file_load',
    '__x64_sys_bpf',
    '__x64_sys_execveat',
    '__x64_sys_userfaultfd',
    '__x64_sys_membarrier',
    '__x64_sys_mlock2',
    '__x64_sys_copy_file_range',
    '__x64_sys_preadv2',
    '__x64_sys_pwritev2',
    '__x64_sys_pkey_mprotect',
    '__x64_sys_pkey_alloc',
    '__x64_sys_pkey_free',
    '__x64_sys_statx',
    '__x64_sys_io_pgetevents',
    '__x64_sys_rseq'
]

class RkCheckFunctions(gdb.Command):
    """Check the integrity of the functions in the kernel."""

    f = None
    s = None

    symbols = None
    headers = None

    #Key: symbol, value: tuple (size, code bytes from ELF file)
    code_dict = {}

    #Key: symbol, value: list of ranges for exclude bytes (relative to function entry!)
    altinstr_dict = {}
    paravirt_dict = {}

    def __init__(self):
        super(RkCheckFunctions, self).__init__("rk-check-functions", gdb.COMMAND_USER, gdb.COMMAND_DATA)

    # assuming rk-load-symbols has already been run
    def invoke(self, arg, from_tty):
        global file_g

        if file_g is None:
            print("no object file has been read in to calculate offsets, please run `rk-load-symbols` first")
            return None

        found = False
        for root, _, files in os.walk("."):
            if "xbfunc.gdb" in files:
                found = True
                gdb.execute(f'source {os.path.join(root, "xbfunc.gdb")}')

        if not found:
            print("could not locate the `xbfunc.gdb` file that is required to perform the function check")
            return None

        self.f = elffile.ELFFile(open(file_g, "rb"))
        self.s = self.f.get_section_by_name(".symtab")

        print("this might take a while")

        print("populating dictionaries...", end='', flush=True)
        self.fill_code_dict()
        print(self.code_dict)
        self.fill_altinstr_dict()
        # print(self.altinstr_dict)
        self.fill_paravirt_dict()
        # print(self.paravirt_dict)
        self.compare_functions()
        print(" done!")

    def fill_code_dict(self):
        sym_i = 0
        for symbol in self.s.iter_symbols():
            if sym_i == 100:
                break

            if symbol.entry["st_info"]["type"] == "STT_FUNC":
                name = symbol.name
                size = symbol.entry["st_size"]
            else:
                continue

            if name is None or ".cold." in name or ".part." in name or ".constprop." in name:
                continue

            addr = self.get_v_addr(name)
            if addr is None:
                continue

            objdump = subprocess.check_output(f"objdump -z --disassemble={name} {file_g}", shell=True)
            objdump = objdump.split(b"\n")[:-1]

            start = None
            end = None

            for i, s in enumerate(objdump):
                if start is not None:
                    if end is None and s == b'':
                        end = i
                else:
                    if name in s.decode(sys.stdout.encoding):
                        start = i + 1

                if start is not None and end is not None:
                    break

            if end is not None:
                objdump = objdump[start:end]
            else:
                objdump = objdump[start:]

            objdump = [line.split(b"\t") for line in objdump]

            elf_bytes = [line[1].decode(sys.stdout.encoding).strip().replace(' ', '') for line in objdump]
            elf_bytes = "".join(elf_bytes)

            self.code_dict[name] = (size, elf_bytes)
            sym_i += 1

    def fill_altinstr_dict(self):
        global file_g
        global v_off_g

        # alt_instr layout (read from elf section .altinstructions, size: 13 bytes):
        # .long offset          <-- Adress to instructions we ignore: addr = (__alt_instructions + cur (offset into .altinstructions)) + offset + v_off_g
        # .long repl_offset
        # .word cpuid
        # .byte instrlen
        # .byte replacementlen  <-- How many instructions we skip
        # .byte padlen

        sec = self.f.get_section_by_name(".altinstructions")
        data = sec.data()

        alt_instr_sz = 13
        replacementlen_off = 11

        i = 0
        while i < sec["sh_size"]:
            addr = (sec["sh_addr"] + i) + int.from_bytes(data[i:(i + 4)], byteorder="little", signed=True) + v_off_g
            replacementlen = int.from_bytes(data[(i + replacementlen_off):(i + replacementlen_off + 1)], byteorder="little", signed=False)

            info = gdb.execute(f"info symbol {addr}", to_string=True).split(" ")

            key = info[0]

            if info[1] == "+":
                t = int(info[2])
                value = range(t, t + replacementlen)
            else:
                value = range(replacementlen)

            if key in self.altinstr_dict:
                self.altinstr_dict[key].append(value)
            else:
                self.altinstr_dict[key] = [value]

            i = i + alt_instr_sz

    def fill_paravirt_dict(self):
        global file_g
        global v_off_g

        # paravirt_patch_site layout (read from elf section .parainstructions, size with padding: 16 bytes):
        # .quad instr          <-- Adress to instruction = instr + v_off_G
        # .byte instrtype
        # .byte len
        # .short clobbers
        # 4 byte padding

        sec = self.f.get_section_by_name(".parainstructions")
        data = sec.data()

        paravirt_patch_site_sz = 16
        len_off = 9

        i = 0
        while i < sec["sh_size"]:
            addr = int.from_bytes(data[i:(i + 8)], byteorder="little", signed=False) + v_off_g
            _len = int.from_bytes(data[(i + len_off):(i + len_off + 1)], byteorder="little", signed=False)

            info = gdb.execute(f"info symbol {addr}", to_string=True).split(" ")

            key = info[0]

            if info[1] == "+":
                t = int(info[2])
                value = range(t, t + _len)
            else:
                value = range(_len)

            if key in self.paravirt_dict:
                self.paravirt_dict[key].append(value)
            else:
                self.paravirt_dict[key] = [value]

            i = i + paravirt_patch_site_sz

    def compare_functions(self):
        for size, bytes in self.code_dict:
            pass

    def get_v_addr(self, symbol):
        try:
            return gdb.execute(f"x {symbol}", to_string=True).split(" ")[0]
        except:
            return None

RkCheckFunctions()

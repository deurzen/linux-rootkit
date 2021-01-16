import os

file = None

class RkLoadSymbols (gdb.Command):
    """Determine the KASLR-Offset and map the symbols."""

    v_off = 0
    symbol = "native_safe_halt"

    def __init__ (self):
        super (RkLoadSymbols, self).__init__ ("rk-load-symbols", gdb.COMMAND_USER, gdb.COMMAND_DATA)


    def invoke (self, arg, from_tty):
        self.get_v_off(arg)
        self.load_sym(arg)

    def load_sym (self, arg):
        v_off = hex(self.v_off)

        print(f"attempting to load symbols from \"{arg}\" with offset {v_off}")
        try:
            gdb.execute(f"add-symbol-file {arg} -o {self.v_off}")
        except:
            print("error loading symbol file, does it exist?")
            return None

    def get_v_off (self, arg):
        global file

        sym_addr = get_symbol_address(arg, self.symbol)

        if sym_addr is None:
            return None

        file = arg

        #minimal assumption: user is at login prompt
        try:
            real = gdb.execute("where", to_string=True).split(" ")[2]
        except:
            print("error executing where, is the VM running?")
            return None

        real_addr = int(real, 16)
        self.v_off = ((real_addr - sym_addr) & (~0xf))

RkLoadSymbols ()




class RkKaslrOffset (gdb.Command):
    """Output the calculated physical and virtual KASLR offset."""

    symbol = "native_safe_halt"
    obj_addr = None

    def __init__ (self):
        super (RkKaslrOffset, self).__init__ ("rk-kaslr-offset", gdb.COMMAND_USER, gdb.COMMAND_DATA)

    # assuming rk-load-symbols has already been run
    def invoke (self, arg, from_tty):
        global file

        if file is None:
            print("no object file has been read in to calculate offsets, please run `rk-load-symbols` first.")
            return None

        self.obj_addr = get_symbol_address(file, self.symbol)
        obj_addr = hex(self.obj_addr)

        print(f"address for symbol `{self.symbol}` inside object file \"{file}\" is {obj_addr}")

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


    def get_off (self, addr):
        global file

        if self.obj_addr is None:
            return None

        real_addr = int(addr, 16)

        return hex((real_addr - self.obj_addr) & (~0xf))


RkKaslrOffset ()




class RkSyscallCheck (gdb.Command):
    """Check the integrity of the syscall table. Run rk-load-symbols first."""

    def __init__ (self):
        super (RkSyscallCheck, self).__init__ ("rk-syscall-check", gdb.COMMAND_USER, gdb.COMMAND_DATA)


    def invoke (self, arg, from_tty):
        print("Soose!")

RkSyscallCheck ()




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
        print(f"error retrieving address from '{arg}', did you specify a file?")
        return None

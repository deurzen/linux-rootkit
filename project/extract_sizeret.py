#!/usr/bin/python3

import gdb
import re
import json

# allocator mapped to register containing size argument
break_arg = {
    "kmem_cache_alloc_trace": "rdx",
    "kmalloc_order": "rdi",
    "__kmalloc": "rdi",
    "vmalloc": "rdi",
    "vzalloc": "rdi",
    "vmalloc_user": "rdi",
    "vmalloc_node": "rdi",
    "vzalloc_node": "rdi",
    "vmalloc_exec": "rdi",
    "vmalloc_32": "rdi",
    "vmalloc_32_user": "rdi",
}

free_funcs = {
    "kfree": "rdi",
    "vfree": "rdi",
    "kmem_cache_free": "rsi"
}

entries = set()
exits = set()
types = {}

# Maps address to tuples of (type, size, caller)
mem_map = {}

size_at_entry = None

debug = True

class RkPrintMem(gdb.Command):
    def __init__(self):
        super(RkPrintMem, self).__init__("rk-print-mem", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global mem_map

        if not mem_map:
            return None

        for addr, (type, size, caller) in mem_map.items():
            print(f"type: {type[7:]}, size: {size} B, addr: {hex(addr)}, caller: {caller}")

RkPrintMem()

class RkDebug(gdb.Command):
    def __init__(self):
        super(RkDebug, self).__init__("rk-debug", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global debug
        debug = not debug
        print(f"Debug messages set to {debug}")

RkDebug()

class RkPrintData(gdb.Command):
    """Print data of a block in the memory map.\nUsage: rk-data <addr>"""

    def __init__(self):
        super(RkPrintData, self).__init__("rk-data", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global mem_map

        if int(arg, 16) in mem_map:
            (type, size, _) = mem_map[int(arg, 16)]

            try:
                data = gdb.execute(f"print *(({type[7:]}){arg})", to_string=True)
                print(f"resolving {arg} to {type}\n")
                print(data)
            except:
                print(f"could not resolve {type} at {arg}")
                return
        else:
            print(f"{arg} does not point to the start of a kernel-allocated portion of the heap")

RkPrintData()


class EntryExitBreakpoint(gdb.Breakpoint):
    def __init__(self, b):
        gdb.Breakpoint.__init__(self, b)

    def stop(self):
        frame = gdb.newest_frame()

        if not frame.is_valid():
            return False

        if frame.unwind_stop_reason() != gdb.FRAME_UNWIND_NO_REASON:
            return False

        typeret = self.type_lookup(frame)

        if typeret is None:
            return False

        (type, caller) = typeret

        extret = self.extract(frame)

        if extret is None:
            return False

        (size, address) = extret

        mem_map[address] = (type, size, caller)

        if debug:
            print("Allocating ", (type, size, caller), "at", hex(address))

        return False

    def extract(self, frame):
        global break_arg
        global entries
        global exits
        global size_at_entry

        if self.number in entries:
            # extract size from correct register
            if int(frame.read_register(break_arg[frame.name()])) > 0:
                size_at_entry = int(frame.read_register(break_arg[frame.name()]))
                return None

        elif self.number in exits and size_at_entry is not None:
            # extract return value, return tuple (size, address)
            ret = (size_at_entry, int(frame.read_register('rax')) & (2 ** 64 - 1))
            size_at_entry = None
            return ret

    def type_lookup(self, frame):
        global types

        f_iter = frame.older()

        while f_iter is not None and f_iter.is_valid():
            sym = f_iter.find_sal()
            symtab = sym.symtab

            if symtab is None:
                break

            key = f"{symtab.filename}:{sym.line}"

            if key in types:
                return (types[key], key)

            f_iter = f_iter.older()

        return None

class FreeBreakpoint(gdb.Breakpoint):
    def __init__(self, b):
        gdb.Breakpoint.__init__(self, b)

    def stop(self):
        global mem_map
        global free_funcs
        global debug

        frame = gdb.newest_frame()

        if not frame.is_valid():
            return False

        address = int(frame.read_register(free_funcs[frame.name()])) & (2 ** 64 - 1)

        if address is None:
            return False

        if address in mem_map:
            if debug:
                print("Freeing ", mem_map[address], "at", hex(address))
            mem_map.pop(address)

        return False

class Stage3():
    breakpoints = []

    dictfile = ".dict"

    def __init__(self):
        global break_arg
        global entries
        global exits
        global types

        gdb.execute("set pagination off")

        with open(self.dictfile, 'r') as dct:
            types = json.load(dct)

        for b in break_arg.keys():
            # set breakpoint at function entry, to extract size
            b_entry = EntryExitBreakpoint(b)
            self.breakpoints.append(b_entry)
            entries.add(b_entry.number)

            # lookup offset from function entry to retq, account for possibility of >1 retq occurrence
            disass = gdb.execute(f"disass {b}", to_string=True).strip().split("\n")
            disass = [instr.split("\t") for instr in disass]
            instrs = [(instr[0].strip(), instr[1].split(" ")[0].strip()) for instr in disass if len(instr) > 1]
            retqs = [int(loc.split("<")[1].split(">")[0]) for (loc, instr) in instrs if instr == "ret" or instr == "retq"]

            # set breakpoints at function exits (retq), to extract return value
            for retq in retqs:
                b_exit = EntryExitBreakpoint(f"*{hex(int(str(gdb.parse_and_eval(b).address).split(' ')[0], 16) + retq)}")
                self.breakpoints.append(b_exit)
                exits.add(b_exit.number)

        for f in free_funcs:
            FreeBreakpoint(f)

Stage3()

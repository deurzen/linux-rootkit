#!/usr/bin/python3

import gdb
import re
import json
from enum import IntEnum

# allocator |-> register containing size argument
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

break_arg_access = {
    "kmem_cache_alloc_node": ("rdi", "struct kmem_cache *", "object_size"),
}

# { type |-> [(access chain, critical value)] }
#
# Make sure each entry in an access chain (apart from the last entry)
# is a pointer, as it is dereferenced to obtain the next field
#
# If `critical_value` is set to None, any changes to the field are reported
watch_write_access_chain = {
    "struct task_struct *": [
        # (((struct task_struct *)<address>)->real_cred)->uid
        (["real_cred", "uid"], 0),
    ]
}

avail_hw_breakpoints = 4
watchpoints = {}
n_watchpoints = 0

# memory freeing functions |-> register with argument
free_funcs = {
    "kfree": "rdi",
    "vfree": "rdi",
    "kmem_cache_free": "rsi",
}

entries = set()
exits = set()
types = {}

# Maps address to tuples of (type, size, caller)
mem_map = {}

size_at_entry = None

class DebugLevel(IntEnum):
    __order__ = 'WARN INFO TRACE'
    WARN = 0
    INFO = 1
    TRACE = 2

debug_level = DebugLevel.INFO

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
        global debug_level
        debug_level = DebugLevel((int(debug_level) + 1) % len(list(map(int, DebugLevel))))
        print(f"debug_level messages set to {debug_level.name}")

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
        global avail_hw_breakpoints
        global watchpoints
        global n_watchpoints
        global watch_write_access_chain
        global mem_map

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

        if type[7:] in watch_write_access_chain:
            access_chains = watch_write_access_chain[type[7:]]
            for access_chain, critical_value in access_chains:
                if n_watchpoints + len(access_chain) <= avail_hw_breakpoints:
                    watchpoint = WriteWatchpoint(address, type[7:], access_chain, critical_value)

                    if address in watchpoints:
                        watchpoints[address].append(watchpoint)
                    else:
                        watchpoints[address] = [watchpoint]

                    n_watchpoints += len(access_chain)
                    if n_watchpoints >= avail_hw_breakpoints:
                        break

        if debug_level >= DebugLevel.TRACE:
            print("Allocating", (type, size, caller), "at", hex(address))

        return False

    def extract(self, frame):
        global break_arg
        global entries
        global exits
        global size_at_entry

        if self.number in entries:
            # extract size from correct register
            if frame.name() in break_arg:
                size = int(frame.read_register(break_arg[frame.name()]))
                if size > 0:
                    size_at_entry = size
                    return None

            elif frame.name() in break_arg_access:
                (reg, type, field) = break_arg_access[frame.name()]
                size = int(gdb.execute(f"p (({type})${reg})->{field}",
                                       to_string=True).strip().split(" ")[2])

                if size > 0:
                    size_at_entry = size
                    return None

        elif self.number in exits and size_at_entry is not None:
            # extract return value, return tuple (size, address)
            ret = (size_at_entry, int(frame.read_register('rax')) & (2 ** 64 - 1))
            size_at_entry = None
            return ret

        return None

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
        global watchpoints
        global n_watchpoints
        global free_funcs
        global debug_level

        frame = gdb.newest_frame()

        if not frame.is_valid():
            return False

        address = int(frame.read_register(free_funcs[frame.name()])) & (2 ** 64 - 1)

        if address is None:
            return False

        if address in watchpoints:
            for watchpoint in watchpoints[address]:
                if debug_level >= DebugLevel.INFO:
                    print("Deleting watchpoint on", watchpoint.current_chain,
                          "which is at", hex(address))

                watchpoint.delete()
                n_watchpoints -= len(watchpoint.access_chain)

            del(watchpoints[address])

        if address in mem_map:
            if debug_level >= DebugLevel.TRACE:
                print("Freeing", mem_map[address], "at", hex(address))
            mem_map.pop(address)

        return False

class WriteWatchpoint(gdb.Breakpoint):
    address = None
    type = None
    access_chain = None
    critical_value = None
    previous_value = None
    previous_value_print = None

    def __init__(self, address, type, access_chain, critical_value):
        global watchpoints

        self.address = address
        self.type = type
        self.access_chain = access_chain
        self.critical_value = critical_value

        current_chain = f"(({type}){hex(address)})"
        for field in access_chain:
            current_chain = "(" + current_chain + "->" + field + ")"

        self.previous_value = self.get_value(current_chain)
        self.previous_value_print = self.get_value_print(current_chain)

        if debug_level >= DebugLevel.INFO:
            print("Setting watchpoint on", current_chain, "which is at", hex(address))

        self.current_chain = current_chain
        gdb.Breakpoint.__init__(self, current_chain, internal=True, type=gdb.BP_WATCHPOINT)

    def stop(self):
        current_chain = f"(({self.type}){hex(self.address)})"
        for field in self.access_chain:
            current_chain = "(" + current_chain + "->" + field + ")"

        current_value = self.get_value(current_chain)
        current_value_print = self.get_value_print(current_chain)

        if self.previous_value is not None and current_value is not None:
            if self.previous_value != current_value:
                if debug_level >= DebugLevel.INFO:
                    print(current_chain, "changed from", self.previous_value_print,
                          "to", current_value_print)

                if debug_level >= DebugLevel.WARN:
                    current_value = int.from_bytes(bytes(current_value), "little")
                    if current_value == self.critical_value:
                        print(f"WARNING: critical value {self.critical_value} set to {current_chain}")

        self.previous_value = current_value
        self.previous_value_print = current_value_print

        return False

    def get_value_print(self, name):
        try:
            return "\n".join([line.strip() for line in
                              gdb.execute(f"p {name}", to_string=True).strip().split("\n")[1:-1]])
        except:
            return None

    def get_value(self, name):
        try:
            size = int(gdb.parse_and_eval(f"sizeof({name})"))
        except:
            return None

        try:
            address = int(gdb.execute(f"p &({name})", to_string = True).strip().split(" ")[-1], 16)
        except:
            return None

        try:
            return gdb.selected_inferior().read_memory(address, size)
        except:
            return None

class Stage3():
    breakpoints = []

    dictfile = ".dict"

    def __init__(self):
        global break_arg
        global entries
        global exits
        global types

        # system can hang when pagination is on
        gdb.execute("set pagination off")

        # for rk-data
        gdb.execute("set print pretty on")

        with open(self.dictfile, 'r') as dct:
            types = json.load(dct)

        types["./kernel/fork.c:812"] = "type = struct task_struct *"

        for b in (break_arg.keys() | break_arg_access.keys()):
            # set breakpoint at function entry, to extract size
            b_entry = EntryExitBreakpoint(b)
            self.breakpoints.append(b_entry)
            entries.add(b_entry.number)

            # lookup offset from function entry to ret{,q}, account for possibility of >1 ret{,q} occurrence
            disass = gdb.execute(f"disass {b}", to_string=True).strip().split("\n")
            disass = [instr.split("\t") for instr in disass]
            instrs = [(instr[0].strip(), instr[1].split(" ")[0].strip()) for instr in disass if len(instr) > 1]
            retqs = [int(loc.split("<")[1].split(">")[0]) for (loc, instr) in instrs if instr == "ret" or instr == "retq"]

            # set breakpoints at function exits (ret{,q}), to extract return value
            for retq in retqs:
                b_exit = EntryExitBreakpoint(f"*{hex(int(str(gdb.parse_and_eval(b).address).split(' ')[0], 16) + retq)}")
                self.breakpoints.append(b_exit)
                exits.add(b_exit.number)

        for f in free_funcs:
            FreeBreakpoint(f)

Stage3()

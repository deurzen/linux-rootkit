#!/usr/bin/python3

import gdb

# allocator mapped to register containing size argument
break_arg = {
    "kmem_cache_alloc_trace": "$rdx",
    "kmalloc_order": "$rdi",
    "__kmalloc": "$rdi",
}

# allocator mapped to offset to retq
break_retq = {
    "kmem_cache_alloc_trace": 232,
    "kmalloc_order": 47,
    "__kmalloc": 265,
}

entries = set()
exits = set()

prev_entry = None

class EntryExitBreakpoint(gdb.Breakpoint):
    def __init__(self, b):
        gdb.Breakpoint.__init__(self, b)

    def stop(self):
        global break_arg
        global args
        global entries
        global exits
        global prev_entry

        f = gdb.newest_frame()

        if not f.is_valid():
            return False

        if f.unwind_stop_reason() != gdb.FRAME_UNWIND_NO_REASON:
            return False

        if self.number in entries:
            # extract size from correct register, print for now
            prev_entry = f"size={gdb.parse_and_eval(break_arg[f.name()])}"

        elif self.number in exits:
            if prev_entry is None:
                return False

            # extract return value, print for now
            print(f"f{prev_entry}, ret={hex(int(str(gdb.parse_and_eval('$rax')), 10) & (2 ** 64 - 1))}", flush=True)
            prev_entry = None

        # TODO: extract filename

        return False

class Stage3():
    breakpoints = []

    def __init__(self):
        global break_retq
        global entries
        global exits

        for b, retq in break_retq.items():
            # set breakpoint at function entry, to extract size
            b_entry = EntryExitBreakpoint(b)
            self.breakpoints.append(b_entry)
            entries.add(b_entry.number)

            # set breakpoint at function exit (retq), to extract return value
            b_exit = EntryExitBreakpoint(f"*{hex(int(str(gdb.parse_and_eval(b).address).split(' ')[0], 16) + retq)}")
            self.breakpoints.append(b_exit)
            exits.add(b_exit.number)

Stage3()

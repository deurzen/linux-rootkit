# LiveDM - Proof of Concept

This a small user's guide to supplement the slides.



## Usage

### Up-front Setup

1. Clone the kernel sources. The version has to match that of the running kernel (including the sublevel)!
2. Run `occ.sh`. It takes the path the the kernel sources as its argument and generates all occurrences of our functions of interest.
3. Fire up the VM, attach GDB, and source `type_dict.py`. This will, based on the results of `occ.sh`, generate the dictionary. (Note: this will take ~5 min)
4. The setup is now ready

### Memory Tracing

Simply source `livedm.py` from within GDB. All memory allocations / frees for selected defined functions will now be tracked.

Commands available:

```c
rk-print-mem		Prints the currently allocated memory
rk-debug			Toggle between different output levels*
rk-data <addr>		Output the data inside a buffer/struct; argument is address of rk-print-mem output
```



Output levels:*

```
WARN 	# warn when critical fields (in this case task_struct->cred.uid) change to suspicious values
INFO 	# also print watchpoint additions
TRACE 	# also print every memory allocation
```


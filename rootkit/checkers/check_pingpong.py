#!/usr/bin/env python3

import fcntl
import os
import unittest
import argparse
import sys

IOCTL_PING = 0xc0084000
IOCTL_INVALID = IOCTL_PING + 1

proc_fd = None

class TestIOCTLPing(unittest.TestCase):
    def test_ping(self):
        arg = b"PING"
        res = fcntl.ioctl(proc_fd, IOCTL_PING, arg)
        self.assertEqual(res, b"PONG")

    def test_duck(self):
        arg = b"DUCK"
        res = fcntl.ioctl(proc_fd, IOCTL_PING, arg)
        self.assertEqual(res, b"DUCK")

    def test_invalid(self):
        with self.assertRaises(IOError):
            fcntl.ioctl(proc_fd, IOCTL_PING, 0)

    def test_invalid2(self):
        with self.assertRaises(IOError):
            fcntl.ioctl(proc_fd, IOCTL_INVALID, 0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("proc_file")
    args, remaining = parser.parse_known_args()
    proc_fd = os.open(args.proc_file, os.O_RDWR)

    unittest.main(argv=[sys.argv[0]] + remaining)

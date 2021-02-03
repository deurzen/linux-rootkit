###################################################################
# Format of input file:
# First line:
#   directory prefix to prune
#
# Rest of lines:
#    <filename> <func or global> <line> <var or call to free>
###################################################################

###################################################################
# Format of dictionary:
# ('filename:line') |-> ('type')
###################################################################

import json
import os, errno
import gdb

def delfile(name):
    try:
        os.remove(name)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise

class CodeDict():
    in_n = ".funcs"
    out_n = ".dict"

    inf = None
    outf = None

    dict = {}

    def __init__(self):
        self.setup()
        self.parse()

        self.outf.write(json.dumps(self.dict))

    def setup(self):
        try:
            self.inf = open(self.in_n, "r")
        except:
            print(f"No file {in_n} found! Run occ.sh first")
            raise

        delfile(self.out_n)
        self.outf = open(self.out_n, "w+")

    def parse(self):
        ignore = ["*", "->", "(", ")", "[", "]"]

        line = self.inf.readline()
        dir = len(line) - 1 if line[-1] == "/" else len(line)

        for line in self.inf.readlines():
            # Remove directory prefix, insert ./ to reflect the frame representation of source file in gdb
            l = ("./" + (line[dir:])).split(" ")

            src = l[0]
            fn = l[1]
            lnr = l[2]
            var = l[3]

            if any(s in var for s in ignore):
                continue

            if fn == "<global>":
                try:
                    type_info = gdb.execute(f"whatis '{src}'::{var}", to_string = True)
                except:
                    continue
            else:
                try:
                    type_info = gdb.execute(f"whatis '{fn}'::{var}", to_string = True)
                except:
                    continue

            if type_info is not None:
                key = f"{src}:{lnr}"
                self.dict[key] = type_info.replace('\n','')
CodeDict()

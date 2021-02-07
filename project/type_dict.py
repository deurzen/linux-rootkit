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
import re

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
        print("Creating dictionary, this can take 5 minutes or more..")
        self.parse()
        print("..done!")

        self.outf.write(json.dumps(self.dict))

    def setup(self):
        try:
            self.inf = open(self.in_n, "r")
        except:
            print(f"{in_n} file not found, run `occ.sh` first")
            raise

        delfile(self.out_n)
        self.outf = open(self.out_n, "w+")

    def parse(self):
        for line in self.inf.readlines():
            # Insert ./ to reflect the frame representation of source file in gdb
            l = ("./" + line).split(" ")

            if len(l) < 5 or l[4] != "=":
                continue

            src = l[0]
            fn = l[1]
            lnr = l[2]
            var = l[3]

            # ugly, but necessary since gdb does not like $ whatis 'dup_task_struct'::tsk
            # and task_struct is too important to give up
            if "dup_task_struct" in line:
                key = f"{src}:{lnr}"
                val = "type = struct task_struct *"
                continue

            var = re.split('\-\>|\.', var)
            var[0] = re.sub('[.*?]', '', var[0])

            if fn == "<global>":
                try:
                    type_info = gdb.execute(f"whatis '{src}'::{var}", to_string = True)
                except:
                    continue
            else:
                try:
                    type_info = gdb.execute(f"whatis '{fn}'::{var[0]}", to_string = True)
                except:
                    continue

            if len(var) > 1:
                type_info = self.parse_chain(type_info[7:], var, 1)

            if type_info is not None:
                key = f"{src}:{lnr}"
                self.dict[key] = type_info.replace('\n','')

    def parse_chain(self, next_type, chain, index):
        # we're at the final field access, return its type
        if index >= len(chain):
            return "type = " + next_type.strip()

        # we need to look for the type of the next field in the field access chain
        field = chain[index]
        field = re.sub('\[.*?\]', '', field)

        # obtain the fields of the compound type to search through
        ptype = gdb.execute(f"ptype {next_type}", to_string = True).split("\n")[1:-2]

        # loop over the compound type's fields, attempt to match field we're looking for
        for f in ptype:
            # account for possible bit field
            bitfield = f.rfind(':')
            if bitfield > 0:
                f = f[:bitfield]

            # account for possible array
            f = re.sub('\[.*?\]', '', f)

            # match on field name, everything preceding it is its type
            name = re.search(f"[^_A-Za-z]({field})[^_A-Za-z0-9]", f)

            # field name was found, extract type and recurse if necessary
            if bool(name):
                return self.parse_chain(f[:name.start(1)], chain, index + 1)

        # field not found
        return None


CodeDict()

import os

class RKLoadSymbols (gdb.Command):
  """Determine the KASLR-Offset and map the symbols."""

  v_off = 0
  p_off = 0

  symbol = "native_safe_halt"

  def __init__ (self):
    super (RKLoadSymbols, self).__init__ ("rk-load-symbols", gdb.COMMAND_USER, gdb.COMMAND_DATA)


  def invoke (self, arg, from_tty):
    self.get_v_off(arg)
    self.load_sym(arg)

  def load_sym (self, arg):
    print(f"Trying to load symbols from {arg} with offset {self.v_off}..")
    try:
        gdb.execute(f"add-symbol-file {arg} -o {self.v_off}")
    except:
        print("Error loading symbol file, does it exist?")
        return None

  def get_v_off (self, arg):
    sym_addr = get_symbol_address(arg, self.symbol)

    if sym_addr is None:
      return None

    #minimal assumption: user is at login prompt 
    try:
      real = gdb.execute("where", to_string=True).split(" ")[2]
    except:
      print("Error executing where, is the VM running?")
      return None

    real_addr = int(real, 16)

    self.v_off = (real_addr - sym_addr - 0xe)
    
RKLoadSymbols ()




class RKSyscallCheck (gdb.Command):
  """Check the integrity of the syscall table. Run rk-load-symbols first."""

  def __init__ (self):
    super (RKSyscallCheck, self).__init__ ("rk-syscall-check", gdb.COMMAND_USER, gdb.COMMAND_DATA)


  def invoke (self, arg, from_tty):
    print("Soose!")

RKSyscallCheck ()




#Return address of symbol from file through nm
def get_symbol_address(file, symbol):
  stream = os.popen(f"nm {file} | grep -w {symbol} | cut -d \" \" -f1")
  sym = stream.read()
  stream.close()
  
  #symbol address _before_ randomization
  try:
    sym_addr = int(sym, 16)
    return sym_addr
  except:
    print(f"Error retrieving address from '{arg}', did you specify a file?")
    return None

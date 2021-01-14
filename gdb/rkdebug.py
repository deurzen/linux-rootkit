class RKLoadSymbols (gdb.Command):
  """Determine the KASLR-Offset and map the symbols."""

  def __init__ (self):
    super (RKLoadSymbols, self).__init__ ("rk-load-symbols", gdb.COMMAND_USER, gdb.COMMAND_DATA)

  def invoke (self, arg, from_tty):
    print(f"Trying to load symbols from {arg}..")
    try:
        gdb.execute(f"add-symbol-file {arg}")
    except:
        print("Error loading symbol file, does it exist?")

RKLoadSymbols ()
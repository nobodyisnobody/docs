# generic arm shellcoding template
from pwn import *

context.update(arch="mips", os="linux", endian="big")
# choose your terminal for debugging (you should set pos on screen too for graphic terminal)
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
#context.terminal = ["tmux", "splitw", "-h"]	# for command line terminal, launch tmux first before launching python code
context.log_level = 'error'

if (len(sys.argv) < 1):
  print('%s [RUN or GDB or EXE]' % (sys.argv[0]))
  exit(1)

def dumpit(shellc):
  print('shellcode length: {:d} bytes'.format(len(shellc)))
  # dump as hex number array
  print('\n\"\\x{}\"'.format('\\x'.join([format(b, '02x') for b in bytearray(shellc)])))
  # dump as C array
  print("\nunsigned char shellc[] = {{{}}};".format(", ".join([format(b, '#02x') for b in bytearray(shellc)])))
  # dump as hex array
  print('\nproblematic values are highlighted (00,0a,20)...\n')
  print(hexdump(shellc, highlight=b'\x0a\x20\x00'))

shellc = asm ('''
''')

# remove padding nop added by gas eventually
#if shellc[-2:] == b'\x00\xbf':
#	shellc=shellc[0:-2]

dumpit(shellc)

if args.EXE:
  ELF.from_bytes(shellc).save('binary')

if args.RUN:
  p = run_shellcode(shellc)
  p.interactive()
elif args.GDB:
  p = debug_shellcode(shellc, gdbscript='''
    # set your pwndbg path here
    source ~/gdb.plugins/pwndbg/gdbinit.py
    set show-flags on
    set show-retaddr-reg on
    set show-compact-regs on
    context
  ''')
  p.interactive()

